#!/usr/bin/env python3
"""
SMTP Tunnel Client - Fast Binary Mode

Version: 1.3.0

Protocol:
1. SMTP handshake (EHLO, STARTTLS, AUTH) - looks like real SMTP
2. After AUTH, send "BINARY" to switch to streaming mode
3. Full-duplex binary protocol - data flows as fast as TCP allows

Features:
- Multi-user support (username + secret authentication)
"""

import asyncio
import ssl
import logging
import argparse
import struct
import time
import os
import socket
import random
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

from common import (
    ActiveFrameBuffer,
    ClientConfig,
    CONTROL_CHANNEL_ID,
    FRAME_CLOSE,
    FRAME_CONNECT,
    FRAME_CONNECT_FAIL,
    FRAME_CONNECT_OK,
    FRAME_DATA,
    FRAME_KEEPALIVE,
    FRAME_KEEPALIVE_ACK,
    FrameProtocolError,
    IPWhitelist,
    MAX_CHANNEL_ID,
    MODE_NORMAL,
    MODE_REVERSE_LISTEN,
    ReverseListenConfig,
    SMTPConfig,
    TunnelConfig,
    TunnelCrypto,
    UserConfig,
    build_reverse_listen_config,
    build_smtp_config,
    build_tunnel_config,
    get_client_mode,
    encode_frame,
    load_config,
    make_connect_payload,
    validate_tcp_port,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('smtp-tunnel-client')


# ============================================================================
# SOCKS5
# ============================================================================

class SOCKS5:
    VERSION = 0x05
    AUTH_NONE = 0x00
    CMD_CONNECT = 0x01
    ATYP_IPV4 = 0x01
    ATYP_DOMAIN = 0x03
    ATYP_IPV6 = 0x04
    REP_SUCCESS = 0x00
    REP_FAILURE = 0x01


@dataclass
class Channel:
    channel_id: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    host: str
    port: int
    connected: bool = False


# ============================================================================
# Tunnel Client
# ============================================================================

class TunnelClient:
    def __init__(
        self,
        config: ClientConfig,
        ca_cert: str = None,
        tunnel_config: TunnelConfig = None,
        smtp_config: SMTPConfig = None
    ):
        self.config = config
        self.ca_cert = ca_cert
        self.tunnel_config = tunnel_config or TunnelConfig()
        self.smtp_config = smtp_config or SMTPConfig()

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False

        self.channels: Dict[int, Channel] = {}
        self.opening_channels: Set[int] = set()
        self.pending_channel_data: Dict[int, List[bytes]] = {}
        self.pending_close_channels: Set[int] = set()
        self.pending_channel_data_limit = 1024 * 1024
        self.next_channel_id = 1
        self.channel_lock = asyncio.Lock()

        self.connect_events: Dict[int, asyncio.Event] = {}
        self.connect_results: Dict[int, bool] = {}

        self.write_lock = asyncio.Lock()
        self.keepalive_ack_event = asyncio.Event()

    async def connect(self) -> bool:
        """Connect and do SMTP handshake, then switch to binary mode."""
        try:
            logger.info(f"Connecting to {self.config.server_host}:{self.config.server_port}")

            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.server_host, self.config.server_port),
                timeout=30.0
            )

            # SMTP Handshake
            if not await self._smtp_handshake():
                return False

            self.connected = True
            logger.info("Connected - binary mode active")
            return True

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    async def _smtp_handshake(self) -> bool:
        """Do SMTP handshake then switch to binary."""
        try:
            # Wait for greeting
            line = await self._read_line()
            if not line or not line.startswith('220'):
                return False

            # EHLO
            await self._send_line(f"EHLO {self.smtp_config.ehlo_name}")
            if not await self._expect_250():
                return False

            # STARTTLS
            await self._send_line("STARTTLS")
            line = await self._read_line()
            if not line or not line.startswith('220'):
                return False

            # Upgrade TLS
            await self._upgrade_tls()

            # EHLO again
            await self._send_line(f"EHLO {self.smtp_config.ehlo_name}")
            if not await self._expect_250():
                return False

            # AUTH
            timestamp = int(time.time())
            crypto = TunnelCrypto(self.config.secret, is_server=False)
            token = crypto.generate_auth_token(timestamp, self.config.username)

            await self._send_line(f"AUTH PLAIN {token}")
            line = await self._read_line()
            if not line or not line.startswith('235'):
                logger.error(f"Auth failed: {line}")
                return False

            # Switch to binary mode
            await self._send_line("BINARY")
            line = await self._read_line()
            if not line or not line.startswith('299'):
                logger.error(f"Binary mode failed: {line}")
                return False

            return True

        except Exception as e:
            logger.error(f"Handshake error: {e}")
            return False

    async def _upgrade_tls(self):
        """Upgrade to TLS."""
        ssl_context = ssl.create_default_context()
        if self.ca_cert:
            if os.path.exists(self.ca_cert):
                ssl_context.load_verify_locations(self.ca_cert)
                logger.debug(f"TLS certificate verification enabled with CA: {self.ca_cert}")
            else:
                logger.warning(
                    f"CA certificate configured but not found: {self.ca_cert}; "
                    "TLS certificate verification is disabled"
                )
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
        else:
            logger.warning("No ca_cert configured; TLS certificate verification is disabled")
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        transport = self.writer.transport
        protocol = self.writer._protocol
        loop = asyncio.get_event_loop()

        new_transport = await loop.start_tls(
            transport, protocol, ssl_context,
            server_hostname=self.config.server_host
        )

        self.writer._transport = new_transport
        self.reader._transport = new_transport
        logger.debug("TLS established")

    async def _send_line(self, line: str):
        self.writer.write(f"{line}\r\n".encode())
        await self.writer.drain()

    async def _read_line(self) -> Optional[str]:
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=60.0)
            if not data:
                return None
            return data.decode('utf-8', errors='replace').strip()
        except:
            return None

    async def _expect_250(self) -> bool:
        while True:
            line = await self._read_line()
            if not line:
                return False
            if line.startswith('250 '):
                return True
            if line.startswith('250-'):
                continue
            return False

    async def start_receiver(self):
        """Start background task to receive frames from server."""
        asyncio.create_task(self._receiver_loop())

    async def _receiver_loop(self):
        """Receive and dispatch frames from server."""
        frame_buffer = ActiveFrameBuffer()

        while self.connected:
            try:
                chunk = await asyncio.wait_for(self.reader.read(65536), timeout=300.0)
                if not chunk:
                    break
                frame_buffer.append(chunk)

                for frame in frame_buffer.get_frames():
                    await self._handle_frame(frame.frame_type, frame.channel_id, frame.payload)

            except asyncio.TimeoutError:
                continue
            except FrameProtocolError as e:
                logger.warning(f"Malformed tunnel frame from server: {e}")
                break
            except Exception as e:
                logger.error(f"Receiver error: {e}")
                break

        self.connected = False

    async def keepalive_loop(self):
        """Send optional application-level keepalives and enforce timeout."""
        interval = float(self.tunnel_config.keepalive_interval or 0)
        timeout = float(self.tunnel_config.keepalive_timeout or 0)
        if interval <= 0:
            return

        if timeout <= 0:
            timeout = 30.0

        logger.info(f"Keepalive enabled: interval={interval:g}s timeout={timeout:g}s")

        while self.connected:
            try:
                await asyncio.sleep(interval)
                if not self.connected:
                    break

                self.keepalive_ack_event.clear()
                await self.send_frame(FRAME_KEEPALIVE, CONTROL_CHANNEL_ID)
                await asyncio.wait_for(self.keepalive_ack_event.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("Keepalive timeout; reconnecting tunnel")
                self.connected = False
                if self.writer:
                    self.writer.close()
                break
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.debug(f"Keepalive error: {e}")
                self.connected = False
                break

    async def _handle_frame(self, frame_type: int, channel_id: int, payload: bytes):
        """Handle received frame."""
        if frame_type == FRAME_CONNECT_OK:
            if channel_id in self.connect_events:
                self.opening_channels.add(channel_id)
                self.connect_results[channel_id] = True
                self.connect_events[channel_id].set()
            else:
                logger.debug(f"Ignoring CONNECT_OK for unknown ch={channel_id}")

        elif frame_type == FRAME_CONNECT_FAIL:
            if channel_id in self.connect_events:
                self.connect_results[channel_id] = False
                self.connect_events[channel_id].set()
            else:
                logger.debug(f"Ignoring CONNECT_FAIL for unknown ch={channel_id}")
            self.opening_channels.discard(channel_id)

        elif frame_type == FRAME_DATA:
            channel = self.channels.get(channel_id)
            if channel and channel.connected:
                try:
                    channel.writer.write(payload)
                    await channel.writer.drain()
                except:
                    await self._close_channel(channel)
            elif channel_id in self.opening_channels or channel_id in self.connect_events:
                pending = self.pending_channel_data.setdefault(channel_id, [])
                pending_size = sum(len(item) for item in pending)
                if pending_size + len(payload) <= self.pending_channel_data_limit:
                    pending.append(payload)
                    logger.debug(f"Buffered early DATA for ch={channel_id}")
                else:
                    logger.warning(f"Dropping early DATA for ch={channel_id}: buffer limit exceeded")
            else:
                logger.debug(f"Dropping DATA for unknown ch={channel_id}")

        elif frame_type == FRAME_CLOSE:
            channel = self.channels.get(channel_id)
            if channel:
                await self._close_channel(channel)
            elif channel_id in self.opening_channels or channel_id in self.connect_events:
                self.pending_close_channels.add(channel_id)
            else:
                logger.debug(f"Ignoring CLOSE for unknown ch={channel_id}")

        elif frame_type == FRAME_KEEPALIVE:
            await self.send_frame(FRAME_KEEPALIVE_ACK, CONTROL_CHANNEL_ID)

        elif frame_type == FRAME_KEEPALIVE_ACK:
            self.keepalive_ack_event.set()

    async def send_frame(self, frame_type: int, channel_id: int, payload: bytes = b''):
        """Send frame to server."""
        if not self.connected or not self.writer:
            return
        async with self.write_lock:
            try:
                frame = encode_frame(frame_type, channel_id, payload)
                self.writer.write(frame)
                await self.writer.drain()
            except FrameProtocolError as e:
                logger.error(f"Refusing to send malformed tunnel frame: {e}")
            except Exception:
                self.connected = False

    async def _allocate_channel_id(self) -> int:
        """Allocate an unused channel id, wrapping safely at 65535."""
        async with self.channel_lock:
            for _ in range(MAX_CHANNEL_ID):
                channel_id = self.next_channel_id
                self.next_channel_id += 1
                if self.next_channel_id > MAX_CHANNEL_ID:
                    self.next_channel_id = 1

                if (
                    channel_id not in self.channels
                    and channel_id not in self.connect_events
                    and channel_id not in self.opening_channels
                ):
                    return channel_id

        raise RuntimeError("No free tunnel channel ids")

    async def register_channel(self, channel: Channel):
        """Register a SOCKS channel and flush data that arrived early."""
        self.channels[channel.channel_id] = channel
        self.opening_channels.discard(channel.channel_id)

        pending_data = self.pending_channel_data.pop(channel.channel_id, [])
        for payload in pending_data:
            if not channel.connected:
                break
            try:
                channel.writer.write(payload)
                await channel.writer.drain()
            except Exception:
                await self._close_channel(channel)
                break

        if channel.channel_id in self.pending_close_channels:
            self.pending_close_channels.discard(channel.channel_id)
            await self._close_channel(channel)

    async def open_channel(self, host: str, port: int, channel_id: int = None) -> Tuple[int, bool]:
        """Open a tunnel channel."""
        if not self.connected:
            return 0, False

        if channel_id is None:
            try:
                channel_id = await self._allocate_channel_id()
            except RuntimeError as e:
                logger.warning(str(e))
                return 0, False
        elif (
            channel_id in self.channels
            or channel_id in self.connect_events
            or channel_id in self.opening_channels
        ):
            logger.warning(f"Channel id already in use on tunnel: {channel_id}")
            return channel_id, False

        event = asyncio.Event()
        self.connect_events[channel_id] = event
        self.connect_results[channel_id] = False

        # Send CONNECT
        try:
            payload = make_connect_payload(host, port)
            await self.send_frame(FRAME_CONNECT, channel_id, payload)
            if not self.connected:
                raise ConnectionError("Tunnel disconnected while opening channel")
        except Exception:
            self.connect_events.pop(channel_id, None)
            self.connect_results.pop(channel_id, None)
            self.opening_channels.discard(channel_id)
            return channel_id, False

        # Wait for response
        try:
            await asyncio.wait_for(event.wait(), timeout=30.0)
            success = self.connect_results.get(channel_id, False)
        except asyncio.TimeoutError:
            success = False

        self.connect_events.pop(channel_id, None)
        self.connect_results.pop(channel_id, None)
        if not success:
            self.opening_channels.discard(channel_id)
            self.pending_channel_data.pop(channel_id, None)
            self.pending_close_channels.discard(channel_id)

        return channel_id, success

    async def send_data(self, channel_id: int, data: bytes):
        """Send data on channel."""
        await self.send_frame(FRAME_DATA, channel_id, data)

    async def close_channel_remote(self, channel_id: int):
        """Tell server to close channel."""
        await self.send_frame(FRAME_CLOSE, channel_id)

    async def _close_channel(self, channel: Channel):
        """Close local channel."""
        if not channel.connected:
            return
        channel.connected = False

        try:
            channel.writer.close()
            await asyncio.wait_for(channel.writer.wait_closed(), timeout=5.0)
        except:
            pass

        self.channels.pop(channel.channel_id, None)
        self.opening_channels.discard(channel.channel_id)
        self.pending_channel_data.pop(channel.channel_id, None)
        self.pending_close_channels.discard(channel.channel_id)

    async def disconnect(self):
        """Disconnect and cleanup."""
        self.connected = False
        for channel in list(self.channels.values()):
            await self._close_channel(channel)
        if self.writer:
            try:
                self.writer.close()
                await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
            except:
                pass
        self.reader = None
        self.writer = None
        self.channels.clear()
        self.connect_events.clear()
        self.connect_results.clear()
        self.opening_channels.clear()
        self.pending_channel_data.clear()
        self.pending_close_channels.clear()


# ============================================================================
# Reverse Access Node Listener
# ============================================================================

class ReverseSessionPool:
    """Pool of authenticated reverse tunnel sessions for SOCKS channel routing."""

    def __init__(self):
        self.sessions: Dict[int, TunnelClient] = {}
        self.channel_to_session: Dict[int, int] = {}
        self.opening_channels: Set[int] = set()
        self.pending_channel_data: Dict[int, List[bytes]] = {}
        self.pending_close_channels: Set[int] = set()
        self.next_session_id = 1
        self.next_channel_id = 1
        self.lock = asyncio.Lock()

    @property
    def connected(self) -> bool:
        return any(tunnel.connected for tunnel in self.sessions.values())

    async def add_session(self, tunnel: TunnelClient) -> int:
        async with self.lock:
            session_id = self.next_session_id
            self.next_session_id += 1
            tunnel.session_id = session_id
            self.sessions[session_id] = tunnel
            logger.info(f"Reverse session {session_id} authenticated; active sessions={len(self.sessions)}")
            return session_id

    async def remove_session(self, session_id: int):
        async with self.lock:
            tunnel = self.sessions.pop(session_id, None)
            dead_channels = [cid for cid, sid in self.channel_to_session.items() if sid == session_id]
            for channel_id in dead_channels:
                self.channel_to_session.pop(channel_id, None)
                self.opening_channels.discard(channel_id)
                self.pending_channel_data.pop(channel_id, None)
                self.pending_close_channels.discard(channel_id)
            logger.info(
                f"Reverse session {session_id} disconnected; "
                f"closed_channels={len(dead_channels)} active sessions={len(self.sessions)}"
            )
        if tunnel:
            await tunnel.disconnect()

    def _session_active_count(self, session_id: int) -> int:
        return sum(1 for sid in self.channel_to_session.values() if sid == session_id)

    async def choose_session(self) -> Tuple[int, TunnelClient]:
        async with self.lock:
            candidates = [
                (self._session_active_count(session_id), session_id, tunnel)
                for session_id, tunnel in self.sessions.items()
                if tunnel.connected
            ]
            if not candidates:
                return 0, None
            _, session_id, tunnel = min(candidates, key=lambda item: (item[0], item[1]))
            return session_id, tunnel

    async def _allocate_channel_id_locked(self) -> int:
        for _ in range(MAX_CHANNEL_ID):
            channel_id = self.next_channel_id
            self.next_channel_id += 1
            if self.next_channel_id > MAX_CHANNEL_ID:
                self.next_channel_id = 1
            if channel_id not in self.channel_to_session and channel_id not in self.opening_channels:
                return channel_id
        raise RuntimeError("No free reverse channel ids")

    async def open_channel(self, host: str, port: int) -> Tuple[int, bool]:
        async with self.lock:
            candidates = [
                (self._session_active_count(session_id), session_id, tunnel)
                for session_id, tunnel in self.sessions.items()
                if tunnel.connected
            ]
            if not candidates:
                logger.warning(f"No reverse tunnel session available for CONNECT {host}:{port}")
                return 0, False
            _, session_id, tunnel = min(candidates, key=lambda item: (item[0], item[1]))
            try:
                channel_id = await self._allocate_channel_id_locked()
            except RuntimeError as e:
                logger.warning(str(e))
                return 0, False
            self.opening_channels.add(channel_id)
            self.channel_to_session[channel_id] = session_id

        logger.debug(f"Assigning ch={channel_id} -> reverse session {session_id}")
        returned_channel_id, success = await tunnel.open_channel(host, port, channel_id=channel_id)
        if not success:
            async with self.lock:
                self.opening_channels.discard(channel_id)
                self.channel_to_session.pop(channel_id, None)
                self.pending_channel_data.pop(channel_id, None)
                self.pending_close_channels.discard(channel_id)
        return returned_channel_id, success

    async def register_channel(self, channel: Channel):
        async with self.lock:
            session_id = self.channel_to_session.get(channel.channel_id)
            self.opening_channels.discard(channel.channel_id)
            tunnel = self.sessions.get(session_id) if session_id else None
        if tunnel and tunnel.connected:
            await tunnel.register_channel(channel)
        else:
            logger.debug(f"Cannot register ch={channel.channel_id}: reverse session unavailable")
            await self._close_writer(channel.writer)

    async def send_data(self, channel_id: int, data: bytes):
        tunnel = await self._tunnel_for_channel(channel_id)
        if tunnel:
            await tunnel.send_data(channel_id, data)

    async def close_channel_remote(self, channel_id: int):
        tunnel = await self._tunnel_for_channel(channel_id)
        if tunnel:
            await tunnel.close_channel_remote(channel_id)

    async def _close_channel(self, channel: Channel):
        tunnel = await self._tunnel_for_channel(channel.channel_id)
        if tunnel:
            await tunnel._close_channel(channel)
        else:
            await self._close_writer(channel.writer)
        async with self.lock:
            self.channel_to_session.pop(channel.channel_id, None)
            self.opening_channels.discard(channel.channel_id)
            self.pending_channel_data.pop(channel.channel_id, None)
            self.pending_close_channels.discard(channel.channel_id)

    async def _tunnel_for_channel(self, channel_id: int) -> Optional[TunnelClient]:
        async with self.lock:
            session_id = self.channel_to_session.get(channel_id)
            tunnel = self.sessions.get(session_id) if session_id else None
            if tunnel and tunnel.connected:
                return tunnel
            return None

    async def _close_writer(self, writer: asyncio.StreamWriter):
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
        except Exception:
            pass


class ReverseAccessListener:
    """Access Node reverse listener. The VPS dials into this server."""

    def __init__(
        self,
        reverse_config: ReverseListenConfig,
        socks_host: str,
        socks_port: int,
        tunnel_config: TunnelConfig = None,
        smtp_config: SMTPConfig = None
    ):
        self.reverse_config = reverse_config
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.tunnel_config = tunnel_config or TunnelConfig()
        self.smtp_config = smtp_config or SMTPConfig()
        self.session_pool = ReverseSessionPool()
        self.ssl_context = self._create_ssl_context()
        self.allowed_ips = IPWhitelist(reverse_config.allowed_dialer_ips)

    def _create_ssl_context(self) -> ssl.SSLContext:
        tls = self.reverse_config.tls
        if not tls.cert_file or not tls.key_file:
            raise ValueError("client.reverse.tls.cert_file and key_file are required for reverse-listen mode")
        if not os.path.exists(tls.cert_file):
            raise ValueError(f"reverse TLS cert_file does not exist: {tls.cert_file}")
        if not os.path.exists(tls.key_file):
            raise ValueError(f"reverse TLS key_file does not exist: {tls.key_file}")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls.cert_file, tls.key_file)

        if self.reverse_config.mtls.enabled:
            raise ValueError("reverse mTLS is planned for Stage 1b and is not implemented in Stage 1")

        return ctx

    async def _send_line(self, writer: asyncio.StreamWriter, line: str):
        writer.write(f"{line}\r\n".encode())
        await writer.drain()

    async def _read_line(self, reader: asyncio.StreamReader) -> Optional[str]:
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=60.0)
            if not data:
                return None
            return data.decode('utf-8', errors='replace').strip()
        except Exception:
            return None

    async def _expect_ehlo(self, reader: asyncio.StreamReader) -> bool:
        line = await self._read_line(reader)
        return bool(line and line.upper().startswith(('EHLO', 'HELO')))

    async def _upgrade_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        transport = writer.transport
        protocol = writer._protocol
        loop = asyncio.get_event_loop()

        new_transport = await loop.start_tls(
            transport, protocol, self.ssl_context, server_side=True
        )
        writer._transport = new_transport
        reader._transport = new_transport

    async def _smtp_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer_str: str) -> bool:
        hostname = self.reverse_config.tls.domain or socket.gethostname()
        await self._send_line(writer, f"220 {hostname} ESMTP Postfix (Ubuntu)")

        if not await self._expect_ehlo(reader):
            return False

        await self._send_line(writer, f"250-{hostname}")
        await self._send_line(writer, "250-STARTTLS")
        await self._send_line(writer, "250-AUTH PLAIN")
        await self._send_line(writer, "250 8BITMIME")

        line = await self._read_line(reader)
        if not line or line.upper() != 'STARTTLS':
            return False

        await self._send_line(writer, "220 2.0.0 Ready to start TLS")
        await self._upgrade_tls(reader, writer)

        if not await self._expect_ehlo(reader):
            return False

        await self._send_line(writer, f"250-{hostname}")
        await self._send_line(writer, "250-AUTH PLAIN")
        await self._send_line(writer, "250 8BITMIME")

        line = await self._read_line(reader)
        if not line or not line.upper().startswith('AUTH'):
            return False

        parts = line.split(' ', 2)
        if len(parts) < 3 or parts[1].upper() != 'PLAIN':
            await self._send_line(writer, "535 5.7.8 Authentication failed")
            return False

        users = {
            self.reverse_config.auth_username: UserConfig(
                username=self.reverse_config.auth_username,
                secret=self.reverse_config.auth_secret,
            )
        }
        valid, username = TunnelCrypto.verify_auth_token_multi_user(parts[2], users)
        if not valid or username != self.reverse_config.auth_username:
            logger.warning(f"Reverse authentication failed from {peer_str}")
            await self._send_line(writer, "535 5.7.8 Authentication failed")
            await asyncio.sleep(1.0)
            return False

        await self._send_line(writer, "235 2.7.0 Authentication successful")

        line = await self._read_line(reader)
        if line != "BINARY":
            return False
        await self._send_line(writer, "299 Binary mode activated")
        return True

    async def handle_dialer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info('peername')
        peer_ip = peer[0] if peer else "unknown"
        peer_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        logger.info(f"Reverse dialer connected from {peer_str}")

        if self.allowed_ips and not self.allowed_ips.is_allowed(peer_ip):
            logger.warning(f"Reverse dialer IP not allowed: {peer_ip}")
            writer.close()
            await writer.wait_closed()
            return

        tunnel = None
        receiver_task = None
        keepalive_task = None

        try:
            if not await self._smtp_handshake(reader, writer, peer_str):
                logger.warning(f"Reverse handshake failed from {peer_str}")
                return

            tunnel = TunnelClient(
                ClientConfig(
                    server_host=peer_ip,
                    server_port=self.reverse_config.listen_port,
                    socks_host=self.socks_host,
                    socks_port=self.socks_port,
                    username=self.reverse_config.auth_username,
                    secret=self.reverse_config.auth_secret,
                ),
                tunnel_config=self.tunnel_config,
                smtp_config=self.smtp_config,
            )
            tunnel.reader = reader
            tunnel.writer = writer
            tunnel.connected = True
            session_id = await self.session_pool.add_session(tunnel)

            logger.info(f"Reverse tunnel session {session_id} authenticated: {peer_str}")
            receiver_task = asyncio.create_task(tunnel._receiver_loop())
            keepalive_task = asyncio.create_task(tunnel.keepalive_loop())
            await receiver_task
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Reverse listener session error from {peer_str}: {e}")
        finally:
            if tunnel:
                await self.session_pool.remove_session(getattr(tunnel, 'session_id', 0))
            for task in (receiver_task, keepalive_task):
                if task:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            logger.info(f"Reverse tunnel session ended: {peer_str}")

    async def start(self):
        socks = SOCKS5Server(self.session_pool, self.socks_host, self.socks_port)
        socks_server = await asyncio.start_server(
            socks.handle_client,
            socks.host,
            socks.port,
            reuse_address=True
        )
        reverse_server = await asyncio.start_server(
            self.handle_dialer,
            self.reverse_config.listen_host,
            self.reverse_config.listen_port,
            reuse_address=True
        )

        socks_addr = socks_server.sockets[0].getsockname()
        reverse_addr = reverse_server.sockets[0].getsockname()
        logger.info(f"SOCKS5 proxy on {socks_addr[0]}:{socks_addr[1]}")
        logger.info(f"Reverse listener on {reverse_addr[0]}:{reverse_addr[1]}")
        if self.reverse_config.allowed_dialer_ips:
            logger.info(f"Reverse allowed dialer IPs: {', '.join(self.reverse_config.allowed_dialer_ips)}")
        else:
            logger.warning("reverse.allowed_dialer_ips is empty; any source IP can attempt TLS/auth")

        async with socks_server, reverse_server:
            await asyncio.gather(
                socks_server.serve_forever(),
                reverse_server.serve_forever(),
            )


# ============================================================================
# SOCKS5 Server
# ============================================================================

class SOCKS5Server:
    def __init__(self, tunnel: TunnelClient, host: str = '127.0.0.1', port: int = 1080):
        self.tunnel = tunnel
        self.host = host
        self.port = port
        self.read_timeout = 30.0

    async def _read_exact(self, reader: asyncio.StreamReader, size: int) -> bytes:
        return await asyncio.wait_for(reader.readexactly(size), timeout=self.read_timeout)

    async def _send_reply(self, writer: asyncio.StreamWriter, rep: int):
        writer.write(bytes([SOCKS5.VERSION, rep, 0, SOCKS5.ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        await writer.drain()

    async def _parse_request(self, reader: asyncio.StreamReader) -> Tuple[int, str, int]:
        data = await self._read_exact(reader, 4)
        version, cmd, reserved, atyp = data

        if version != SOCKS5.VERSION or reserved != 0:
            raise ValueError("Invalid SOCKS5 request header")

        if atyp == SOCKS5.ATYP_IPV4:
            addr_data = await self._read_exact(reader, 4)
            host = socket.inet_ntoa(addr_data)
        elif atyp == SOCKS5.ATYP_DOMAIN:
            length = (await self._read_exact(reader, 1))[0]
            if length == 0:
                raise ValueError("SOCKS5 domain length is zero")
            host = (await self._read_exact(reader, length)).decode('utf-8')
        elif atyp == SOCKS5.ATYP_IPV6:
            addr_data = await self._read_exact(reader, 16)
            host = socket.inet_ntop(socket.AF_INET6, addr_data)
        else:
            raise ValueError(f"Unsupported SOCKS5 address type: {atyp}")

        port_data = await self._read_exact(reader, 2)
        port = struct.unpack('>H', port_data)[0]
        return cmd, host, port

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle SOCKS5 client."""
        channel = None
        try:
            # Check tunnel is connected
            if not self.tunnel.connected:
                writer.close()
                return

            # SOCKS5 handshake
            data = await self._read_exact(reader, 2)
            if len(data) < 2 or data[0] != SOCKS5.VERSION:
                return

            nmethods = data[1]
            methods = await self._read_exact(reader, nmethods)
            if SOCKS5.AUTH_NONE not in methods:
                writer.write(bytes([SOCKS5.VERSION, 0xFF]))
                await writer.drain()
                return

            writer.write(bytes([SOCKS5.VERSION, SOCKS5.AUTH_NONE]))
            await writer.drain()

            # Request
            cmd, host, port = await self._parse_request(reader)

            if cmd != SOCKS5.CMD_CONNECT:
                await self._send_reply(writer, 0x07)
                return

            logger.info(f"CONNECT {host}:{port}")

            # Open tunnel
            channel_id, success = await self.tunnel.open_channel(host, port)

            if success:
                await self._send_reply(writer, SOCKS5.REP_SUCCESS)

                channel = Channel(
                    channel_id=channel_id,
                    reader=reader,
                    writer=writer,
                    host=host,
                    port=port,
                    connected=True
                )
                await self.tunnel.register_channel(channel)

                # Forward loop
                await self._forward_loop(channel)
            else:
                await self._send_reply(writer, SOCKS5.REP_FAILURE)

        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            logger.debug("SOCKS client disconnected during handshake")
        except Exception as e:
            logger.debug(f"SOCKS error: {e}")
        finally:
            if channel:
                await self.tunnel.close_channel_remote(channel.channel_id)
                await self.tunnel._close_channel(channel)
            elif 'channel_id' in locals() and channel_id:
                self.tunnel.opening_channels.discard(channel_id)
                self.tunnel.pending_channel_data.pop(channel_id, None)
                self.tunnel.pending_close_channels.discard(channel_id)
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
            except:
                pass

    async def _forward_loop(self, channel: Channel):
        """Forward data from SOCKS client to tunnel."""
        try:
            while channel.connected and self.tunnel.connected:
                data = await channel.reader.read(32768)
                if data:
                    await self.tunnel.send_data(channel.channel_id, data)
                else:
                    break
        except:
            pass

    async def start(self):
        """Start SOCKS5 server."""
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        addr = server.sockets[0].getsockname()
        logger.info(f"SOCKS5 proxy on {addr[0]}:{addr[1]}")

        async with server:
            await server.serve_forever()


# ============================================================================
# Main
# ============================================================================

def _jitter_delay(delay: float, jitter: float) -> float:
    if jitter <= 0:
        return delay
    spread = delay * jitter
    return max(0.0, delay + random.uniform(-spread, spread))


async def _sleep_before_reconnect(delay: float, jitter: float):
    sleep_for = _jitter_delay(delay, jitter)
    logger.warning(f"Reconnecting in {sleep_for:.1f}s")
    await asyncio.sleep(sleep_for)


async def run_client(
    config: ClientConfig,
    ca_cert: str,
    tunnel_config: TunnelConfig = None,
    smtp_config: SMTPConfig = None
):
    """Run client with auto-reconnect."""
    tunnel_config = tunnel_config or TunnelConfig()
    smtp_config = smtp_config or SMTPConfig()

    reconnect_delay = max(0.1, float(tunnel_config.reconnect_initial_delay or 2.0))
    max_reconnect_delay = max(reconnect_delay, float(tunnel_config.reconnect_max_delay or 30.0))
    reconnect_jitter = max(0.0, float(tunnel_config.reconnect_jitter or 0.0))
    current_delay = reconnect_delay

    while True:
        tunnel = TunnelClient(config, ca_cert, tunnel_config, smtp_config)
        receiver_task = None
        keepalive_task = None

        # Try to connect
        if not await tunnel.connect():
            await _sleep_before_reconnect(current_delay, reconnect_jitter)
            current_delay = min(current_delay * 2, max_reconnect_delay)
            continue

        # Connected - reset delay
        current_delay = reconnect_delay

        # Start receiver in background
        receiver_task = asyncio.create_task(tunnel._receiver_loop())
        keepalive_task = asyncio.create_task(tunnel.keepalive_loop())

        # Start SOCKS server
        socks = SOCKS5Server(tunnel, config.socks_host, config.socks_port)

        try:
            # Create SOCKS server but don't block on it
            socks_server = await asyncio.start_server(
                socks.handle_client,
                socks.host,
                socks.port,
                reuse_address=True  # Allow quick rebind after restart
            )
            addr = socks_server.sockets[0].getsockname()
            logger.info(f"SOCKS5 proxy on {addr[0]}:{addr[1]}")

            # Wait for either: receiver dies (connection lost) or KeyboardInterrupt
            async with socks_server:
                try:
                    # Wait for receiver to finish (means connection lost)
                    await receiver_task
                except asyncio.CancelledError:
                    pass

            if tunnel.connected:
                tunnel.connected = False

            logger.warning("Tunnel disconnected")

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            await tunnel.disconnect()
            return 0
        except OSError as e:
            if "Address already in use" in str(e):
                logger.error(f"Port {socks.port} already in use, waiting...")
                await asyncio.sleep(2)
            else:
                logger.error(f"SOCKS server error: {e}")
        finally:
            await tunnel.disconnect()
            for task in (receiver_task, keepalive_task):
                if task:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

        await _sleep_before_reconnect(current_delay, reconnect_jitter)
        current_delay = min(current_delay * 2, max_reconnect_delay)


def build_client_settings(config_data: dict, args) -> Tuple[ClientConfig, Optional[str], TunnelConfig, SMTPConfig]:
    """Build validated client settings from config and CLI overrides."""
    client_conf = (config_data or {}).get('client', {}) or {}

    config = ClientConfig(
        server_host=args.server or client_conf.get('server_host', 'localhost'),
        server_port=validate_tcp_port(
            args.server_port if args.server_port is not None else client_conf.get('server_port'),
            587,
            'client.server_port'
        ),
        socks_port=validate_tcp_port(
            args.socks_port if args.socks_port is not None else client_conf.get('socks_port'),
            1080,
            'client.socks_port'
        ),
        socks_host=client_conf.get('socks_host', '127.0.0.1'),
        username=args.username or client_conf.get('username', ''),
        secret=args.secret or client_conf.get('secret', ''),
    )

    ca_cert = args.ca_cert or client_conf.get('ca_cert')
    tunnel_config = build_tunnel_config(config_data)
    smtp_config = build_smtp_config(config_data)
    return config, ca_cert, tunnel_config, smtp_config


def check_client_config(config_path: str, args) -> int:
    """Validate client configuration without starting the tunnel."""
    errors = []
    warnings = []

    try:
        config_data = load_config(config_path)
        mode = get_client_mode(config_data)
        config, ca_cert, tunnel_config, smtp_config = build_client_settings(config_data, args)
        reverse_config = build_reverse_listen_config(config_data) if mode == MODE_REVERSE_LISTEN else None
    except FileNotFoundError:
        print(f"ERROR: config file not found: {config_path}")
        return 1
    except Exception as e:
        print(f"ERROR: invalid client config: {e}")
        return 1

    if not config.socks_host:
        errors.append("client.socks_host is required")

    if mode == MODE_NORMAL:
        if not config.server_host:
            errors.append("client.server_host is required")
        if not config.username:
            errors.append("client.username is required")
        if not config.secret:
            errors.append("client.secret is required")

        if ca_cert:
            if not os.path.exists(ca_cert):
                errors.append(f"client.ca_cert does not exist: {ca_cert}")
            elif not os.path.isfile(ca_cert):
                errors.append(f"client.ca_cert is not a file: {ca_cert}")
        else:
            warnings.append("client.ca_cert is not configured; TLS verification will be disabled")
    else:
        if not reverse_config.auth_username:
            errors.append("client.reverse.auth_username is required")
        if not reverse_config.auth_secret:
            errors.append("client.reverse.auth_secret or auth_secret_file is required")
        if not reverse_config.tls.cert_file:
            errors.append("client.reverse.tls.cert_file is required")
        elif not os.path.isfile(reverse_config.tls.cert_file):
            errors.append(f"client.reverse.tls.cert_file does not exist: {reverse_config.tls.cert_file}")
        if not reverse_config.tls.key_file:
            errors.append("client.reverse.tls.key_file is required")
        elif not os.path.isfile(reverse_config.tls.key_file):
            errors.append(f"client.reverse.tls.key_file does not exist: {reverse_config.tls.key_file}")
        if reverse_config.mtls.enabled:
            errors.append("reverse mTLS is planned for Stage 1b and is not implemented in Stage 1")

    if tunnel_config.keepalive_interval > 0 and tunnel_config.keepalive_timeout <= 0:
        errors.append("tunnel.keepalive_timeout must be positive when keepalive is enabled")

    print("Client config check")
    print(f"  Config: {config_path}")
    print(f"  Mode:   {mode}")
    if mode == MODE_NORMAL:
        print(f"  Server: {config.server_host}:{config.server_port}")
        print(f"  CA cert: {ca_cert or '(not configured)'}")
    else:
        print(f"  Reverse listen: {reverse_config.listen_host}:{reverse_config.listen_port}")
        print(f"  Reverse TLS cert: {reverse_config.tls.cert_file}")
        print(f"  Reverse allowed IPs: {', '.join(reverse_config.allowed_dialer_ips) or '(none)'}")
    print(f"  SOCKS:  {config.socks_host}:{config.socks_port}")
    print(f"  EHLO:   {smtp_config.ehlo_name}")
    print(f"  Keepalive interval: {tunnel_config.keepalive_interval:g}s")

    for warning in warnings:
        print(f"WARNING: {warning}")
    for error in errors:
        print(f"ERROR: {error}")

    if errors:
        return 1

    print("OK: client config is valid")
    return 0


def main():
    parser = argparse.ArgumentParser(description='SMTP Tunnel Client (Fast)')
    parser.add_argument('--config', '-c', default='config.yaml')
    parser.add_argument('--server', default=None, help='Server domain name (FQDN required for TLS)')
    parser.add_argument('--server-port', type=int, default=None)
    parser.add_argument('--socks-port', '-p', type=int, default=None)
    parser.add_argument('--username', '-u', default=None, help='Username for authentication')
    parser.add_argument('--secret', '-s', default=None)
    parser.add_argument('--ca-cert', default=None)
    parser.add_argument('--check', action='store_true', help='Validate configuration and exit')
    parser.add_argument('--debug', '-d', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config_data = load_config(args.config)
    except FileNotFoundError:
        config_data = {}

    if args.check:
        return check_client_config(args.config, args)

    try:
        mode = get_client_mode(config_data)
        config, ca_cert, tunnel_config, smtp_config = build_client_settings(config_data, args)
    except Exception as e:
        logger.error(f"Invalid client config: {e}")
        return 1

    if mode == MODE_REVERSE_LISTEN:
        try:
            reverse_config = build_reverse_listen_config(config_data)
            listener = ReverseAccessListener(
                reverse_config,
                config.socks_host,
                config.socks_port,
                tunnel_config,
                smtp_config,
            )
        except Exception as e:
            logger.error(f"Invalid reverse-listen config: {e}")
            return 1

        try:
            return asyncio.run(listener.start())
        except KeyboardInterrupt:
            return 0

    if not config.username:
        logger.error("No username configured!")
        return 1

    if not config.secret:
        logger.error("No secret configured!")
        return 1

    try:
        return asyncio.run(run_client(config, ca_cert, tunnel_config, smtp_config))
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    exit(main())
