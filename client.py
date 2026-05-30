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
    LoggingConfig,
    MAX_CHANNEL_ID,
    MetricsConfig,
    MODE_NORMAL,
    MODE_REVERSE_LISTEN,
    ReverseListenConfig,
    SMTPConfig,
    TransportConfig,
    TunnelConfig,
    TunnelCrypto,
    UserConfig,
    build_logging_config,
    build_metrics_config,
    build_reverse_listen_config,
    build_smtp_config,
    build_tunnel_config,
    build_transport_config,
    format_destination,
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
        smtp_config: SMTPConfig = None,
        transport_config: TransportConfig = None,
        logging_config: LoggingConfig = None,
    ):
        self.config = config
        self.ca_cert = ca_cert
        self.tunnel_config = tunnel_config or TunnelConfig()
        self.smtp_config = smtp_config or SMTPConfig()
        self.transport_config = transport_config or TransportConfig()
        self.logging_config = logging_config or LoggingConfig()

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False

        self.channels: Dict[int, Channel] = {}
        self.opening_channels: Set[int] = set()
        self.pending_channel_data: Dict[int, List[bytes]] = {}
        self.pending_close_channels: Set[int] = set()
        self.pending_channel_data_limit = self.transport_config.pending_buffer_limit
        self.next_channel_id = 1
        self.channel_lock = asyncio.Lock()

        self.connect_events: Dict[int, asyncio.Event] = {}
        self.connect_results: Dict[int, bool] = {}

        self.write_lock = asyncio.Lock()
        self.drain_state: Dict[int, Tuple[int, float]] = {}
        self.drain_tasks: Dict[int, asyncio.Task] = {}
        self.keepalive_ack_event = asyncio.Event()
        self.session_id = 0
        self.session_pool = None
        self.session_stats = None

    async def connect(self) -> bool:
        """Connect and do SMTP handshake, then switch to binary mode."""
        try:
            logger.info(f"Connecting to {self.config.server_host}:{self.config.server_port}")

            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.server_host, self.config.server_port),
                timeout=30.0
            )
            self._apply_socket_options()

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
        self._apply_socket_options()
        logger.debug("TLS established")

    def _apply_socket_options(self):
        sock = self.writer.get_extra_info('socket') if self.writer else None
        if not sock:
            return
        try:
            if self.transport_config.tcp_nodelay and sock.family in (socket.AF_INET, socket.AF_INET6):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.transport_config.tcp_keepalive:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if self.transport_config.socket_send_buffer > 0:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.transport_config.socket_send_buffer)
            if self.transport_config.socket_recv_buffer > 0:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.transport_config.socket_recv_buffer)
        except OSError as e:
            logger.debug(f"Could not apply socket options: {e}")

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

    async def _drain_writer(self, writer: asyncio.StreamWriter, byte_count: int, is_data: bool):
        if not is_data:
            await writer.drain()
            return

        key = id(writer)
        pending_bytes, last_drain_at = self.drain_state.get(key, (0, time.monotonic()))
        pending_bytes += byte_count
        interval = self.transport_config.drain_interval_ms / 1000.0
        now = time.monotonic()
        transport = getattr(writer, 'transport', None)
        write_buffer_size = transport.get_write_buffer_size() if transport else 0
        if (
            pending_bytes >= self.transport_config.drain_bytes
            or interval <= 0
            or now - last_drain_at >= interval
            or write_buffer_size >= self.transport_config.pending_buffer_limit
        ):
            task = self.drain_tasks.pop(key, None)
            if task:
                task.cancel()
            await writer.drain()
            if transport and transport.get_write_buffer_size() >= self.transport_config.pending_buffer_limit:
                raise BufferError("writer buffer limit exceeded")
            self.drain_state[key] = (0, now)
        else:
            self.drain_state[key] = (pending_bytes, last_drain_at)
            if key not in self.drain_tasks:
                self.drain_tasks[key] = asyncio.create_task(self._delayed_drain(writer, key, interval))

    async def _delayed_drain(self, writer: asyncio.StreamWriter, key: int, interval: float):
        try:
            await asyncio.sleep(interval)
            pending = self.drain_state.get(key, (0, 0.0))[0]
            if pending <= 0 or writer.is_closing():
                return
            await writer.drain()
            self.drain_state[key] = (0, time.monotonic())
        except asyncio.CancelledError:
            raise
        except Exception:
            self.connected = False
        finally:
            self.drain_tasks.pop(key, None)

    async def start_receiver(self):
        """Start background task to receive frames from server."""
        asyncio.create_task(self._receiver_loop())

    async def _receiver_loop(self):
        """Receive and dispatch frames from server."""
        frame_buffer = ActiveFrameBuffer()

        while self.connected:
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(self.transport_config.read_chunk_size),
                    timeout=300.0
                )
                if not chunk:
                    break
                if self.session_stats:
                    self.session_stats.bytes_in += len(chunk)
                    self.session_stats.last_read = time.time()
                frame_buffer.append(chunk)

                for frame_type, channel_id, payload in frame_buffer.iter_frames():
                    await self._handle_frame(frame_type, channel_id, payload)

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
                    await self._drain_writer(channel.writer, len(payload), is_data=True)
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

    async def send_frame(self, frame_type: int, channel_id: int, payload: bytes = b'') -> bool:
        """Send frame to server."""
        if not self.connected or not self.writer:
            return False
        async with self.write_lock:
            try:
                frame = encode_frame(frame_type, channel_id, payload)
                self.writer.write(frame)
                if self.session_stats:
                    self.session_stats.bytes_out += len(frame)
                    self.session_stats.last_write = time.time()
                await self._drain_writer(self.writer, len(frame), is_data=(frame_type == FRAME_DATA))
                return True
            except FrameProtocolError as e:
                logger.error(f"Refusing to send malformed tunnel frame: {e}")
            except Exception:
                self.connected = False
                if self.session_pool:
                    await self.session_pool.mark_unhealthy(self.session_id)
        return False

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
                await self._drain_writer(channel.writer, len(payload), is_data=True)
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
            if not await self.send_frame(FRAME_CONNECT, channel_id, payload):
                raise ConnectionError("Tunnel write failed while opening channel")
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
        return await self.send_frame(FRAME_DATA, channel_id, data)

    async def close_channel_remote(self, channel_id: int):
        """Tell server to close channel."""
        return await self.send_frame(FRAME_CLOSE, channel_id)

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
        if channel.writer:
            task = self.drain_tasks.pop(id(channel.writer), None)
            if task:
                task.cancel()
            self.drain_state.pop(id(channel.writer), None)
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
        for task in self.drain_tasks.values():
            task.cancel()
        self.drain_tasks.clear()
        self.drain_state.clear()


# ============================================================================
# Reverse Access Node Listener
# ============================================================================

@dataclass
class ReverseSessionStats:
    session_id: int
    authenticated: bool = True
    writable: bool = True
    last_read: float = 0.0
    last_write: float = 0.0
    active_channels: int = 0
    total_channels: int = 0
    failure_count: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    connected_since: float = 0.0


class ReverseSessionPool:
    """Pool of authenticated reverse tunnel sessions for SOCKS channel routing."""

    def __init__(self, logging_config: LoggingConfig = None):
        self.sessions: Dict[int, TunnelClient] = {}
        self.stats: Dict[int, ReverseSessionStats] = {}
        self.channel_to_session: Dict[int, int] = {}
        self.opening_channels: Set[int] = set()
        self.pending_channel_data: Dict[int, List[bytes]] = {}
        self.pending_close_channels: Set[int] = set()
        self.next_session_id = 1
        self.next_channel_id = 1
        self.lock = asyncio.Lock()
        self.logging_config = logging_config or LoggingConfig()

    @property
    def connected(self) -> bool:
        return any(self._is_healthy_locked(session_id, tunnel) for session_id, tunnel in self.sessions.items())

    async def add_session(self, tunnel: TunnelClient) -> int:
        async with self.lock:
            session_id = self.next_session_id
            self.next_session_id += 1
            tunnel.session_id = session_id
            tunnel.session_pool = self
            self.sessions[session_id] = tunnel
            now = time.time()
            self.stats[session_id] = ReverseSessionStats(
                session_id=session_id,
                last_read=now,
                last_write=now,
                connected_since=now,
            )
            tunnel.session_stats = self.stats[session_id]
            if self.logging_config.log_session_events:
                logger.info(f"Reverse session {session_id} authenticated; active sessions={len(self.sessions)}")
            return session_id

    async def remove_session(self, session_id: int):
        async with self.lock:
            tunnel = self.sessions.pop(session_id, None)
            stat = self.stats.pop(session_id, None)
            dead_channels = [cid for cid, sid in self.channel_to_session.items() if sid == session_id]
            for channel_id in dead_channels:
                self.channel_to_session.pop(channel_id, None)
                self.opening_channels.discard(channel_id)
                self.pending_channel_data.pop(channel_id, None)
                self.pending_close_channels.discard(channel_id)
            if stat:
                stat.active_channels = 0
                stat.writable = False
            if self.logging_config.log_session_events:
                logger.info(
                    f"Reverse session {session_id} disconnected; "
                    f"closed_channels={len(dead_channels)} active sessions={len(self.sessions)}"
                )
        if tunnel:
            await tunnel.disconnect()

    def _is_healthy_locked(self, session_id: int, tunnel: TunnelClient) -> bool:
        stat = self.stats.get(session_id)
        writer = getattr(tunnel, 'writer', None)
        return bool(
            tunnel
            and tunnel.connected
            and stat
            and stat.authenticated
            and stat.writable
            and (writer is None or not writer.is_closing())
        )

    async def choose_session(self) -> Tuple[int, TunnelClient]:
        async with self.lock:
            candidates = [
                (self.stats[session_id].active_channels, session_id, tunnel)
                for session_id, tunnel in self.sessions.items()
                if self._is_healthy_locked(session_id, tunnel)
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

    def _forget_channel_locked(self, channel_id: int):
        session_id = self.channel_to_session.pop(channel_id, None)
        if session_id:
            stat = self.stats.get(session_id)
            if stat and stat.active_channels > 0:
                stat.active_channels -= 1
        self.opening_channels.discard(channel_id)
        self.pending_channel_data.pop(channel_id, None)
        self.pending_close_channels.discard(channel_id)

    async def mark_unhealthy(self, session_id: int):
        async with self.lock:
            stat = self.stats.get(session_id)
            if stat:
                stat.writable = False
                stat.failure_count += 1
            tunnel = self.sessions.get(session_id)
            if tunnel:
                tunnel.connected = False

    async def record_read(self, session_id: int, byte_count: int):
        async with self.lock:
            stat = self.stats.get(session_id)
            if stat:
                stat.bytes_in += byte_count
                stat.last_read = time.time()

    async def record_write(self, session_id: int, byte_count: int):
        async with self.lock:
            stat = self.stats.get(session_id)
            if stat:
                stat.bytes_out += byte_count
                stat.last_write = time.time()

    async def snapshot(self) -> Tuple[int, List[ReverseSessionStats]]:
        async with self.lock:
            return len(self.sessions), [
                ReverseSessionStats(**vars(stat))
                for _, stat in sorted(self.stats.items())
            ]

    async def open_channel(self, host: str, port: int) -> Tuple[int, bool]:
        for attempt in range(2):
            async with self.lock:
                candidates = [
                    (self.stats[session_id].active_channels, session_id, tunnel)
                    for session_id, tunnel in self.sessions.items()
                    if self._is_healthy_locked(session_id, tunnel)
                ]
                if not candidates:
                    logger.warning("No healthy reverse tunnel session available for CONNECT destination=[redacted]")
                    return 0, False
                _, session_id, tunnel = min(candidates, key=lambda item: (item[0], item[1]))
                try:
                    channel_id = await self._allocate_channel_id_locked()
                except RuntimeError as e:
                    logger.warning(str(e))
                    return 0, False
                self.opening_channels.add(channel_id)
                self.channel_to_session[channel_id] = session_id
                stat = self.stats[session_id]
                stat.active_channels += 1
                stat.total_channels += 1
                active_count = stat.active_channels

            logger.info(f"Assigned channel {channel_id} to reverse session {session_id} active_channels={active_count}")
            returned_channel_id, success = await tunnel.open_channel(host, port, channel_id=channel_id)
            if success:
                return returned_channel_id, True

            async with self.lock:
                self._forget_channel_locked(channel_id)
                session_failed = not self._is_healthy_locked(session_id, tunnel)
                if session_failed:
                    stat = self.stats.get(session_id)
                    if stat:
                        stat.failure_count += 1
                        stat.writable = False

            if session_failed and attempt == 0:
                logger.warning(f"Reverse session {session_id} became unhealthy during CONNECT; retrying another session")
                continue
            return returned_channel_id, False

        return 0, False

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
            async with self.lock:
                self._forget_channel_locked(channel.channel_id)

    async def send_data(self, channel_id: int, data: bytes):
        tunnel = await self._tunnel_for_channel(channel_id)
        if tunnel:
            if not await tunnel.send_data(channel_id, data):
                await self.mark_unhealthy(getattr(tunnel, 'session_id', 0))

    async def close_channel_remote(self, channel_id: int):
        tunnel = await self._tunnel_for_channel(channel_id)
        if tunnel:
            await tunnel.close_channel_remote(channel_id)

    async def cleanup_channel(self, channel_id: int):
        async with self.lock:
            self._forget_channel_locked(channel_id)

    async def _close_channel(self, channel: Channel):
        tunnel = await self._tunnel_for_channel(channel.channel_id)
        if tunnel:
            await tunnel._close_channel(channel)
        else:
            await self._close_writer(channel.writer)
        async with self.lock:
            self._forget_channel_locked(channel.channel_id)

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
        smtp_config: SMTPConfig = None,
        metrics_config: MetricsConfig = None,
        logging_config: LoggingConfig = None,
        transport_config: TransportConfig = None,
    ):
        self.reverse_config = reverse_config
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.tunnel_config = tunnel_config or TunnelConfig()
        self.smtp_config = smtp_config or SMTPConfig()
        self.metrics_config = metrics_config or MetricsConfig()
        self.logging_config = logging_config or LoggingConfig()
        self.transport_config = transport_config or TransportConfig()
        self.session_pool = ReverseSessionPool(self.logging_config)
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
                transport_config=self.transport_config,
                logging_config=self.logging_config,
            )
            tunnel.reader = reader
            tunnel.writer = writer
            tunnel.connected = True
            tunnel._apply_socket_options()
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
        socks = SOCKS5Server(
            self.session_pool,
            self.socks_host,
            self.socks_port,
            self.logging_config,
            self.transport_config,
        )
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

        metrics_task = asyncio.create_task(self._metrics_loop())
        try:
            async with socks_server, reverse_server:
                await asyncio.gather(
                    socks_server.serve_forever(),
                    reverse_server.serve_forever(),
                )
        finally:
            metrics_task.cancel()
            try:
                await metrics_task
            except asyncio.CancelledError:
                pass

    async def _metrics_loop(self):
        if not (self.metrics_config.enabled and self.logging_config.log_metrics):
            return
        interval = max(1.0, float(self.metrics_config.log_interval or 30.0))
        while True:
            await asyncio.sleep(interval)
            active_sessions, stats = await self.session_pool.snapshot()
            configured_sessions = max(int(self.tunnel_config.connections or 1), active_sessions)
            total_active_channels = sum(stat.active_channels for stat in stats)
            total_channels = sum(stat.total_channels for stat in stats)
            total_failures = sum(stat.failure_count for stat in stats)
            total_bytes_in = sum(stat.bytes_in for stat in stats)
            total_bytes_out = sum(stat.bytes_out for stat in stats)
            mode = 'adaptive' if self.tunnel_config.adaptive_connections else 'fixed'
            parts = [
                f"Reverse status: mode={mode}",
                f"min={self.tunnel_config.min_connections}",
                f"max={self.tunnel_config.max_connections}",
                f"target={configured_sessions}",
                f"active={active_sessions}",
                f"active_channels={total_active_channels}",
                f"total_channels={total_channels}",
                f"failures={total_failures}",
                f"bytes_in={total_bytes_in}",
                f"bytes_out={total_bytes_out}",
            ]
            if self.metrics_config.verbose or logger.isEnabledFor(logging.DEBUG):
                for stat in stats:
                    parts.append(
                        f"session{stat.session_id}_active_channels={stat.active_channels} "
                        f"session{stat.session_id}_total_channels={stat.total_channels} "
                        f"session{stat.session_id}_bytes_in={stat.bytes_in} "
                        f"session{stat.session_id}_bytes_out={stat.bytes_out} "
                        f"session{stat.session_id}_failures={stat.failure_count}"
                    )
            logger.info(" ".join(parts))


# ============================================================================
# SOCKS5 Server
# ============================================================================

class SOCKS5Server:
    def __init__(
        self,
        tunnel: TunnelClient,
        host: str = '127.0.0.1',
        port: int = 1080,
        logging_config: LoggingConfig = None,
        transport_config: TransportConfig = None,
    ):
        self.tunnel = tunnel
        self.host = host
        self.port = port
        self.read_timeout = 30.0
        self.logging_config = logging_config or LoggingConfig()
        self.transport_config = transport_config or getattr(tunnel, 'transport_config', TransportConfig())

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

            logger.info(f"CONNECT destination={format_destination(host, port, self.logging_config)}")

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
                if hasattr(self.tunnel, 'cleanup_channel'):
                    await self.tunnel.cleanup_channel(channel_id)
                else:
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
                data = await channel.reader.read(self.transport_config.read_chunk_size)
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
    smtp_config: SMTPConfig = None,
    logging_config: LoggingConfig = None,
    transport_config: TransportConfig = None,
):
    """Run client with auto-reconnect."""
    tunnel_config = tunnel_config or TunnelConfig()
    smtp_config = smtp_config or SMTPConfig()
    logging_config = logging_config or LoggingConfig()
    transport_config = transport_config or TransportConfig()

    reconnect_delay = max(0.1, float(tunnel_config.reconnect_initial_delay or 2.0))
    max_reconnect_delay = max(reconnect_delay, float(tunnel_config.reconnect_max_delay or 30.0))
    reconnect_jitter = max(0.0, float(tunnel_config.reconnect_jitter or 0.0))
    current_delay = reconnect_delay

    while True:
        tunnel = TunnelClient(config, ca_cert, tunnel_config, smtp_config, transport_config, logging_config)
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
        socks = SOCKS5Server(tunnel, config.socks_host, config.socks_port, logging_config, transport_config)

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


def build_client_settings(config_data: dict, args) -> Tuple[
    ClientConfig,
    Optional[str],
    TunnelConfig,
    SMTPConfig,
    MetricsConfig,
    LoggingConfig,
    TransportConfig,
]:
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
    metrics_config = build_metrics_config(config_data)
    logging_config = build_logging_config(config_data)
    transport_config = build_transport_config(config_data)
    return config, ca_cert, tunnel_config, smtp_config, metrics_config, logging_config, transport_config


def check_client_config(config_path: str, args) -> int:
    """Validate client configuration without starting the tunnel."""
    errors = []
    warnings = []

    try:
        config_data = load_config(config_path)
        mode = get_client_mode(config_data)
        config, ca_cert, tunnel_config, smtp_config, metrics_config, logging_config, transport_config = build_client_settings(config_data, args)
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
    print(f"  Metrics logging: {metrics_config.enabled and logging_config.log_metrics}")
    print(f"  Log destinations: {logging_config.log_destinations}")
    print(f"  Read chunk size: {transport_config.read_chunk_size}")

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
        config, ca_cert, tunnel_config, smtp_config, metrics_config, logging_config, transport_config = build_client_settings(config_data, args)
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
                metrics_config,
                logging_config,
                transport_config,
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
        return asyncio.run(run_client(config, ca_cert, tunnel_config, smtp_config, logging_config, transport_config))
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    exit(main())
