#!/usr/bin/env python3
"""
SMTP Tunnel Server - Fast Binary Mode

Version: 1.3.0

Protocol:
1. SMTP handshake (EHLO, STARTTLS, AUTH) - looks like real SMTP
2. After AUTH success, switch to binary streaming mode
3. Full-duplex binary protocol - no more SMTP overhead

Features:
- Multi-user support with per-user secrets
- Per-user IP whitelist
- Per-user logging (optional)
"""

import asyncio
import ssl
import logging
import argparse
import os
import random
import time
import socket
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

from common import (
    ActiveFrameBuffer,
    CONTROL_CHANNEL_ID,
    FRAME_CLOSE,
    FRAME_CONNECT,
    FRAME_CONNECT_FAIL,
    FRAME_CONNECT_OK,
    FRAME_DATA,
    FRAME_KEEPALIVE,
    FRAME_KEEPALIVE_ACK,
    FrameProtocolError,
    LoggingConfig,
    MODE_NORMAL,
    MODE_REVERSE_DIAL,
    ReverseDialConfig,
    TransportConfig,
    TunnelConfig,
    TunnelCrypto,
    build_logging_config,
    build_reverse_dial_config,
    build_tunnel_config,
    build_transport_config,
    encode_frame,
    format_destination,
    get_server_mode,
    load_config,
    load_users,
    parse_connect_payload,
    ServerConfig,
    UserConfig,
    verify_peer_fingerprint,
    validate_tcp_port,
    IPWhitelist,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('smtp-tunnel-server')


def apply_socket_options(writer: asyncio.StreamWriter, transport_config: TransportConfig):
    sock = writer.get_extra_info('socket') if writer else None
    if not sock:
        return
    try:
        if transport_config.tcp_nodelay and sock.family in (socket.AF_INET, socket.AF_INET6):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if transport_config.tcp_keepalive:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if transport_config.socket_send_buffer > 0:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, transport_config.socket_send_buffer)
        if transport_config.socket_recv_buffer > 0:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, transport_config.socket_recv_buffer)
    except OSError as e:
        logger.debug(f"Could not apply socket options: {e}")


# ============================================================================
# Channel - A tunneled TCP connection
# ============================================================================

@dataclass
class Channel:
    channel_id: int
    host: str
    port: int
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    connected: bool = False


# ============================================================================
# Tunnel Session
# ============================================================================

class TunnelSession:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        config: ServerConfig,
        ssl_context: ssl.SSLContext,
        users: Dict[str, UserConfig],
        tunnel_config: TunnelConfig = None,
        logging_config: LoggingConfig = None,
        transport_config: TransportConfig = None,
    ):
        self.reader = reader
        self.writer = writer
        self.config = config
        self.ssl_context = ssl_context
        self.users = users
        self.tunnel_config = tunnel_config or TunnelConfig()
        self.logging_config = logging_config or LoggingConfig()
        self.transport_config = transport_config or TransportConfig()
        self.authenticated = False
        self.binary_mode = False
        self.channels: Dict[int, Channel] = {}
        self.channel_tasks: Dict[int, asyncio.Task] = {}
        self.write_lock = asyncio.Lock()
        self.drain_state: Dict[int, Tuple[int, float]] = {}
        self.drain_tasks: Dict[int, asyncio.Task] = {}
        self.keepalive_ack_event = asyncio.Event()

        # User info (set after authentication)
        self.username: Optional[str] = None
        self.user_config: Optional[UserConfig] = None

        peer = writer.get_extra_info('peername')
        self.client_ip = peer[0] if peer else "unknown"
        self.peer_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"

    def _log(self, level: int, msg: str):
        """Log message with optional user info."""
        if self.username and not self.config.log_users:
            return

        if self.user_config and not self.user_config.logging:
            return  # Logging disabled for this user

        if self.username:
            logger.log(level, f"[{self.username}] {msg}")
        else:
            logger.log(level, msg)

    async def run(self):
        """Main session handler."""
        apply_socket_options(self.writer, self.transport_config)
        logger.info(f"Connection from {self.peer_str}")

        try:
            # Phase 1: SMTP handshake
            if not await self._smtp_handshake():
                return

            self._log(logging.INFO, f"Authenticated, entering binary mode: {self.peer_str}")

            # Phase 2: Binary streaming mode
            await self._binary_mode()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._log(logging.ERROR, f"Session error: {e}")
        finally:
            await self._cleanup()
            self._log(logging.INFO, f"Session ended: {self.peer_str}")

    async def _smtp_handshake(self) -> bool:
        """Do SMTP handshake - this is what DPI sees."""
        try:
            # Send greeting
            await self._send_line(f"220 {self.config.hostname} ESMTP Postfix (Ubuntu)")

            # Wait for EHLO
            line = await self._read_line()
            if not line or not line.upper().startswith(('EHLO', 'HELO')):
                return False

            # Send capabilities
            await self._send_line(f"250-{self.config.hostname}")
            await self._send_line("250-STARTTLS")
            await self._send_line("250-AUTH PLAIN")
            await self._send_line("250 8BITMIME")

            # Wait for STARTTLS
            line = await self._read_line()
            if not line or line.upper() != 'STARTTLS':
                return False

            await self._send_line("220 2.0.0 Ready to start TLS")

            # Upgrade to TLS
            await self._upgrade_tls()

            # Wait for EHLO again
            line = await self._read_line()
            if not line or not line.upper().startswith(('EHLO', 'HELO')):
                return False

            await self._send_line(f"250-{self.config.hostname}")
            await self._send_line("250-AUTH PLAIN")
            await self._send_line("250 8BITMIME")

            # Wait for AUTH
            line = await self._read_line()
            if not line or not line.upper().startswith('AUTH'):
                return False

            parts = line.split(' ', 2)
            if len(parts) < 3 or parts[1].upper() != 'PLAIN':
                await self._send_line("535 5.7.8 Authentication failed")
                return False

            token = parts[2]

            # Multi-user authentication
            valid, username = TunnelCrypto.verify_auth_token_multi_user(token, self.users)

            if not valid or not username:
                logger.warning(f"Authentication failed from {self.peer_str}")
                await self._send_line("535 5.7.8 Authentication failed")
                return False

            # Get user config
            self.username = username
            self.user_config = self.users.get(username)

            # Check per-user IP whitelist
            if self.user_config and self.user_config.whitelist:
                user_whitelist = IPWhitelist(self.user_config.whitelist)
                if not user_whitelist.is_allowed(self.client_ip):
                    logger.warning(f"User {username} not allowed from IP {self.client_ip}")
                    await self._send_line("535 5.7.8 Authentication failed")
                    return False

            await self._send_line("235 2.7.0 Authentication successful")
            self.authenticated = True

            # Signal binary mode - client sends special marker
            line = await self._read_line()
            if line == "BINARY":
                await self._send_line("299 Binary mode activated")
                self.binary_mode = True
                return True

            return False

        except Exception as e:
            logger.error(f"Handshake error: {e}")
            return False

    async def _upgrade_tls(self):
        """Upgrade connection to TLS."""
        transport = self.writer.transport
        protocol = self.writer._protocol
        loop = asyncio.get_event_loop()

        new_transport = await loop.start_tls(
            transport, protocol, self.ssl_context, server_side=True
        )

        self.writer._transport = new_transport
        self.reader._transport = new_transport
        apply_socket_options(self.writer, self.transport_config)
        logger.debug(f"TLS established: {self.peer_str}")

    async def _send_line(self, line: str):
        """Send SMTP line."""
        self.writer.write(f"{line}\r\n".encode())
        await self.writer.drain()

    async def _read_line(self) -> Optional[str]:
        """Read SMTP line."""
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=60.0)
            if not data:
                return None
            return data.decode('utf-8', errors='replace').strip()
        except:
            return None

    async def _binary_mode(self):
        """Handle binary streaming mode - this is FAST."""
        frame_buffer = ActiveFrameBuffer()

        while True:
            # Read data
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(self.transport_config.read_chunk_size),
                    timeout=60.0
                )
                if not chunk:
                    self._log(logging.DEBUG, "Connection closed by client")
                    break
            except asyncio.TimeoutError:
                # Check if connection is still alive
                if self.writer.is_closing():
                    break
                continue
            except FrameProtocolError as e:
                self._log(logging.WARNING, f"Malformed tunnel frame: {e}")
                break
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                self._log(logging.DEBUG, f"Connection error: {e}")
                break

            try:
                frame_buffer.append(chunk)
                for frame_type, channel_id, payload in frame_buffer.iter_frames():
                    await self._handle_frame(frame_type, channel_id, payload)
            except FrameProtocolError as e:
                self._log(logging.WARNING, f"Malformed tunnel frame: {e}")
                break

    async def _handle_frame(self, frame_type: int, channel_id: int, payload: bytes):
        """Handle a binary frame."""
        if frame_type == FRAME_CONNECT:
            await self._handle_connect(channel_id, payload)
        elif frame_type == FRAME_DATA:
            await self._handle_data(channel_id, payload)
        elif frame_type == FRAME_CLOSE:
            await self._handle_close(channel_id)
        elif frame_type == FRAME_KEEPALIVE:
            await self._send_frame(FRAME_KEEPALIVE_ACK, CONTROL_CHANNEL_ID)
        elif frame_type == FRAME_KEEPALIVE_ACK:
            self.keepalive_ack_event.set()

    async def _handle_connect(self, channel_id: int, payload: bytes):
        """Handle CONNECT request."""
        try:
            host, port = parse_connect_payload(payload)

            self._log(logging.INFO, f"CONNECT ch={channel_id} destination={format_destination(host, port, self.logging_config)}")

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.tunnel_config.connect_timeout
                )
                if os.name != 'nt':
                    apply_socket_options(writer, self.transport_config)

                channel = Channel(
                    channel_id=channel_id,
                    host=host,
                    port=port,
                    reader=reader,
                    writer=writer,
                    connected=True
                )
                self.channels[channel_id] = channel

                # Send success before reading from the destination, otherwise
                # fast servers can send DATA before the client processes CONNECT_OK.
                await self._send_frame(FRAME_CONNECT_OK, channel_id)

                # Start reading from destination after the open acknowledgement.
                self.channel_tasks[channel_id] = asyncio.create_task(self._channel_reader(channel))
                self._log(logging.INFO, f"CONNECT success ch={channel_id}")

            except Exception as e:
                self._log(logging.ERROR, f"CONNECT failure ch={channel_id}: {e}")
                await self._send_frame(FRAME_CONNECT_FAIL, channel_id, str(e).encode()[:100])

        except FrameProtocolError as e:
            self._log(logging.WARNING, f"Invalid CONNECT frame ch={channel_id}: {e}")
            await self._send_frame(FRAME_CONNECT_FAIL, channel_id)
        except Exception as e:
            self._log(logging.ERROR, f"Handle connect error ch={channel_id}: {e}")
            await self._send_frame(FRAME_CONNECT_FAIL, channel_id)

    async def _handle_data(self, channel_id: int, payload: bytes):
        """Forward data to destination."""
        channel = self.channels.get(channel_id)
        if channel and channel.connected and channel.writer:
            try:
                channel.writer.write(payload)
                await self._drain_writer(channel.writer, len(payload), is_data=True)
            except:
                await self._close_channel(channel)
        else:
            self._log(logging.DEBUG, f"Dropping DATA for unknown ch={channel_id}")

    async def _handle_close(self, channel_id: int):
        """Close channel."""
        channel = self.channels.get(channel_id)
        if channel:
            await self._close_channel(channel)
        else:
            self._log(logging.DEBUG, f"Ignoring CLOSE for unknown ch={channel_id}")

    async def _channel_reader(self, channel: Channel):
        """Read from destination and send to client."""
        try:
            while channel.connected:
                data = await channel.reader.read(self.transport_config.read_chunk_size)
                if not data:
                    break

                await self._send_frame(FRAME_DATA, channel.channel_id, data)

        except Exception as e:
            logger.debug(f"Channel reader error: {e}")
        finally:
            self.channel_tasks.pop(channel.channel_id, None)
            if channel.connected:
                await self._send_frame(FRAME_CLOSE, channel.channel_id)
                await self._close_channel(channel)

    async def _send_frame(self, frame_type: int, channel_id: int, payload: bytes = b''):
        """Send binary frame to client."""
        if self.writer.is_closing():
            return
        try:
            async with self.write_lock:
                frame = encode_frame(frame_type, channel_id, payload)
                self.writer.write(frame)
                await self._drain_writer(self.writer, len(frame), is_data=(frame_type == FRAME_DATA))
        except FrameProtocolError as e:
            self._log(logging.ERROR, f"Refusing to send malformed tunnel frame: {e}")
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

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
            pass
        finally:
            self.drain_tasks.pop(key, None)

    async def _close_channel(self, channel: Channel):
        """Close a channel."""
        if not channel.connected:
            return
        channel.connected = False

        if channel.writer:
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
        self._log(logging.INFO, f"channel close ch={channel.channel_id}")
        self._log(logging.DEBUG, f"Closed ch={channel.channel_id}")

    async def _cleanup(self):
        """Cleanup session."""
        for channel in list(self.channels.values()):
            await self._close_channel(channel)
        for task in list(self.channel_tasks.values()):
            task.cancel()
        for task in list(self.channel_tasks.values()):
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.channel_tasks.clear()
        for task in self.drain_tasks.values():
            task.cancel()
        self.drain_tasks.clear()
        self.drain_state.clear()
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), timeout=5.0)
        except:
            pass


# ============================================================================
# Server
# ============================================================================

class TunnelServer:
    def __init__(
        self,
        config: ServerConfig,
        users: Dict[str, UserConfig],
        tunnel_config: TunnelConfig = None,
        logging_config: LoggingConfig = None,
        transport_config: TransportConfig = None,
    ):
        self.config = config
        self.users = users
        self.tunnel_config = tunnel_config or TunnelConfig()
        self.logging_config = logging_config or LoggingConfig()
        self.transport_config = transport_config or TransportConfig()
        self.ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.config.cert_file, self.config.key_file)
        return ctx

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session = TunnelSession(
            reader,
            writer,
            self.config,
            self.ssl_context,
            self.users,
            self.tunnel_config,
            self.logging_config,
            self.transport_config,
        )
        await session.run()

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client,
            self.config.host,
            self.config.port
        )
        addr = server.sockets[0].getsockname()
        logger.info(f"SMTP Tunnel Server on {addr[0]}:{addr[1]}")
        logger.info(f"Hostname: {self.config.hostname}")
        logger.info(f"Users loaded: {len(self.users)}")

        async with server:
            await server.serve_forever()


# ============================================================================
# Reverse Dialer - Exit Node
# ============================================================================

class ReverseExitSession:
    """Binary frame handler for a reverse-dial tunnel session."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        reverse_config: ReverseDialConfig,
        tunnel_config: TunnelConfig = None,
        logging_config: LoggingConfig = None,
        transport_config: TransportConfig = None,
        session_id: int = 1,
    ):
        self.reader = reader
        self.writer = writer
        self.reverse_config = reverse_config
        self.tunnel_config = tunnel_config or TunnelConfig()
        self.logging_config = logging_config or LoggingConfig()
        self.transport_config = transport_config or TransportConfig()
        self.session_id = session_id
        self.channels: Dict[int, Channel] = {}
        self.channel_tasks: Dict[int, asyncio.Task] = {}
        self.write_lock = asyncio.Lock()
        self.drain_state: Dict[int, Tuple[int, float]] = {}
        self.drain_tasks: Dict[int, asyncio.Task] = {}
        self.keepalive_ack_event = asyncio.Event()
        self.connected = True

    async def run(self):
        frame_buffer = ActiveFrameBuffer()
        try:
            while self.connected:
                try:
                    chunk = await asyncio.wait_for(
                        self.reader.read(self.transport_config.read_chunk_size),
                        timeout=60.0
                    )
                    if not chunk:
                        break
                    frame_buffer.append(chunk)
                    for frame_type, channel_id, payload in frame_buffer.iter_frames():
                        await self._handle_frame(frame_type, channel_id, payload)
                except asyncio.TimeoutError:
                    if self.writer.is_closing():
                        break
                    continue
                except FrameProtocolError as e:
                    logger.warning(f"[reverse session {self.session_id}] Malformed reverse tunnel frame: {e}")
                    break
        finally:
            self.connected = False
            await self._cleanup()

    async def _handle_frame(self, frame_type: int, channel_id: int, payload: bytes):
        if frame_type == FRAME_CONNECT:
            await self._handle_connect(channel_id, payload)
        elif frame_type == FRAME_DATA:
            await self._handle_data(channel_id, payload)
        elif frame_type == FRAME_CLOSE:
            await self._handle_close(channel_id)
        elif frame_type == FRAME_KEEPALIVE:
            await self._send_frame(FRAME_KEEPALIVE_ACK, CONTROL_CHANNEL_ID)
        elif frame_type == FRAME_KEEPALIVE_ACK:
            self.keepalive_ack_event.set()

    async def _handle_connect(self, channel_id: int, payload: bytes):
        try:
            host, port = parse_connect_payload(payload)
            logger.info(
                f"[reverse session {self.session_id}] CONNECT start ch={channel_id} "
                f"destination={format_destination(host, port, self.logging_config)}"
            )
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.tunnel_config.connect_timeout
                )
                if os.name != 'nt':
                    apply_socket_options(writer, self.transport_config)
                channel = Channel(
                    channel_id=channel_id,
                    host=host,
                    port=port,
                    reader=reader,
                    writer=writer,
                    connected=True,
                )
                self.channels[channel_id] = channel
                await self._send_frame(FRAME_CONNECT_OK, channel_id)
                self.channel_tasks[channel_id] = asyncio.create_task(self._channel_reader(channel))
                logger.info(f"[reverse session {self.session_id}] CONNECT success ch={channel_id}")
            except Exception as e:
                logger.warning(f"[reverse session {self.session_id}] CONNECT failure ch={channel_id}: {e}")
                await self._send_frame(FRAME_CONNECT_FAIL, channel_id, str(e).encode()[:100])
        except FrameProtocolError as e:
            logger.warning(f"[reverse session {self.session_id}] Invalid CONNECT ch={channel_id}: {e}")
            await self._send_frame(FRAME_CONNECT_FAIL, channel_id)

    async def _handle_data(self, channel_id: int, payload: bytes):
        channel = self.channels.get(channel_id)
        if channel and channel.connected and channel.writer:
            try:
                channel.writer.write(payload)
                await self._drain_writer(channel.writer, len(payload), is_data=True)
            except Exception:
                await self._close_channel(channel)
        else:
            logger.debug(f"[reverse session {self.session_id}] Dropping DATA for unknown ch={channel_id}")

    async def _handle_close(self, channel_id: int):
        channel = self.channels.get(channel_id)
        if channel:
            await self._close_channel(channel)

    async def _channel_reader(self, channel: Channel):
        try:
            while channel.connected and self.connected:
                data = await channel.reader.read(self.transport_config.read_chunk_size)
                if not data:
                    break
                await self._send_frame(FRAME_DATA, channel.channel_id, data)
        except Exception as e:
            logger.debug(f"[reverse session {self.session_id}] Channel reader error: {e}")
        finally:
            self.channel_tasks.pop(channel.channel_id, None)
            if channel.connected:
                await self._send_frame(FRAME_CLOSE, channel.channel_id)
                await self._close_channel(channel)

    async def _send_frame(self, frame_type: int, channel_id: int, payload: bytes = b''):
        if self.writer.is_closing():
            return
        try:
            async with self.write_lock:
                frame = encode_frame(frame_type, channel_id, payload)
                self.writer.write(frame)
                await self._drain_writer(self.writer, len(frame), is_data=(frame_type == FRAME_DATA))
        except FrameProtocolError as e:
            logger.error(f"[reverse session {self.session_id}] Refusing malformed frame: {e}")
        except (ConnectionResetError, BrokenPipeError, OSError):
            self.connected = False

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

    async def _close_channel(self, channel: Channel):
        if not channel.connected:
            return
        channel.connected = False
        if channel.writer:
            try:
                channel.writer.close()
                await asyncio.wait_for(channel.writer.wait_closed(), timeout=5.0)
            except Exception:
                pass
        self.channels.pop(channel.channel_id, None)
        if channel.writer:
            task = self.drain_tasks.pop(id(channel.writer), None)
            if task:
                task.cancel()
            self.drain_state.pop(id(channel.writer), None)
        logger.info(f"[reverse session {self.session_id}] channel close ch={channel.channel_id}")

    async def _cleanup(self):
        for channel in list(self.channels.values()):
            await self._close_channel(channel)
        for task in list(self.channel_tasks.values()):
            task.cancel()
        for task in list(self.channel_tasks.values()):
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.channel_tasks.clear()
        for task in self.drain_tasks.values():
            task.cancel()
        self.drain_tasks.clear()
        self.drain_state.clear()
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), timeout=5.0)
        except Exception:
            pass


class ReverseDialer:
    """Exit Node dialer for reverse mode."""

    def __init__(
        self,
        reverse_config: ReverseDialConfig,
        tunnel_config: TunnelConfig = None,
        logging_config: LoggingConfig = None,
        transport_config: TransportConfig = None,
    ):
        self.reverse_config = reverse_config
        self.tunnel_config = tunnel_config or TunnelConfig()
        self.logging_config = logging_config or LoggingConfig()
        self.transport_config = transport_config or TransportConfig()

    def _create_ssl_context(self) -> ssl.SSLContext:
        tls = self.reverse_config.tls
        if tls.verify_mode == 'fingerprint':
            logger.warning("Using reverse TLS fingerprint pinning; CA verification is replaced by explicit fingerprint check")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            if tls.verify_mode == 'private-ca':
                if not tls.ca_cert:
                    raise ValueError("server.reverse.tls.ca_cert is required for private-ca verification")
                ctx.load_verify_locations(tls.ca_cert)

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

    async def _expect_250(self, reader: asyncio.StreamReader) -> bool:
        while True:
            line = await self._read_line(reader)
            if not line:
                return False
            if line.startswith('250 '):
                return True
            if line.startswith('250-'):
                continue
            return False

    async def _upgrade_tls(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ssl_context: ssl.SSLContext,
    ):
        transport = writer.transport
        protocol = writer._protocol
        loop = asyncio.get_event_loop()
        server_name = self.reverse_config.tls_server_name or self.reverse_config.access_host

        new_transport = await loop.start_tls(
            transport,
            protocol,
            ssl_context,
            server_hostname=server_name,
        )
        writer._transport = new_transport
        reader._transport = new_transport
        apply_socket_options(writer, self.transport_config)

        if self.reverse_config.tls.verify_mode == 'fingerprint':
            ssl_object = writer.get_extra_info('ssl_object')
            if not verify_peer_fingerprint(ssl_object, self.reverse_config.tls.cert_fingerprint_sha256):
                raise ssl.SSLError("reverse TLS certificate fingerprint mismatch")

    async def _smtp_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        line = await self._read_line(reader)
        if not line or not line.startswith('220'):
            return False

        await self._send_line(writer, f"EHLO {self.reverse_config.tls_server_name or self.reverse_config.access_host}")
        if not await self._expect_250(reader):
            return False

        await self._send_line(writer, "STARTTLS")
        line = await self._read_line(reader)
        if not line or not line.startswith('220'):
            return False

        await self._upgrade_tls(reader, writer, self._create_ssl_context())

        await self._send_line(writer, f"EHLO {self.reverse_config.tls_server_name or self.reverse_config.access_host}")
        if not await self._expect_250(reader):
            return False

        token = TunnelCrypto(self.reverse_config.auth_secret, is_server=False).generate_auth_token(
            int(time.time()),
            self.reverse_config.auth_username,
        )
        await self._send_line(writer, f"AUTH PLAIN {token}")
        line = await self._read_line(reader)
        if not line or not line.startswith('235'):
            logger.warning("Reverse authentication rejected by Access Node")
            return False

        await self._send_line(writer, "BINARY")
        line = await self._read_line(reader)
        if not line or not line.startswith('299'):
            return False
        return True

    async def connect_once(self, session_id: int):
        logger.info(
            f"Reverse dial session {session_id} connecting to "
            f"{self.reverse_config.access_host}:{self.reverse_config.access_port}"
        )
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.reverse_config.access_host, self.reverse_config.access_port),
            timeout=30.0,
        )
        apply_socket_options(writer, self.transport_config)
        try:
            if not await self._smtp_handshake(reader, writer):
                raise ConnectionError("reverse SMTP/TLS/auth handshake failed")
            logger.info(f"Reverse dial session {session_id} authenticated")
            session = ReverseExitSession(
                reader,
                writer,
                self.reverse_config,
                self.tunnel_config,
                self.logging_config,
                self.transport_config,
                session_id=session_id,
            )
            await session.run()
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
            except Exception:
                pass

    async def run_session_forever(self, session_id: int):
        initial = max(0.1, float(self.tunnel_config.reconnect_initial_delay or 2.0))
        max_delay = max(initial, float(self.tunnel_config.reconnect_max_delay or 30.0))
        jitter = max(0.0, float(self.tunnel_config.reconnect_jitter or 0.0))
        delay = initial

        while True:
            try:
                await self.connect_once(session_id)
                delay = initial
                logger.warning(f"Reverse dial session {session_id} disconnected")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"Reverse dial session {session_id} failed: {e}")

            spread = delay * jitter
            sleep_for = max(0.0, delay + random.uniform(-spread, spread))
            logger.info(f"Reverse dial session {session_id} reconnect in {sleep_for:.1f}s")
            await asyncio.sleep(sleep_for)
            delay = min(delay * 2, max_delay)

    async def run_forever(self):
        connections = max(1, int(self.tunnel_config.connections or 1))
        logger.info(f"Reverse dial configured sessions: {connections}")
        tasks = [
            asyncio.create_task(self.run_session_forever(session_id))
            for session_id in range(1, connections + 1)
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                try:
                    await task
                except asyncio.CancelledError:
                    pass


def build_server_settings(config_data: dict, args) -> Tuple[
    ServerConfig,
    TunnelConfig,
    str,
    LoggingConfig,
    TransportConfig,
]:
    """Build validated server settings from config and CLI overrides."""
    server_conf = (config_data or {}).get('server', {}) or {}

    config = ServerConfig(
        host=server_conf.get('host', '0.0.0.0'),
        port=validate_tcp_port(server_conf.get('port'), 587, 'server.port'),
        hostname=server_conf.get('hostname', 'mail.example.com'),
        cert_file=server_conf.get('cert_file', 'server.crt'),
        key_file=server_conf.get('key_file', 'server.key'),
        users_file=server_conf.get('users_file', 'users.yaml'),
        log_users=server_conf.get('log_users', True),
    )
    users_file = args.users or config.users_file
    tunnel_config = build_tunnel_config(config_data)
    logging_config = build_logging_config(config_data)
    transport_config = build_transport_config(config_data)
    return config, tunnel_config, users_file, logging_config, transport_config


def check_server_config(config_path: str, args) -> int:
    """Validate server configuration without starting the listener."""
    errors = []
    warnings = []

    try:
        config_data = load_config(config_path)
        mode = get_server_mode(config_data)
        config, tunnel_config, users_file, logging_config, transport_config = build_server_settings(config_data, args)
        reverse_config = build_reverse_dial_config(config_data) if mode == MODE_REVERSE_DIAL else None
    except FileNotFoundError:
        print(f"ERROR: config file not found: {config_path}")
        return 1
    except Exception as e:
        print(f"ERROR: invalid server config: {e}")
        return 1

    users = {}
    if mode == MODE_NORMAL:
        if not config.host:
            errors.append("server.host is required")
        if not config.hostname:
            errors.append("server.hostname is required")

        for label, path in (
            ("server.cert_file", config.cert_file),
            ("server.key_file", config.key_file),
            ("server.users_file", users_file),
        ):
            if not path:
                errors.append(f"{label} is required")
            elif not os.path.exists(path):
                errors.append(f"{label} does not exist: {path}")
            elif not os.path.isfile(path):
                errors.append(f"{label} is not a file: {path}")

        users = load_users(users_file) if os.path.exists(users_file) else {}
        if not users:
            warnings.append("users file contains no users; all authentication attempts will fail")
    else:
        if not reverse_config.access_host:
            errors.append("server.reverse.access_host is required")
        if not reverse_config.tls_server_name:
            errors.append("server.reverse.tls_server_name is required")
        if not reverse_config.auth_username:
            errors.append("server.reverse.auth_username is required")
        if not reverse_config.auth_secret:
            errors.append("server.reverse.auth_secret or auth_secret_file is required")
        if reverse_config.tls.verify_mode == 'private-ca':
            if not reverse_config.tls.ca_cert:
                errors.append("server.reverse.tls.ca_cert is required for private-ca verification")
            elif not os.path.isfile(reverse_config.tls.ca_cert):
                errors.append(f"server.reverse.tls.ca_cert does not exist: {reverse_config.tls.ca_cert}")
        if reverse_config.tls.verify_mode == 'fingerprint' and not reverse_config.tls.cert_fingerprint_sha256:
            errors.append("server.reverse.tls.cert_fingerprint_sha256 is required for fingerprint verification")
        if reverse_config.mtls.enabled:
            errors.append("reverse mTLS is planned for Stage 1b and is not implemented in Stage 1")

    print("Server config check")
    print(f"  Config: {config_path}")
    print(f"  Mode: {mode}")
    if mode == MODE_NORMAL:
        print(f"  Listen: {config.host}:{config.port}")
        print(f"  Hostname: {config.hostname}")
        print(f"  Cert: {config.cert_file}")
        print(f"  Key: {config.key_file}")
        print(f"  Users: {users_file} ({len(users)} loaded)")
        print("  Keepalive response: enabled when client sends keepalive frames")
    else:
        print(f"  Reverse target: {reverse_config.access_host}:{reverse_config.access_port}")
        print(f"  TLS server name: {reverse_config.tls_server_name}")
        print(f"  TLS verify mode: {reverse_config.tls.verify_mode}")
    print(f"  Configured keepalive interval for generated/shared configs: {tunnel_config.keepalive_interval:g}s")
    print(f"  Connect timeout: {tunnel_config.connect_timeout:g}s")
    print(f"  Log destinations: {logging_config.log_destinations}")
    print(f"  Read chunk size: {transport_config.read_chunk_size}")

    for warning in warnings:
        print(f"WARNING: {warning}")
    for error in errors:
        print(f"ERROR: {error}")

    if errors:
        return 1

    print("OK: server config is valid")
    return 0


def main():
    parser = argparse.ArgumentParser(description='SMTP Tunnel Server')
    parser.add_argument('--config', '-c', default='config.yaml')
    parser.add_argument('--users', '-u', default=None, help='Users file (default: from config or users.yaml)')
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
        return check_server_config(args.config, args)

    try:
        mode = get_server_mode(config_data)
        config, tunnel_config, users_file, logging_config, transport_config = build_server_settings(config_data, args)
    except Exception as e:
        logger.error(f"Invalid server config: {e}")
        return 1

    if mode == MODE_REVERSE_DIAL:
        try:
            reverse_config = build_reverse_dial_config(config_data)
            dialer = ReverseDialer(reverse_config, tunnel_config, logging_config, transport_config)
            asyncio.run(dialer.run_forever())
        except KeyboardInterrupt:
            logger.info("Reverse dialer stopped")
        except Exception as e:
            logger.error(f"Invalid reverse-dial config: {e}")
            return 1
        return 0

    # Load users file (command line override or from config)
    if not os.path.exists(users_file):
        logger.error(f"Users file not found: {users_file}")
        return 1

    users = load_users(users_file)

    if not users:
        logger.warning(f"No users configured in {users_file}; authentication will fail until a user is added")
        logger.warning("Use smtp-tunnel-adduser to add users, then restart the service")

    if not os.path.exists(config.cert_file):
        logger.error(f"Certificate not found: {config.cert_file}")
        return 1

    server = TunnelServer(config, users, tunnel_config, logging_config, transport_config)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Server stopped")

    return 0


if __name__ == '__main__':
    exit(main())
