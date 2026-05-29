"""
SMTP Tunnel - Common Protocol and Utilities
Shared components for both client and server.

Version: 1.3.0
"""

import struct
import asyncio
import random
import hashlib
import hmac
import os
import base64
import time
import ssl
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# ============================================================================
# Protocol Constants
# ============================================================================

PROTOCOL_VERSION = 1
MAX_PAYLOAD_SIZE = 65535
NONCE_SIZE = 12
TAG_SIZE = 16
MODE_NORMAL = 'normal'
MODE_REVERSE_LISTEN = 'reverse-listen'
MODE_REVERSE_DIAL = 'reverse-dial'
TLS_CERT_MODE_LETSENCRYPT = 'letsencrypt'
TLS_CERT_MODE_EXISTING = 'existing'
TLS_CERT_MODE_PRIVATE_CA = 'private-ca'
TLS_VERIFY_SYSTEM_CA = 'system-ca'
TLS_VERIFY_PRIVATE_CA = 'private-ca'
TLS_VERIFY_FINGERPRINT = 'fingerprint'

# Message types
class MsgType(IntEnum):
    DATA = 0x01           # Tunnel data
    CONNECT = 0x02        # Open new channel (SOCKS CONNECT)
    CONNECT_OK = 0x03     # Connection established
    CONNECT_FAIL = 0x04   # Connection failed
    CLOSE = 0x05          # Close channel
    KEEPALIVE = 0x06      # Keep connection alive
    KEEPALIVE_ACK = 0x07  # Keepalive response


# ============================================================================
# Active Binary Frame Protocol
# ============================================================================

# This is the active wire protocol used by client.py and server.py after the
# SMTP/STARTTLS/AUTH/BINARY handshake. The TunnelMessage class below is kept for
# compatibility with older/experimental code paths, but it is not the active
# framing format.

FRAME_DATA = MsgType.DATA.value
FRAME_CONNECT = MsgType.CONNECT.value
FRAME_CONNECT_OK = MsgType.CONNECT_OK.value
FRAME_CONNECT_FAIL = MsgType.CONNECT_FAIL.value
FRAME_CLOSE = MsgType.CLOSE.value
FRAME_KEEPALIVE = MsgType.KEEPALIVE.value
FRAME_KEEPALIVE_ACK = MsgType.KEEPALIVE_ACK.value

FRAME_HEADER_SIZE = 5  # type(1) + channel_id(2) + payload_len(2)
MAX_CHANNEL_ID = 0xFFFF
CONTROL_CHANNEL_ID = 0

VALID_FRAME_TYPES = {
    FRAME_DATA,
    FRAME_CONNECT,
    FRAME_CONNECT_OK,
    FRAME_CONNECT_FAIL,
    FRAME_CLOSE,
    FRAME_KEEPALIVE,
    FRAME_KEEPALIVE_ACK,
}

CONTROL_FRAME_TYPES = {FRAME_KEEPALIVE, FRAME_KEEPALIVE_ACK}
CHANNEL_FRAME_TYPES = VALID_FRAME_TYPES - CONTROL_FRAME_TYPES


class FrameProtocolError(ValueError):
    """Raised when an active binary frame is malformed."""


@dataclass
class ActiveFrame:
    """One active 5-byte-header tunnel frame."""

    frame_type: int
    channel_id: int
    payload: bytes = b''


def validate_frame_header(frame_type: int, channel_id: int, payload_len: int) -> None:
    """Validate active frame metadata before sending or dispatching."""
    if frame_type not in VALID_FRAME_TYPES:
        raise FrameProtocolError(f"Unknown frame type: {frame_type}")

    if not 0 <= channel_id <= MAX_CHANNEL_ID:
        raise FrameProtocolError(f"Invalid channel id: {channel_id}")

    if not 0 <= payload_len <= MAX_PAYLOAD_SIZE:
        raise FrameProtocolError(f"Invalid payload length: {payload_len}")

    if frame_type in CONTROL_FRAME_TYPES:
        if channel_id != CONTROL_CHANNEL_ID:
            raise FrameProtocolError("Control frames must use channel id 0")
    elif channel_id == CONTROL_CHANNEL_ID:
        raise FrameProtocolError("Channel frames must use channel id 1..65535")


def encode_frame(frame_type: int, channel_id: int, payload: bytes = b'') -> bytes:
    """Encode an active 5-byte-header tunnel frame."""
    if payload is None:
        payload = b''
    if not isinstance(payload, (bytes, bytearray)):
        raise FrameProtocolError("Frame payload must be bytes")

    payload_bytes = payload if isinstance(payload, bytes) else bytes(payload)
    validate_frame_header(frame_type, channel_id, len(payload_bytes))
    return struct.pack('>BHH', frame_type, channel_id, len(payload_bytes)) + payload_bytes


def parse_frame_header(data: bytes) -> Tuple[int, int, int]:
    """Parse and validate an active frame header."""
    if len(data) < FRAME_HEADER_SIZE:
        raise FrameProtocolError("Insufficient data for frame header")

    frame_type, channel_id, payload_len = struct.unpack('>BHH', data[:FRAME_HEADER_SIZE])
    validate_frame_header(frame_type, channel_id, payload_len)
    return frame_type, channel_id, payload_len


def make_connect_payload(host: str, port: int) -> bytes:
    """Create a CONNECT payload: host_len(1) + host + port(2)."""
    if not host:
        raise FrameProtocolError("CONNECT host is empty")

    host_bytes = host.encode('utf-8')
    if len(host_bytes) > 255:
        raise FrameProtocolError("CONNECT host is too long")

    if not 1 <= int(port) <= 65535:
        raise FrameProtocolError(f"Invalid CONNECT port: {port}")

    return struct.pack('>B', len(host_bytes)) + host_bytes + struct.pack('>H', int(port))


def parse_connect_payload(payload: bytes) -> Tuple[str, int]:
    """Parse and validate a CONNECT payload."""
    if len(payload) < 4:
        raise FrameProtocolError("CONNECT payload too short")

    host_len = payload[0]
    if host_len == 0:
        raise FrameProtocolError("CONNECT host is empty")

    expected_len = 1 + host_len + 2
    if len(payload) != expected_len:
        raise FrameProtocolError("CONNECT payload length mismatch")

    host = payload[1:1 + host_len].decode('utf-8')
    port = struct.unpack('>H', payload[1 + host_len:expected_len])[0]
    if not 1 <= port <= 65535:
        raise FrameProtocolError(f"Invalid CONNECT port: {port}")

    return host, port


class ActiveFrameBuffer:
    """Accumulates stream bytes and extracts complete active frames."""

    def __init__(self):
        self.buffer = bytearray()

    def append(self, data: bytes):
        self.buffer.extend(data)

    def get_frames(self) -> List[ActiveFrame]:
        return [
            ActiveFrame(frame_type, channel_id, payload)
            for frame_type, channel_id, payload in self.iter_frames()
        ]

    def iter_frames(self):
        """Yield complete frames without allocating an intermediate frame list."""
        while len(self.buffer) >= FRAME_HEADER_SIZE:
            frame_type, channel_id, payload_len = parse_frame_header(self.buffer)
            total_len = FRAME_HEADER_SIZE + payload_len

            if len(self.buffer) < total_len:
                break

            payload = bytes(self.buffer[FRAME_HEADER_SIZE:total_len])
            del self.buffer[:total_len]
            yield frame_type, channel_id, payload

    def clear(self):
        self.buffer.clear()


# ============================================================================
# Tunnel Protocol Message
# ============================================================================

@dataclass
class TunnelMessage:
    """
    Binary protocol for multiplexed tunnel traffic.

    Wire format (before encryption):
    ┌─────────┬────────────┬────────────┬──────────────┬─────────────┐
    │ Version │ Msg Type   │ Channel ID │ Payload Len  │   Payload   │
    │ 1 byte  │  1 byte    │  2 bytes   │  2 bytes     │  variable   │
    └─────────┴────────────┴────────────┴──────────────┴─────────────┘
    """
    msg_type: MsgType
    channel_id: int
    payload: bytes

    HEADER_SIZE = 6  # 1 + 1 + 2 + 2

    def serialize(self) -> bytes:
        """Serialize message to bytes."""
        header = struct.pack(
            '>BBHH',
            PROTOCOL_VERSION,
            self.msg_type,
            self.channel_id,
            len(self.payload)
        )
        return header + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple['TunnelMessage', bytes]:
        """Deserialize message from bytes. Returns (message, remaining_bytes)."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Insufficient data for header")

        version, msg_type, channel_id, payload_len = struct.unpack(
            '>BBHH', data[:cls.HEADER_SIZE]
        )

        if version != PROTOCOL_VERSION:
            raise ValueError(f"Unknown protocol version: {version}")

        total_len = cls.HEADER_SIZE + payload_len
        if len(data) < total_len:
            raise ValueError("Insufficient data for payload")

        payload = data[cls.HEADER_SIZE:total_len]
        remaining = data[total_len:]

        return cls(MsgType(msg_type), channel_id, payload), remaining

    @classmethod
    def data(cls, channel_id: int, data: bytes) -> 'TunnelMessage':
        """Create a DATA message."""
        return cls(MsgType.DATA, channel_id, data)

    @classmethod
    def connect(cls, channel_id: int, host: str, port: int) -> 'TunnelMessage':
        """Create a CONNECT message."""
        # Payload: host_len (1) + host + port (2)
        host_bytes = host.encode('utf-8')
        payload = struct.pack('>B', len(host_bytes)) + host_bytes + struct.pack('>H', port)
        return cls(MsgType.CONNECT, channel_id, payload)

    @classmethod
    def connect_ok(cls, channel_id: int) -> 'TunnelMessage':
        """Create a CONNECT_OK message."""
        return cls(MsgType.CONNECT_OK, channel_id, b'')

    @classmethod
    def connect_fail(cls, channel_id: int, reason: str = '') -> 'TunnelMessage':
        """Create a CONNECT_FAIL message."""
        return cls(MsgType.CONNECT_FAIL, channel_id, reason.encode('utf-8'))

    @classmethod
    def close(cls, channel_id: int) -> 'TunnelMessage':
        """Create a CLOSE message."""
        return cls(MsgType.CLOSE, channel_id, b'')

    @classmethod
    def keepalive(cls) -> 'TunnelMessage':
        """Create a KEEPALIVE message."""
        return cls(MsgType.KEEPALIVE, 0, b'')

    @classmethod
    def keepalive_ack(cls) -> 'TunnelMessage':
        """Create a KEEPALIVE_ACK message."""
        return cls(MsgType.KEEPALIVE_ACK, 0, b'')

    def parse_connect(self) -> Tuple[str, int]:
        """Parse CONNECT payload to get host and port."""
        if self.msg_type != MsgType.CONNECT:
            raise ValueError("Not a CONNECT message")
        host_len = self.payload[0]
        host = self.payload[1:1+host_len].decode('utf-8')
        port = struct.unpack('>H', self.payload[1+host_len:3+host_len])[0]
        return host, port


# ============================================================================
# Cryptography
# ============================================================================

class TunnelCrypto:
    """
    Handles encryption/decryption of tunnel messages.
    Uses ChaCha20-Poly1305 for authenticated encryption.
    Key derivation from pre-shared secret using HKDF.
    """

    def __init__(self, secret: str, is_server: bool = False):
        """
        Initialize crypto with pre-shared secret.

        Args:
            secret: Pre-shared key string
            is_server: True for server, False for client
        """
        self.secret = secret.encode('utf-8')
        self.is_server = is_server

        # Derive separate keys for client->server and server->client
        self._derive_keys()

        # Sequence numbers for nonce generation (prevent replay)
        self.send_seq = 0
        self.recv_seq = 0

    def _derive_keys(self):
        """Derive encryption keys from secret using HKDF."""
        # Derive master key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for each direction
            salt=b'smtp-tunnel-v1',
            info=b'tunnel-keys',
            backend=default_backend(),
        )
        key_material = hkdf.derive(self.secret)

        # Split into client->server and server->client keys
        c2s_key = key_material[:32]
        s2c_key = key_material[32:]

        if self.is_server:
            self.send_key = ChaCha20Poly1305(s2c_key)
            self.recv_key = ChaCha20Poly1305(c2s_key)
        else:
            self.send_key = ChaCha20Poly1305(c2s_key)
            self.recv_key = ChaCha20Poly1305(s2c_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data with authenticated encryption.
        Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        # Generate nonce from sequence number + random
        nonce = struct.pack('>Q', self.send_seq) + os.urandom(4)
        self.send_seq += 1

        ciphertext = self.send_key.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt and verify data.
        Input: nonce (12 bytes) + ciphertext + tag (16 bytes)
        Returns: plaintext
        """
        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise ValueError("Data too short")

        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]

        plaintext = self.recv_key.decrypt(nonce, ciphertext, None)
        self.recv_seq += 1

        return plaintext

    def generate_auth_token(self, timestamp: int, username: str = None) -> str:
        """
        Generate authentication token for SMTP AUTH.
        Uses HMAC-SHA256 with timestamp to prevent replay.

        Args:
            timestamp: Unix timestamp
            username: Optional username (for multi-user mode)

        Returns:
            Base64 encoded token
        """
        if username:
            message = f"smtp-tunnel-auth:{username}:{timestamp}".encode()
            mac = hmac.new(self.secret, message, hashlib.sha256).digest()
            # Format: base64(username:timestamp:mac)
            token = f"{username}:{timestamp}:{base64.b64encode(mac).decode()}"
        else:
            # Legacy format for backward compatibility
            message = f"smtp-tunnel-auth:{timestamp}".encode()
            mac = hmac.new(self.secret, message, hashlib.sha256).digest()
            # Format: base64(timestamp:mac)
            token = f"{timestamp}:{base64.b64encode(mac).decode()}"
        return base64.b64encode(token.encode()).decode()

    def verify_auth_token(self, token: str, max_age: int = 300) -> Tuple[bool, Optional[str]]:
        """
        Verify authentication token.

        Args:
            token: Base64 encoded auth token
            max_age: Maximum age in seconds (default 5 minutes)

        Returns:
            Tuple of (is_valid, username) - username is None for legacy tokens
        """
        try:
            decoded = base64.b64decode(token).decode()
            parts = decoded.split(':')

            if len(parts) == 3:
                # New format: username:timestamp:mac
                username, timestamp_str, mac_b64 = parts
                timestamp = int(timestamp_str)
            elif len(parts) == 2:
                # Legacy format: timestamp:mac
                username = None
                timestamp_str, mac_b64 = parts
                timestamp = int(timestamp_str)
            else:
                return False, None

            # Check timestamp freshness
            now = int(time.time())
            if abs(now - timestamp) > max_age:
                return False, None

            # Verify HMAC
            expected_token = self.generate_auth_token(timestamp, username)
            if hmac.compare_digest(token, expected_token):
                return True, username
            return False, None
        except Exception:
            return False, None

    @staticmethod
    def verify_auth_token_multi_user(token: str, users: dict, max_age: int = 300) -> Tuple[bool, Optional[str]]:
        """
        Verify authentication token against multiple users.

        Args:
            token: Base64 encoded auth token
            users: Dict of {username: UserConfig} or {username: secret_string}
            max_age: Maximum age in seconds (default 5 minutes)

        Returns:
            Tuple of (is_valid, username)
        """
        import logging
        logger = logging.getLogger('smtp-tunnel')
        try:
            decoded = base64.b64decode(token).decode()
            parts = decoded.split(':')

            if len(parts) != 3:
                logger.debug(f"Auth: Invalid token format, got {len(parts)} parts")
                return False, None

            username, timestamp_str, mac_b64 = parts
            timestamp = int(timestamp_str)

            # Check timestamp freshness
            now = int(time.time())
            if abs(now - timestamp) > max_age:
                logger.debug(f"Auth: Timestamp expired. Diff: {abs(now-timestamp)}s")
                return False, None

            # Look up user
            if username not in users:
                logger.debug(f"Auth: User '{username}' not found")
                return False, None

            user_data = users[username]
            if isinstance(user_data, UserConfig):
                secret = user_data.secret
            elif isinstance(user_data, dict):
                secret = user_data.get('secret', '')
            else:
                secret = str(user_data)

            # Verify HMAC with user's secret
            crypto = TunnelCrypto(secret)
            expected_token = crypto.generate_auth_token(timestamp, username)
            if hmac.compare_digest(token, expected_token):
                return True, username
            logger.debug(f"Auth: HMAC mismatch for user '{username}'")
            return False, None
        except Exception as e:
            logger.warning(f"Auth: Exception - {e}")
            return False, None


# ============================================================================
# Traffic Shaping
# ============================================================================

class TrafficShaper:
    """
    Implements DPI evasion through traffic shaping:
    - Random delays between messages
    - Padding to standard sizes
    - Occasional dummy messages
    """

    # Standard padding sizes (common email attachment sizes)
    PAD_SIZES = [4096, 8192, 16384, 32768]

    def __init__(
        self,
        min_delay_ms: int = 50,
        max_delay_ms: int = 500,
        dummy_probability: float = 0.1
    ):
        """
        Initialize traffic shaper.

        Args:
            min_delay_ms: Minimum delay between messages
            max_delay_ms: Maximum delay between messages
            dummy_probability: Probability of sending dummy message
        """
        self.min_delay_ms = min_delay_ms
        self.max_delay_ms = max_delay_ms
        self.dummy_probability = dummy_probability

    async def delay(self):
        """Add random delay to simulate human behavior."""
        delay_ms = random.randint(self.min_delay_ms, self.max_delay_ms)
        await asyncio.sleep(delay_ms / 1000.0)

    def pad_data(self, data: bytes) -> bytes:
        """
        Pad data to next standard size.
        Padding format: data_length (2 bytes) + data + random_padding
        """
        data_len = len(data)

        # Find next standard size (need space for 2-byte length prefix)
        total_needed = data_len + 2
        target_size = self.PAD_SIZES[-1]  # Default to largest
        for size in self.PAD_SIZES:
            if total_needed <= size:
                target_size = size
                break

        padding_len = target_size - total_needed
        padding = os.urandom(padding_len) if padding_len > 0 else b''

        # Format: length prefix + data + padding
        return struct.pack('>H', data_len) + data + padding

    @staticmethod
    def unpad_data(padded_data: bytes) -> bytes:
        """Remove padding from data."""
        if len(padded_data) < 2:
            return padded_data

        # Read data length from first 2 bytes
        data_len = struct.unpack('>H', padded_data[:2])[0]

        # Extract data (skip 2-byte length prefix)
        return padded_data[2:2 + data_len]

    def should_send_dummy(self) -> bool:
        """Determine if we should send a dummy message."""
        return random.random() < self.dummy_probability

    def generate_dummy_data(self, min_size: int = 100, max_size: int = 1000) -> bytes:
        """Generate random dummy data."""
        size = random.randint(min_size, max_size)
        return os.urandom(size)


# ============================================================================
# SMTP Message Generation
# ============================================================================

class SMTPMessageGenerator:
    """
    Generates realistic-looking SMTP messages to wrap tunnel data.
    """

    # Realistic subject lines
    SUBJECTS = [
        "Re: Your order #{order_id} has shipped",
        "Invoice attached - Account #{account_id}",
        "Meeting notes from {date}",
        "Fwd: Document you requested",
        "Weekly report - Week {week}",
        "RE: Quick question about the project",
        "Updated files attached",
        "Confirmation: Your appointment on {date}",
        "Receipt for your purchase",
        "Action required: Please review",
        "FW: Important update",
        "Re: Follow up on our conversation",
    ]

    # Sender domains (common providers)
    DOMAINS = [
        "gmail.com", "outlook.com", "yahoo.com", "protonmail.com",
        "icloud.com", "mail.com", "hotmail.com"
    ]

    # First names for realistic From headers
    FIRST_NAMES = [
        "John", "Jane", "Michael", "Sarah", "David", "Emily",
        "James", "Emma", "Robert", "Olivia", "William", "Sophia"
    ]

    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
        "Miller", "Davis", "Rodriguez", "Martinez", "Wilson", "Anderson"
    ]

    # Text bodies for the plain text part
    BODY_TEMPLATES = [
        "Please find the attached document.\n\nBest regards",
        "As discussed, here are the files.\n\nThanks",
        "Attached is the information you requested.\n\nRegards",
        "Please review the attached.\n\nThank you",
        "Here's the document.\n\nBest",
    ]

    def __init__(self, from_domain: str = "example.com", to_domain: str = "example.org"):
        """
        Initialize message generator.

        Args:
            from_domain: Domain for sender addresses
            to_domain: Domain for recipient addresses
        """
        self.from_domain = from_domain
        self.to_domain = to_domain
        self._message_counter = 0

    def generate_message_id(self) -> str:
        """Generate a realistic Message-ID."""
        random_part = os.urandom(8).hex()
        timestamp = int(time.time() * 1000) % 1000000
        return f"<{random_part}.{timestamp}@{self.from_domain}>"

    def generate_subject(self) -> str:
        """Generate a realistic subject line."""
        template = random.choice(self.SUBJECTS)
        now = datetime.now()
        return template.format(
            order_id=random.randint(10000, 99999),
            account_id=random.randint(1000, 9999),
            date=now.strftime("%B %d"),
            week=now.isocalendar()[1]
        )

    def generate_sender(self) -> Tuple[str, str]:
        """Generate realistic From name and address."""
        first = random.choice(self.FIRST_NAMES)
        last = random.choice(self.LAST_NAMES)
        name = f"{first} {last}"

        # Generate email variations
        email_styles = [
            f"{first.lower()}.{last.lower()}",
            f"{first.lower()}{last.lower()}",
            f"{first[0].lower()}{last.lower()}",
            f"{first.lower()}{random.randint(1, 99)}",
        ]
        email = f"{random.choice(email_styles)}@{random.choice(self.DOMAINS)}"

        return name, email

    def generate_recipient(self) -> Tuple[str, str]:
        """Generate realistic To address."""
        first = random.choice(self.FIRST_NAMES)
        last = random.choice(self.LAST_NAMES)
        name = f"{first} {last}"
        email = f"{first.lower()}.{last.lower()}@{self.to_domain}"
        return name, email

    def generate_boundary(self) -> str:
        """Generate MIME boundary."""
        return f"----=_Part_{os.urandom(6).hex()}"

    def wrap_tunnel_data(self, tunnel_data: bytes, filename: str = "document.dat") -> Tuple[str, str, str, str]:
        """
        Wrap tunnel data in a realistic MIME email message.

        Returns:
            Tuple of (from_addr, to_addr, subject, message_body)
        """
        from_name, from_addr = self.generate_sender()
        to_name, to_addr = self.generate_recipient()
        subject = self.generate_subject()
        message_id = self.generate_message_id()
        boundary = self.generate_boundary()

        # Current date in RFC 2822 format
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%a, %d %b %Y %H:%M:%S %z")

        # Base64 encode tunnel data (76 char line width per RFC 2045)
        b64_data = base64.b64encode(tunnel_data).decode('ascii')
        b64_lines = [b64_data[i:i+76] for i in range(0, len(b64_data), 76)]
        b64_formatted = '\r\n'.join(b64_lines)

        # Build MIME message
        body_text = random.choice(self.BODY_TEMPLATES)

        message = f"""From: {from_name} <{from_addr}>
To: {to_name} <{to_addr}>
Subject: {subject}
Date: {date_str}
Message-ID: {message_id}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"

--{boundary}
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

{body_text}

--{boundary}
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="{filename}"

{b64_formatted}
--{boundary}--"""

        # Convert to CRLF line endings
        message = message.replace('\n', '\r\n')

        return from_addr, to_addr, subject, message

    def extract_tunnel_data(self, message: str) -> Optional[bytes]:
        """
        Extract tunnel data from MIME message.

        Returns:
            Extracted binary data or None if not found
        """
        try:
            # Find base64 attachment section
            # Look for Content-Transfer-Encoding: base64 followed by data
            lines = message.replace('\r\n', '\n').split('\n')
            in_attachment = False
            b64_lines = []

            for i, line in enumerate(lines):
                if 'Content-Transfer-Encoding: base64' in line:
                    in_attachment = True
                    continue

                if in_attachment:
                    if line.startswith('--'):
                        break
                    if line.strip():
                        b64_lines.append(line.strip())

            if b64_lines:
                b64_data = ''.join(b64_lines)
                return base64.b64decode(b64_data)

            return None
        except Exception:
            return None


# ============================================================================
# SMTP State Machine
# ============================================================================

class SMTPState:
    """SMTP session state machine for protocol compliance."""

    INITIAL = 'initial'
    GREETED = 'greeted'
    TLS_STARTED = 'tls_started'
    AUTHENTICATED = 'authenticated'
    MAIL_FROM = 'mail_from'
    RCPT_TO = 'rcpt_to'
    DATA = 'data'
    QUIT = 'quit'

    # SMTP Response codes
    READY = 220
    CLOSING = 221
    AUTH_SUCCESS = 235
    OK = 250
    START_INPUT = 354
    AUTH_CONTINUE = 334
    TEMP_FAIL = 421
    SYNTAX_ERROR = 500
    COMMAND_UNRECOGNIZED = 502
    BAD_SEQUENCE = 503
    AUTH_REQUIRED = 530
    AUTH_FAILED = 535


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class UserConfig:
    """Per-user configuration."""
    username: str
    secret: str
    whitelist: List[str] = None  # Per-user IP whitelist (empty = allow all)
    logging: bool = True  # Per-user logging

    def __post_init__(self):
        if self.whitelist is None:
            self.whitelist = []


@dataclass
class ServerConfig:
    """Server configuration."""
    host: str = '0.0.0.0'
    port: int = 587
    hostname: str = 'mail.example.com'
    cert_file: str = 'server.crt'
    key_file: str = 'server.key'
    users_file: str = 'users.yaml'  # Path to users configuration
    log_users: bool = True  # Global logging setting (can be overridden per-user)


class IPWhitelist:
    """
    IP address whitelist with CIDR notation support.

    Usage:
        whitelist = IPWhitelist(['192.168.1.0/24', '10.0.0.1'])
        if whitelist.is_allowed('192.168.1.100'):
            # allow connection
    """

    def __init__(self, entries: List[str] = None):
        """
        Initialize whitelist.

        Args:
            entries: List of IP addresses or CIDR ranges
                    Empty list = allow all connections
        """
        self.entries = entries or []
        self._parsed = []
        self._parse_entries()

    def _parse_entries(self):
        """Parse IP entries into (network, mask) tuples."""
        import ipaddress

        for entry in self.entries:
            try:
                # Try parsing as network (CIDR notation)
                if '/' in entry:
                    network = ipaddress.ip_network(entry, strict=False)
                    self._parsed.append(network)
                else:
                    # Single IP address
                    addr = ipaddress.ip_address(entry)
                    # Convert to /32 (IPv4) or /128 (IPv6) network
                    if addr.version == 4:
                        network = ipaddress.ip_network(f"{entry}/32")
                    else:
                        network = ipaddress.ip_network(f"{entry}/128")
                    self._parsed.append(network)
            except ValueError:
                # Invalid entry, skip it
                pass

    def is_allowed(self, ip: str) -> bool:
        """
        Check if an IP address is allowed.

        Args:
            ip: IP address to check

        Returns:
            True if allowed (empty whitelist = allow all),
            False if not in whitelist
        """
        # Empty whitelist means allow all
        if not self.entries:
            return True

        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)

            for network in self._parsed:
                if addr in network:
                    return True

            return False
        except ValueError:
            # Invalid IP address
            return False

    def __bool__(self):
        """Return True if whitelist has entries (is active)."""
        return bool(self.entries)


@dataclass
class ClientConfig:
    """Client configuration."""
    server_host: str = 'localhost'
    server_port: int = 587
    socks_port: int = 1080
    socks_host: str = '127.0.0.1'
    username: str = ''  # Username for multi-user auth
    secret: str = ''


@dataclass
class TunnelConfig:
    """Runtime tunnel behavior shared by client and server."""
    keepalive_interval: float = 0.0  # 0 disables application-level keepalive
    keepalive_timeout: float = 30.0
    reconnect_initial_delay: float = 2.0
    reconnect_max_delay: float = 30.0
    reconnect_jitter: float = 0.2
    connections: int = 1
    connect_timeout: float = 10.0


@dataclass
class MetricsConfig:
    """Runtime diagnostics for reverse sessions."""
    enabled: bool = True
    log_interval: float = 30.0


@dataclass
class LoggingConfig:
    """Privacy and event logging behavior."""
    log_destinations: bool = False
    log_session_events: bool = True
    log_metrics: bool = True


@dataclass
class TransportConfig:
    """Transport buffering and socket tuning."""
    read_chunk_size: int = 65535
    drain_bytes: int = 262144
    drain_interval_ms: int = 10
    socket_send_buffer: int = 0
    socket_recv_buffer: int = 0
    tcp_nodelay: bool = True
    tcp_keepalive: bool = True
    pending_buffer_limit: int = 1048576


@dataclass
class PerformanceConfig:
    """Named performance profile."""
    profile: str = 'balanced'


@dataclass
class SMTPConfig:
    """SMTP compatibility knobs."""
    ehlo_name: str = 'tunnel-client.local'


@dataclass
class ReverseListenTLSConfig:
    """TLS server settings for Access Node reverse-listen mode."""
    cert_mode: str = TLS_CERT_MODE_EXISTING
    domain: str = ''
    cert_file: str = ''
    key_file: str = ''
    letsencrypt_email: str = ''
    letsencrypt_challenge: str = 'http-01'
    auto_renew: bool = True


@dataclass
class ReverseMTLSConfig:
    """Optional mTLS settings for reverse mode."""
    enabled: bool = False
    client_ca_cert: str = ''
    client_cert_file: str = ''
    client_key_file: str = ''


@dataclass
class ReverseListenConfig:
    """Access Node reverse listener settings."""
    listen_host: str = '0.0.0.0'
    listen_port: int = 587
    auth_username: str = ''
    auth_secret: str = ''
    auth_secret_file: str = ''
    allowed_dialer_ips: List[str] = None
    tls: ReverseListenTLSConfig = None
    mtls: ReverseMTLSConfig = None

    def __post_init__(self):
        if self.allowed_dialer_ips is None:
            self.allowed_dialer_ips = []
        if self.tls is None:
            self.tls = ReverseListenTLSConfig()
        if self.mtls is None:
            self.mtls = ReverseMTLSConfig()


@dataclass
class ReverseDialTLSConfig:
    """TLS client verification settings for Exit Node reverse-dial mode."""
    verify_mode: str = TLS_VERIFY_SYSTEM_CA
    ca_cert: str = ''
    cert_fingerprint_sha256: str = ''


@dataclass
class ReverseDialConfig:
    """Exit Node reverse dialer settings."""
    access_host: str = ''
    access_port: int = 587
    tls_server_name: str = ''
    auth_username: str = ''
    auth_secret: str = ''
    auth_secret_file: str = ''
    tls: ReverseDialTLSConfig = None
    mtls: ReverseMTLSConfig = None

    def __post_init__(self):
        if self.tls is None:
            self.tls = ReverseDialTLSConfig()
        if self.mtls is None:
            self.mtls = ReverseMTLSConfig()


@dataclass
class StealthConfig:
    """Stealth/traffic shaping configuration."""
    min_delay_ms: int = 50
    max_delay_ms: int = 500
    pad_to_sizes: List[int] = None
    dummy_message_probability: float = 0.1

    def __post_init__(self):
        if self.pad_to_sizes is None:
            self.pad_to_sizes = [4096, 8192, 16384]


def load_config(path: str) -> dict:
    """Load configuration from YAML file."""
    import yaml
    with open(path, 'r') as f:
        return yaml.safe_load(f) or {}


def _as_float(value, default: float, name: str, minimum: float = None) -> float:
    """Parse a numeric config value with a clear validation error."""
    if value is None:
        value = default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number")
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{name} must be >= {minimum:g}")
    return parsed


def _as_port(value, default: int, name: str) -> int:
    """Parse and validate a TCP port."""
    if value is None:
        value = default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")
    if not 1 <= parsed <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return parsed


def _as_bool(value, default: bool, name: str) -> bool:
    """Parse a boolean config value."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ('1', 'true', 'yes', 'on'):
            return True
        if lowered in ('0', 'false', 'no', 'off'):
            return False
    raise ValueError(f"{name} must be a boolean")


def _as_int(value, default: int, name: str, minimum: int = None, maximum: int = None) -> int:
    """Parse an integer config value with bounds."""
    if value is None:
        value = default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return parsed


def _as_optional_int(value, default: int, name: str, minimum: int = None, maximum: int = None) -> int:
    """Parse an optional integer config value. 0 disables optional settings."""
    if value is None:
        return default
    return _as_int(value, default, name, minimum, maximum)


def _as_str_list(value, name: str) -> List[str]:
    """Parse a list of strings."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    parsed = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{name} entries must be non-empty strings")
        parsed.append(item.strip())
    return parsed


def load_secret_value(inline_secret: str = '', secret_file: str = '', name: str = 'secret') -> str:
    """Load a secret from either an inline value or a file, preferring the file."""
    if secret_file:
        if not os.path.exists(secret_file):
            raise ValueError(f"{name}_file does not exist: {secret_file}")
        if not os.path.isfile(secret_file):
            raise ValueError(f"{name}_file is not a file: {secret_file}")
        with open(secret_file, 'r', encoding='utf-8') as f:
            secret = f.readline().strip()
        if not secret:
            raise ValueError(f"{name}_file is empty: {secret_file}")
        return secret
    return (inline_secret or '').strip()


def normalize_sha256_fingerprint(value: str) -> str:
    """Normalize a SHA-256 fingerprint to lowercase hex without separators."""
    normalized = (value or '').replace(':', '').replace(' ', '').lower()
    if normalized and (len(normalized) != 64 or any(c not in '0123456789abcdef' for c in normalized)):
        raise ValueError("SHA-256 certificate fingerprint must be 64 hex characters")
    return normalized


def sha256_fingerprint_from_der(cert_der: bytes) -> str:
    """Return lowercase SHA-256 fingerprint for DER certificate bytes."""
    return hashlib.sha256(cert_der).hexdigest()


def sha256_fingerprint_from_pem_file(path: str) -> str:
    """Return SHA-256 fingerprint for the first PEM certificate in a file."""
    with open(path, 'r', encoding='utf-8') as f:
        pem = f.read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    return sha256_fingerprint_from_der(der)


def verify_peer_fingerprint(ssl_object, expected_fingerprint: str) -> bool:
    """Verify the peer certificate fingerprint from a live TLS connection."""
    expected = normalize_sha256_fingerprint(expected_fingerprint)
    if not expected or ssl_object is None:
        return False
    cert_der = ssl_object.getpeercert(binary_form=True)
    if not cert_der:
        return False
    actual = sha256_fingerprint_from_der(cert_der)
    return hmac.compare_digest(actual, expected)


def build_tunnel_config(config_data: dict) -> TunnelConfig:
    """Build TunnelConfig from raw YAML with backward-compatible defaults."""
    tunnel_conf = (config_data or {}).get('tunnel', {}) or {}
    config = TunnelConfig(
        keepalive_interval=_as_float(
            tunnel_conf.get('keepalive_interval'), 0.0,
            'tunnel.keepalive_interval', minimum=0.0
        ),
        keepalive_timeout=_as_float(
            tunnel_conf.get('keepalive_timeout'), 30.0,
            'tunnel.keepalive_timeout', minimum=1.0
        ),
        reconnect_initial_delay=_as_float(
            tunnel_conf.get('reconnect_initial_delay'), 2.0,
            'tunnel.reconnect_initial_delay', minimum=0.1
        ),
        reconnect_max_delay=_as_float(
            tunnel_conf.get('reconnect_max_delay'), 30.0,
            'tunnel.reconnect_max_delay', minimum=0.1
        ),
        reconnect_jitter=_as_float(
            tunnel_conf.get('reconnect_jitter'), 0.2,
            'tunnel.reconnect_jitter', minimum=0.0
        ),
        connections=_as_int(
            tunnel_conf.get('connections'), 1,
            'tunnel.connections', minimum=1
        ),
        connect_timeout=_as_float(
            tunnel_conf.get('connect_timeout'), 10.0,
            'tunnel.connect_timeout', minimum=0.1
        ),
    )
    if config.reconnect_max_delay < config.reconnect_initial_delay:
        raise ValueError("tunnel.reconnect_max_delay must be >= tunnel.reconnect_initial_delay")
    return config


def build_metrics_config(config_data: dict) -> MetricsConfig:
    """Build metrics logging config with production-safe defaults."""
    metrics_conf = (config_data or {}).get('metrics', {}) or {}
    return MetricsConfig(
        enabled=_as_bool(metrics_conf.get('enabled'), True, 'metrics.enabled'),
        log_interval=_as_float(
            metrics_conf.get('log_interval'), 30.0,
            'metrics.log_interval', minimum=1.0
        ),
    )


def build_logging_config(config_data: dict) -> LoggingConfig:
    """Build privacy/event logging config."""
    logging_conf = (config_data or {}).get('logging', {}) or {}
    return LoggingConfig(
        log_destinations=_as_bool(
            logging_conf.get('log_destinations'), False,
            'logging.log_destinations'
        ),
        log_session_events=_as_bool(
            logging_conf.get('log_session_events'), True,
            'logging.log_session_events'
        ),
        log_metrics=_as_bool(
            logging_conf.get('log_metrics'), True,
            'logging.log_metrics'
        ),
    )


def build_performance_config(config_data: dict) -> PerformanceConfig:
    """Build named performance profile config."""
    performance_conf = (config_data or {}).get('performance', {}) or {}
    profile = (performance_conf.get('profile', 'balanced') or 'balanced').strip().lower()
    if profile not in ('compatibility', 'balanced', 'throughput'):
        raise ValueError("performance.profile must be compatibility, balanced, or throughput")
    return PerformanceConfig(profile=profile)


def build_transport_config(config_data: dict) -> TransportConfig:
    """Build transport tuning config without changing the wire protocol."""
    transport_conf = (config_data or {}).get('transport', {}) or {}
    performance = build_performance_config(config_data)
    if performance.profile == 'compatibility':
        defaults = {
            'read_chunk_size': 32768,
            'drain_bytes': 65536,
            'drain_interval_ms': 0,
            'socket_send_buffer': 0,
            'socket_recv_buffer': 0,
            'pending_buffer_limit': 1048576,
        }
    elif performance.profile == 'throughput':
        defaults = {
            'read_chunk_size': 65535,
            'drain_bytes': 1048576,
            'drain_interval_ms': 25,
            'socket_send_buffer': 1048576,
            'socket_recv_buffer': 1048576,
            'pending_buffer_limit': 4194304,
        }
    else:
        defaults = {
            'read_chunk_size': 65535,
            'drain_bytes': 262144,
            'drain_interval_ms': 10,
            'socket_send_buffer': 0,
            'socket_recv_buffer': 0,
            'pending_buffer_limit': 1048576,
        }

    return TransportConfig(
        read_chunk_size=_as_int(
            transport_conf.get('read_chunk_size'), defaults['read_chunk_size'],
            'transport.read_chunk_size', minimum=1024, maximum=65535
        ),
        drain_bytes=_as_int(
            transport_conf.get('drain_bytes'), defaults['drain_bytes'],
            'transport.drain_bytes', minimum=1
        ),
        drain_interval_ms=_as_int(
            transport_conf.get('drain_interval_ms'), defaults['drain_interval_ms'],
            'transport.drain_interval_ms', minimum=0
        ),
        socket_send_buffer=_as_optional_int(
            transport_conf.get('socket_send_buffer'), defaults['socket_send_buffer'],
            'transport.socket_send_buffer', minimum=0
        ),
        socket_recv_buffer=_as_optional_int(
            transport_conf.get('socket_recv_buffer'), defaults['socket_recv_buffer'],
            'transport.socket_recv_buffer', minimum=0
        ),
        tcp_nodelay=_as_bool(
            transport_conf.get('tcp_nodelay'), True,
            'transport.tcp_nodelay'
        ),
        tcp_keepalive=_as_bool(
            transport_conf.get('tcp_keepalive'), True,
            'transport.tcp_keepalive'
        ),
        pending_buffer_limit=_as_int(
            transport_conf.get('pending_buffer_limit'), defaults['pending_buffer_limit'],
            'transport.pending_buffer_limit', minimum=65536
        ),
    )


def format_destination(host: str, port: int, logging_config: LoggingConfig = None) -> str:
    """Return a destination string, redacting host/IP by default."""
    logging_config = logging_config or LoggingConfig()
    if logging_config.log_destinations:
        return f"{host}:{port}"
    return "[redacted]"


def get_client_mode(config_data: dict) -> str:
    """Return client mode with backward-compatible default."""
    client_conf = (config_data or {}).get('client', {}) or {}
    mode = client_conf.get('mode', MODE_NORMAL) or MODE_NORMAL
    if mode not in (MODE_NORMAL, MODE_REVERSE_LISTEN):
        raise ValueError("client.mode must be normal or reverse-listen")
    return mode


def get_server_mode(config_data: dict) -> str:
    """Return server mode with backward-compatible default."""
    server_conf = (config_data or {}).get('server', {}) or {}
    mode = server_conf.get('mode', MODE_NORMAL) or MODE_NORMAL
    if mode not in (MODE_NORMAL, MODE_REVERSE_DIAL):
        raise ValueError("server.mode must be normal or reverse-dial")
    return mode


def build_reverse_listen_config(config_data: dict) -> ReverseListenConfig:
    """Build reverse-listen config from nested or legacy-flat client keys."""
    client_conf = (config_data or {}).get('client', {}) or {}
    reverse_conf = client_conf.get('reverse', {}) or {}
    tls_conf = reverse_conf.get('tls', client_conf.get('reverse_tls', {}) or {}) or {}
    mtls_conf = reverse_conf.get('mtls', client_conf.get('reverse_mtls', {}) or {}) or {}

    cert_mode = tls_conf.get('cert_mode', TLS_CERT_MODE_EXISTING) or TLS_CERT_MODE_EXISTING
    if cert_mode in ('letsencrypt-http', 'letsencrypt-dns'):
        cert_mode = TLS_CERT_MODE_LETSENCRYPT
    if cert_mode not in (TLS_CERT_MODE_LETSENCRYPT, TLS_CERT_MODE_EXISTING, TLS_CERT_MODE_PRIVATE_CA):
        raise ValueError("client.reverse.tls.cert_mode must be letsencrypt, existing, or private-ca")

    challenge = tls_conf.get('letsencrypt_challenge', 'http-01') or 'http-01'
    if challenge not in ('http-01', 'dns-01', 'manual'):
        raise ValueError("client.reverse.tls.letsencrypt_challenge must be http-01, dns-01, or manual")

    tls = ReverseListenTLSConfig(
        cert_mode=cert_mode,
        domain=tls_conf.get('domain', '') or '',
        cert_file=tls_conf.get('cert_file', '') or '',
        key_file=tls_conf.get('key_file', '') or '',
        letsencrypt_email=tls_conf.get('letsencrypt_email', '') or '',
        letsencrypt_challenge=challenge,
        auto_renew=_as_bool(tls_conf.get('auto_renew'), True, 'client.reverse.tls.auto_renew'),
    )

    mtls = ReverseMTLSConfig(
        enabled=_as_bool(mtls_conf.get('enabled'), False, 'client.reverse.mtls.enabled'),
        client_ca_cert=mtls_conf.get('client_ca_cert', '') or '',
    )

    config = ReverseListenConfig(
        listen_host=reverse_conf.get('listen_host', client_conf.get('reverse_listen_host', '0.0.0.0')) or '0.0.0.0',
        listen_port=_as_port(
            reverse_conf.get('listen_port', client_conf.get('reverse_listen_port')),
            587,
            'client.reverse.listen_port'
        ),
        auth_username=reverse_conf.get('auth_username', client_conf.get('username', '')) or '',
        auth_secret=reverse_conf.get('auth_secret', client_conf.get('secret', '')) or '',
        auth_secret_file=reverse_conf.get('auth_secret_file', client_conf.get('secret_file', '')) or '',
        allowed_dialer_ips=_as_str_list(
            reverse_conf.get('allowed_dialer_ips', client_conf.get('reverse_allowed_dialer_ips')),
            'client.reverse.allowed_dialer_ips'
        ),
        tls=tls,
        mtls=mtls,
    )
    config.auth_secret = load_secret_value(config.auth_secret, config.auth_secret_file, 'client.reverse.auth_secret')
    return config


def build_reverse_dial_config(config_data: dict) -> ReverseDialConfig:
    """Build reverse-dial config from nested or legacy-flat server keys."""
    server_conf = (config_data or {}).get('server', {}) or {}
    reverse_conf = server_conf.get('reverse', {}) or {}
    tls_conf = reverse_conf.get('tls', {}) or {}
    mtls_conf = reverse_conf.get('mtls', server_conf.get('reverse_mtls', {}) or {}) or {}

    verify_mode = tls_conf.get('verify_mode', 'system-ca') or 'system-ca'
    legacy_ca = server_conf.get('reverse_ca_cert')
    legacy_fingerprint = server_conf.get('reverse_cert_fingerprint_sha256')
    if legacy_ca and verify_mode == 'system-ca':
        verify_mode = TLS_VERIFY_PRIVATE_CA
    if legacy_fingerprint:
        verify_mode = TLS_VERIFY_FINGERPRINT

    if verify_mode not in (TLS_VERIFY_SYSTEM_CA, TLS_VERIFY_PRIVATE_CA, TLS_VERIFY_FINGERPRINT):
        raise ValueError("server.reverse.tls.verify_mode must be system-ca, private-ca, or fingerprint")

    tls = ReverseDialTLSConfig(
        verify_mode=verify_mode,
        ca_cert=tls_conf.get('ca_cert', legacy_ca or '') or '',
        cert_fingerprint_sha256=normalize_sha256_fingerprint(
            tls_conf.get('cert_fingerprint_sha256', legacy_fingerprint or '') or ''
        ),
    )

    mtls = ReverseMTLSConfig(
        enabled=_as_bool(mtls_conf.get('enabled'), False, 'server.reverse.mtls.enabled'),
        client_cert_file=mtls_conf.get('client_cert_file', '') or '',
        client_key_file=mtls_conf.get('client_key_file', '') or '',
    )

    access_host = reverse_conf.get('access_host', server_conf.get('reverse_client_host', '')) or ''
    tls_server_name = reverse_conf.get('tls_server_name', server_conf.get('reverse_tls_server_name', access_host)) or access_host

    config = ReverseDialConfig(
        access_host=access_host,
        access_port=_as_port(
            reverse_conf.get('access_port', server_conf.get('reverse_client_port')),
            587,
            'server.reverse.access_port'
        ),
        tls_server_name=tls_server_name,
        auth_username=reverse_conf.get('auth_username', server_conf.get('reverse_username', '')) or '',
        auth_secret=reverse_conf.get('auth_secret', server_conf.get('reverse_secret', '')) or '',
        auth_secret_file=reverse_conf.get('auth_secret_file', server_conf.get('reverse_secret_file', '')) or '',
        tls=tls,
        mtls=mtls,
    )
    config.auth_secret = load_secret_value(config.auth_secret, config.auth_secret_file, 'server.reverse.auth_secret')
    return config


def build_smtp_config(config_data: dict) -> SMTPConfig:
    """Build SMTPConfig from raw YAML with backward-compatible defaults."""
    smtp_conf = (config_data or {}).get('smtp', {}) or {}
    ehlo_name = smtp_conf.get('ehlo_name', SMTPConfig().ehlo_name) or SMTPConfig().ehlo_name
    if not isinstance(ehlo_name, str):
        raise ValueError("smtp.ehlo_name must be a string")
    ehlo_name = ehlo_name.strip()
    if not ehlo_name:
        raise ValueError("smtp.ehlo_name must not be empty")
    return SMTPConfig(ehlo_name=ehlo_name)


def validate_tcp_port(value, default: int, name: str) -> int:
    """Public wrapper for port validation used by config checks."""
    return _as_port(value, default, name)


def load_users(path: str) -> Dict[str, UserConfig]:
    """
    Load users from YAML file.

    Args:
        path: Path to users.yaml

    Returns:
        Dict of {username: UserConfig}
    """
    import yaml

    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

    users = {}
    users_data = data.get('users', {})

    for username, user_data in users_data.items():
        if isinstance(user_data, dict):
            users[username] = UserConfig(
                username=username,
                secret=user_data.get('secret', ''),
                whitelist=user_data.get('whitelist', []),
                logging=user_data.get('logging', True)
            )
        elif isinstance(user_data, str):
            # Simple format: username: secret
            users[username] = UserConfig(
                username=username,
                secret=user_data,
                whitelist=[],
                logging=True
            )

    return users


def save_users(path: str, users: Dict[str, UserConfig]):
    """
    Save users to YAML file.

    Args:
        path: Path to users.yaml
        users: Dict of {username: UserConfig}
    """
    lines = ["# SMTP Tunnel Users", "# Managed by smtp-tunnel-adduser", "", "users:"]

    for username, user in users.items():
        lines.append(f"  {username}:")
        lines.append(f"    secret: {user.secret}")
        lines.append(f"    logging: {str(user.logging).lower()}")

        if user.whitelist:
            lines.append("    whitelist:")
            for ip in user.whitelist:
                lines.append(f"      - {ip}")
        else:
            lines.append("    # whitelist:")
            lines.append("    #   - 192.168.1.100")
            lines.append("    #   - 10.0.0.0/8")

        lines.append("")

    with open(path, 'w') as f:
        f.write('\n'.join(lines))


# ============================================================================
# Utilities
# ============================================================================

class FrameBuffer:
    """
    Buffer for accumulating and parsing tunnel messages.
    Handles partial reads and message boundaries.
    """

    def __init__(self):
        self.buffer = b''

    def append(self, data: bytes):
        """Add data to buffer."""
        self.buffer += data

    def get_messages(self) -> List[TunnelMessage]:
        """
        Extract complete messages from buffer.
        Returns list of messages, updates buffer to contain remainder.
        """
        messages = []

        while len(self.buffer) >= TunnelMessage.HEADER_SIZE:
            try:
                # Peek at payload length
                _, _, _, payload_len = struct.unpack(
                    '>BBHH', self.buffer[:TunnelMessage.HEADER_SIZE]
                )
                total_len = TunnelMessage.HEADER_SIZE + payload_len

                if len(self.buffer) < total_len:
                    break  # Wait for more data

                msg, remaining = TunnelMessage.deserialize(self.buffer)
                messages.append(msg)
                self.buffer = remaining

            except ValueError:
                break

        return messages

    def clear(self):
        """Clear the buffer."""
        self.buffer = b''


class AsyncQueue:
    """Simple async queue wrapper for message passing."""

    def __init__(self, maxsize: int = 0):
        self._queue = asyncio.Queue(maxsize=maxsize)

    async def put(self, item):
        await self._queue.put(item)

    async def get(self):
        return await self._queue.get()

    def put_nowait(self, item):
        self._queue.put_nowait(item)

    def get_nowait(self):
        return self._queue.get_nowait()

    def empty(self) -> bool:
        return self._queue.empty()

    def qsize(self) -> int:
        return self._queue.qsize()
