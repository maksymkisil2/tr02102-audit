"""TLS wire format: build ClientHello messages and parse server replies.

Everything here is pure: bytes in, bytes or dataclasses out. Parsers treat
their input as hostile. Every length field is checked against the data that
is actually present, and any inconsistency raises ``ParseError``.
"""

import os
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

# Record content types (RFC 8446, section 5.1)
CT_ALERT = 21
CT_HANDSHAKE = 22

# Handshake message types
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_SERVER_HELLO_DONE = 14

# Extension types
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ENCRYPT_THEN_MAC = 22
EXT_EXTENDED_MASTER_SECRET = 23
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_RENEGOTIATION_INFO = 0xFF01

# A ServerHello with this random value is a HelloRetryRequest (RFC 8446, 4.1.3).
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

MAX_RECORD_PAYLOAD = 2**14 + 2048  # RFC 8446, 5.2: ciphertext limit
MAX_HANDSHAKE_MESSAGE = 128 * 1024  # generous for long certificate chains

ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    47: "illegal_parameter",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
}


class ParseError(ValueError):
    """The peer sent bytes that do not form a valid message."""


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def _u8(n: int) -> bytes:
    return struct.pack("!B", n)


def _u16(n: int) -> bytes:
    return struct.pack("!H", n)


def _u24(n: int) -> bytes:
    return struct.pack("!I", n)[1:]


def _vec8(data: bytes) -> bytes:
    return _u8(len(data)) + data


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _u16_list(values: Iterable[int]) -> bytes:
    return b"".join(_u16(v) for v in values)


def _ext(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _vec16(data)


@dataclass(frozen=True, slots=True)
class HelloSpec:
    """What a probe offers to the server."""

    client_version: int
    cipher_suites: Sequence[int]
    server_name: str | None = None
    groups: Sequence[int] = ()
    signature_schemes: Sequence[int] = ()
    tls13: bool = False  # adds supported_versions and an empty key_share
    record_version: int = 0x0301


def build_client_hello(spec: HelloSpec) -> bytes:
    """Return a complete TLS record containing one ClientHello."""
    extensions = b""
    if spec.server_name:
        name = spec.server_name.encode("idna")
        entry = _u8(0) + _vec16(name)  # name_type host_name
        extensions += _ext(EXT_SERVER_NAME, _vec16(entry))
    if spec.groups:
        extensions += _ext(EXT_SUPPORTED_GROUPS, _vec16(_u16_list(spec.groups)))
    extensions += _ext(EXT_EC_POINT_FORMATS, _vec8(b"\x00"))
    if spec.signature_schemes:
        extensions += _ext(EXT_SIGNATURE_ALGORITHMS, _vec16(_u16_list(spec.signature_schemes)))
    extensions += _ext(EXT_ENCRYPT_THEN_MAC, b"")
    extensions += _ext(EXT_EXTENDED_MASTER_SECRET, b"")
    if spec.tls13:
        extensions += _ext(EXT_SUPPORTED_VERSIONS, _vec8(_u16(0x0304)))
        extensions += _ext(EXT_PSK_KEY_EXCHANGE_MODES, _vec8(b"\x01"))
        # An empty key_share list: the server must answer with a
        # HelloRetryRequest naming the group it selected. No key is needed.
        extensions += _ext(EXT_KEY_SHARE, _vec16(b""))
    extensions += _ext(EXT_RENEGOTIATION_INFO, _vec8(b""))

    body = (
        _u16(spec.client_version)
        + os.urandom(32)
        + _vec8(os.urandom(32))  # session id, for middlebox compatibility
        + _vec16(_u16_list(spec.cipher_suites))
        + _vec8(b"\x00")  # compression: null only
        + _vec16(extensions)
    )
    handshake = _u8(HS_CLIENT_HELLO) + _u24(len(body)) + body
    return _u8(CT_HANDSHAKE) + _u16(spec.record_version) + _vec16(handshake)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class Reader:
    """Bounds-checked cursor over a byte string."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def take(self, n: int) -> bytes:
        if n < 0 or n > self.remaining:
            raise ParseError(f"need {n} bytes, have {self.remaining}")
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        value: int = struct.unpack("!H", self.take(2))[0]
        return value

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vec8(self) -> bytes:
        return self.take(self.u8())

    def vec16(self) -> bytes:
        return self.take(self.u16())

    def vec24(self) -> bytes:
        return self.take(self.u24())


@dataclass(frozen=True, slots=True)
class ServerHello:
    """The parts of a ServerHello (or HelloRetryRequest) a probe needs."""

    legacy_version: int
    version: int  # negotiated version, after supported_versions
    cipher_suite: int
    is_hrr: bool
    extensions: dict[int, bytes] = field(default_factory=dict)

    @property
    def selected_group(self) -> int | None:
        """Group named in key_share (HelloRetryRequest or TLS 1.3 ServerHello)."""
        data = self.extensions.get(EXT_KEY_SHARE)
        if data is None or len(data) < 2:
            return None
        return int.from_bytes(data[:2], "big")


def parse_server_hello(body: bytes) -> ServerHello:
    """Parse the body of a ServerHello handshake message."""
    r = Reader(body)
    legacy_version = r.u16()
    random = r.take(32)
    r.vec8()  # session id
    cipher_suite = r.u16()
    r.u8()  # compression method
    extensions: dict[int, bytes] = {}
    if r.remaining:
        ext_reader = Reader(r.vec16())
        while ext_reader.remaining:
            ext_type = ext_reader.u16()
            if ext_type in extensions:
                raise ParseError(f"duplicate extension {ext_type}")
            extensions[ext_type] = ext_reader.vec16()
    if r.remaining:
        raise ParseError("trailing bytes after ServerHello")

    version = legacy_version
    sv = extensions.get(EXT_SUPPORTED_VERSIONS)
    if sv is not None:
        if len(sv) != 2:
            raise ParseError("malformed supported_versions in ServerHello")
        version = int.from_bytes(sv, "big")
    return ServerHello(
        legacy_version=legacy_version,
        version=version,
        cipher_suite=cipher_suite,
        is_hrr=random == HRR_RANDOM,
        extensions=extensions,
    )


def parse_certificate_chain(body: bytes) -> list[bytes]:
    """Parse a TLS 1.2 Certificate message into DER certificates, leaf first."""
    r = Reader(body)
    chain = Reader(r.vec24())
    certs: list[bytes] = []
    while chain.remaining:
        der = chain.vec24()
        if not der:
            raise ParseError("empty certificate in chain")
        certs.append(der)
        if len(certs) > 16:
            raise ParseError("certificate chain too long")
    return certs


@dataclass(frozen=True, slots=True)
class KeyExchangeParams:
    """Server key-exchange parameters from a TLS 1.2 ServerKeyExchange."""

    named_group: int | None = None  # ECDHE
    dh_prime_bits: int | None = None  # DHE


def parse_server_key_exchange(body: bytes, *, ecdhe: bool) -> KeyExchangeParams:
    """Extract the curve (ECDHE) or the prime size (DHE). Signatures are ignored."""
    r = Reader(body)
    if ecdhe:
        curve_type = r.u8()
        if curve_type != 3:  # named_curve
            raise ParseError(f"unsupported ECDHE curve type {curve_type}")
        return KeyExchangeParams(named_group=r.u16())
    prime = r.vec16().lstrip(b"\x00")
    if not prime:
        raise ParseError("empty DH prime")
    return KeyExchangeParams(dh_prime_bits=int.from_bytes(prime, "big").bit_length())


@dataclass(frozen=True, slots=True)
class Alert:
    level: int
    description: int

    @property
    def name(self) -> str:
        return ALERT_DESCRIPTIONS.get(self.description, f"alert_{self.description}")


def parse_alert(payload: bytes) -> Alert:
    if len(payload) < 2:
        raise ParseError("short alert")
    return Alert(level=payload[0], description=payload[1])


def split_handshake_messages(buffer: bytearray) -> list[tuple[int, bytes]]:
    """Remove complete handshake messages from ``buffer`` and return them."""
    messages: list[tuple[int, bytes]] = []
    while len(buffer) >= 4:
        msg_type = buffer[0]
        length = int.from_bytes(buffer[1:4], "big")
        if length > MAX_HANDSHAKE_MESSAGE:
            raise ParseError(f"handshake message of {length} bytes exceeds limit")
        if len(buffer) < 4 + length:
            break
        messages.append((msg_type, bytes(buffer[4 : 4 + length])))
        del buffer[: 4 + length]
    return messages
