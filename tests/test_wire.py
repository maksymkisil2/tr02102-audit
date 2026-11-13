"""TLS wire format: ClientHello construction and hostile-input parsing."""

import struct

import pytest

from tr02102_audit.tls import wire
from tr02102_audit.tls.registry import suite_info


def _server_hello(
    cipher: int, *, version: int = 0x0303, exts: bytes = b"", random: bytes | None = None
) -> bytes:
    body = (
        struct.pack("!H", version)
        + (random or bytes(32))
        + b"\x00"
        + struct.pack("!H", cipher)
        + b"\x00"
    )
    if exts:
        body += struct.pack("!H", len(exts)) + exts
    return body


def _ext(t: int, data: bytes) -> bytes:
    return struct.pack("!HH", t, len(data)) + data


def test_client_hello_is_a_well_formed_record() -> None:
    spec = wire.HelloSpec(
        client_version=0x0303,
        cipher_suites=[0xC02B, 0x1301],
        server_name="example.org",
        groups=[23, 29],
        signature_schemes=[0x0403],
        tls13=True,
    )
    record = wire.build_client_hello(spec)
    assert record[0] == wire.CT_HANDSHAKE
    assert int.from_bytes(record[3:5], "big") == len(record) - 5
    assert record[5] == wire.HS_CLIENT_HELLO
    assert int.from_bytes(record[6:9], "big") == len(record) - 9
    assert b"example.org" in record
    assert struct.pack("!HH", wire.EXT_KEY_SHARE, 2) + b"\x00\x00" in record  # empty key_share


def test_server_hello_tls12() -> None:
    hello = wire.parse_server_hello(
        _server_hello(0xC02F, exts=_ext(wire.EXT_EXTENDED_MASTER_SECRET, b""))
    )
    assert (hello.version, hello.cipher_suite, hello.is_hrr) == (0x0303, 0xC02F, False)
    assert wire.EXT_EXTENDED_MASTER_SECRET in hello.extensions


def test_hello_retry_request_reports_version_and_group() -> None:
    exts = _ext(wire.EXT_SUPPORTED_VERSIONS, b"\x03\x04") + _ext(wire.EXT_KEY_SHARE, b"\x00\x17")
    hello = wire.parse_server_hello(_server_hello(0x1302, exts=exts, random=wire.HRR_RANDOM))
    assert hello.is_hrr and hello.version == 0x0304 and hello.selected_group == 23


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\x03\x03" + bytes(10),  # truncated random
        _server_hello(0x002F)[:-1],  # missing compression byte
        _server_hello(0x002F) + b"\x00\x10\x00",  # extensions length beyond data
        _server_hello(0x002F, exts=_ext(23, b"") + _ext(23, b"")),  # duplicate extension
    ],
)
def test_malformed_server_hello_is_rejected(body: bytes) -> None:
    with pytest.raises(wire.ParseError):
        wire.parse_server_hello(body)


def test_certificate_chain_and_limits() -> None:
    cert = b"\x30\x03abc"
    entry = len(cert).to_bytes(3, "big") + cert
    body = (len(entry) * 2).to_bytes(3, "big") + entry * 2
    assert wire.parse_certificate_chain(body) == [cert, cert]
    with pytest.raises(wire.ParseError):
        wire.parse_certificate_chain(b"\x00\x00\x10" + entry)  # declared length too long


def test_server_key_exchange() -> None:
    assert (
        wire.parse_server_key_exchange(
            b"\x03\x00\x18" + b"\x41" + bytes(65), ecdhe=True
        ).named_group
        == 24
    )
    prime = (2**3071 + 1).to_bytes(384, "big")
    params = wire.parse_server_key_exchange(struct.pack("!H", len(prime)) + prime, ecdhe=False)
    assert params.dh_prime_bits == 3072


def test_handshake_messages_split_across_records() -> None:
    buf = bytearray(b"\x02\x00\x00\x03ab")
    assert wire.split_handshake_messages(buf) == []
    buf += b"c\x0e\x00\x00\x00"
    assert wire.split_handshake_messages(buf) == [(2, b"abc"), (14, b"")]
    with pytest.raises(wire.ParseError):
        wire.split_handshake_messages(bytearray(b"\x0b\xff\xff\xff"))  # 16 MiB message


@pytest.mark.parametrize(
    ("name", "pfs", "aead", "cbc", "broken"),
    [
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", True, True, False, False),
        ("TLS_RSA_WITH_AES_128_CBC_SHA", False, False, True, False),
        ("TLS_DH_anon_WITH_AES_128_CBC_SHA", False, False, True, True),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", False, False, True, True),
        ("TLS_AES_256_GCM_SHA384", True, True, False, False),
    ],
)
def test_suite_properties(name: str, pfs: bool, aead: bool, cbc: bool, broken: bool) -> None:
    info = suite_info(name)
    assert (info.forward_secrecy, info.aead, info.cbc, info.broken) == (pfs, aead, cbc, broken)
