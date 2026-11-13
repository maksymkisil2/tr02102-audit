"""Registry of TLS protocol versions, cipher suites and named groups.

Codes and names follow the IANA "TLS Parameters" registry. Only the
properties a policy needs are derived from a suite name: key exchange,
forward secrecy, bulk cipher mode and known-broken primitives.
"""

from dataclasses import dataclass
from enum import StrEnum


class Version(StrEnum):
    """Protocol versions, named as they appear in reports and policies."""

    SSL3 = "SSL3.0"
    TLS10 = "TLS1.0"
    TLS11 = "TLS1.1"
    TLS12 = "TLS1.2"
    TLS13 = "TLS1.3"


VERSION_CODES: dict[Version, int] = {
    Version.SSL3: 0x0300,
    Version.TLS10: 0x0301,
    Version.TLS11: 0x0302,
    Version.TLS12: 0x0303,
    Version.TLS13: 0x0304,
}
VERSION_BY_CODE: dict[int, Version] = {code: v for v, code in VERSION_CODES.items()}

# Key used for a version in fact paths such as "tls.suites.tls12".
FACT_KEY: dict[Version, str] = {
    Version.SSL3: "ssl3",
    Version.TLS10: "tls10",
    Version.TLS11: "tls11",
    Version.TLS12: "tls12",
    Version.TLS13: "tls13",
}

TLS13_SUITES: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}

# Cipher suites for SSL 3.0 to TLS 1.2. The list covers what servers commonly
# accept, including legacy and broken suites, so weak configurations are found.
LEGACY_SUITES: dict[int, str] = {
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM",
    0xC09D: "TLS_RSA_WITH_AES_256_CCM",
    0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
    0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    0xC0AF: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

ALL_SUITES: dict[int, str] = {**LEGACY_SUITES, **TLS13_SUITES}

GROUPS: dict[int, str] = {
    21: "secp224r1",
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    26: "brainpoolP256r1",
    27: "brainpoolP384r1",
    28: "brainpoolP512r1",
    29: "x25519",
    30: "x448",
    31: "brainpoolP256r1tls13",
    32: "brainpoolP384r1tls13",
    33: "brainpoolP512r1tls13",
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
    259: "ffdhe6144",
    260: "ffdhe8192",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
}

# Groups usable for ECDHE in TLS 1.2 (finite-field groups are negotiated
# differently there, and the "tls13" Brainpool codes are TLS 1.3 only).
TLS12_EC_GROUPS: tuple[int, ...] = (21, 23, 24, 25, 26, 27, 28, 29, 30)
TLS13_GROUPS: tuple[int, ...] = (
    23,
    24,
    25,
    29,
    30,
    31,
    32,
    33,
    256,
    257,
    258,
    259,
    260,
    0x11EB,
    0x11EC,
    0x11ED,
)
HYBRID_PQ_GROUPS: frozenset[str] = frozenset(
    {"SecP256r1MLKEM768", "X25519MLKEM768", "SecP384r1MLKEM1024"}
)

SIGNATURE_SCHEMES: tuple[int, ...] = (
    0x0403,
    0x0503,
    0x0603,  # ecdsa_secp256r1_sha256 ... secp521r1_sha512
    0x081A,
    0x081B,
    0x081C,  # ecdsa_brainpool*tls13
    0x0807,
    0x0808,  # ed25519, ed448
    0x0804,
    0x0805,
    0x0806,  # rsa_pss_rsae_sha256 ... sha512
    0x0809,
    0x080A,
    0x080B,  # rsa_pss_pss_sha256 ... sha512
    0x0401,
    0x0501,
    0x0601,  # rsa_pkcs1_sha256 ... sha512
    0x0402,
    0x0502,
    0x0602,  # dsa_sha256 ... (legacy servers)
    0x0203,
    0x0201,
    0x0202,  # ecdsa_sha1, rsa_pkcs1_sha1, dsa_sha1 (legacy)
)

_BROKEN_MARKERS = ("_NULL_", "_anon_", "_EXPORT_", "_RC4_", "_DES_CBC_", "_DES40_", "_MD5")


@dataclass(frozen=True, slots=True)
class SuiteInfo:
    """Properties of a cipher suite derived from its IANA name."""

    name: str
    key_exchange: str
    forward_secrecy: bool
    aead: bool
    cbc: bool
    broken: bool


def suite_info(name: str) -> SuiteInfo:
    """Derive policy-relevant properties from an IANA cipher-suite name."""
    if name in TLS13_SUITES.values():
        # TLS 1.3 suites always use (EC)DHE and an AEAD cipher.
        return SuiteInfo(name, "TLS13", True, True, False, False)
    kx = name.removeprefix("TLS_").split("_WITH_")[0]
    return SuiteInfo(
        name=name,
        key_exchange=kx,
        forward_secrecy=kx.startswith(("DHE_", "ECDHE_")),
        aead=any(m in name for m in ("_GCM_", "_CCM", "_CHACHA20_POLY1305_")),
        cbc="_CBC_" in name,
        broken=any(m in name for m in _BROKEN_MARKERS) or "_3DES_" in name,
    )
