"""Certificate analysis: turn a DER certificate into policy facts."""

from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID


def _cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def analyse(der: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    """Return key, signature and validity facts for a leaf certificate."""
    now = now or datetime.now(UTC)
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()

    key_type: str
    key_bits: int | None
    curve: str | None = None
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits, curve = "EC", key.curve.key_size, key.curve.name
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, key_bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, key_bits = "Ed448", 456
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", key.key_size
    else:
        key_type, key_bits = type(key).__name__, None

    hash_alg = cert.signature_hash_algorithm
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = [str(v) for v in san_ext.value.get_values_for_type(x509.DNSName)]
        san += [str(v) for v in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        san = []

    return {
        "key_type": key_type,
        "key_bits": key_bits,
        "curve": curve,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "signature_hash": hash_alg.name if hash_alg is not None else None,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "lifetime_days": (not_after - not_before).days,
        "days_remaining": (not_after - now).days,
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "subject_cn": _cn(cert.subject),
        "issuer_cn": _cn(cert.issuer),
        "self_signed": cert.issuer == cert.subject,
        "san": san[:50],
        "serial": format(cert.serial_number, "x"),
    }
