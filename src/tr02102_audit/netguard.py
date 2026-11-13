"""Target validation and name resolution.

The web service must not become a proxy into private networks (SSRF). The
host name is resolved once, every resolved address is checked, and all probes
then connect to that one pinned address. A DNS answer that changes between
check and use (DNS rebinding) therefore cannot redirect a probe.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class TargetError(ValueError):
    """The target is malformed, cannot be resolved, or is not allowed."""


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    host: str
    port: int
    ip: str
    sni: str | None  # None when the target was given as an IP address


def parse_target(text: str, default_port: int = 443) -> tuple[str, int]:
    """Split ``host``, ``host:port`` or ``[v6]:port`` into host and port."""
    text = text.strip()
    for prefix in ("https://", "http://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix) :]
    text = text.split("/", 1)[0]
    if not text:
        raise TargetError("empty target")

    host, port_text = text, ""
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise TargetError("unbalanced brackets in IPv6 address")
        host, rest = text[1:end], text[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise TargetError("unexpected text after IPv6 address")
            port_text = rest[1:]
    elif text.count(":") == 1:
        host, port_text = text.split(":")

    port = default_port
    if port_text:
        if not port_text.isdigit():
            raise TargetError("port must be a number")
        port = int(port_text)
    if not 1 <= port <= 65535:
        raise TargetError("port must be between 1 and 65535")
    _validate_host(host)
    return host.rstrip(".").lower(), port


def _validate_host(host: str) -> None:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME.match(host):
            raise TargetError("not a valid host name or IP address") from None


def is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve(host: str, port: int, *, allow_private: bool) -> ResolvedTarget:
    """Resolve ``host`` and pin one address; refuse non-public ones if required."""
    _validate_host(host)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise TargetError(f"cannot resolve {host}") from exc

    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if not addresses:
        raise TargetError(f"no address for {host}")
    if not allow_private:
        blocked = [a for a in addresses if not is_public(a)]
        if blocked:
            raise TargetError(
                "target resolves to a private, loopback or reserved address; "
                "only public addresses can be scanned here"
            )
    ipv4 = [a for a in addresses if ":" not in a]
    chosen = ipv4[0] if ipv4 else addresses[0]

    try:
        ipaddress.ip_address(host)
        sni = None
    except ValueError:
        sni = host
    return ResolvedTarget(host=host, port=port, ip=chosen, sni=sni)
