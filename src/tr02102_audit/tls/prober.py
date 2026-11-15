"""Enumerate what a TLS server accepts, using hand-built ClientHello messages.

Method (see docs/ARCHITECTURE.md, section 6): offer a set of candidates, read
which one the server picks from the cleartext ServerHello, remove it, and
repeat until the server refuses. Every probe ends in one of three states:
accepted, refused, or inconclusive. Inconclusive is never treated as refused.

A refusal and a rate limiter that drops connections look the same on the
wire. After every enumeration the server is therefore asked once more for a
value it accepted before; if it no longer answers, the result is marked
incomplete instead of being reported as a short (and flattering) list.
"""

import os
import socket
import ssl
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from tr02102_audit.netguard import ResolvedTarget
from tr02102_audit.tls import wire
from tr02102_audit.tls.registry import (
    FACT_KEY,
    GROUPS,
    LEGACY_SUITES,
    SIGNATURE_SCHEMES,
    TLS12_EC_GROUPS,
    TLS13_GROUPS,
    TLS13_SUITES,
    VERSION_CODES,
    Version,
    suite_info,
)


@dataclass(frozen=True, slots=True)
class Limits:
    """Upper bounds that keep a scan polite and protect the scanner (T-09, T-10)."""

    connect_timeout: float = 5.0
    read_timeout: float = 5.0
    deadline: float = 120.0
    max_connections: int = 400
    max_bytes_per_connection: int = 256 * 1024


RETRIES = 2  # extra attempts for a probe that got no answer
RETRY_PAUSE = 0.4  # seconds, multiplied by the attempt number


X25519 = 29


class ScanAbortedError(RuntimeError):
    """A limit was reached; the partial result is reported as inconclusive."""


@dataclass(slots=True)
class Outcome:
    kind: Literal["accepted", "refused", "inconclusive"]
    reason: str = ""
    server_hello: wire.ServerHello | None = None
    messages: list[tuple[int, bytes]] = field(default_factory=list)

    def message(self, msg_type: int) -> bytes | None:
        for t, body in self.messages:
            if t == msg_type:
                return body
        return None


class Session:
    """Connections to one pinned target, with connection and time budgets."""

    def __init__(self, target: ResolvedTarget, limits: Limits) -> None:
        self.target = target
        self.limits = limits
        self.connections = 0
        self.started = time.monotonic()
        self.notes: list[str] = []
        # Reasons why the collected facts may be missing something. A scan
        # with any entry here can never be reported as conforming.
        self.incomplete: list[str] = []

    def _check_budget(self) -> None:
        if self.connections >= self.limits.max_connections:
            raise ScanAbortedError(f"connection limit of {self.limits.max_connections} reached")
        if time.monotonic() - self.started > self.limits.deadline:
            raise ScanAbortedError(f"scan deadline of {self.limits.deadline:.0f}s reached")

    def connect(self) -> socket.socket:
        self._check_budget()
        self.connections += 1
        sock = socket.create_connection(
            (self.target.ip, self.target.port), timeout=self.limits.connect_timeout
        )
        sock.settimeout(self.limits.read_timeout)
        return sock

    def check_reachable(self) -> None:
        """Fail fast when the port does not accept TCP connections at all."""
        try:
            self.connect().close()
        except ScanAbortedError:
            raise
        except OSError as exc:
            raise ScanAbortedError(
                f"cannot connect to {self.target.host}:{self.target.port} "
                f"({exc.__class__.__name__})"
            ) from exc

    def probe(self, spec: wire.HelloSpec, *, until_done: bool = False) -> Outcome:
        """Send one ClientHello and classify the reply.

        A probe without an answer (timeout, broken reply) is repeated, because
        a single lost packet must not decide what the report says.
        """
        outcome = self._probe_once(spec, until_done)
        for attempt in range(1, RETRIES + 1):
            if outcome.kind != "inconclusive":
                break
            time.sleep(RETRY_PAUSE * attempt)
            outcome = self._probe_once(spec, until_done)
        return outcome

    def _probe_once(self, spec: wire.HelloSpec, until_done: bool) -> Outcome:
        try:
            sock = self.connect()
        except ScanAbortedError:
            raise
        except OSError as exc:
            return Outcome("inconclusive", f"connect failed: {exc.__class__.__name__}")
        try:
            sock.sendall(wire.build_client_hello(spec))
            return _read_reply(sock, until_done, self.limits.max_bytes_per_connection)
        except TimeoutError:
            return Outcome("inconclusive", "timeout")
        except ConnectionResetError:
            return Outcome("refused", "connection reset")
        except wire.ParseError as exc:
            return Outcome("inconclusive", f"malformed reply: {exc}")
        except OSError as exc:
            return Outcome("inconclusive", f"socket error: {exc.__class__.__name__}")
        finally:
            sock.close()


def _recv_exact(sock: socket.socket, n: int, budget: list[int]) -> bytes | None:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None if not data else bytes(data)
        data += chunk
        budget[0] -= len(chunk)
        if budget[0] < 0:
            raise wire.ParseError("reply exceeds size limit")
    return bytes(data)


def _read_reply(sock: socket.socket, until_done: bool, max_bytes: int) -> Outcome:
    budget = [max_bytes]
    buffer = bytearray()
    outcome: Outcome | None = None
    while True:
        header = _recv_exact(sock, 5, budget)
        if header is None or len(header) < 5:
            if outcome is not None:
                return outcome  # connection closed after a ServerHello
            return Outcome("refused", "connection closed without alert")
        content_type = header[0]
        length = int.from_bytes(header[3:5], "big")
        if length > wire.MAX_RECORD_PAYLOAD:
            raise wire.ParseError(f"record of {length} bytes exceeds limit")
        payload = _recv_exact(sock, length, budget)
        if payload is None or len(payload) < length:
            raise wire.ParseError("truncated record")

        if content_type == wire.CT_ALERT:
            if outcome is not None:
                return outcome
            return Outcome("refused", wire.parse_alert(payload).name)
        if content_type != wire.CT_HANDSHAKE:
            # ChangeCipherSpec or encrypted data: nothing more to read in clear.
            if outcome is None:
                raise wire.ParseError(f"unexpected record type {content_type}")
            return outcome

        buffer += payload
        for msg_type, body in wire.split_handshake_messages(buffer):
            if outcome is None:
                if msg_type != wire.HS_SERVER_HELLO:
                    raise wire.ParseError(f"expected ServerHello, got message {msg_type}")
                hello = wire.parse_server_hello(body)
                outcome = Outcome("accepted", server_hello=hello)
                if hello.is_hrr or hello.version == VERSION_CODES[Version.TLS13]:
                    return outcome  # everything after this is encrypted
                if not until_done:
                    return outcome
            else:
                outcome.messages.append((msg_type, body))
                if msg_type == wire.HS_SERVER_HELLO_DONE:
                    return outcome


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SuiteDetail:
    encrypt_then_mac: bool
    extended_master_secret: bool
    secure_renegotiation: bool


@dataclass(slots=True)
class TlsFacts:
    versions: dict[str, str] = field(default_factory=dict)
    # Per version: accepted suites in the server's order, or None if unknown.
    suites: dict[str, list[str] | None] = field(default_factory=dict)
    suite_details: dict[str, SuiteDetail] = field(default_factory=dict)
    groups_tls12: list[str] | None = None
    groups_tls13: list[str] | None = None
    dhe_prime_bits: int | None = None
    compression: bool | None = None
    certificate_chain: list[bytes] = field(default_factory=list)


def _enumerate(
    session: Session,
    candidates: Sequence[int],
    make_spec: Callable[[list[int]], wire.HelloSpec],
    pick: Callable[[Outcome], int | None],
    *,
    until_done: bool = False,
    on_accept: Callable[[int, Outcome], None] | None = None,
    label: str,
) -> list[int]:
    """Offer all remaining candidates, record the server's pick, repeat.

    Returns the accepted candidates in the server's order of choice. Whenever
    the list may be missing something, a reason is added to
    ``session.incomplete``; the caller keeps the partial list as evidence.
    """
    remaining = list(candidates)
    accepted: list[int] = []
    while remaining:
        outcome = session.probe(make_spec(remaining), until_done=until_done)
        if outcome.kind == "refused":
            break
        if outcome.kind == "inconclusive":
            session.incomplete.append(f"{label}: no answer ({outcome.reason})")
            return accepted
        chosen = pick(outcome)
        if chosen is None:
            break  # answered, but not with what was asked for: same as a refusal
        if chosen not in remaining:
            session.incomplete.append(f"{label}: the server chose a value that was not offered")
            return accepted
        accepted.append(chosen)
        remaining.remove(chosen)
        if on_accept is not None:
            on_accept(chosen, outcome)

    if accepted and remaining:
        canary = session.probe(make_spec([accepted[0]]))
        if canary.kind != "accepted":
            session.incomplete.append(
                f"{label}: the server stopped answering during the scan "
                "(rate limiting?), so the list may be incomplete"
            )
    return accepted


def collect(session: Session) -> TlsFacts:
    """Run all TLS probes against the session's target."""
    target = session.target
    facts = TlsFacts()
    legacy_codes = list(LEGACY_SUITES)
    session.check_reachable()

    def legacy_spec(
        version: Version,
        suites: list[int],
        groups: Sequence[int] = TLS12_EC_GROUPS,
        compression: Sequence[int] = (0,),
    ) -> wire.HelloSpec:
        return wire.HelloSpec(
            client_version=VERSION_CODES[version],
            cipher_suites=suites,
            server_name=target.sni,
            groups=groups,
            signature_schemes=SIGNATURE_SCHEMES,
            record_version=0x0300 if version is Version.SSL3 else 0x0301,
            compression_methods=compression,
        )

    with_share = False  # set when the server insists on a key share up front

    def tls13_spec(suites: list[int], groups: Sequence[int] = TLS13_GROUPS) -> wire.HelloSpec:
        return wire.HelloSpec(
            client_version=VERSION_CODES[Version.TLS12],
            cipher_suites=suites,
            server_name=target.sni,
            groups=groups,
            signature_schemes=SIGNATURE_SCHEMES,
            tls13=True,
            # Any 32 bytes are a valid X25519 public key.
            key_shares=((X25519, os.urandom(32)),) if with_share else (),
        )

    def is_version(outcome: Outcome, version: Version) -> bool:
        hello = outcome.server_hello
        return (
            outcome.kind == "accepted"
            and hello is not None
            and hello.version == VERSION_CODES[version]
        )

    def record_version(version: Version, outcome: Outcome) -> None:
        if outcome.kind == "accepted":
            facts.versions[version] = "accepted" if is_version(outcome, version) else "refused"
        else:
            facts.versions[version] = outcome.kind
        if outcome.kind == "inconclusive":
            session.incomplete.append(f"{version}: no answer ({outcome.reason})")

    # 1. Which protocol versions are accepted?
    for version in (Version.SSL3, Version.TLS10, Version.TLS11, Version.TLS12):
        record_version(version, session.probe(legacy_spec(version, legacy_codes)))
    outcome = session.probe(tls13_spec(list(TLS13_SUITES)))
    if not is_version(outcome, Version.TLS13):
        # Asking the server to choose a group (empty key_share) is valid TLS 1.3,
        # but a stack that mishandles it must not be reported as "no TLS 1.3".
        with_share = True
        second = session.probe(tls13_spec(list(TLS13_SUITES)))
        if is_version(second, Version.TLS13):
            outcome = second
            session.notes.append("TLS1.3: the server only answers when a key share is sent")
        else:
            with_share = False
    record_version(Version.TLS13, outcome)

    # 2. Cipher suites per accepted legacy version.
    def pick_suite(o: Outcome) -> int | None:
        return o.server_hello.cipher_suite if o.server_hello else None

    for version in (Version.SSL3, Version.TLS10, Version.TLS11, Version.TLS12):
        if facts.versions[version] != "accepted":
            continue
        want_version = VERSION_CODES[version]
        is_tls12 = version is Version.TLS12

        def on_accept(code: int, o: Outcome, *, _tls12: bool = is_tls12) -> None:
            hello = o.server_hello
            if hello is None:
                return
            if _tls12:
                facts.suite_details[LEGACY_SUITES[code]] = SuiteDetail(
                    encrypt_then_mac=wire.EXT_ENCRYPT_THEN_MAC in hello.extensions,
                    extended_master_secret=wire.EXT_EXTENDED_MASTER_SECRET in hello.extensions,
                    secure_renegotiation=wire.EXT_RENEGOTIATION_INFO in hello.extensions,
                )
            cert = o.message(wire.HS_CERTIFICATE)
            if cert and not facts.certificate_chain:
                try:
                    facts.certificate_chain = wire.parse_certificate_chain(cert)
                except wire.ParseError as exc:
                    session.notes.append(f"certificate message unreadable: {exc}")

        def pick_for_version(o: Outcome, _want: int = want_version) -> int | None:
            if o.server_hello is None or o.server_hello.version != _want:
                return None
            return o.server_hello.cipher_suite

        def spec_for_version(suites: list[int], _v: Version = version) -> wire.HelloSpec:
            return legacy_spec(_v, suites)

        accepted = _enumerate(
            session,
            legacy_codes,
            spec_for_version,
            pick_for_version,
            until_done=not facts.certificate_chain,
            on_accept=on_accept,
            label=f"{version} cipher suites",
        )
        if accepted:
            facts.suites[FACT_KEY[version]] = [LEGACY_SUITES[c] for c in accepted]
        else:
            # The version was accepted a moment ago, so "no suites" is not an answer.
            facts.suites[FACT_KEY[version]] = None
            session.incomplete.append(f"{version} cipher suites: could not be determined")

    # 3. TLS 1.3 cipher suites and groups.
    if facts.versions[Version.TLS13] == "accepted":
        suites13 = _enumerate(
            session, list(TLS13_SUITES), tls13_spec, pick_suite, label="TLS1.3 cipher suites"
        )
        if suites13:
            facts.suites["tls13"] = [TLS13_SUITES[c] for c in suites13]
        else:
            facts.suites["tls13"] = None
            session.incomplete.append("TLS1.3 cipher suites: could not be determined")

        groups13: list[int] = []
        if suites13 and not with_share:
            groups13 = _enumerate(
                session,
                list(TLS13_GROUPS),
                lambda g: tls13_spec(suites13, g),
                lambda o: o.server_hello.selected_group if o.server_hello else None,
                label="TLS1.3 groups",
            )
        if groups13:
            facts.groups_tls13 = [GROUPS[g] for g in groups13]
        else:
            session.incomplete.append("TLS1.3 groups: could not be determined")

    # 4. TLS 1.2 key-exchange groups, DH parameter size and compression.
    best_legacy = next(
        (v for v in (Version.TLS12, Version.TLS11, Version.TLS10) if facts.suites.get(FACT_KEY[v])),
        None,
    )
    if best_legacy is not None:
        names = facts.suites[FACT_KEY[best_legacy]] or []
        codes = {name: code for code, name in LEGACY_SUITES.items()}
        ecdhe = [codes[n] for n in names if suite_info(n).key_exchange.startswith("ECDHE_")]
        dhe = [codes[n] for n in names if suite_info(n).key_exchange.startswith("DHE_")]

        if ecdhe:

            def pick_group(o: Outcome) -> int | None:
                ske = o.message(wire.HS_SERVER_KEY_EXCHANGE)
                if ske is None:
                    return None
                return wire.parse_server_key_exchange(ske, ecdhe=True).named_group

            cert_curve = _certificate_curve(facts.certificate_chain)
            if cert_curve is None:
                groups12 = _enumerate(
                    session,
                    list(TLS12_EC_GROUPS),
                    lambda g: legacy_spec(best_legacy, ecdhe, g),
                    pick_group,
                    until_done=True,
                    label="TLS1.2 groups",
                )
            else:
                # In TLS 1.2 an ECDSA certificate is only usable if its curve
                # is among the offered groups (RFC 8422, 5.1). Elimination
                # would stop as soon as that curve is removed, so each group
                # is tested on its own, followed by the certificate's curve.
                groups12 = []
                for group in TLS12_EC_GROUPS:
                    offer = [group] if group == cert_curve else [group, cert_curve]
                    o = session.probe(legacy_spec(best_legacy, ecdhe, offer), until_done=True)
                    if o.kind == "accepted" and pick_group(o) == group:
                        groups12.append(group)
                    elif o.kind == "inconclusive":
                        name = GROUPS.get(group, str(group))
                        session.incomplete.append(f"TLS1.2 group {name}: no answer ({o.reason})")
                session.notes.append(
                    "TLS1.2 groups: ECDSA certificate, groups tested one by one; "
                    "a server that prefers its certificate curve may hide others"
                )
            if groups12:
                facts.groups_tls12 = [GROUPS.get(g, f"group_{g}") for g in groups12]
            else:
                session.incomplete.append("TLS1.2 groups: could not be determined")

        if dhe:
            outcome = session.probe(legacy_spec(best_legacy, dhe), until_done=True)
            ske = outcome.message(wire.HS_SERVER_KEY_EXCHANGE)
            if outcome.kind == "accepted" and ske is not None:
                try:
                    params = wire.parse_server_key_exchange(ske, ecdhe=False)
                    facts.dhe_prime_bits = params.dh_prime_bits
                except wire.ParseError as exc:
                    session.incomplete.append(f"DHE parameters unreadable: {exc}")
            else:
                session.incomplete.append("DHE parameters: could not be determined")

        # Does the server pick DEFLATE when it is offered (CRIME)? A server that
        # rejects the offer outright does not compress either.
        all_codes = [codes[n] for n in names]
        outcome = session.probe(legacy_spec(best_legacy, all_codes, compression=(1, 0)))
        if outcome.kind == "accepted" and outcome.server_hello is not None:
            facts.compression = outcome.server_hello.compression != 0
        elif outcome.kind == "refused":
            facts.compression = False
        else:
            session.incomplete.append(f"TLS compression: no answer ({outcome.reason})")
    elif facts.versions.get(Version.TLS13) == "accepted":
        facts.compression = False  # TLS 1.3 has no compression

    return facts


def _certificate_curve(chain: list[bytes]) -> int | None:
    """Group code of the leaf certificate's curve, if it is an EC key."""
    if not chain:
        return None
    try:
        key = x509.load_der_x509_certificate(chain[0]).public_key()
    except ValueError:
        return None
    if not isinstance(key, ec.EllipticCurvePublicKey):
        return None
    codes = {name: code for code, name in GROUPS.items()}
    return codes.get(key.curve.name)


# ---------------------------------------------------------------------------
# Certificate retrieval and trust, through the standard library
# ---------------------------------------------------------------------------


def fetch_leaf_certificate(session: Session) -> bytes | None:
    """Retrieve the leaf certificate with an unverified handshake (TLS 1.3 only servers).

    Validation is disabled on purpose: the collector retrieves, the engine judges.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with (
            session.connect() as sock,
            ctx.wrap_socket(sock, server_hostname=session.target.sni) as tls,
        ):
            return tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        session.notes.append(f"certificate retrieval failed: {exc.__class__.__name__}")
        return None


def check_trust(session: Session, ca_file: str | None = None) -> tuple[bool | None, str]:
    """Validate the chain and host name with the system trust store.

    ``ca_file`` adds trusted CA certificates, for servers that use an internal
    PKI. The question here is only "does the certificate verify?"; protocol
    versions and ciphers are judged elsewhere. The context is therefore as
    permissive as the local TLS library allows, so that a TLS 1.0-only server
    still gets an answer instead of "unknown".

    Python 3.13 turns on VERIFY_X509_STRICT by default, which rejects
    certificates that every browser accepts (for example a CA certificate
    without a key-usage extension). "Trusted" here means what it means to a
    browser, so the strict flag is cleared.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        if ca_file:
            ctx.load_verify_locations(cafile=ca_file)
    except (OSError, ssl.SSLError) as exc:
        return None, f"trust store could not be loaded: {exc.__class__.__name__}"
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass  # the library's defaults remain; the check may end as "unknown"
    server_name = session.target.sni or session.target.host
    try:
        with session.connect() as sock, ctx.wrap_socket(sock, server_hostname=server_name):
            return True, ""
    except ssl.SSLCertVerificationError as exc:
        return False, str(exc.verify_message or "verification failed")
    except (OSError, ssl.SSLError) as exc:
        return None, f"trust check inconclusive: {exc.__class__.__name__}"
