"""Where a TLS audit report counts as evidence.

Certificates such as ISO/IEC 27001, PCI DSS or SOC 2 are issued by accredited
auditors after an assessment of a whole organisation. No scanner can award
them. What an auditor asks for, though, is evidence that encryption in
transit follows a recognised standard, and that is what a report provides.

None of these frameworks lists cipher suites (PCI DSS comes closest). They
all point to "the state of the art" or to "industry-accepted" cryptography,
which in practice means the technical standards this tool evaluates.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Framework:
    name: str
    clause: str
    asks: str
    certified: bool  # True: an accredited body issues a certificate or attestation


FRAMEWORKS: tuple[Framework, ...] = (
    Framework(
        "ISO/IEC 27001:2022",
        "Annex A 8.24, 8.20, 8.21, 5.14",
        "Rules for the effective use of cryptography; security of networks, "
        "network services and information transfer.",
        True,
    ),
    Framework(
        "PCI DSS v4.0.1",
        "Req. 4.2.1, 12.3.3",
        "Strong cryptography for cardholder data in transit; a yearly review "
        "of the protocols and cipher suites in use.",
        True,
    ),
    Framework(
        "SOC 2 (Trust Services Criteria)",
        "CC6.7",
        "Information is protected during transmission.",
        True,
    ),
    Framework(
        "BSI C5:2020",
        "CRY-02",
        "Encryption of data for transmission (transport encryption) for cloud services.",
        True,
    ),
    Framework(
        "NIS2 Directive (EU) 2022/2555",
        "Art. 21(2)(h); Germany: § 30 (2) no. 8 BSIG",
        "Policies and procedures for the use of cryptography and encryption, "
        "following the state of the art.",
        False,
    ),
    Framework(
        "GDPR / DSGVO",
        "Art. 32(1)(a)",
        "Encryption of personal data as a technical measure appropriate to the risk.",
        False,
    ),
    Framework(
        "DORA (EU) 2022/2554",
        "Art. 9; RTS (EU) 2024/1774 Art. 6, 7, 14",
        "A policy on encryption and cryptographic controls for financial "
        "entities, including data in transit.",
        False,
    ),
    Framework(
        "HIPAA Security Rule",
        "45 CFR § 164.312(e)",
        "Transmission security for electronic protected health information.",
        False,
    ),
    Framework(
        "BSI IT-Grundschutz",
        "CON.1, APP.3.2",
        "A crypto concept, and TLS for web servers according to BSI TR-02102.",
        True,
    ),
    Framework(
        "CIS Controls v8",
        "Safeguard 3.10",
        "Encrypt sensitive data in transit.",
        False,
    ),
    Framework(
        "NIST Cybersecurity Framework 2.0",
        "PR.DS-02",
        "The confidentiality and integrity of data in transit are protected.",
        False,
    ),
)
