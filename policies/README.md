# Policies

This directory will hold the BSI TR-02102 recommendations as data: one sub-directory per edition of the guideline, one YAML file per part.

```text
policies/
└── 2026-01/
    ├── tr-02102-2.yaml   # TLS
    ├── tr-02102-3.yaml   # IPsec / IKEv2
    └── tr-02102-4.yaml   # SSH
```

The first policy arrives in milestone M1. The format is described in [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md), section 4.

## Rules for changing a policy

A policy file decides what counts as a finding, so a wrong line here silently changes every audit result.

1. Every rule cites the part, edition and section of TR-02102 it was transcribed from.
2. Rules are transcribed from the German original; the English version is a courtesy translation.
3. Every change is reviewed by the code owner (see `.github/CODEOWNERS`).
4. A change that alters the verdict on a lab target must update the expected results in the same pull request.
