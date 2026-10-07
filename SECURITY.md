# Security Policy

## Supported Versions

QSM is committed to the security of its users. The following versions
are actively supported with security updates:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.x.x   | :white_check_mark: | Active |
| < 1.0   | :x:                | EOL    |

## Reporting a Vulnerability

We take security issues **very seriously** — especially given that QSM
operates on cryptographic infrastructure.

### Please DO NOT:

- Open a public GitHub Issue for security vulnerabilities
- Discuss the issue publicly until a fix is released
- Exploit the vulnerability beyond what is needed to demonstrate it

### Please DO:

**Option 1 — GitHub Private Vulnerability Reporting (Preferred):**

Navigate to the [Security tab](https://github.com/soufianecyber/Quantum-Safe-Migration/security/advisories/new)
of this repository and submit a private advisory.

**Option 2 — Email:**

Send an encrypted report to: `soufiane.cyber.mail@gmail.com` (PGP key in
[`SECURITY.asc`](./SECURITY.asc) if available)

### What to Include

To help us triage quickly, please include:

- **Description** of the vulnerability
- **Impact** — what an attacker can do
- **Reproduction steps** (minimal example)
- **Affected versions**
- **Suggested fix** (optional but appreciated)
- **Your PGP public key** if you want encrypted replies

### Our Commitment

| Timeline | Action |
|----------|--------|
| **48 hours** | Acknowledge receipt of your report |
| **7 days** | Provide initial assessment and severity rating |
| **30 days** | Release a fix or provide detailed mitigation guidance |
| **90 days** | Public disclosure (coordinated with you) |

### Scope

**In Scope:**
- `qsm.py` — main application logic
- Cryptographic migration logic (Nginx, SSHD)
- Backup and rollback integrity mechanisms
- Hybrid enforcement guard bypasses
- Pre-flight checker flaws
- Command injection via `--config` or `--target`

**Out of Scope:**
- Vulnerabilities in dependencies (`rich`, `cryptography`, `liboqs`)
  — please report upstream
- Theoretical attacks on ML-KEM / ML-DSA algorithms themselves
  — please contact NIST
- Misconfigurations by the user
- Issues requiring physical access to the machine

### Recognition

Researchers who responsibly disclose valid vulnerabilities will be
credited in the release notes (unless they prefer to remain anonymous).

We do not offer monetary bug bounties at this time, but we deeply
appreciate your contribution to a safer quantum transition.

---

## Cryptographic Disclaimer

QSM enforces **hybrid post-quantum cryptography** (classical + PQC).
This design is intentional and cannot be disabled by design — if you
find a way to bypass the hybrid enforcement, that **is** a security
vulnerability and should be reported.

Thank you for helping make QSM safe for the entire security community.