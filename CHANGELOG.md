# Changelog

All notable changes to QSM will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Apache HTTP Server migration target
- HAProxy migration target
- Debian `.deb` package
- Docker image (`ghcr.io/soufianecyber/qsm`)
- CI/CD pipeline via GitHub Actions
- `--report json` output mode for SIEM integration

---

## [1.0.1] — 2026-10-07

### Changed
- **BREAKING:** Configuration output now uses **NIST finalized names**
  (`ML-KEM-768`, `ML-DSA-65`) per FIPS 203/204. Previous codenames
  (`Kyber768`, `Dilithium3`) removed from generated configs.
- Nginx PQC group name is now **dynamically selected** based on the
  installed OpenSSL version:
  - OpenSSL ≥ 3.5 → `X25519MLKEM768`
  - OpenSSL 3.2–3.4 → `X25519Kyber768Draft00`
- Project description softened from "enterprise-grade" to reflect
  proof-of-concept status.

### Security
- **Reject symlink targets** in `--migrate` and `--rollback`
- Restrict backup file permissions to **`0o600`** (owner-only)
- Add **file size limit (10 MB)** to prevent DoS via oversized config
- Use **UTC timestamps** for cross-timezone consistency
- Validate config paths before passing to subprocess (defense-in-depth)

### Fixed
- Hybrid enforcement now **ignores commented-out markers**
  (previously, `# ECDHE-ECDSA` in a comment could satisfy the guard)
- `_atomic_write` now cleans up temp file on `os.stat` failure
- Remove duplicate `ssl_protocols TLSv1.3;` directive (was triggering
  `[warn] duplicate value` in nginx)
- Write permission check now targets **actual config files** (not just
  their parent directories)

### Documentation
- New **"Limitations & Honest Disclosure"** section in README
- Badges updated to FIPS 203/204 naming (ML-KEM / ML-DSA)
- Add NIST standards alignment table
- Update pre-flight check descriptions

### Acknowledgements

Special thanks to **[@exocognosis](https://github.com/exocognosis)**
(Rick Glenn — creator of [@DytallixHQ](https://github.com/DytallixHQ))
for the technical correction that prompted this release:

> *"Kyber and Dilithium are pre-standard codenames. The finalized standards
> are ML-KEM and ML-DSA. Ship the standards, not the codenames."*

This feedback drove the migration to NIST FIPS 203/204 terminology
throughout the codebase and documentation. Thank you for holding the
project to a higher standard. 🛡️

---

## [1.0.0] — 2026-10-03

### Added
- Initial public release 🎉
- **Quantum Attack Simulator** (`--simulate`):
  - Shor's Algorithm theoretical time-to-crack calculator
  - HNDL (Harvest Now, Decrypt Later) risk scoring
  - TLS certificate algorithm detection (RSA / ECC / DSA)
  - OpenSSH private key format parser
  - Rich terminal UI with color-coded severity tables

- **Hybrid PQC Migrator** (`--migrate`):
  - Nginx configuration patcher (hybrid ciphers + PQC groups)
  - OpenSSH (`sshd_config`) updater (sntrup761x25519 KEX)
  - **Atomic writes** with checksum-verified rollback
  - **Auto-rollback** on validation failure
  - Timestamped backups (`.bak.YYYYMMDD-HHMMSS` format)
  - `--dry-run` preview mode

- **Rollback Engine** (`--rollback`):
  - Interactive backup selection
  - Timestamp-targeted restoration
  - SHA-256 integrity verification

- **Pre-Flight Checker** (`--preflight`):
  - Python version validation
  - liboqs-python bindings detection
  - ML-KEM / ML-DSA availability check
  - OpenSSL version verification
  - Filesystem write permission audit

- **Status Reporter** (`--status`):
  - Enumerates all available PQC mechanisms
  - Highlights recommended algorithms

### Security
- Hybrid enforcement invariant: pure PQC is architecturally forbidden
- All system file modifications are atomic and reversible
- Checksum validation prevents corrupted rollbacks

### Verified
- ✅ Tested on Parrot OS Security (kernel 7.1.13+parrot7-amd64)
- ✅ Python 3.13.5 · OpenSSL 3.5.7 · liboqs-python 0.12+
- ✅ Real-world migration test on Nginx 1.26.3 (`/etc/nginx/nginx.conf`)
- ✅ Checksum-verified rollback restores original state byte-for-byte
- ✅ Unit tests passing

---

## Version Format

- **MAJOR** — incompatible API or CLI changes
- **MINOR** — new features, backward compatible
- **PATCH** — bug fixes, backward compatible

---

[Unreleased]: https://github.com/soufianecyber/Quantum-Safe-Migration/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/soufianecyber/Quantum-Safe-Migration/releases/tag/v1.0.1
[1.0.0]: https://github.com/soufianecyber/Quantum-Safe-Migration/releases/tag/v1.0.0
