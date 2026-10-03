# Changelog

All notable changes to QSM will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Apache HTTP Server migration target
- HAProxy migration target
- `pyproject.toml` for PyPI publishing
- Debian `.deb` package
- Docker image (`ghcr.io/soufianecyber/qsm`)
- CI/CD pipeline via GitHub Actions
- Unit test suite with pytest
- `--report json` output mode for SIEM integration

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
  - Kyber768 / Dilithium3 availability check
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
- ✅ 17/17 unit tests passing

---

## Version Format

- **MAJOR** — incompatible API or CLI changes
- **MINOR** — new features, backward compatible
- **PATCH** — bug fixes, backward compatible

---

[Unreleased]: https://github.com/soufianecyber/Quantum-Safe-Migration/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/soufianecyber/Quantum-Safe-Migration/releases/tag/v1.0.0
