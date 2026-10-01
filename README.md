# 🌌 Quantum-Safe Migration (QSM)

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?logo=opensourceinitiative&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Debian-orange?logo=linux&logoColor=white)
![Security Focus](https://img.shields.io/badge/security-Post--Quantum%20Cryptography-purple?logo=letsencrypt&logoColor=white)
![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Hybrid PQC](https://img.shields.io/badge/PQC-Hybrid%20Enforced-blueviolet)
![NIST](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204-red)
![Kyber](https://img.shields.io/badge/Kyber768-ML--KEM-9cf)
![Dilithium](https://img.shields.io/badge/Dilithium3-ML--DSA-9cf)
![Code Style](https://img.shields.io/badge/code%20style-black-000000?logo=python&logoColor=white)

---

**Enterprise-Grade Post-Quantum Cryptography Migration & Security Auditing Platform.**

---

## 🛠️ Overview

QSM is an advanced, production-ready security toolkit implemented in Python 3.10+, designed specifically for DevOps engineers and security auditors on distributions like **Parrot OS Security**. It addresses the critical threat vector of **"Harvest Now, Decrypt Later" (HNDL)** by assessing infrastructure cryptographic postures and automating hybrid post-quantum migrations.

> ⚠️ **Strict Architectural Principle:** QSM **never** permits pure post-quantum deployment. All operations enforce a secure, backward-compatible **Hybrid Paradigm** combining classical and PQC algorithms (e.g., ECDSA + Dilithium3 for authentication and X25519 + Kyber768 for key exchange).

---

## 🚀 Dual operational modes

QSM is built to run adaptively across environments without blocking your security workflow:

1. **Lightweight Mode (Simulation & Dry-Run):** Requires zero advanced C-dependencies. Instantly simulate Shor's Algorithm attacks, risk scores, and preview migration configurations safely.
2. **Production Mode (Active Migration):** Requires `liboqs` system integration to patch configuration layers atomically with integrated checksum-verified rollback logic.

---

## ⚡ Installation & Quick Start

### 1. Zero-Dependency Simulation Start
```bash
# Clone and enter the vault
git clone https://github.com/soufianecyber/Quantum-Safe-Migration
cd Quantum-Safe-Migration

# Initialize virtual environment
python3 -m venv venv
source venv/bin/activate

# Install lightweight dependencies
pip install -r requirements.txt
```

### 2. Verify Your Matrix
```bash
python3 qsm.py --preflight
```

---

## 🎮 CLI Reference Guide

```bash
# 1. Run Quantum Attack Simulation on target assets
python3 qsm.py --simulate --target example.com
python3 qsm.py --simulate --keyfile ./test_legacy_key.pem

# 2. Preview Hybrid Migration Block (Safe Dry-Run)
python3 qsm.py --migrate --target nginx --config ./dummy_nginx.conf --dry-run

# 3. Apply Production Migration (Requires Sudo)
sudo venv/bin/python3 qsm.py --migrate --target nginx --config /etc/nginx/nginx.conf
sudo venv/bin/python3 qsm.py --migrate --target sshd --config /etc/ssh/sshd_config

# 4. Atomic Rollback Checksum Restoration
sudo venv/bin/python3 qsm.py --rollback --target /etc/nginx/nginx.conf
```

---

## 🛡️ License & Legal Framework

Distributed under the **MIT License**. See `LICENSE` for details. 
*Disclaimer: This toolkit is built exclusively for authorized testing and infrastructure migration verification purposes.*

---

## 👤 Author

**Soufiane Cyber**

- 🐙 GitHub: [github.com/soufianecyber](https://github.com/soufianecyber)
- 🔐 Focus: Offensive Security · Post-Quantum Cryptography · DevSecOps

---

## 🙏 Acknowledgements

- [Open Quantum Safe](https://openquantumsafe.org/) for `liboqs`
- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography) for FIPS 203/204
- [Shields.io](https://shields.io) for badge infrastructure

---

## ⭐ Support the Project

If QSM helps you secure your infrastructure against quantum threats, 
please consider giving it a **star** on GitHub. It helps the project 
gain visibility and reach more security teams who need it.

[![Star this repo](https://img.shields.io/github/stars/soufianecyber/Quantum-Safe-Migration?style=social)](https://github.com/soufianecyber/Quantum-Safe-Migration/stargazers)
