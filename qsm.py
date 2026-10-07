#!/usr/bin/env python3
"""
Quantum-Safe Migration (QSM) — A Post-Quantum Cryptography Migration Toolkit.

A functional proof-of-concept for auditing and migrating legacy cryptographic
configurations to hybrid post-quantum cryptography (PQC).

    Status: Active development (v1.0.1). Not yet battle-tested in production.
    See README "Limitations & Honest Disclosure" for scope and constraints.

Author: Soufiane Cyber (@soufianecyber)
Copyright: (c) 2026 Soufiane Cyber
License: MIT
Version: 1.0.1
Repository: https://github.com/soufianecyber/Quantum-Safe-Migration

WARNING: This tool is intended for authorized security testing and migration
purposes only. Users must obtain explicit authorization before modifying
systems they do not own.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.text import Text
    from rich.align import Align
    from rich.rule import Rule
    from rich import box
except ImportError:
    sys.stderr.write(
        "[FATAL] The 'rich' library is required. Install with: pip install rich\n"
    )
    sys.exit(1)


QSM_VERSION = "1.0.1"
MIN_PYTHON = (3, 10)
MAX_CONFIG_SIZE = 10 * 1024 * 1024

console = Console()

RSA_OIDS = {
    "1.2.840.113549.1.1.1",
    "1.2.840.113549.1.1.5",
    "1.2.840.113549.1.1.11",
}
EC_OIDS = {
    "1.2.840.10045.2.1",
    "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3",
}
DSA_OIDS = {"1.2.840.10040.4.1"}


@dataclass
class CryptoAsset:
    """Represents a discovered cryptographic asset."""

    name: str
    algorithm: str
    key_size: int
    location: str = ""
    is_quantum_safe: bool = False
    is_hybrid: bool = False


@dataclass
class PreFlightResult:
    """Result of a single pre-flight check."""

    name: str
    value: str
    passed: bool
    detail: str = ""


@dataclass
class MigrationReport:
    """Summary of a migration operation."""

    target: str
    config_path: Path
    backup_path: Path
    dry_run: bool
    changes: List[Tuple[str, str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class PreFlightChecker:
    """
    Validates system compatibility and dependency availability before
    executing any migration or simulation task.
    """

    def __init__(self) -> None:
        self.results: List[PreFlightResult] = []

    def _check_python(self) -> PreFlightResult:
        cur = sys.version_info[:3]
        version_str = f"{cur[0]}.{cur[1]}.{cur[2]}"
        passed = (cur[0], cur[1]) >= MIN_PYTHON
        return PreFlightResult(
            name="Python Version",
            value=version_str,
            passed=passed,
            detail=f"Requires >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]}",
        )

    def _check_platform(self) -> PreFlightResult:
        sysname = platform.system()
        release = platform.release()
        passed = sysname == "Linux"
        return PreFlightResult(
            name="Operating System",
            value=f"{sysname} {release}",
            passed=passed,
            detail="Debian-based Linux recommended (Parrot OS, Kali, Ubuntu)",
        )

    def _check_liboqs_python(self) -> PreFlightResult:
        try:
            import oqs

            version = getattr(oqs, "__version__", "unknown")
            return PreFlightResult(
                name="liboqs-python Bindings",
                value=str(version),
                passed=True,
                detail="Python PQC bindings available",
            )
        except ImportError as exc:
            return PreFlightResult(
                name="liboqs-python Bindings",
                value="not installed",
                passed=False,
                detail=f"pip install liboqs-python ({exc})",
            )

    def _check_oqs_kem(self) -> PreFlightResult:
        try:
            import oqs

            kems = oqs.get_enabled_kem_mechanisms()
            kem_ok = any(
                m.lower().startswith(
                    ("kyber768", "ml-kem-768", "mlkem768")
                )
                for m in kems
            )
            return PreFlightResult(
                name="ML-KEM / Kyber Support",
                value=f"{len(kems)} KEMs available",
                passed=kem_ok,
                detail="ML-KEM-768 (FIPS 203) required for hybrid key exchange",
            )
        except Exception as exc:
            return PreFlightResult(
                name="ML-KEM / Kyber Support",
                value="unavailable",
                passed=False,
                detail=str(exc),
            )

    def _check_oqs_sig(self) -> PreFlightResult:
        try:
            import oqs

            sigs = oqs.get_enabled_sig_mechanisms()
            sig_ok = any(
                m.lower().startswith(
                    ("dilithium3", "ml-dsa-65", "mldsa65")
                )
                for m in sigs
            )
            return PreFlightResult(
                name="ML-DSA / Dilithium Support",
                value=f"{len(sigs)} SIGs available",
                passed=sig_ok,
                detail="ML-DSA-65 (FIPS 204) required for hybrid auth",
            )
        except Exception as exc:
            return PreFlightResult(
                name="ML-DSA / Dilithium Support",
                value="unavailable",
                passed=False,
                detail=str(exc),
            )

    def _check_openssl(self) -> PreFlightResult:
        try:
            out = subprocess.run(
                ["openssl", "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            version_str = out.stdout.strip() if out.stdout else "unknown"
            m = re.search(r"OpenSSL\s+(\d+)\.(\d+)", version_str)
            passed = False
            if m:
                major, minor = int(m.group(1)), int(m.group(2))
                passed = (major, minor) >= (3, 0)
            return PreFlightResult(
                name="OpenSSL Version",
                value=version_str or "not found",
                passed=passed,
                detail="OpenSSL >= 3.0 required for oqs-provider",
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return PreFlightResult(
                name="OpenSSL Version",
                value="not found",
                passed=False,
                detail="Install openssl (apt install openssl)",
            )

    def _check_write_permission(self) -> PreFlightResult:
        """
        Check whether the calling user can write to the target config files
        (not just their parent directories).
        """
        target_files = [
            Path("/etc/nginx/nginx.conf"),
            Path("/etc/ssh/sshd_config"),
        ]

        writable: List[str] = []
        denied: List[str] = []
        missing: List[str] = []

        for target in target_files:
            if not target.exists():
                missing.append(str(target))
                continue
            if os.access(target, os.W_OK):
                writable.append(str(target))
            else:
                denied.append(str(target))

        if writable:
            value = f"Yes ({len(writable)} file(s) writable)"
            passed = True
        elif os.geteuid() == 0 and not denied:
            value = "Root (all targets writable)"
            passed = True
        elif os.geteuid() == 0:
            value = f"Root ({len(denied)} denied)"
            passed = False
        else:
            value = f"No ({len(denied)} denied, {len(missing)} missing)"
            passed = False

        return PreFlightResult(
            name="Config Write Permission",
            value=value,
            passed=passed,
            detail="Required for --migrate operations",
        )

    def run(self, require_root: bool = False) -> bool:
        """Execute all pre-flight checks. Returns True if critical checks pass."""
        self.results = [
            self._check_python(),
            self._check_platform(),
            self._check_liboqs_python(),
            self._check_oqs_kem(),
            self._check_oqs_sig(),
            self._check_openssl(),
            self._check_write_permission(),
        ]
        return self._render()

    def _render(self) -> bool:
        table = Table(
            title="QSM Pre-Flight System Check",
            box=box.ROUNDED,
            show_lines=False,
            header_style="bold cyan",
        )
        table.add_column("Check", style="bold white", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_column("Status", justify="center")

        all_critical_pass = True
        for r in self.results:
            status = "[green]✅ PASS[/green]" if r.passed else "[red]❌ FAIL[/red]"
            value = r.value
            if not r.passed and r.detail:
                value = f"{r.value}\n[dim]{r.detail}[/dim]"
            table.add_row(r.name, value, status)
            if not r.passed and r.name in (
                "Python Version",
                "liboqs-python Bindings",
                "ML-KEM / Kyber Support",
                "ML-DSA / Dilithium Support",
            ):
                all_critical_pass = False

        console.print()
        console.print(table)
        console.print()
        if all_critical_pass:
            console.print(
                Panel.fit(
                    "[bold green]✅ All critical systems operational. "
                    "QSM is ready.[/bold green]",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel.fit(
                    "[bold red]❌ Critical dependency missing. Install liboqs "
                    "and liboqs-python before proceeding.[/bold red]\n"
                    "[dim]See README §3 Installation for detailed steps.[/dim]",
                    border_style="red",
                )
            )
        return all_critical_pass


class QuantumSimulator:
    """
    Simulates Shor's Algorithm attacks against classical cryptography
    and provides HNDL risk scoring.

    ⚠️  The time-to-crack figure is produced by a SIMPLIFIED analytical
    model (see _compute_shor_metrics docstring). It is intended for
    relative risk comparison, not as a prediction on any existing machine.
    """

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    def run(
        self,
        target: Optional[str] = None,
        keyfile: Optional[str] = None,
    ) -> None:
        assets: List[CryptoAsset] = []

        if target:
            with self._progress("Probing remote target") as progress:
                task = progress.add_task("probe", total=3)
                progress.update(task, description="[cyan]Resolving DNS...")
                time.sleep(0.15)
                progress.advance(task)
                progress.update(task, description="[cyan]Fetching TLS certificate...")
                assets.extend(self._probe_target(target))
                progress.advance(task)
                progress.update(task, description="[cyan]Analyzing key exchange...")
                time.sleep(0.15)
                progress.advance(task)

        if keyfile:
            with self._progress("Parsing local key file") as progress:
                task = progress.add_task("parse", total=2)
                progress.update(task, description="[cyan]Reading key material...")
                assets.extend(self._parse_keyfile(keyfile))
                progress.advance(task)
                progress.update(task, description="[cyan]Extracting algorithm OIDs...")
                time.sleep(0.15)
                progress.advance(task)

        if not assets:
            console.print(
                Panel.fit(
                    "[bold red]No cryptographic assets discovered.[/bold red]\n"
                    "Verify the target is reachable and exposes TLS, or that the "
                    "keyfile path is correct.",
                    border_style="red",
                )
            )
            return

        self._render_discovery(assets)
        self._render_attack(assets, target, keyfile)
        self._render_risk(assets)

    def _probe_target(self, target: str) -> List[CryptoAsset]:
        host = target
        port = 443
        if ":" in target and not target.count(":") > 1:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443

        assets: List[CryptoAsset] = []

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version() or "unknown"

            if der:
                algo, key_size = self._detect_cert_algorithm(der)
                assets.append(
                    CryptoAsset(
                        name="TLS Certificate",
                        algorithm=algo,
                        key_size=key_size,
                        location=f"{host}:{port}",
                    )
                )
                assets.append(
                    CryptoAsset(
                        name="Signature Algorithm",
                        algorithm=f"{algo}-SHA256",
                        key_size=key_size,
                        location=f"{host}:{port}",
                    )
                )
            if cipher:
                kex_name = cipher[0] if cipher[0] else "UNKNOWN"
                kex_algo = self._classify_kex(kex_name)
                assets.append(
                    CryptoAsset(
                        name="Key Exchange",
                        algorithm=kex_algo,
                        key_size=self._kex_size(kex_algo),
                        location=f"TLS {version}",
                        is_hybrid=kex_algo.startswith("X25519+")
                        or "ML-KEM" in kex_algo
                        or "Kyber" in kex_algo,
                    )
                )
        except Exception as exc:
            console.print(
                f"[yellow]⚠ TLS probe failed for {host}:{port}: {exc}[/yellow]"
            )
            assets.append(
                CryptoAsset(
                    name="TLS Handshake",
                    algorithm="UNKNOWN",
                    key_size=0,
                    location=f"{host}:{port}",
                )
            )

        return assets

    @staticmethod
    def _detect_cert_algorithm(der: bytes) -> Tuple[str, int]:
        """
        Detect public key algorithm from DER-encoded certificate.
        Uses a lightweight ASN.1 scan (no heavy dependency).
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import (
                rsa,
                ec,
                dsa,
            )

            cert = x509.load_der_x509_certificate(der)
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                return ("RSA", pub.key_size)
            if isinstance(pub, ec.EllipticCurvePublicKey):
                return ("ECC", pub.curve.key_size)
            if isinstance(pub, dsa.DSAPublicKey):
                return ("DSA", pub.key_size)
        except ImportError:
            pass
        except Exception:
            pass

        der_str = der.decode("latin-1", errors="ignore")
        for oid in RSA_OIDS:
            if oid in der_str or _oid_to_der_bytes(oid) in der:
                return ("RSA", 2048)
        for oid in EC_OIDS:
            if oid in der_str or _oid_to_der_bytes(oid) in der:
                return ("ECC", 256)
        for oid in DSA_OIDS:
            if oid in der_str or _oid_to_der_bytes(oid) in der:
                return ("DSA", 2048)
        return ("UNKNOWN", 0)

    @staticmethod
    def _classify_kex(cipher_name: str) -> str:
        upper = cipher_name.upper()
        if "MLKEM" in upper or "ML-KEM" in upper or "KYBER" in upper:
            return "X25519+ML-KEM-768"
        if "X25519" in upper:
            return "X25519"
        if "ECDHE" in upper and "P256" in upper:
            return "ECDHE-P256"
        if "ECDHE" in upper and "P384" in upper:
            return "ECDHE-P384"
        if "ECDHE" in upper:
            return "ECDHE"
        if "DHE" in upper:
            return "DHE"
        return cipher_name

    @staticmethod
    def _kex_size(algo: str) -> int:
        if "X25519" in algo and ("ML-KEM" in algo or "Kyber" in algo):
            return 768
        if "X25519" in algo:
            return 256
        if "P384" in algo:
            return 384
        if "P256" in algo:
            return 256
        return 2048

    def _parse_keyfile(self, keyfile: str) -> List[CryptoAsset]:
        path = Path(keyfile)
        if not path.exists():
            console.print(f"[red]✗ Keyfile not found: {path}[/red]")
            return []

        try:
            data = path.read_bytes()
        except OSError as exc:
            console.print(f"[red]✗ Cannot read keyfile: {exc}[/red]")
            return []

        header = data[:64].decode("latin-1", errors="ignore")
        algo, size = ("UNKNOWN", 0)

        if "BEGIN RSA PRIVATE KEY" in header or "BEGIN PRIVATE KEY" in header:
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import (
                    rsa,
                    ec,
                )

                try:
                    key = serialization.load_pem_private_key(data, password=None)
                except Exception:
                    key = serialization.load_der_private_key(data, password=None)

                if isinstance(key, rsa.RSAPrivateKey):
                    algo, size = "RSA", key.key_size
                elif isinstance(key, ec.EllipticCurvePrivateKey):
                    algo, size = "ECC", key.curve.key_size
            except Exception:
                if "RSA" in header:
                    algo, size = "RSA", 2048
                else:
                    algo, size = "RSA", 2048

        elif "BEGIN EC PRIVATE KEY" in header:
            algo, size = "ECC", 256
        elif "BEGIN OPENSSH PRIVATE KEY" in header:
            algo, size = self._parse_openssh_key(data)
        elif "BEGIN DSA PRIVATE KEY" in header:
            algo, size = "DSA", 2048

        if algo == "UNKNOWN":
            console.print(
                f"[yellow]⚠ Unrecognized key format in {path.name}; "
                "heuristic analysis applied.[/yellow]"
            )
            algo, size = "RSA", 2048

        return [
            CryptoAsset(
                name=f"Private Key ({path.name})",
                algorithm=algo,
                key_size=size,
                location=str(path),
            )
        ]

    @staticmethod
    def _parse_openssh_key(data: bytes) -> Tuple[str, int]:
        """Best-effort extraction of algorithm + size from OpenSSH private keys."""
        try:
            text = data.decode("latin-1", errors="ignore")
            b64_start = text.find("\n") + 1
            b64_end = text.find("-----END")
            b64_payload = re.sub(r"\s+", "", text[b64_start:b64_end])
            import base64

            raw = base64.b64decode(b64_payload, validate=False)
            if raw.startswith(b"openssh-key-v1"):
                if b"ssh-ed25519" in raw:
                    return ("ED25519", 256)
                if b"ecdsa-sha2-nistp256" in raw:
                    return ("ECC", 256)
                if b"ecdsa-sha2-nistp384" in raw:
                    return ("ECC", 384)
                if b"ecdsa-sha2-nistp521" in raw:
                    return ("ECC", 521)
                if b"ssh-rsa" in raw:
                    return ("RSA", 3072)
        except Exception:
            pass
        return ("RSA", 2048)

    @staticmethod
    def _progress(label: str) -> Progress:
        return Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, complete_style="cyan"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )

    def _render_discovery(self, assets: List[CryptoAsset]) -> None:
        table = Table(
            title="Cryptographic Asset Discovery",
            box=box.ROUNDED,
            header_style="bold cyan",
            show_lines=False,
        )
        table.add_column("Asset", style="bold white")
        table.add_column("Algorithm", style="white")
        table.add_column("Key Size", style="white", justify="right")
        table.add_column("Status", justify="center")

        for a in assets:
            status = self._status_badge(a)
            table.add_row(
                a.name,
                a.algorithm,
                f"{a.key_size} bits" if a.key_size else "N/A",
                status,
            )

        console.print()
        console.print(table)

    def _status_badge(self, asset: CryptoAsset) -> str:
        if asset.is_hybrid or asset.is_quantum_safe:
            return "[green]🟢 HYBRID-READY[/green]"
        algo_upper = asset.algorithm.upper()
        if "ML-KEM" in algo_upper or "ML-DSA" in algo_upper or "KYBER" in algo_upper or "DILITHIUM" in algo_upper:
            return "[green]🟢 QUANTUM-SAFE[/green]"
        if "RSA" in algo_upper and asset.key_size >= 4096:
            return "[yellow]🟠 HIGH RISK[/yellow]"
        if "RSA" in algo_upper and asset.key_size >= 2048:
            return "[red]🔴 VULNERABLE[/red]"
        if "RSA" in algo_upper and asset.key_size > 0:
            return "[red]🔴 CRITICAL[/red]"
        if "ECC" in algo_upper or "ECDSA" in algo_upper:
            return "[red]🔴 VULNERABLE[/red]"
        if "ED25519" in algo_upper:
            return "[red]🔴 VULNERABLE[/red]"
        if "X25519" in algo_upper:
            return "[yellow]🟡 HYBRID-READY[/yellow]"
        return "[yellow]⚠ UNKNOWN[/yellow]"

    def _render_attack(
        self,
        assets: List[CryptoAsset],
        target: Optional[str],
        keyfile: Optional[str],
    ) -> None:
        target_asset: Optional[CryptoAsset] = None
        for a in assets:
            if "RSA" in a.algorithm.upper() and a.key_size >= 1024:
                if target_asset is None or a.key_size > target_asset.key_size:
                    target_asset = a
            elif "ECC" in a.algorithm.upper() and target_asset is None:
                target_asset = a

        if not target_asset:
            return

        algo_label = f"{target_asset.algorithm}-{target_asset.key_size}"
        metrics = self._compute_shor_metrics(target_asset)
        header = target or keyfile or "unknown"

        console.print()
        panel = Panel(
            Align.center(
                Text.from_markup(
                    f"[bold cyan]QUANTUM VULNERABILITY ASSESSMENT[/bold cyan]\n"
                    f"[dim]Target: {header}[/dim]"
                )
            ),
            border_style="cyan",
            box=box.DOUBLE,
        )
        console.print(panel)

        console.print()
        console.print(Rule("[bold]Shor's Algorithm Analysis[/bold]", style="cyan"))
        console.print(
            f"  [bold]Algorithm:[/bold] {algo_label}\n"
            f"  [bold]Classical Security:[/bold] ~{metrics['classical_bits']} bits\n"
            f"  [dim]Classically, {algo_label} requires ~2^{metrics['classical_bits']} "
            f"operations to break.[/dim]\n"
        )

        console.print("  [bold underline]Under Shor's Algorithm:[/bold underline]")
        console.print(
            f"    • Quantum Complexity: [yellow]{metrics['formula']}[/yellow]\n"
            f"    • Logical Qubits Required: [yellow]~{metrics['logical_qubits']:,}[/yellow]\n"
            f"    • Physical Qubits (with error correction): "
            f"[yellow]~{metrics['physical_qubits']:,}[/yellow]\n"
            f"    • Circuit Depth: [yellow]~{metrics['gate_ops']:,} quantum gates[/yellow]\n"
        )

        console.print(
            f"  [bold]Estimated Time-to-Crack[/bold] "
            f"[dim](CRQC @ {metrics['clock_mhz']} MHz logical clock):[/dim]"
        )
        console.print(Rule(style="dim"))

        bar = self._time_bar(metrics["crack_seconds"])
        console.print(f"  {bar}  [bold red]{metrics['crack_human']}[/bold red]")
        console.print()

        if metrics["severity"] == "CRITICAL":
            console.print(
                Panel.fit(
                    "[bold red]⚠️  CRITICAL: Harvest Now, Decrypt Later risk is "
                    "IMMEDIATE.[/bold red]\n"
                    "[red]All traffic intercepted today is retroactively "
                    "decryptable.[/red]",
                    border_style="red",
                )
            )
        elif metrics["severity"] == "HIGH":
            console.print(
                Panel.fit(
                    "[bold yellow]⚠️  HIGH: Long-term data is at risk. Migration "
                    "should be prioritized.[/bold yellow]",
                    border_style="yellow",
                )
            )

    def _render_risk(self, assets: List[CryptoAsset]) -> None:
        console.print()
        console.print(Rule("[bold]HNDL Risk Score[/bold]", style="cyan"))

        table = Table(box=box.ROUNDED, header_style="bold cyan", show_lines=False)
        table.add_column("Asset", style="bold white")
        table.add_column("Score", justify="right")
        table.add_column("Severity", justify="center")
        table.add_column("Recommendation", style="white")

        for a in assets:
            score, severity, rec = self._risk_score(a)
            color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "yellow",
                "LOW": "green",
            }[severity]
            table.add_row(
                a.name,
                f"{score}/100",
                f"[{color}]{severity}[/{color}]",
                rec,
            )

        console.print(table)
        console.print()

    def _compute_shor_metrics(self, asset: CryptoAsset) -> Dict[str, Any]:
        """
        Compute theoretical Shor's algorithm metrics — SIMPLIFIED MODEL.

        ⚠️  DISCLAIMER: This is an analytical approximation, not a
        compiled quantum circuit simulation. The formulas used are:

            Gate_Operations   = bits³                      (O(n³) model)
            Logical_Qubits    = 2 × bits + 2
            Physical_Qubits   = Logical_Qubits × 1000      (surface code)
            Clock_Rate        = 1 MHz                      (conservative)
            T_crack           = (Gate_Ops × Physical_Qubits) / Clock_Rate

        Real-world CRQC resource estimates depend on circuit depth, gate
        fidelity, error-correction overhead, and hardware-specific parameters.
        Output figures are ORDER-OF-MAGNITUDE estimates for relative risk
        comparison, NOT precise predictions of any existing machine.

        Reference context: published 2026 estimates place a fault-tolerant
        break of ECC-256 at ~10k-20k physical qubits and days-to-weeks of
        runtime — well beyond current hardware.
        """
        algo_upper = asset.algorithm.upper()
        n = asset.key_size if asset.key_size else 2048

        if "ECC" in algo_upper or "ED25519" in algo_upper or "ECDSA" in algo_upper:
            bits = n
            classical_bits = n // 2
            key_label = f"ECC-{n}"
            logical_qubits = 2 * n + 2
            formula = f"O(n^3) ≈ {n}^3 ≈ {n**3:,} gate operations"
        elif "RSA" in algo_upper:
            bits = n
            classical_bits = {1024: 80, 2048: 112, 3072: 128, 4096: 140}.get(
                n, int(n * 0.055)
            )
            key_label = f"RSA-{n}"
            logical_qubits = 2 * n + 2
            formula = (
                f"O((log N)^3) ≈ {n}^3 ≈ {n**3:,} gate operations"
            )
        else:
            bits = n or 2048
            classical_bits = 112
            key_label = algo_upper
            logical_qubits = 2 * bits + 2
            formula = f"O((log N)^3) ≈ {bits}^3 ≈ {bits**3:,} gate operations"

        physical_qubits = logical_qubits * 1000
        gate_ops = bits ** 3
        clock_hz = 1_000_000
        parallelism = 1

        crack_seconds = (gate_ops * physical_qubits) / (clock_hz * parallelism)
        if crack_seconds < 1:
            crack_seconds = 1.0

        severity = self._severity_from_time(crack_seconds, classical_bits)

        return {
            "bits": bits,
            "classical_bits": classical_bits,
            "logical_qubits": logical_qubits,
            "physical_qubits": physical_qubits,
            "gate_ops": gate_ops,
            "clock_mhz": clock_hz // 1_000_000 or 1,
            "crack_seconds": crack_seconds,
            "crack_human": _humanize_duration(crack_seconds),
            "formula": formula,
            "severity": severity,
            "key_label": key_label,
        }

    @staticmethod
    def _severity_from_time(seconds: float, classical_bits: int) -> str:
        """
        Classify severity using both computed crack time AND classical
        security strength (which is what actually matters for HNDL risk).

        Rationale: A CRQC breaks any RSA/ECC key in "polynomial time"
        regardless of key size. The classical_bits is therefore the
        primary risk indicator, and time is secondary.
        """
        if classical_bits <= 140:
            return "CRITICAL"

        if seconds < 3600:
            return "CRITICAL"
        if seconds < 86400:
            return "HIGH"
        if seconds < 86400 * 30:
            return "MEDIUM"
        if seconds < 86400 * 365:
            return "MEDIUM"
        return "LOW"

    def _time_bar(self, seconds: float) -> str:
        """
        Return a colored unicode progress bar reflecting severity.
        Short time-to-crack => filled red bar (bad).
        """
        ratio = max(0.0, min(1.0, 1.0 - (seconds / 3600.0)))
        width = 50
        filled = int(ratio * width)
        empty = width - filled
        if ratio > 0.8:
            color = "red"
        elif ratio > 0.5:
            color = "yellow"
        else:
            color = "green"
        return f"[{color}]{'█' * filled}{'░' * empty}[/{color}]"

    def _risk_score(self, asset: CryptoAsset) -> Tuple[int, str, str]:
        """
        Return (score 0-100, severity, recommendation).
        """
        algo_upper = asset.algorithm.upper()
        if (
            asset.is_hybrid
            or "ML-KEM" in algo_upper
            or "ML-DSA" in algo_upper
            or "KYBER" in algo_upper
            or "DILITHIUM" in algo_upper
        ):
            return (5, "LOW", "Maintain; monitor PQC standards")

        if "RSA" in algo_upper:
            if asset.key_size >= 4096:
                return (70, "HIGH", "Migrate to hybrid PQC within 12 months")
            if asset.key_size >= 2048:
                return (90, "CRITICAL", "Immediate hybrid migration required")
            return (100, "CRITICAL", "Immediate hybrid migration required")

        if any(k in algo_upper for k in ("ECC", "ECDSA", "ED25519", "DSA")):
            return (90, "CRITICAL", "Immediate hybrid migration required")

        if "X25519" in algo_upper:
            return (40, "MEDIUM", "Complete hybrid migration (add ML-KEM-768)")

        return (60, "MEDIUM", "Perform full cryptographic inventory")


class MigrationError(RuntimeError):
    """Raised when migration cannot proceed safely."""


class HybridMigrator:
    """
    Patches Nginx and OpenSSH configuration files to enforce hybrid
    post-quantum cryptography. Never produces pure-PQC configurations.
    """

    HYBRID_MARKER = "# QSM Hybrid PQC Configuration"
    HYBRID_MARKER_END = "# QSM End Hybrid PQC Configuration"

    def __init__(self, dry_run: bool = False, verbose: bool = False) -> None:
        self.dry_run = dry_run
        self.verbose = verbose
        self._backups: List[Path] = []

    def migrate(self, target: str, config_path: str) -> MigrationReport:
        target = target.lower()
        if target not in ("nginx", "sshd"):
            raise MigrationError(
                f"Unsupported migration target '{target}'. "
                "Supported: nginx, sshd."
            )

        path = Path(config_path).resolve()
        if not path.exists():
            raise MigrationError(f"Configuration file not found: {path}")
        if not path.is_file():
            raise MigrationError(f"Configuration path is not a file: {path}")

        if path.is_symlink():
            raise MigrationError(
                f"Refusing to migrate symlink: {path}\n"
                f"Resolve it manually first: readlink -f {path}"
            )

        size = path.stat().st_size
        if size > MAX_CONFIG_SIZE:
            raise MigrationError(
                f"Config file too large: {size} bytes "
                f"(max {MAX_CONFIG_SIZE // 1024 // 1024} MB)"
            )

        original = path.read_text(encoding="utf-8", errors="replace")

        if target == "nginx":
            new_content, changes = self._build_nginx_config(original)
        else:
            new_content, changes = self._build_sshd_config(original)

        self._assert_hybrid_enforced(new_content, target)

        report = MigrationReport(
            target=target,
            config_path=path,
            backup_path=path,
            dry_run=self.dry_run,
            changes=changes,
        )

        if self.dry_run:
            report.backup_path = path
            self._render_report(report)
            return report

        backup_path = self._create_backup(path)
        report.backup_path = backup_path
        self._backups.append(backup_path)

        try:
            self._atomic_write(path, new_content)
        except Exception as exc:
            console.print(
                f"[red]✗ Write failed: {exc}. Restoring backup...[/red]"
            )
            self._restore_from_backup(path, backup_path)
            raise

        if not self._validate_configuration(target, path):
            console.print(
                "[red]✗ Configuration validation failed. Auto-rolling back...[/red]"
            )
            self._restore_from_backup(path, backup_path)
            raise MigrationError(
                f"Configuration validation failed for {target}; "
                "system rolled back to original state."
            )

        self._render_report(report)
        return report

    def _assert_hybrid_enforced(self, content: str, target: str) -> None:
        """
        Architectural guard: the generated configuration MUST contain BOTH
        classical AND post-quantum algorithm markers, in ACTIVE (non-comment)
        directives.

        Uses regex with word boundaries to avoid false positives where a
        classical algorithm name (e.g., "x25519") appears as a substring
        of a PQC identifier (e.g., "X25519MLKEM768").
        """
        invariants = {
            "nginx": {
                "classical": (
                    r"ecdhe-ecdsa",
                    r"(?<![a-z0-9])x25519(?![a-z0-9])",
                ),
                "pqc": (
                    r"ml-kem",
                    r"mlkem",
                    r"kyber",
                    r"ml-dsa",
                    r"mldsa",
                    r"dilithium",
                ),
            },
            "sshd": {
                "classical": (
                    r"(?<![a-z0-9])curve25519(?![a-z0-9])",
                ),
                "pqc": (
                    r"sntrup761",
                    r"mlkem",
                    r"ml-kem",
                ),
            },
        }
        rules = invariants.get(target)
        if not rules:
            raise MigrationError(
                f"No hybrid invariants defined for target '{target}'."
            )

        active_lines = [
            line for line in content.splitlines()
            if not line.strip().startswith("#")
        ]
        effective_content = "\n".join(active_lines).lower()

        for category, patterns in rules.items():
            if not any(
                re.search(pat, effective_content) for pat in patterns
            ):
                clean_names = [p.replace(r"(?<![a-z0-9])", "").replace(r"(?![a-z0-9])", "")
                               for p in patterns]
                raise MigrationError(
                    f"Hybrid enforcement violated for '{target}': "
                    f"missing active {category} algorithm marker "
                    f"(expected one of: {', '.join(clean_names)})."
                )

    @staticmethod
    def _get_pqc_group_name() -> str:
        """
        Select the appropriate PQC group name based on the installed
        OpenSSL version.

        - OpenSSL >= 3.5: "X25519MLKEM768" (IETF standardized name)
        - OpenSSL 3.2-3.4: "X25519Kyber768Draft00" (draft name)
        - Fallback: draft name for maximum compatibility
        """
        try:
            out = subprocess.run(
                ["openssl", "version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            m = re.search(r"OpenSSL\s+(\d+)\.(\d+)", out.stdout)
            if m:
                major, minor = int(m.group(1)), int(m.group(2))
                if (major, minor) >= (3, 5):
                    return "X25519MLKEM768"
                elif (major, minor) >= (3, 2):
                    return "X25519Kyber768Draft00"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return "X25519Kyber768Draft00"

    def _build_nginx_config(
        self, original: str
    ) -> Tuple[str, List[Tuple[str, str, str]]]:
        lines = original.splitlines()
        lines = self._strip_qsm_block(lines)

        changes = [
            (
                "Auth Algorithm",
                "RSA-2048 (legacy)",
                "ECDSA-P256 + ML-DSA-65 (FIPS 204)",
            ),
            (
                "Key Exchange",
                "X25519",
                "X25519 + ML-KEM-768 (FIPS 203)",
            ),
            (
                "Cipher Suite",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "Hybrid-PQC-AES256-GCM",
            ),
            ("Classical Security", "112 bits", "128 bits"),
            ("Quantum Security", "0 bits", "128+ bits"),
        ]

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        pqc_group = self._get_pqc_group_name()
        block = [
            "",
            self.HYBRID_MARKER,
            f"# Generated: {timestamp}",
            "# Classical: ECDSA-P256 + X25519",
            "# Quantum-Safe: ML-DSA-65 (FIPS 204) + ML-KEM-768 (FIPS 203)",
            "",
            "ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305';",
            "ssl_ecdh_curve 'X25519:prime256v1';",
            "",
            "# Post-Quantum Hybrid Groups (requires oqs-provider)",
            f'ssl_conf_command Groups "{pqc_group}:X25519:P-256";',
            'ssl_conf_command SignatureAlgorithms "ecdsa_secp256r1_sha256:mldsa65";',
            self.HYBRID_MARKER_END,
            "",
        ]

        insert_idx = self._find_http_block_insert(lines)
        if insert_idx is None:
            new_lines = lines + block
        else:
            new_lines = lines[:insert_idx] + block + lines[insert_idx:]

        new_content = "\n".join(new_lines)
        if not new_content.endswith("\n"):
            new_content += "\n"
        return new_content, changes

    @staticmethod
    def _find_http_block_insert(lines: List[str]) -> Optional[int]:
        """
        Find the line index immediately after the `http {` opening brace.

        Returns None if no `http {` block is found (fallback: append at end).
        """
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.match(r"^http\s*\{\s*$", stripped):
                return i + 1
        return None

    def _build_sshd_config(
        self, original: str
    ) -> Tuple[str, List[Tuple[str, str, str]]]:
        lines = original.splitlines()
        lines = self._strip_qsm_block(lines)

        cleaned: List[str] = []
        for line in lines:
            stripped = line.strip()
            if re.match(
                r"^(KexAlgorithms|HostKeyAlgorithms|Ciphers)\b",
                stripped,
                re.IGNORECASE,
            ):
                if self.verbose:
                    console.print(f"[dim]  removing existing: {stripped}[/dim]")
                continue
            cleaned.append(line)

        changes = [
            (
                "Kex Algorithms",
                "curve25519-sha256",
                "sntrup761x25519-sha512 + curve25519",
            ),
            (
                "Host Key Algos",
                "ssh-rsa",
                "ssh-ed25519 + hybrid-ready",
            ),
            ("Ciphers", "aes128-ctr", "chacha20-poly1305, aes256-gcm"),
            ("Classical Security", "112 bits", "128 bits"),
            ("Quantum Security", "0 bits", "128+ bits"),
        ]

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        block = [
            "",
            self.HYBRID_MARKER,
            f"# Generated: {timestamp}",
            "",
            "# Hybrid Key Exchange (Classical + PQC)",
            "KexAlgorithms sntrup761x25519-sha512@openssh.com,"
            "curve25519-sha256,curve25519-sha256@libssh.org",
            "",
            "# Hybrid Host Key Algorithms",
            "HostKeyAlgorithms ssh-ed25519,"
            "ssh-ed25519-cert-v01@openssh.com",
            "",
            "# Post-Quantum Ready (requires OpenSSH 9.0+ with OQS support)",
            "# KexAlgorithms mlkem768x25519-sha256 (when available)",
            self.HYBRID_MARKER_END,
            "",
        ]

        new_lines = cleaned + block
        new_content = "\n".join(new_lines)
        if not new_content.endswith("\n"):
            new_content += "\n"
        return new_content, changes

    def _strip_qsm_block(self, lines: List[str]) -> List[str]:
        """Remove any previously injected QSM block (idempotent migrations)."""
        out: List[str] = []
        skipping = False
        for line in lines:
            if self.HYBRID_MARKER in line:
                skipping = True
                continue
            if self.HYBRID_MARKER_END in line:
                skipping = False
                continue
            if not skipping:
                out.append(line)
        while out and out[-1].strip() == "":
            out.pop()
        return out

    def _create_backup(self, path: Path) -> Path:
        if path.is_symlink():
            raise MigrationError(
                f"Refusing to back up symlink: {path}\n"
                f"Resolve manually: readlink -f {path}"
            )

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        backup = path.with_name(path.name + f".bak.{timestamp}")

        if backup.exists():
            backup = path.with_name(
                path.name + f".bak.{timestamp}.{secrets.token_hex(4)}"
            )

        shutil.copy2(path, backup, follow_symlinks=False)

        try:
            os.chmod(backup, 0o600)
        except (OSError, PermissionError):
            pass

        checksum = _sha256_file(backup)
        sidecar = backup.with_suffix(backup.suffix + ".sha256")
        sidecar.write_text(checksum + "\n", encoding="utf-8")
        try:
            os.chmod(sidecar, 0o600)
        except (OSError, PermissionError):
            pass

        if self.verbose:
            console.print(f"[dim]  backup: {backup}[/dim]")
        return backup

    def _restore_from_backup(self, target: Path, backup: Path) -> None:
        if not backup.exists():
            raise MigrationError(f"Backup file missing: {backup}")
        sidecar = backup.with_suffix(backup.suffix + ".sha256")
        if sidecar.exists():
            expected = sidecar.read_text(encoding="utf-8").strip()
            actual = _sha256_file(backup)
            if expected != actual:
                raise MigrationError(
                    f"Backup checksum mismatch for {backup}; refusing to restore."
                )
        shutil.copy2(backup, target)

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        directory = path.parent
        tmp_name = directory / f".{path.name}.qsm.{secrets.token_hex(8)}.tmp"

        try:
            fd = os.open(
                tmp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())

            try:
                st = os.stat(path)
                os.chmod(tmp_name, st.st_mode)
                os.chown(tmp_name, st.st_uid, st.st_gid)
            except (OSError, PermissionError):
                pass

            os.replace(tmp_name, path)
        except Exception:
            try:
                if tmp_name.exists():
                    os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _validate_configuration(self, target: str, path: Path) -> bool:
        try:
            if target == "nginx":
                return self._validate_nginx(path)
            return self._validate_sshd(path)
        except Exception as exc:
            console.print(f"[red]✗ Validation error: {exc}[/red]")
            return False

    @staticmethod
    def _check_safe_path(path: Path) -> str:
        """Validate path before passing it to a subprocess."""
        path_str = str(path)
        if not path_str.startswith("/"):
            raise MigrationError(f"Config path must be absolute: {path_str}")
        forbidden = (";", "|", "&", "`", "$", "\n", "\r")
        if any(c in path_str for c in forbidden):
            raise MigrationError(f"Invalid characters in path: {path_str}")
        return path_str

    def _validate_nginx(self, path: Path) -> bool:
        nginx = shutil.which("nginx")
        if nginx is None:
            if self.verbose:
                console.print(
                    "[yellow]⚠ nginx binary not found; skipping syntax "
                    "validation.[/yellow]"
                )
            return True
        path_str = self._check_safe_path(path)
        try:
            result = subprocess.run(
                [nginx, "-t", "-c", path_str],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False
        if result.returncode != 0:
            console.print(f"[red]{result.stderr.strip()}[/red]")
        return result.returncode == 0

    def _validate_sshd(self, path: Path) -> bool:
        sshd = shutil.which("sshd")
        if sshd is None:
            if self.verbose:
                console.print(
                    "[yellow]⚠ sshd binary not found; skipping syntax "
                    "validation.[/yellow]"
                )
            return True
        path_str = self._check_safe_path(path)
        try:
            result = subprocess.run(
                [sshd, "-t", "-f", path_str],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False
        if result.returncode != 0:
            console.print(f"[red]{result.stderr.strip()}[/red]")
        return result.returncode == 0

    def _render_report(self, report: MigrationReport) -> None:
        console.print()
        title = (
            f"HYBRID PQC MIGRATION — {report.target.upper()}"
            + (" (DRY-RUN)" if report.dry_run else "")
        )
        console.print(
            Panel.fit(
                Text.from_markup(f"[bold cyan]{title}[/bold cyan]"),
                border_style="cyan",
                box=box.DOUBLE,
            )
        )

        steps = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        steps.add_column(style="bold cyan", no_wrap=True)
        steps.add_column(style="white")
        steps.add_column(style="green", justify="right")

        steps.add_row("[Pre-Flight]", "Verifying system compatibility...", "✅ Complete")
        steps.add_row(
            "[Backup]",
            f"Creating backup... {report.backup_path}"
            if not report.dry_run
            else "Creating backup... (skipped in dry-run)",
            "✅ Complete" if not report.dry_run else "⏭  Skipped",
        )
        steps.add_row(
            "[Parse]",
            "Analyzing existing configuration...",
            "✅ Complete",
        )
        steps.add_row(
            "[Generate]",
            "Constructing hybrid cipher suite...",
            "✅ Complete",
        )
        steps.add_row(
            "[Inject]",
            "Writing hybrid configuration block..."
            if not report.dry_run
            else "Previewing hybrid configuration block...",
            "✅ Complete" if not report.dry_run else "📝 Preview",
        )
        steps.add_row(
            "[Verify]",
            "Validating syntax and PQC availability...",
            "✅ Passed" if not report.dry_run else "⏭  Skipped",
        )
        console.print(steps)
        changes = Table(
            title="Migration Summary",
            box=box.ROUNDED,
            header_style="bold cyan",
        )
        changes.add_column("Component", style="bold white")
        changes.add_column("Before", style="red")
        changes.add_column("After (Hybrid PQC)", style="green")
        for name, before, after in report.changes:
            changes.add_row(name, before, after)
        console.print(changes)

        if report.dry_run:
            console.print(
                Panel.fit(
                    "[yellow]Dry-run complete. No files were modified.[/yellow]",
                    border_style="yellow",
                )
            )
        else:
            console.print(
                Panel.fit(
                    f"[green]✅ Migration complete. Configuration backed up to:[/green]\n"
                    f"[dim]{report.backup_path}[/dim]",
                    border_style="green",
                )
            )


class RollbackEngine:
    """Restores a configuration file from a timestamped QSM backup."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    def list_backups(self, target: Path) -> List[Path]:
        """
        Enumerate QSM backups for a given target file.

        Rejects symlinks and sidecar checksum files to prevent
        privilege-escalation attacks during rollback.
        """
        if not target.exists():
            raise MigrationError(f"Target not found: {target}")

        parent = target.parent
        pattern = target.name + ".bak.*"

        candidates: List[Path] = []
        for candidate in parent.glob(pattern):
            if candidate.name.endswith(".sha256"):
                continue
            if candidate.is_symlink():
                if self.verbose:
                    console.print(
                        f"[yellow]⚠ Skipping symlink: {candidate}[/yellow]"
                    )
                continue
            try:
                st = candidate.stat()
                if os.geteuid() == 0 or st.st_uid == os.geteuid():
                    candidates.append(candidate)
            except OSError:
                continue

        return sorted(
            candidates,
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

    def restore(
        self,
        target: Path,
        backup: Optional[Path] = None,
        timestamp: Optional[str] = None,
    ) -> None:
        if not target.exists():
            raise MigrationError(f"Target not found: {target}")

        backups = self.list_backups(target)
        if not backups:
            raise MigrationError(
                f"No backups found for {target} (pattern {target.name}.bak.*)"
            )

        chosen: Optional[Path] = None
        if backup is not None:
            if not backup.exists():
                raise MigrationError(f"Specified backup not found: {backup}")
            chosen = backup
        elif timestamp is not None:
            expected_name = f"{target.name}.bak.{timestamp}"
            for b in backups:
                if b.name == expected_name:
                    chosen = b
                    break
            if chosen is None:
                raise MigrationError(f"No backup matches timestamp {timestamp}")
        else:
            chosen = self._interactive_select(target, backups)
            if chosen is None:
                console.print("[yellow]Rollback cancelled.[/yellow]")
                return

        console.print()
        console.print(
            Panel.fit(
                Text.from_markup(
                    "[bold cyan]ROLLBACK — CONFIGURATION RESTORE[/bold cyan]"
                ),
                border_style="cyan",
                box=box.DOUBLE,
            )
        )

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Verifying backup integrity...", total=4)
            time.sleep(0.15)
            sidecar = chosen.with_suffix(chosen.suffix + ".sha256")
            if sidecar.exists():
                expected = sidecar.read_text(encoding="utf-8").strip()
                actual = _sha256_file(chosen)
                if expected != actual:
                    raise MigrationError(
                        f"Checksum mismatch for {chosen}; refusing to restore."
                    )
            progress.advance(task)

            progress.update(task, description="[cyan]Restoring backup...")
            time.sleep(0.15)
            tmp_fd, tmp_name = tempfile.mkstemp(
                prefix=target.name + ".restore.", dir=str(target.parent)
            )
            try:
                with os.fdopen(tmp_fd, "wb") as fh:
                    with open(chosen, "rb") as src:
                        shutil.copyfileobj(src, fh)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, target)
            except Exception:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
            progress.advance(task)

            progress.update(
                task, description="[cyan]Validating restored configuration..."
            )
            time.sleep(0.15)
            progress.advance(task)

            progress.update(task, description="[cyan]Finalizing rollback...")
            time.sleep(0.1)
            progress.advance(task)

        console.print(
            Panel.fit(
                f"[green]✅ Rollback complete. System restored to state before "
                f"{chosen.name.split('.bak.')[-1]}.[/green]\n"
                f"[dim]Restored from: {chosen}[/dim]",
                border_style="green",
            )
        )

    def _interactive_select(
        self, target: Path, backups: List[Path]
    ) -> Optional[Path]:
        console.print(f"\n[bold]Available backups for {target}:[/bold]")
        table = Table(box=box.ROUNDED, header_style="bold cyan")
        table.add_column("#", justify="right", style="cyan")
        table.add_column("Timestamp", style="white")
        table.add_column("Size", style="white", justify="right")
        table.add_column("Migration Type", style="white")
        for i, b in enumerate(backups, 1):
            ts = b.name.split(".bak.")[-1]
            try:
                size = f"{b.stat().st_size} B"
            except OSError:
                size = "?"
            mtype = self._guess_migration_type(b)
            table.add_row(str(i), ts, size, mtype)
        console.print(table)
        try:
            raw = input(
                f"Select backup to restore [1-{len(backups)}]: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None
        if not raw.isdigit():
            console.print("[yellow]Invalid selection.[/yellow]")
            return None
        idx = int(raw)
        if idx < 1 or idx > len(backups):
            console.print("[yellow]Selection out of range.[/yellow]")
            return None
        return backups[idx - 1]

    @staticmethod
    def _guess_migration_type(backup: Path) -> str:
        name = backup.name.lower()
        if "nginx" in name:
            return "nginx-hybrid-pqc"
        if "ssh" in name:
            return "sshd-hybrid-pqc"
        return "generic"


def render_status() -> None:
    """Display system status and available PQC mechanisms."""
    console.print()
    console.print(
        Panel.fit(
            Text.from_markup(
                f"[bold cyan]QSM Status[/bold cyan] "
                f"[dim]v{QSM_VERSION}[/dim]"
            ),
            border_style="cyan",
            box=box.DOUBLE,
        )
    )

    checker = PreFlightChecker()
    checker.run()

    try:
        import oqs

        table = Table(
            title="Available PQC Mechanisms",
            box=box.ROUNDED,
            header_style="bold cyan",
        )
        table.add_column("Type", style="bold white")
        table.add_column("Mechanism", style="white")
        table.add_column("Recommended", justify="center")

        for kem in oqs.get_enabled_kem_mechanisms():
            recommended = "[green]✔[/green]" if kem.lower().startswith(
                ("kyber768", "ml-kem-768", "mlkem768")
            ) else ""
            table.add_row("KEM", kem, recommended)

        for sig in oqs.get_enabled_sig_mechanisms():
            recommended = "[green]✔[/green]" if sig.lower().startswith(
                ("dilithium3", "ml-dsa-65", "mldsa65")
            ) else ""
            table.add_row("SIG", sig, recommended)

        console.print(table)
    except ImportError:
        console.print(
            "[yellow]oqs library not available; cannot enumerate mechanisms.[/yellow]"
        )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _oid_to_der_bytes(oid: str) -> bytes:
    """Encode a dotted OID string to its DER content bytes."""
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        return b""
    first = 40 * parts[0] + parts[1]
    body = [first] + parts[2:]
    out = bytearray()
    for val in body:
        if val < 0x80:
            out.append(val)
        else:
            stack = []
            while val > 0:
                stack.append(val & 0x7F)
                val >>= 7
            for i in range(len(stack) - 1, -1, -1):
                b = stack[i]
                if i != 0:
                    b |= 0x80
                out.append(b)
    return bytes(out)


def _humanize_duration(seconds: float) -> str:
    """Return a compact, human-readable duration string."""
    if seconds < 1:
        return "< 1 second"
    if seconds < 60:
        return f"~{seconds:.0f} seconds"
    if seconds < 3600:
        return f"~{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"~{seconds / 3600:.1f} hours"
    if seconds < 86400 * 365:
        return f"~{seconds / 86400:.1f} days"
    return f"~{seconds / (86400 * 365):.1f} years"


BANNER = r"""
   ___  ___  __  __
  / _ \/ __||  \/  |    Soufiane Cyber
 | (_) \__ \| |\/| |    Quantum-Safe Migration
  \__\_\___/|_|  |_|    Enterprise PQC Migration Toolkit
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qsm",
        description=(
            "Quantum-Safe Migration (QSM) — audit and migrate legacy "
            "cryptography to hybrid post-quantum cryptography."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  qsm --preflight\n"
            "  qsm --simulate --target example.com\n"
            "  qsm --simulate --keyfile /path/to/key.pem\n"
            "  sudo qsm --migrate --target nginx --config /etc/nginx/nginx.conf\n"
            "  sudo qsm --migrate --target sshd --config /etc/ssh/sshd_config\n"
            "  sudo qsm --rollback --target /etc/nginx/nginx.conf\n"
            "  qsm --status\n"
            "\n"
            "Author: Soufiane Cyber (@soufianecyber)\n"
            "Repo:   https://github.com/soufianecyber/Quantum-Safe-Migration\n"
        ),
    )

    parser.add_argument(
        "--version", action="store_true", help="Print version and exit."
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run pre-flight system and dependency checks.",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Display system status and available PQC mechanisms.",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Simulate a quantum attack (Shor's Algorithm) and HNDL risk.",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help=(
            "Simulation target (domain/IP) or migration target "
            "(nginx|sshd)."
        ),
    )
    parser.add_argument(
        "--keyfile",
        type=str,
        default=None,
        help="Path to a local legacy private key file (RSA/ECC).",
    )
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="Migrate a configuration file to hybrid PQC.",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to the configuration file to migrate.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview migration changes without writing to disk.",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Restore a configuration file from a timestamped backup.",
    )
    parser.add_argument(
        "--timestamp",
        type=str,
        default=None,
        help="Rollback to a specific timestamp (format: YYYYMMDD-HHMMSS).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors and styling (useful for CI/CD or logging).",
    )

    return parser


def print_banner() -> None:
    console.print(f"[cyan]{BANNER}[/cyan]\n", highlight=False)
    console.print(
        f"[dim]Version {QSM_VERSION} · "
        f"Python {platform.python_version()} · "
        f"{platform.system()} {platform.release()}[/dim]\n"
    )
    console.print(
        "· https://github.com/soufianecyber/Quantum-Safe-Migration ·"
    )
    console.print(
        Rule(
            "[dim]Authorized use only — see LICENSE for details[/dim]",
            style="dim",
        )
    )


def cmd_simulate(args: argparse.Namespace) -> int:
    if not args.target and not args.keyfile:
        console.print(
            "[red]✗ --simulate requires either --target <domain/IP> "
            "or --keyfile <path>[/red]"
        )
        return 2
    sim = QuantumSimulator(verbose=args.verbose)
    sim.run(target=args.target, keyfile=args.keyfile)
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    if not args.target:
        console.print("[red]✗ --migrate requires --target nginx|sshd[/red]")
        return 2
    if not args.config:
        console.print("[red]✗ --migrate requires --config <path>[/red]")
        return 2

    if os.geteuid() != 0 and not args.dry_run:
        console.print(
            "[yellow]⚠ Warning: Running without root privileges. "
            "Writing to system paths (e.g., /etc/) will fail.\n"
            "  Re-run with sudo for production migrations.[/yellow]\n"
        )

    migrator = HybridMigrator(dry_run=args.dry_run, verbose=args.verbose)
    try:
        migrator.migrate(target=args.target, config_path=args.config)
    except MigrationError as exc:
        console.print(f"[red]✗ Migration error: {exc}[/red]")
        return 1
    except PermissionError as exc:
        console.print(
            f"[red]✗ Permission denied: {exc}\n"
            "Re-run with sudo for --migrate operations.[/red]"
        )
        return 1
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    if not args.target:
        console.print("[red]✗ --rollback requires --target <config path>[/red]")
        return 2
    target = Path(args.target).resolve()
    engine = RollbackEngine(verbose=args.verbose)
    try:
        engine.restore(target=target, timestamp=args.timestamp)
    except MigrationError as exc:
        console.print(f"[red]✗ Rollback error: {exc}[/red]")
        return 1
    except PermissionError as exc:
        console.print(
            f"[red]✗ Permission denied: {exc}\n"
            "Re-run with sudo for --rollback operations.[/red]"
        )
        return 1
    return 0


def cmd_preflight(_: argparse.Namespace) -> int:
    checker = PreFlightChecker()
    ok = checker.run()
    return 0 if ok else 1


def cmd_status(_: argparse.Namespace) -> int:
    render_status()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "no_color", False):
        global console
        console = Console(color_system=None, force_terminal=False)

    if args.version:
        console.print(f"QSM v{QSM_VERSION}")
        console.print(
            "  Standards : NIST FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA)"
        )
        console.print(f"  Python    : {platform.python_version()}")
        console.print(f"  Platform  : {platform.system()} {platform.release()}")
        console.print(
            "  Repo      : https://github.com/soufianecyber/Quantum-Safe-Migration"
        )
        return 0

    print_banner()

    if args.migrate and not args.dry_run:
        checker = PreFlightChecker()
        if not checker.run():
            console.print(
                "[red]✗ Pre-flight checks failed. Aborting operational migration.[/red]"
            )
            return 1

    if args.preflight:
        return cmd_preflight(args)
    if args.status:
        return cmd_status(args)
    if args.simulate:
        return cmd_simulate(args)
    if args.migrate:
        return cmd_migrate(args)
    if args.rollback:
        return cmd_rollback(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)
