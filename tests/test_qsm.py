"""
Test suite for QSM — hybrid enforcement, Shor's metrics, and rollback logic.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from qsm import (  # noqa: E402
    CryptoAsset,
    HybridMigrator,
    MigrationError,
    QuantumSimulator,
    RollbackEngine,
    _humanize_duration,
    _sha256_file,
)


# ---------------------------------------------------------------------------
# Hybrid Enforcement — the CORE security invariant
# ---------------------------------------------------------------------------
class TestHybridEnforcement:
    def test_pure_pqc_content_is_rejected(self) -> None:
        """Pure PQC (no classical component) must be rejected."""
        migrator = HybridMigrator(dry_run=True)
        with pytest.raises(MigrationError, match="Hybrid enforcement violated"):
            migrator._assert_hybrid_enforced(
                'ssl_conf_command Groups "X25519MLKEM768";\n'
                'ssl_conf_command SignatureAlgorithms "mldsa65";',
                "nginx",
            )

    def test_commented_out_hybrid_is_rejected(self) -> None:
        """Hybrid markers inside comments must NOT satisfy the guard."""
        migrator = HybridMigrator(dry_run=True)
        with pytest.raises(MigrationError, match="Hybrid enforcement violated"):
            migrator._assert_hybrid_enforced(
                "# ECDHE-ECDSA\n# X25519\n# ML-KEM-768\n# ML-DSA-65\n",
                "nginx",
            )

    def test_pure_classical_content_is_rejected(self) -> None:
        """Pure classical (no PQC component) must be rejected."""
        migrator = HybridMigrator(dry_run=True)
        with pytest.raises(MigrationError, match="Hybrid enforcement violated"):
            migrator._assert_hybrid_enforced(
                "ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384';\n"
                "ssl_ecdh_curve 'X25519:prime256v1';",
                "nginx",
            )

    def test_hybrid_nginx_content_passes(self) -> None:
        """Proper hybrid content (classical + PQC) must pass validation."""
        migrator = HybridMigrator(dry_run=True)
        content = (
            "ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384';\n"
            "ssl_ecdh_curve 'X25519:prime256v1';\n"
            'ssl_conf_command Groups "X25519MLKEM768:X25519:P-256";\n'
            'ssl_conf_command SignatureAlgorithms "ecdsa_secp256r1_sha256:mldsa65";'
        )
        migrator._assert_hybrid_enforced(content, "nginx")

    def test_hybrid_sshd_content_passes(self) -> None:
        """Proper hybrid sshd content must pass validation."""
        migrator = HybridMigrator(dry_run=True)
        content = (
            "KexAlgorithms sntrup761x25519-sha512@openssh.com,"
            "curve25519-sha256"
        )
        migrator._assert_hybrid_enforced(content, "sshd")

    def test_unknown_target_raises(self) -> None:
        migrator = HybridMigrator(dry_run=True)
        with pytest.raises(MigrationError, match="No hybrid invariants"):
            migrator._assert_hybrid_enforced("any content", "apache")


# ---------------------------------------------------------------------------
# Shor's Metrics
# ---------------------------------------------------------------------------
class TestShorMetrics:
    def test_rsa_2048_severity(self) -> None:
        sim = QuantumSimulator()
        asset = CryptoAsset("test", "RSA", 2048)
        metrics = sim._compute_shor_metrics(asset)
        assert metrics["severity"] in ("CRITICAL", "HIGH")
        assert metrics["logical_qubits"] == 2 * 2048 + 2
        assert metrics["classical_bits"] == 112

    def test_ecc_256_classical_bits(self) -> None:
        sim = QuantumSimulator()
        asset = CryptoAsset("test", "ECC", 256)
        metrics = sim._compute_shor_metrics(asset)
        assert metrics["classical_bits"] == 128

    def test_rsa_4096_high_risk(self) -> None:
        sim = QuantumSimulator()
        asset = CryptoAsset("test", "RSA", 4096)
        metrics = sim._compute_shor_metrics(asset)
        assert metrics["classical_bits"] == 140


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class TestHelpers:
    def test_humanize_seconds(self) -> None:
        assert "seconds" in _humanize_duration(30)

    def test_humanize_minutes(self) -> None:
        assert "minutes" in _humanize_duration(120)

    def test_humanize_hours(self) -> None:
        assert "hours" in _humanize_duration(7200)

    def test_humanize_days(self) -> None:
        assert "days" in _humanize_duration(86400 * 5)

    def test_humanize_years(self) -> None:
        assert "years" in _humanize_duration(86400 * 365 * 5)

    def test_sha256_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        digest = _sha256_file(f)
        assert len(digest) == 64
        assert digest == (
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )


# ---------------------------------------------------------------------------
# Rollback Engine
# ---------------------------------------------------------------------------
class TestRollbackEngine:
    def test_no_backups_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "config.conf"
        target.write_text("original")
        engine = RollbackEngine()
        with pytest.raises(MigrationError, match="No backups found"):
            engine.restore(target=target)

    def test_list_backups_ignores_sidecar(self, tmp_path: Path) -> None:
        target = tmp_path / "config.conf"
        target.write_text("original")
        bak = tmp_path / "config.conf.bak.20260101-120000"
        bak.write_text("backup")
        sidecar = tmp_path / "config.conf.bak.20260101-120000.sha256"
        sidecar.write_text("deadbeef")
        engine = RollbackEngine()
        backups = engine.list_backups(target)
        assert len(backups) == 1
        assert backups[0] == bak

    def test_target_not_found_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist.conf"
        engine = RollbackEngine()
        with pytest.raises(MigrationError, match="Target not found"):
            engine.list_backups(missing)
