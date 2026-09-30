"""Tests for TransferManager."""

import hashlib
import json

import pytest

from secure_transfer.transfer import TransferManager, TransferResult


class TestTransferManager:
    def test_stage_file(self, tmp_path):
        staging = tmp_path / "staging"
        src = tmp_path / "data.vcf"
        src.write_text("##fileformat=VCFv4.2\n")
        mgr = TransferManager(staging_dir=staging)
        expected = hashlib.sha256(src.read_bytes()).hexdigest()
        record = mgr.stage_file(src, checksum=expected)
        assert record.status == "staged"
        assert record.checksum == expected
        assert record.filename == "data.vcf"
        assert (staging / "data.vcf").exists()

    def test_stage_batch(self, tmp_path):
        staging = tmp_path / "staging"
        f1 = tmp_path / "a.vcf"
        f1.write_text("a")
        f2 = tmp_path / "b.vcf"
        f2.write_text("b")
        mgr = TransferManager(staging_dir=staging)
        result = mgr.stage_batch([f1, f2])
        assert result.transferred == 2
        assert result.success_rate == 1.0

    def test_stage_missing_file(self, tmp_path):
        staging = tmp_path / "staging"
        mgr = TransferManager(staging_dir=staging)
        result = mgr.stage_batch(["/nonexistent/file.vcf"])
        assert len(result.failed) == 1
        assert result.success_rate == 0.0

    def test_audit_trail(self, tmp_path):
        staging = tmp_path / "staging"
        src = tmp_path / "data.vcf"
        src.write_text("data")
        mgr = TransferManager(staging_dir=staging)
        mgr.stage_file(src, checksum="xyz")
        audit_path = tmp_path / "audit.json"
        mgr.export_audit_trail(audit_path)
        data = json.loads(audit_path.read_text())
        assert len(data["audit_trail"]) == 1
        entry = data["audit_trail"][0]
        # The trail records the computed checksum, and flags the mismatch with
        # the caller's claim instead of recording the claim as fact.
        assert entry["checksum"] == hashlib.sha256(b"data").hexdigest()
        assert entry["expected_checksum"] == "xyz"
        assert entry["status"] == "checksum_mismatch"

    def test_staged_count(self, tmp_path):
        staging = tmp_path / "staging"
        src = tmp_path / "f.vcf"
        src.write_text("f")
        mgr = TransferManager(staging_dir=staging)
        assert mgr.staged_count == 0
        mgr.stage_file(src)
        assert mgr.staged_count == 1

    def test_transfer_result_empty(self):
        result = TransferResult()
        assert result.success_rate == 0.0


class TestStagingSafeguards:
    def test_mismatch_not_counted_as_transferred(self, tmp_path):
        src = tmp_path / "a.vcf"
        src.write_text("a")
        mgr = TransferManager(staging_dir=tmp_path / "staging")
        result = mgr.stage_batch([src], checksums={str(src): "0" * 64})
        assert result.transferred == 0
        assert result.failed == [str(src)]

    def test_same_name_not_overwritten(self, tmp_path):
        (tmp_path / "x").mkdir()
        (tmp_path / "y").mkdir()
        (tmp_path / "x" / "data.vcf").write_text("one")
        (tmp_path / "y" / "data.vcf").write_text("two")
        mgr = TransferManager(staging_dir=tmp_path / "staging")
        mgr.stage_file(tmp_path / "x" / "data.vcf")
        with pytest.raises(FileExistsError):
            mgr.stage_file(tmp_path / "y" / "data.vcf")

    def test_plaintext_refused_when_encryption_required(self, tmp_path):
        src = tmp_path / "plain.vcf"
        src.write_text("##fileformat=VCFv4.2\n")
        mgr = TransferManager(staging_dir=tmp_path / "staging", require_encrypted=True)
        with pytest.raises(ValueError, match="does not look like an encrypted"):
            mgr.stage_file(src)
        assert not (tmp_path / "staging" / "plain.vcf").exists()

    def test_encrypted_flag_is_detected_not_asserted(self, tmp_path):
        armoured = tmp_path / "data.vcf.asc"
        armoured.write_text("-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----\n")
        plain = tmp_path / "data.vcf"
        plain.write_text("plain")
        mgr = TransferManager(staging_dir=tmp_path / "staging")
        assert mgr.stage_file(armoured).encrypted is True
        assert mgr.stage_file(plain).encrypted is False
        with pytest.raises(ValueError):
            mgr.stage_file(plain, encrypted=True, overwrite=True)
