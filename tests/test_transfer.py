"""Tests for TransferManager."""

import json

from secure_transfer.transfer import TransferManager, TransferResult


class TestTransferManager:
    def test_stage_file(self, tmp_path):
        staging = tmp_path / "staging"
        src = tmp_path / "data.vcf"
        src.write_text("##fileformat=VCFv4.2\n")
        mgr = TransferManager(staging_dir=staging)
        record = mgr.stage_file(src, checksum="abc123")
        assert record.status == "staged"
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
        assert data["audit_trail"][0]["checksum"] == "xyz"

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
