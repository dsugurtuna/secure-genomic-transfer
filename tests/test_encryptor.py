"""Tests for GPGEncryptor and ChecksumVerifier."""

from secure_transfer.encryptor import GPGEncryptor, EncryptionResult
from secure_transfer.checksum import ChecksumVerifier


class TestGPGEncryptor:
    def test_build_encrypt_cmd(self):
        enc = GPGEncryptor(recipient="test@example.com")
        cmd = enc._build_encrypt_cmd("input.vcf", "output.vcf.gpg")
        assert "--recipient" in cmd
        assert "test@example.com" in cmd
        assert "--encrypt" in cmd
        assert "input.vcf" in cmd

    def test_armour_flag(self):
        enc = GPGEncryptor(recipient="test@example.com", armour=True)
        cmd = enc._build_encrypt_cmd("input.vcf", "output.vcf.gpg")
        assert "--armor" in cmd

    def test_no_armour_flag(self):
        enc = GPGEncryptor(recipient="test@example.com", armour=False)
        cmd = enc._build_encrypt_cmd("input.vcf", "output.vcf.gpg")
        assert "--armor" not in cmd

    def test_encryption_result_success_rate(self):
        result = EncryptionResult(
            encrypted_files=["a.gpg", "b.gpg"],
            failed_files=["c"],
            total_input=3,
        )
        assert abs(result.success_rate - 2 / 3) < 0.01

    def test_encryption_result_empty(self):
        result = EncryptionResult()
        assert result.success_rate == 0.0

    def test_batch_with_missing_files(self):
        enc = GPGEncryptor(recipient="test@example.com")
        result = enc.encrypt_batch(["/nonexistent/file.vcf"])
        assert len(result.failed_files) == 1
        assert result.success_rate == 0.0


class TestChecksumVerifier:
    def test_compute(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("hello world")
        verifier = ChecksumVerifier()
        digest = verifier.compute(f)
        assert len(digest) == 64  # SHA-256 hex length

    def test_manifest_roundtrip(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f1.write_text("alpha")
        f2 = tmp_path / "b.txt"
        f2.write_text("bravo")
        verifier = ChecksumVerifier()
        manifest = verifier.generate_manifest([str(f1), str(f2)])
        assert len(manifest) == 2

        manifest_file = tmp_path / "SHA256SUMS"
        verifier.write_manifest(manifest, manifest_file)
        loaded = verifier.read_manifest(manifest_file)
        assert loaded == manifest

    def test_verify_all_pass(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x00\x01\x02")
        verifier = ChecksumVerifier()
        manifest = verifier.generate_manifest([str(f)])
        report = verifier.verify(manifest)
        assert report.all_passed
        assert report.verified == 1

    def test_verify_mismatch(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x00\x01\x02")
        verifier = ChecksumVerifier()
        manifest = {str(f): "0000000000000000000000000000000000000000000000000000000000000000"}
        report = verifier.verify(manifest)
        assert not report.all_passed
        assert len(report.mismatched) == 1

    def test_verify_missing(self):
        verifier = ChecksumVerifier()
        manifest = {"/nonexistent/file.bin": "abcd"}
        report = verifier.verify(manifest)
        assert not report.all_passed
        assert len(report.missing) == 1
