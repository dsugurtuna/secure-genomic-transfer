"""Tests for GPGEncryptor and ChecksumVerifier."""

from secure_transfer.checksum import ChecksumVerifier
from secure_transfer.encryptor import EncryptionResult, GPGEncryptor


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


class TestSaferDefaults:
    def test_no_trust_model_override_by_default(self):
        cmd = GPGEncryptor(recipient="ABCDEF")._build_encrypt_cmd("in", "out")
        assert "--trust-model" not in cmd

    def test_trust_model_is_explicit_opt_in(self):
        cmd = GPGEncryptor(recipient="ABCDEF", trust_model="always")._build_encrypt_cmd("in", "out")
        assert cmd[cmd.index("--trust-model") + 1] == "always"

    def test_homedir_passed(self):
        cmd = GPGEncryptor(recipient="ABCDEF", gnupg_home="/tmp/k")._build_encrypt_cmd("i", "o")
        assert cmd[cmd.index("--homedir") + 1] == "/tmp/k"

    def test_passphrase_not_on_command_line(self, monkeypatch):
        import subprocess

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake_run)
        GPGEncryptor.decrypt_file("in.gpg", "out", passphrase="s3cret")
        cmd, kwargs = calls[0]
        assert "s3cret" not in " ".join(cmd)
        assert kwargs["input"] == "s3cret\n"
        assert "--passphrase-fd" in cmd

    def test_batch_records_gpg_error(self, tmp_path):
        import shutil

        if shutil.which("gpg") is None:
            import pytest

            pytest.skip("gpg not installed")
        f = tmp_path / "a.vcf"
        f.write_text("x")
        home = tmp_path / "gnupg"
        home.mkdir(mode=0o700)
        enc = GPGEncryptor(recipient="0" * 40, gnupg_home=str(home))
        result = enc.encrypt_batch([str(f)])
        assert result.failed_files == [str(f)]
        assert result.errors[str(f)]


class TestManifestPortability:
    def test_relative_paths_with_base_dir(self, tmp_path):
        (tmp_path / "sub").mkdir()
        f = tmp_path / "sub" / "a.vcf.gpg"
        f.write_bytes(b"abc")
        v = ChecksumVerifier()
        manifest = v.generate_manifest([f], base_dir=tmp_path)
        assert list(manifest) == ["sub/a.vcf.gpg"]
        assert v.verify(manifest, base_dir=tmp_path).all_passed

    def test_reads_binary_mode_and_uppercase(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"abc")
        v = ChecksumVerifier()
        digest = v.compute(f).upper()
        sums = tmp_path / "SHA256SUMS"
        sums.write_text(f"{digest} *a.bin\n")
        assert v.verify(v.read_manifest(sums), base_dir=tmp_path).all_passed

    def test_manifest_accepted_by_sha256sum(self, tmp_path):
        import shutil
        import subprocess

        import pytest

        if shutil.which("sha256sum") is None:
            pytest.skip("sha256sum not installed")
        f = tmp_path / "file with space.vcf"
        f.write_text("data")
        v = ChecksumVerifier()
        v.write_manifest(v.generate_manifest([f], base_dir=tmp_path), tmp_path / "SHA256SUMS")
        proc = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=tmp_path, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_unknown_algorithm_rejected(self):
        import pytest

        with pytest.raises(ValueError):
            ChecksumVerifier("sha257")
