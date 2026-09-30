"""Round-trip tests against the real GnuPG binary, in throwaway keyrings.

Skipped when gpg is not installed. Keys are generated per test run for a
synthetic identity at example.invalid and deleted afterwards.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from secure_transfer.encryptor import GPGEncryptor, looks_like_openpgp_message

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")


def _gpg(home: str, *args: str, stdin: str | None = None) -> str:
    proc = subprocess.run(
        ["gpg", "--batch", "--homedir", home, *args],
        capture_output=True,
        text=True,
        input=stdin,
        check=True,
    )
    return proc.stdout


def _new_home() -> str:
    # Short path: gpg-agent's socket path has a length limit.
    return tempfile.mkdtemp(prefix="sgt-")


def _cleanup(home: str) -> None:
    subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"], capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


def _make_key(home: str, passphrase: str) -> str:
    _gpg(
        home,
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        passphrase,  # test-only key; the library itself never passes secrets in argv
        "--quick-gen-key",
        "Synthetic Recipient <recipient@example.invalid>",
        "default",
        "default",
        "never",
    )
    for line in _gpg(home, "--list-keys", "--with-colons").splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise AssertionError("no fingerprint")


@pytest.fixture()
def recipient() -> Iterator[tuple[str, str]]:
    home = _new_home()
    try:
        yield home, _make_key(home, "correct horse")
    finally:
        _cleanup(home)


def test_round_trip_with_passphrase_on_stdin(recipient, tmp_path: Path) -> None:
    home, fpr = recipient
    plain = tmp_path / "cohort.vcf"
    plain.write_text("##fileformat=VCFv4.2\n")
    enc = GPGEncryptor(recipient=fpr, gnupg_home=home)
    out = enc.encrypt_file(str(plain))
    assert looks_like_openpgp_message(out)
    assert not looks_like_openpgp_message(plain)

    # Wrong passphrase first: gpg-agent would otherwise cache the right one.
    with pytest.raises(subprocess.CalledProcessError):
        GPGEncryptor.decrypt_file(out, str(tmp_path / "x"), passphrase="wrong", gnupg_home=home)
    back = tmp_path / "back.vcf"
    GPGEncryptor.decrypt_file(out, str(back), passphrase="correct horse", gnupg_home=home)
    assert back.read_text() == plain.read_text()


def test_armoured_output_detected(recipient, tmp_path: Path) -> None:
    home, fpr = recipient
    plain = tmp_path / "p.txt"
    plain.write_text("x")
    out = GPGEncryptor(recipient=fpr, gnupg_home=home, armour=True).encrypt_file(str(plain))
    assert out.endswith(".asc")
    assert looks_like_openpgp_message(out)


def test_unvalidated_key_refused_unless_trust_model_overridden(recipient, tmp_path: Path) -> None:
    home, fpr = recipient
    public_key = _gpg(home, "--armor", "--export", fpr)
    sender = _new_home()
    try:
        _gpg(sender, "--import", stdin=public_key)
        plain = tmp_path / "p.txt"
        plain.write_text("x")
        with pytest.raises(subprocess.CalledProcessError) as err:
            GPGEncryptor(recipient=fpr, gnupg_home=sender).encrypt_file(str(plain))
        assert "no assurance" in (err.value.stderr or "").lower()

        out = GPGEncryptor(recipient=fpr, gnupg_home=sender, trust_model="always").encrypt_file(str(plain))
        assert looks_like_openpgp_message(out)
    finally:
        _cleanup(sender)
