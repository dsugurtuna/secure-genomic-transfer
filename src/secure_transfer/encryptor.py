"""GPG encryption module.

Wraps the GnuPG command line for batch encryption and decryption of files.

Security notes
--------------
* Name recipients by full fingerprint. A user ID or e-mail can match more
  than one key in a keyring.
* By default GnuPG's own trust model applies, so it refuses to encrypt to a
  key that has not been validated (signed or marked trusted) in the keyring.
  ``trust_model="always"`` skips that check; use it only when the key's
  fingerprint has been verified out of band.
* Passphrases are passed on stdin (``--passphrase-fd 0``), never on the
  command line, where other users could read them from the process list.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# First byte of a binary OpenPGP message that starts with an encrypted
# session key packet (public-key tag 1 or symmetric tag 3), in the old or
# new packet format (RFC 4880 section 4.2; RFC 9580 section 4.2).
_ENCRYPTED_FIRST_BYTES = frozenset({0x84, 0x85, 0x86, 0x87, 0x8C, 0x8D, 0x8E, 0x8F, 0xC1, 0xC3})
_ARMOUR_HEADER = b"-----BEGIN PGP MESSAGE-----"


def looks_like_openpgp_message(path: str | Path) -> bool:
    """Heuristic: does the file start like an encrypted OpenPGP message?

    Checks for an ASCII-armoured message header or a binary packet header
    for an encrypted session key. It does not prove the file decrypts, only
    that it is not obviously plaintext.
    """
    with open(path, "rb") as fh:
        head = fh.read(len(_ARMOUR_HEADER))
    if not head:
        return False
    return head.startswith(_ARMOUR_HEADER) or head[0] in _ENCRYPTED_FIRST_BYTES


@dataclass
class EncryptionResult:
    """Outcome of a batch encryption operation."""

    encrypted_files: list[str] = field(default_factory=list)
    failed_files: list[str] = field(default_factory=list)
    total_input: int = 0
    errors: dict[str, str] = field(default_factory=dict)  # input path -> gpg message

    @property
    def success_rate(self) -> float:
        if self.total_input == 0:
            return 0.0
        return len(self.encrypted_files) / self.total_input


class GPGEncryptor:
    """Encrypt and decrypt files using GPG.

    Parameters
    ----------
    recipient : str
        Recipient key, ideally the full 40-hex-character fingerprint.
    gpg_binary : str
        Path to the GPG binary.
    armour : bool
        Whether to produce ASCII-armoured output.
    trust_model : str, optional
        Passed as ``--trust-model`` if set (e.g. ``"always"``). Default: use
        the keyring's trust settings.
    gnupg_home : str, optional
        Passed as ``--homedir``, to use a dedicated keyring.
    """

    def __init__(
        self,
        recipient: str,
        gpg_binary: str = "gpg",
        armour: bool = False,
        trust_model: str | None = None,
        gnupg_home: str | None = None,
    ) -> None:
        self.recipient = recipient
        self.gpg_binary = gpg_binary
        self.armour = armour
        self.trust_model = trust_model
        self.gnupg_home = gnupg_home

    def _base_cmd(self) -> list[str]:
        cmd = [self.gpg_binary, "--batch", "--yes"]
        if self.gnupg_home:
            cmd += ["--homedir", self.gnupg_home]
        return cmd

    def _build_encrypt_cmd(self, input_path: str, output_path: str) -> list[str]:
        cmd = self._base_cmd()
        if self.trust_model:
            cmd += ["--trust-model", self.trust_model]
        cmd += ["--recipient", self.recipient, "--output", output_path]
        if self.armour:
            cmd.append("--armor")
        cmd += ["--encrypt", input_path]
        return cmd

    def encrypt_file(self, input_path: str, output_path: str | None = None) -> str:
        """Encrypt a single file. Returns the output path.

        Raises ``subprocess.CalledProcessError`` if gpg fails, for example
        because the recipient key is unknown or not validated.
        """
        suffix = ".asc" if self.armour else ".gpg"
        out = output_path or f"{input_path}{suffix}"
        cmd = self._build_encrypt_cmd(input_path, out)
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return out

    def encrypt_batch(self, file_paths: list[str]) -> EncryptionResult:
        """Encrypt multiple files; failures are collected, not raised."""
        result = EncryptionResult(total_input=len(file_paths))
        for fp in file_paths:
            try:
                out = self.encrypt_file(fp)
                result.encrypted_files.append(out)
            except subprocess.CalledProcessError as exc:
                result.failed_files.append(fp)
                result.errors[fp] = (exc.stderr or "").strip()
            except FileNotFoundError as exc:
                result.failed_files.append(fp)
                result.errors[fp] = str(exc)
        return result

    @staticmethod
    def decrypt_file(
        input_path: str,
        output_path: str,
        gpg_binary: str = "gpg",
        passphrase: str | None = None,
        gnupg_home: str | None = None,
    ) -> str:
        """Decrypt a single GPG-encrypted file.

        If a passphrase is given it is sent on stdin with loopback pinentry,
        so it never appears in the process list.
        """
        cmd = [gpg_binary, "--batch", "--yes"]
        if gnupg_home:
            cmd += ["--homedir", gnupg_home]
        cmd += ["--output", output_path]
        stdin = None
        if passphrase is not None:
            cmd += ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
            stdin = passphrase + "\n"
        cmd += ["--decrypt", input_path]
        subprocess.run(cmd, check=True, capture_output=True, text=True, input=stdin)
        return output_path
