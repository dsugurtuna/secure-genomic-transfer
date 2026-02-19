"""GPG encryption module.

Wraps GPG command-line operations for batch encryption and decryption
of genomic data files.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class EncryptionResult:
    """Outcome of a batch encryption operation."""

    encrypted_files: List[str] = field(default_factory=list)
    failed_files: List[str] = field(default_factory=list)
    total_input: int = 0

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
        GPG recipient key identifier (email or fingerprint).
    gpg_binary : str
        Path to the GPG binary.
    armour : bool
        Whether to produce ASCII-armoured output.
    """

    def __init__(
        self,
        recipient: str,
        gpg_binary: str = "gpg",
        armour: bool = False,
    ) -> None:
        self.recipient = recipient
        self.gpg_binary = gpg_binary
        self.armour = armour

    def _build_encrypt_cmd(self, input_path: str, output_path: str) -> List[str]:
        cmd = [
            self.gpg_binary,
            "--batch",
            "--yes",
            "--trust-model", "always",
            "--recipient", self.recipient,
            "--output", output_path,
        ]
        if self.armour:
            cmd.append("--armor")
        cmd += ["--encrypt", input_path]
        return cmd

    def encrypt_file(self, input_path: str, output_path: str | None = None) -> str:
        """Encrypt a single file. Returns the output path."""
        out = output_path or f"{input_path}.gpg"
        cmd = self._build_encrypt_cmd(input_path, out)
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return out

    def encrypt_batch(self, file_paths: List[str]) -> EncryptionResult:
        """Encrypt multiple files."""
        result = EncryptionResult(total_input=len(file_paths))
        for fp in file_paths:
            try:
                out = self.encrypt_file(fp)
                result.encrypted_files.append(out)
            except (subprocess.CalledProcessError, FileNotFoundError):
                result.failed_files.append(fp)
        return result

    @staticmethod
    def decrypt_file(
        input_path: str,
        output_path: str,
        gpg_binary: str = "gpg",
        passphrase: str | None = None,
    ) -> str:
        """Decrypt a single GPG-encrypted file."""
        cmd = [gpg_binary, "--batch", "--yes", "--output", output_path]
        if passphrase:
            cmd += ["--passphrase", passphrase, "--pinentry-mode", "loopback"]
        cmd += ["--decrypt", input_path]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return output_path
