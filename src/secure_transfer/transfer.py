"""Transfer management module.

Copies files into a staging directory (the hand-off point for whatever
actually moves the data, such as SFTP or a cloud copy tool), checks each copy
against an expected checksum, and keeps an audit trail of what was staged.

The audit trail records values the code computed itself (checksum, size,
whether the file looks encrypted), not values the caller asserted.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .checksum import ChecksumVerifier
from .encryptor import looks_like_openpgp_message


@dataclass
class TransferRecord:
    """Single file record for the audit trail."""

    filename: str
    checksum: str  # SHA-256 of the staged copy, computed here
    encrypted: bool = False  # staged file looks like an OpenPGP message
    timestamp: str = ""
    status: str = "pending"  # staged | checksum_mismatch
    expected_checksum: str = ""  # as supplied by the caller, if any
    size_bytes: int = 0
    source: str = ""


@dataclass
class TransferResult:
    """Outcome of a staging operation."""

    total_files: int = 0
    transferred: int = 0
    failed: list[str] = field(default_factory=list)
    records: list[TransferRecord] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_files == 0:
            return 0.0
        return self.transferred / self.total_files


class TransferManager:
    """Stage files for transfer and keep an audit trail.

    Parameters
    ----------
    staging_dir : str or Path
        Directory for staging files before transfer.
    require_encrypted : bool
        If True, refuse to stage any file that does not look like an
        encrypted OpenPGP message. Use this when the staging area leaves
        your control, so plaintext cannot be staged by mistake.
    """

    def __init__(self, staging_dir: str | Path, require_encrypted: bool = False) -> None:
        self.staging_dir = Path(staging_dir)
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.require_encrypted = require_encrypted
        self._audit_log: list[TransferRecord] = []
        self._verifier = ChecksumVerifier("sha256")

    def stage_file(
        self,
        source_path: str | Path,
        checksum: str = "",
        encrypted: bool = False,
        overwrite: bool = False,
    ) -> TransferRecord:
        """Copy a file into the staging directory and record it.

        Parameters
        ----------
        source_path : path
            File to stage.
        checksum : str
            Expected SHA-256 (hex). If given, the staged copy is checked
            against it and the record's status is ``checksum_mismatch`` when
            they differ.
        encrypted : bool
            Set True to assert the file is encrypted; staging fails if it does
            not look like an OpenPGP message.
        overwrite : bool
            Allow replacing a staged file with the same name.

        Raises
        ------
        FileNotFoundError
            If the source does not exist.
        FileExistsError
            If a file with the same name is already staged and ``overwrite``
            is False.
        ValueError
            If the file must be encrypted (by argument or ``require_encrypted``)
            and does not look encrypted.
        """
        src = Path(source_path)
        if not src.is_file():
            raise FileNotFoundError(f"Source file not found: {source_path}")

        looks_encrypted = looks_like_openpgp_message(src)
        if (encrypted or self.require_encrypted) and not looks_encrypted:
            raise ValueError(f"{src.name} does not look like an encrypted OpenPGP message")

        dest = self.staging_dir / src.name
        if dest.exists() and not overwrite:
            raise FileExistsError(f"Already staged: {dest.name}")
        shutil.copyfile(src, dest)  # streams; does not load the file into memory

        actual = self._verifier.compute(dest)
        expected = checksum.strip().lower()
        record = TransferRecord(
            filename=src.name,
            checksum=actual,
            encrypted=looks_encrypted,
            timestamp=datetime.now(UTC).isoformat(),
            status="checksum_mismatch" if expected and expected != actual else "staged",
            expected_checksum=expected,
            size_bytes=dest.stat().st_size,
            source=str(src),
        )
        self._audit_log.append(record)
        return record

    def stage_batch(
        self,
        file_paths: list[str | Path],
        checksums: dict[str, str] | None = None,
    ) -> TransferResult:
        """Stage multiple files. A file counts as transferred only if it was
        staged and matched its expected checksum (when one was given)."""
        checksums = checksums or {}
        result = TransferResult(total_files=len(file_paths))

        for fp in file_paths:
            try:
                record = self.stage_file(fp, checksum=checksums.get(str(fp), ""))
            except (FileNotFoundError, FileExistsError, PermissionError, ValueError):
                result.failed.append(str(fp))
                continue
            result.records.append(record)
            if record.status == "staged":
                result.transferred += 1
            else:
                result.failed.append(str(fp))

        return result

    def export_audit_trail(self, output_path: str | Path) -> None:
        """Export the audit trail to JSON."""
        entries = [asdict(rec) for rec in self._audit_log]
        with open(output_path, "w") as fh:
            json.dump({"audit_trail": entries}, fh, indent=2)

    @property
    def staged_count(self) -> int:
        return len(self._audit_log)
