"""Transfer management module.

Orchestrates staged file transfers with encryption, checksumming,
and audit trail generation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class TransferRecord:
    """Single file transfer record for audit trail."""

    filename: str
    checksum: str
    encrypted: bool = False
    timestamp: str = ""
    status: str = "pending"


@dataclass
class TransferResult:
    """Outcome of a transfer operation."""

    total_files: int = 0
    transferred: int = 0
    failed: List[str] = field(default_factory=list)
    records: List[TransferRecord] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_files == 0:
            return 0.0
        return self.transferred / self.total_files


class TransferManager:
    """Manage staged genomic data transfers.

    Produces audit trails recording each file's checksum, encryption
    status, and transfer timestamp.

    Parameters
    ----------
    staging_dir : str or Path
        Directory for staging files before transfer.
    """

    def __init__(self, staging_dir: str | Path) -> None:
        self.staging_dir = Path(staging_dir)
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self._audit_log: List[TransferRecord] = []

    def stage_file(
        self,
        source_path: str | Path,
        checksum: str = "",
        encrypted: bool = False,
    ) -> TransferRecord:
        """Stage a file for transfer.

        Copies the file to the staging directory and creates
        an audit record.
        """
        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {source_path}")

        dest = self.staging_dir / src.name
        dest.write_bytes(src.read_bytes())

        record = TransferRecord(
            filename=src.name,
            checksum=checksum,
            encrypted=encrypted,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status="staged",
        )
        self._audit_log.append(record)
        return record

    def stage_batch(
        self,
        file_paths: List[str | Path],
        checksums: Dict[str, str] | None = None,
    ) -> TransferResult:
        """Stage multiple files."""
        checksums = checksums or {}
        result = TransferResult(total_files=len(file_paths))

        for fp in file_paths:
            try:
                cksum = checksums.get(str(fp), "")
                record = self.stage_file(fp, checksum=cksum)
                result.transferred += 1
                result.records.append(record)
            except (FileNotFoundError, PermissionError):
                result.failed.append(str(fp))

        return result

    def export_audit_trail(self, output_path: str | Path) -> None:
        """Export the audit trail to JSON."""
        entries = []
        for rec in self._audit_log:
            entries.append({
                "filename": rec.filename,
                "checksum": rec.checksum,
                "encrypted": rec.encrypted,
                "timestamp": rec.timestamp,
                "status": rec.status,
            })
        with open(output_path, "w") as fh:
            json.dump({"audit_trail": entries}, fh, indent=2)

    @property
    def staged_count(self) -> int:
        return len(self._audit_log)
