"""Checksum verification module.

Generates and verifies SHA-256 checksums for data integrity assurance.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ChecksumReport:
    """Checksum verification report."""

    total_files: int = 0
    verified: int = 0
    mismatched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    checksums: dict[str, str] = field(default_factory=dict)

    @property
    def all_passed(self) -> bool:
        return len(self.mismatched) == 0 and len(self.missing) == 0


class ChecksumVerifier:
    """Generate and verify SHA-256 checksums.

    Parameters
    ----------
    algorithm : str
        Hash algorithm name (default: sha256).
    chunk_size : int
        Read chunk size in bytes.
    """

    def __init__(
        self,
        algorithm: str = "sha256",
        chunk_size: int = 8192,
    ) -> None:
        self.algorithm = algorithm
        self.chunk_size = chunk_size

    def compute(self, file_path: str | Path) -> str:
        """Compute checksum of a single file."""
        h = hashlib.new(self.algorithm)
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(self.chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def generate_manifest(self, file_paths: list[str | Path]) -> dict[str, str]:
        """Generate a checksum manifest for multiple files."""
        manifest: dict[str, str] = {}
        for fp in file_paths:
            manifest[str(fp)] = self.compute(fp)
        return manifest

    def write_manifest(
        self,
        manifest: dict[str, str],
        output_path: str | Path,
    ) -> None:
        """Write manifest to a checksum file (SHA256SUMS format)."""
        with open(output_path, "w") as fh:
            for filepath, checksum in sorted(manifest.items()):
                fh.write(f"{checksum}  {filepath}\n")

    def read_manifest(self, manifest_path: str | Path) -> dict[str, str]:
        """Read a checksum manifest file."""
        manifest: dict[str, str] = {}
        with open(manifest_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("  ", 1)
                if len(parts) == 2:
                    manifest[parts[1]] = parts[0]
        return manifest

    def verify(self, manifest: dict[str, str]) -> ChecksumReport:
        """Verify files against a checksum manifest."""
        report = ChecksumReport(total_files=len(manifest))
        for filepath, expected in manifest.items():
            path = Path(filepath)
            if not path.exists():
                report.missing.append(filepath)
                continue
            actual = self.compute(filepath)
            report.checksums[filepath] = actual
            if actual == expected:
                report.verified += 1
            else:
                report.mismatched.append(filepath)
        return report
