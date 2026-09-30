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
        chunk_size: int = 1024 * 1024,
    ) -> None:
        if algorithm not in hashlib.algorithms_guaranteed:
            raise ValueError(f"Unsupported hash algorithm: {algorithm!r}")
        self.algorithm = algorithm
        self.chunk_size = chunk_size

    def compute(self, file_path: str | Path) -> str:
        """Compute the checksum of a single file, reading it in chunks."""
        h = hashlib.new(self.algorithm)
        with open(file_path, "rb") as fh:
            while chunk := fh.read(self.chunk_size):
                h.update(chunk)
        return h.hexdigest()

    def generate_manifest(
        self,
        file_paths: list[str | Path],
        base_dir: str | Path | None = None,
    ) -> dict[str, str]:
        """Generate a checksum manifest for multiple files.

        With ``base_dir``, paths are stored relative to it, so the manifest
        can be checked on the receiving side (``sha256sum -c`` run from the
        same directory) rather than only on the machine that wrote it.
        """
        manifest: dict[str, str] = {}
        base = Path(base_dir).resolve() if base_dir is not None else None
        for fp in file_paths:
            key = str(Path(fp).resolve().relative_to(base)) if base else str(fp)
            if "\n" in key:
                raise ValueError(f"File names with newlines are not supported: {key!r}")
            manifest[key] = self.compute(fp)
        return manifest

    def write_manifest(
        self,
        manifest: dict[str, str],
        output_path: str | Path,
    ) -> None:
        """Write the manifest in GNU coreutils format (``<hash>  <path>``).

        The file can be checked with ``sha256sum -c`` (or the matching tool
        for the chosen algorithm).
        """
        with open(output_path, "w") as fh:
            for filepath, checksum in sorted(manifest.items()):
                fh.write(f"{checksum}  {filepath}\n")

    def read_manifest(self, manifest_path: str | Path) -> dict[str, str]:
        """Read a manifest in text (``hash  path``) or binary (``hash *path``) mode."""
        manifest: dict[str, str] = {}
        with open(manifest_path) as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                digest, sep, rest = line.partition(" ")
                if not sep or not rest:
                    continue
                path = rest[1:] if rest[:1] in (" ", "*") else rest
                manifest[path] = digest.lower()
        return manifest

    def verify(
        self,
        manifest: dict[str, str],
        base_dir: str | Path | None = None,
    ) -> ChecksumReport:
        """Verify files against a checksum manifest.

        Relative paths are resolved against ``base_dir`` when given.
        """
        report = ChecksumReport(total_files=len(manifest))
        base = Path(base_dir) if base_dir is not None else None
        for filepath, expected in manifest.items():
            path = base / filepath if base is not None else Path(filepath)
            if not path.exists():
                report.missing.append(filepath)
                continue
            actual = self.compute(path)
            report.checksums[filepath] = actual
            if actual == expected.lower():
                report.verified += 1
            else:
                report.mismatched.append(filepath)
        return report
