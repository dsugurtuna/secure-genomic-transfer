"""Offline demo: encrypt, checksum, stage and audit a synthetic file.

Needs GnuPG (`gpg`) on PATH. A throwaway keyring and key for a synthetic
recipient (recipient@example.invalid) are created in a temporary directory
and deleted at the end. The data file is made up.

Run from the repository root:  python examples/demo.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from secure_transfer import ChecksumVerifier, GPGEncryptor, TransferManager


def make_throwaway_key(home: str) -> str:
    subprocess.run(
        # Throwaway key with an empty passphrase, for the demo only.
        ["gpg", "--batch", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-gen-key", "Synthetic Recipient <recipient@example.invalid>",
         "default", "default", "never"],
        check=True, capture_output=True,
    )  # fmt: skip
    listing = subprocess.run(
        ["gpg", "--batch", "--homedir", home, "--list-keys", "--with-colons"],
        check=True, capture_output=True, text=True,
    ).stdout  # fmt: skip
    return next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))


def main() -> None:
    if shutil.which("gpg") is None:
        raise SystemExit("This demo needs GnuPG (gpg) on PATH.")
    home = tempfile.mkdtemp(prefix="sgt-demo-")  # short path for gpg-agent's socket
    work = Path(tempfile.mkdtemp(prefix="sgt-work-"))
    try:
        fingerprint = make_throwaway_key(home)
        data = work / "outgoing"
        data.mkdir()
        plain = data / "synthetic_cohort.vcf"
        plain.write_text("##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\n1\t100\trs1\tA\tG\n")

        # 1. Encrypt to the recipient's fingerprint.
        encrypted = GPGEncryptor(recipient=fingerprint, gnupg_home=home).encrypt_file(str(plain))
        print(f"Encrypted: {Path(encrypted).name}")

        # 2. Checksum manifest with paths relative to the outgoing folder.
        verifier = ChecksumVerifier()
        manifest = verifier.generate_manifest([encrypted], base_dir=data)
        verifier.write_manifest(manifest, data / "SHA256SUMS")
        print(f"Manifest entries: {sorted(manifest)}")

        # 3. Stage for transfer; only encrypted files are allowed.
        staging = TransferManager(work / "staging", require_encrypted=True)
        record = staging.stage_file(encrypted, checksum=manifest[Path(encrypted).name])
        print(f"Staged {record.filename}: status={record.status}, encrypted={record.encrypted}")
        try:
            staging.stage_file(plain)
        except ValueError as exc:
            print(f"Refused: {exc}")

        # 4. The recipient checks the staged copy against the manifest.
        report = verifier.verify(verifier.read_manifest(data / "SHA256SUMS"), base_dir=work / "staging")
        print(f"Recipient check: {report.verified}/{report.total_files} verified")

        staging.export_audit_trail(work / "audit.json")
        entry = json.loads((work / "audit.json").read_text())["audit_trail"][0]
        print(f"Audit fields: {sorted(entry)}")
    finally:
        subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"], capture_output=True)
        shutil.rmtree(home, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
