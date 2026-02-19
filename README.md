# Secure Genomic Transfer

[![CI](https://github.com/dsugurtuna/secure-genomic-transfer/actions/workflows/ci.yml/badge.svg)](https://github.com/dsugurtuna/secure-genomic-transfer/actions/workflows/ci.yml)

**Encrypted genomic file transfer with checksum verification and audit trail generation.**

Provides GPG encryption wrapper, SHA-256 checksum manifest generation/verification, and staged transfer management with full audit logging — designed for secure provisioning of genomic data between institutional environments.

> **Portfolio project.** Demonstrates generalised secure transfer workflows. No real data or credentials are included.

---

## Architecture

```
src/secure_transfer/
    __init__.py      # Public API exports
    encryptor.py     # GPG encryption/decryption wrapper (GPGEncryptor)
    checksum.py      # SHA-256 manifest generation and verification (ChecksumVerifier)
    transfer.py      # Staged transfer with audit trail (TransferManager)
tests/
    test_encryptor.py  # Encryption command and checksum tests
    test_transfer.py   # Staging and audit trail tests
```

---

## Quick start

```bash
pip install -e ".[dev]"
pytest -v
```

### Python API

```python
from secure_transfer import GPGEncryptor, ChecksumVerifier, TransferManager

# Encrypt files
enc = GPGEncryptor(recipient="collaborator@example.com")
result = enc.encrypt_batch(["cohort_data.vcf", "phenotypes.tsv"])

# Generate checksums
verifier = ChecksumVerifier()
manifest = verifier.generate_manifest(["cohort_data.vcf.gpg"])
verifier.write_manifest(manifest, "SHA256SUMS")

# Verify integrity after transfer
loaded = verifier.read_manifest("SHA256SUMS")
report = verifier.verify(loaded)
assert report.all_passed

# Staged transfer with audit trail
mgr = TransferManager(staging_dir="/tmp/staging")
mgr.stage_file("cohort_data.vcf.gpg", checksum="abc123", encrypted=True)
mgr.export_audit_trail("audit_trail.json")
```

---

## Key features

| Feature | Detail |
| :--- | :--- |
| **GPG encryption** | Batch encrypt/decrypt with recipient key, optional ASCII armour |
| **Checksum manifests** | SHA-256 generation, manifest file I/O, batch verification |
| **Staged transfers** | Copy files to staging directory with metadata tracking |
| **Audit trails** | JSON audit log with timestamps, checksums, and encryption status |
| **Integrity reports** | Detailed mismatch/missing file reporting |

## Development

```bash
make dev        # install with dev dependencies
make test       # run pytest
make lint       # run ruff
make clean      # remove build artefacts
```

## Jira provenance

| Ticket | Description |
| :--- | :--- |
| BIOIN-89 | Secure data provisioning pipeline with GPG encryption |
| BIOIN-405 | AzCopy staging and checksum verification workflows |

---

*Created by [dsugurtuna](https://github.com/dsugurtuna)*
