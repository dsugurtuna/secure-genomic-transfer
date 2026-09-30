# Why it's built this way

## The problem

Sending genomic data to a collaborator means encrypting it to the right key, proving it arrived
intact, and being able to show later what was sent. Most failures here are silent: the wrong key,
a leaked passphrase, a plaintext file in the outgoing folder, or a log that records claims instead
of facts.

## Design choices

**Why not force `--trust-model always`?** Because it tells gpg to encrypt to any key matching the
recipient string, validated or not. If someone slips a look-alike key into the keyring, data goes
to them. GnuPG's default refuses unvalidated keys; overriding that is now an explicit choice.

**Why pass the passphrase on stdin?** Because anything on a command line can be read by other
users of the machine through the process list. Stdin with `--passphrase-fd 0` avoids that.

**Why compute checksums in the audit trail instead of accepting them?** Because an audit trail
that records whatever it is told is not evidence. The trail now stores the checksum of the staged
copy and marks a mismatch with the caller's expected value.

**Why refuse plaintext at staging?** Because staging is the last point the sender controls. A
header check that rejects non-OpenPGP files turns "we always encrypt first" from a habit into a
control.

**Why relative paths and coreutils format for the manifest?** Because the recipient should be able
to verify with `sha256sum -c` and nothing else. Absolute paths from the sender's machine do not
exist on theirs.

**Why test against real GnuPG?** Because mocking `subprocess` proves the command line was built,
not that encryption works or that an unvalidated key is refused. The integration tests use
throwaway keyrings and are skipped only when gpg is missing.

## Questions worth asking

**"The file starts like an OpenPGP message. Is it encrypted to the right person?"**
Not necessarily. The header check separates ciphertext from plaintext; it cannot tell which key
was used. `gpg --list-packets` shows the recipient key IDs without decrypting, and checking those
against the intended fingerprint is on the roadmap.

**"How does the recipient know the manifest itself was not altered?"**
They cannot yet. Integrity of the files depends on integrity of `SHA256SUMS`. Signing the manifest
with the sender's key, and verifying that signature on receipt, closes the gap and is the first
roadmap item.

**"Is the audit trail good enough for an investigation?"**
It records the right facts, but it is a JSON export: no actor identity, no tamper evidence, and
nothing stops someone editing it afterwards. For that you need an append-only, hash-chained log,
the kind of control developed in
[agent-guardrails](https://github.com/dsugurtuna/agent-guardrails).

## What's next

- Sign and verify `SHA256SUMS`.
- Check encrypted files' recipient key IDs against the intended fingerprint.
- Hash-chained audit log with actor identity.
