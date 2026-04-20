# LatticePGP

> [!WARNING]
> **Use with caution.**
> This project was heavily **vibe-coded / AI-assisted** and is **not independently verified as secure**.
> It has **not** been audited or professionally reviewed.
> Do **not** rely on it for high-stakes, production, regulated, or life-critical use without an independent security review.

Small command-line tool for **post-quantum public-key encryption and signing**.

It aims to be:
- **simple**
- **small**
- **practical**
- **nice to use**
- and based on **modern PQ primitives** instead of handwritten lattice crypto

---

## Status

![Status](https://img.shields.io/badge/status-experimental-orange)
![Security](https://img.shields.io/badge/security-not_audited-red)
![Go](https://img.shields.io/badge/Go-1.26%2B-blue)
![Crypto](https://img.shields.io/badge/crypto-post--quantum-purple)

## What it does

- Generate a post-quantum keypair
- Encrypt files or stdin to a recipient public key
- Decrypt ciphertext with the secret key
- Create detached signatures
- Verify detached signatures
- Write ASCII-armored outputs in a PGP-like style
- Keep the CLI small and easy to remember

## Security note

This project tries to avoid the most dangerous mistake from the earlier version: **custom handwritten cryptography**.

The current design uses modern building blocks instead:

- **ML-KEM-768** for post-quantum key encapsulation
- **AES-256-GCM** for authenticated symmetric encryption
- **ML-DSA-65** for post-quantum signatures

That is much better than a homebrew lattice design.

But that still does **not** mean the tool as a whole is trustworthy enough for serious production use.

The overall implementation, file format, parsing logic, error handling, key handling, UX choices, and integration behavior are still **not independently audited**.

## Quick start

### Build

Inside the project directory:

```bash
go mod init lpgp
go get github.com/cloudflare/circl@v1.6.3
go mod tidy
go build -o lpgp .
```

If `go.mod` already exists:

```bash
go mod tidy
go build -o lpgp .
```

### Generate keys

```bash
./lpgp keygen -name alice
```

This creates:

- `alice.lpub`
- `alice.lsec`

### Encrypt

```bash
./lpgp encrypt -pubkey alice.lpub -in message.txt -out message.enc
```

### Decrypt

```bash
./lpgp decrypt -seckey alice.lsec -in message.enc -out message.dec.txt
```

### Sign

```bash
./lpgp sign -seckey alice.lsec -in message.txt -out message.sig
```

### Verify

```bash
./lpgp verify -pubkey alice.lpub -sig message.sig -in message.txt
```

Expected output:

```text
GOOD SIGNATURE
```

---

## Installation requirements

- **Go 1.26+** recommended
- Go modules enabled
- Internet access during initial dependency resolution
- External dependency for signatures:
  - `github.com/cloudflare/circl`

## CLI usage

```text
lpgp keygen  [-name BASENAME]
lpgp encrypt -pubkey FILE [-in FILE] [-out FILE]
lpgp decrypt -seckey FILE [-in FILE] [-out FILE]
lpgp sign    -seckey FILE [-in FILE] [-out FILE]
lpgp verify  -pubkey FILE -sig FILE [-in FILE]
```

If `-in` or `-out` is omitted, the tool uses `stdin` / `stdout`.

## Example session

```bash
./lpgp keygen -name test
echo "hello world" > msg.txt

./lpgp sign -seckey test.lsec -in msg.txt -out msg.sig
./lpgp verify -pubkey test.lpub -sig msg.sig -in msg.txt

./lpgp encrypt -pubkey test.lpub -in msg.txt -out msg.enc
./lpgp decrypt -seckey test.lsec -in msg.enc -out msg.out

cat msg.out
```

## File types

Generated key files:

- `NAME.lpub` — armored public key
- `NAME.lsec` — armored secret key

Other outputs:

- encrypted message block
- signature block

These are **custom application formats**.  
They are **not OpenPGP-compatible** and are **not meant to interoperate with GPG**.

## Project layout

Typical files:

- `main.go` — main application source
- `go.mod` — Go module file
- `go.sum` — dependency checksums
- `README.md` — this file

## What this may help against

- future quantum attacks against classical public-key schemes
- passive interception of encrypted stored data
- basic tampering detection for signed files

## What this does not solve

- endpoint compromise
- malware on sender or receiver systems
- poor secret-key handling
- operational mistakes
- accidental plaintext leaks
- supply-chain compromise
- the absence of professional review

## Things you should **not** assume

Do not assume any of the following:

- “post-quantum” means “safe”
- “standard algorithms” means the application is secure
- “it compiles” means it is robust
- “it works for my test file” means it is production-ready
- “AI-assisted” means it was carefully checked

## Recommended caution before serious use

Before using this for anything important, you should:

1. manually review the code
2. test encrypt/decrypt and sign/verify thoroughly
3. fuzz malformed armor and malformed binary inputs
4. test corrupted files and truncated records
5. get an independent security review
6. minimize secret-key exposure
7. avoid making this your only security layer

## Current limitations

- not independently audited
- custom file/container format
- no OpenPGP interoperability
- no trust web / identity framework
- no encrypted secret-key passphrase storage unless you add it
- signature support depends on an external module
- not intended as a mature replacement for established secure tooling

## Good future improvements

- passphrase-encrypted secret key storage
- embedded sign+encrypt workflow
- better malformed-input diagnostics
- tests and fuzzing
- reproducible builds
- machine-readable fingerprints
- compatibility/versioning tests
- secret-key import/export hardening

## Trust statement

Treat this project as an **experimental utility**.

It may be neat, useful, and much better than the earlier handwritten crypto design, but it is still **not independently verified secure**.

If the data really matters, prefer mature and professionally reviewed tools.

---

## License / usage note

Use at your own risk.

**Plain English:** this tool may be cool and useful, but you should **not blindly trust it**.
