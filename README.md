# debsign-rs

Sign Debian packages with GPG, written in Rust.

## Features

- Sign `.deb` files with detached GPG signatures
- Verify existing signatures on `.deb` files
- Support for ASCII-armored key files
- Generates MD5, SHA1, and SHA256 checksums
- Pure Rust GPG implementation via sequoia-openpgp

## Installation

### From source

```bash
cargo install --path .
```

### From .deb package

```bash
sudo dpkg -i debsign-rs_0.1.0_arm64.deb
```

## Usage

### Sign a package

```bash
# Sign with an exported key file
debsign --key-file key.asc package.deb

# Sign with passphrase
debsign --key-file key.asc --passphrase "secret" package.deb

# Write to a different output file
debsign --key-file key.asc --output signed.deb package.deb

# Verbose output
debsign -V --key-file key.asc package.deb
```

### Verify a signature

```bash
debsign --verify package.deb
```

### Export your GPG key

```bash
gpg --export-secret-keys --armor YOUR_KEY_ID > key.asc
```

## Command Line Options

```
Usage: debsign [OPTIONS] <DEB_FILE>

Arguments:
  <DEB_FILE>  Path to the .deb file to sign

Options:
  -k, --key <KEY>                GPG key ID or fingerprint to use for signing
  -f, --key-file <KEY_FILE>      Path to secret key file (ASCII armored)
  -p, --passphrase <PASSPHRASE>  Passphrase for the secret key
  -o, --output <OUTPUT>          Output file (default: overwrites input)
  -v, --verify                   Verify signature instead of signing
  -V, --verbose                  Show verbose output
  -h, --help                     Print help
```

## How it works

A `.deb` file is an `ar` archive containing:
- `debian-binary` - version string
- `control.tar.*` - package metadata
- `data.tar.*` - package contents

When signed, debsign adds a `_gpgorigin` file containing a detached GPG signature of the checksums (MD5, SHA1, SHA256) of all archive members.

## Build dependencies

- Rust 1.70+
- nettle-dev
- clang
- llvm

## License

MIT OR Apache-2.0
