# CryptoPass

A single-file PHP web app that brings hashing, encoding, and practical cryptography tools together in a clean, light UI (Tailwind). Ideal for quick experiments, demos, or day-to-day developer utilities.

## Features

### Hash
- MD5, SHA-1, SHA-2 (224/256/384/512), SHA-3 (224/256/384/512), RIPEMD-160, BLAKE2b/BLAKE2s\*  
- CRC32 (text), Double SHA-256 (text)
- File hashing (any supported algorithm)
- Raw/binary output (Base64-wrapped)

\*Shown only when available in your PHP `hash_algos()`.

### Cryptography
- **AES**: 128/192/256-CBC and 256-GCM (IV/nonce + tag handled)
- **DES / Triple DES**: CBC mode
- **RC4** (legacy; for compatibility testing)
- **RSA**: key generation, OAEP encrypt/decrypt, sign/verify (configurable hash)
- **ECDSA**: key generation (e.g., `prime256v1`), sign/verify (configurable hash)

### Encoding
- Hex, Base32 (RFC 4648), Base58 (Bitcoin alphabet), Base64, Base64url
- HTML entities, URL encode/decode

### Format & Convert
- JSON pretty/minify
- XML pretty/minify
- Case conversions: UPPER, lower, Title Case, `snake_case`, `kebab-case`

## Why CryptoPass?

- **All-in-one**: stop bouncing between different sites or CLIs.
- **Zero setup**: a single `index.php` file.
- **Clear UX**: light, distraction-free Tailwind interface.
- **Graceful capability detection**: only shows hash algorithms your PHP build supports.

## Requirements

- PHP 8.0+  
- Extensions: `openssl`, `hash`, `dom`, `gmp` (for Base58)

> **Security note**  
> This project is for testing/learning/utility purposes. Do **not** paste secrets you care about. Legacy algorithms (MD5, SHA-1, DES, RC4) are insecure and included only for compatibility.

## Getting Started

1. Clone the repo or copy `index.php` into a web-served directory.
2. Ensure required extensions are enabled (`php -m` should list `openssl`, `hash`, `dom`, `gmp`).
3. Open in a browser:

