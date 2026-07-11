# Plan: Crypto Sign RSA-SHA256

## Approach
Add `RsaSha256` to `CryptoSignAlgorithm`, implement `sign_rsa_sha256` with the
`rsa` + `sha2` crates, and map socket algorithm enum to the application command.

## Architecture
- Application: `crypto_sign.rs`.
- Adapter: `handlers/proxy.rs` algorithm mapping.
- Workspace deps: `rsa`, `sha2`.

## Out of scope
- RSA-PSS; ECDSA.
