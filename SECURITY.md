# Security Policy

This repository is an experimental research prototype and is not suitable for production use.

## Reporting a vulnerability

Please avoid publishing exploitable details before maintainers have had a chance to assess them. Use GitHub private vulnerability reporting if enabled, or contact the maintainer through a verified private channel.

## Known limitations

- Ed25519 is classical cryptography and provides no post-quantum guarantee.
- No zero-knowledge proof system is implemented.
- The modular equation is easy to solve and is not an authentication factor.
- Replay prevention is in-memory only and does not protect across processes or restarts.
- No network transport, session-key derivation, rate limiting, or production key management is implemented.
