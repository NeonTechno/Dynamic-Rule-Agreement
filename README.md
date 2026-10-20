# Dynamic Rule Agreement (DRA)

**Status: experimental research prototype — not production-ready.**

DRA explores a dynamic challenge-response handshake that combines:
- a fresh random nonce;
- a per-session modular-arithmetic relation and SHA-256 commitment;
- a response containing a witness to that relation;
- Ed25519 authentication of the response transcript;
- freshness checks and in-process replay prevention.

## Security boundaries

- The equation is deliberately easy to solve. It is a consistency check, **not** a security primitive or proof of identity.
- The witness is transmitted openly; this is **not** a zero-knowledge proof.
- Ed25519 is a classical signature scheme; this prototype is **not post-quantum secure**.
- Replay state is process-local and is not safe across verifier restarts or multiple verifier instances.
- A hash commitment provides binding/integrity, not encryption; challenge fields are visible.
- Do not use this prototype to protect production systems, funds, or sensitive data.

Authentication comes from the Ed25519 signature, not from solving the mathematical relation.

## Run

Install the stable Rust toolchain, then run:

```sh
cargo test
cargo run
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Protocol sketch

1. Verifier creates a nonce and a dynamic rule.
2. Peer checks the relation and signs a transcript bound to the challenge.
3. Verifier checks protocol version, freshness, commitment, relation, and signature.
4. Verifier consumes the nonce to reject a replay within its process.

## Research roadmap

1. Specify canonical, versioned wire encoding and network transport.
2. Implement mutual authentication and bind both identities to the full transcript.
3. Define a concrete property before considering a reviewed zero-knowledge proof system.
4. Evaluate a reviewed ML-DSA implementation or a carefully specified hybrid classical/post-quantum signature mode.
5. Add durable atomic replay protection, key lifecycle management, rate limiting, fuzzing, and independent cryptographic review.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
