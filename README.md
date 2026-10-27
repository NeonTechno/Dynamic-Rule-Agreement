# Dynamic Rule Agreement (DRA)

**Status: experimental research prototype — not production-ready.**

DRA explores a versioned challenge-response handshake that combines:
- a fresh random nonce;
- random selection between two registered toy rule families (`Affine` and `ScaledOffset`), or explicit selection for testing/policy;
- a SHA-256 commitment that binds the rule-family identifier, parameters, nonce, timestamp, modulus, and protocol version;
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

1. Verifier creates a nonce and selects a registered rule family; the family identifier is included in the commitment.
2. Peer checks the relation and signs a transcript bound to the challenge.
3. Verifier checks protocol version, freshness, commitment, relation, and signature.
4. Verifier consumes the nonce to reject a replay within its process.

## Dynamic rule engine (v2)

The challenge now identifies one of two rule families: `Affine` (`y = a*x + b mod p`) or `ScaledOffset` (`y = a*(x + b) mod p`). `Challenge::generate()` selects a family using the operating-system random source; `Challenge::generate_with_rule()` lets tests and future negotiated policies choose one explicitly. The selected family is committed, so changing it after challenge creation invalidates the commitment. This is dynamic rule selection, not dynamic cryptographic hardness: both relations are intentionally easy to solve and do not add security beyond the signature.

This changes the challenge commitment format and bumps the protocol/domain version to v2. Do not mix v1 and v2 peers; a future network transport must negotiate supported versions and reject unknown rule IDs explicitly.

## Research roadmap

1. Specify canonical, versioned wire encoding and network transport.
2. Implement mutual authentication and bind both identities to the full transcript.
3. Define a concrete property before considering a reviewed zero-knowledge proof system.
4. Evaluate a reviewed ML-DSA implementation or a carefully specified hybrid classical/post-quantum signature mode.
5. Add durable atomic replay protection, key lifecycle management, rate limiting, fuzzing, and independent cryptographic review.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
