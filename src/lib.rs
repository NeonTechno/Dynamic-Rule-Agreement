//! Dynamic Rule Agreement (DRA), an experimental challenge-response prototype.
//!
//! The modular equation is a toy consistency check, not a hard puzzle or security
//! boundary. Peer authentication comes from the Ed25519 signature.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// A 61-bit Mersenne prime used for the toy equation layer.
pub const MODULUS: u64 = (1_u64 << 61) - 1;
pub const PROTOCOL_VERSION: u16 = 2;
const DOMAIN_CHALLENGE: &[u8] = b"DRA/challenge/v2";
const DOMAIN_RESPONSE: &[u8] = b"DRA/response/v2";

/// Identifier for the mathematical relation used by a challenge.
/// These are toy relations, not cryptographic primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleKind {
    /// y = (a*x + b) mod MODULUS
    Affine = 1,
    /// y = a*(x + b) mod MODULUS
    ScaledOffset = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub kind: RuleKind,
    pub a: u64,
    pub b: u64,
    pub y: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub version: u16,
    pub issued_at_unix: u64,
    pub nonce: [u8; 32],
    pub rule: Rule,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Public witness for the toy relation; not a proof of identity.
    pub witness: u64,
    pub signature: [u8; 64],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DraError {
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("challenge has expired or its issue time is invalid")]
    ExpiredChallenge,
    #[error("challenge commitment does not match its rule")]
    InvalidCommitment,
    #[error("mathematical relation is invalid")]
    InvalidRuleProof,
    #[error("signature is invalid")]
    InvalidSignature,
    #[error("challenge nonce has already been consumed")]
    Replay,
    #[error("invalid rule parameters")]
    InvalidRule,
}

impl Challenge {
    /// Generate a fresh challenge using the operating system CSPRNG.
    pub fn generate(now_unix: u64) -> Self {
        let mut rng = OsRng;
        let mut nonce = [0_u8; 32];
        rng.fill_bytes(&mut nonce);

        let kind = if rng.next_u32() & 1 == 0 { RuleKind::Affine } else { RuleKind::ScaledOffset };
        Self::generate_with_rule(now_unix, kind)
    }

    /// Generate a challenge using a specific registered rule family.
    pub fn generate_with_rule(now_unix: u64, kind: RuleKind) -> Self {
        let mut rng = OsRng;
        let mut nonce = [0_u8; 32];
        rng.fill_bytes(&mut nonce);
        let a = sample_nonzero_field(&mut rng);
        let b = sample_field(&mut rng);
        let hidden_witness = sample_field(&mut rng);
        let y = evaluate_rule(kind, a, b, hidden_witness);
        let rule = Rule { kind, a, b, y };
        let commitment = commitment_for(&nonce, &rule, PROTOCOL_VERSION, now_unix);

        Self {
            version: PROTOCOL_VERSION,
            issued_at_unix: now_unix,
            nonce,
            rule,
            commitment,
        }
    }

    /// Solve the public relation and sign a transcript bound to the challenge.
    pub fn respond(&self, identity: &SigningKey) -> Result<Response, DraError> {
        validate_challenge_shape(self)?;
        if commitment_for(&self.nonce, &self.rule, self.version, self.issued_at_unix)
            != self.commitment
        {
            return Err(DraError::InvalidCommitment);
        }

        let inverse = modular_inverse(self.rule.a, MODULUS).ok_or(DraError::InvalidRule)?;
        let witness = match self.rule.kind {
            RuleKind::Affine => {
                let delta = ((self.rule.y as u128 + MODULUS as u128 - self.rule.b as u128)
                    % MODULUS as u128) as u64;
                ((delta as u128 * inverse as u128) % MODULUS as u128) as u64
            }
            RuleKind::ScaledOffset => {
                let scaled = ((self.rule.y as u128 * inverse as u128) % MODULUS as u128) as u64;
                ((scaled as u128 + MODULUS as u128 - self.rule.b as u128)
                    % MODULUS as u128) as u64
            }
        };

        if evaluate_rule(self.rule.kind, self.rule.a, self.rule.b, witness) != self.rule.y
        {
            return Err(DraError::InvalidRuleProof);
        }

        let signature = identity.sign(&response_message(self, witness)).to_bytes();
        Ok(Response { witness, signature })
    }
}

/// Stateful verifier. Production systems need durable, atomic replay tracking.
pub struct Verifier {
    max_age_seconds: u64,
    consumed_nonces: HashSet<[u8; 32]>,
}

impl Verifier {
    pub fn new(max_age_seconds: u64) -> Self {
        Self {
            max_age_seconds,
            consumed_nonces: HashSet::new(),
        }
    }

    /// Verify freshness, commitment, relation, and peer signature.
    pub fn verify(
        &mut self,
        challenge: &Challenge,
        response: &Response,
        peer_key: &VerifyingKey,
        now_unix: u64,
    ) -> Result<(), DraError> {
        validate_challenge_shape(challenge)?;
        if now_unix < challenge.issued_at_unix
            || now_unix.saturating_sub(challenge.issued_at_unix) > self.max_age_seconds
        {
            return Err(DraError::ExpiredChallenge);
        }
        if self.consumed_nonces.contains(&challenge.nonce) {
            return Err(DraError::Replay);
        }
        if commitment_for(
            &challenge.nonce,
            &challenge.rule,
            challenge.version,
            challenge.issued_at_unix,
        ) != challenge.commitment
        {
            return Err(DraError::InvalidCommitment);
        }
        if response.witness >= MODULUS
            || evaluate_rule(challenge.rule.kind, challenge.rule.a, challenge.rule.b, response.witness)
                != challenge.rule.y
        {
            return Err(DraError::InvalidRuleProof);
        }

        let signature = Signature::from_bytes(&response.signature);
        peer_key
            .verify_strict(&response_message(challenge, response.witness), &signature)
            .map_err(|_| DraError::InvalidSignature)?;

        self.consumed_nonces.insert(challenge.nonce);
        Ok(())
    }
}

pub fn unix_time_now() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn validate_challenge_shape(challenge: &Challenge) -> Result<(), DraError> {
    if challenge.version != PROTOCOL_VERSION {
        return Err(DraError::UnsupportedVersion);
    }
    if challenge.rule.a == 0
        || challenge.rule.a >= MODULUS
        || challenge.rule.b >= MODULUS
        || challenge.rule.y >= MODULUS
    {
        return Err(DraError::InvalidRule);
    }
    Ok(())
}

fn evaluate_rule(kind: RuleKind, a: u64, b: u64, x: u64) -> u64 {
    let value = match kind {
        RuleKind::Affine => (a as u128 * x as u128 + b as u128) % MODULUS as u128,
        RuleKind::ScaledOffset => {
            (a as u128 * ((x as u128 + b as u128) % MODULUS as u128)) % MODULUS as u128
        }
    };
    value as u64
}

fn sample_field(rng: &mut OsRng) -> u64 {
    loop {
        let value = rng.next_u64() >> 3;
        if value < MODULUS {
            return value;
        }
    }
}

fn sample_nonzero_field(rng: &mut OsRng) -> u64 {
    loop {
        let value = sample_field(rng);
        if value != 0 {
            return value;
        }
    }
}

fn commitment_for(nonce: &[u8; 32], rule: &Rule, version: u16, issued_at: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN_CHALLENGE);
    hash.update(version.to_be_bytes());
    hash.update(issued_at.to_be_bytes());
    hash.update(nonce);
    hash.update(MODULUS.to_be_bytes());
    hash.update([rule.kind as u8]);
    hash.update(rule.a.to_be_bytes());
    hash.update(rule.b.to_be_bytes());
    hash.update(rule.y.to_be_bytes());
    hash.finalize().into()
}

fn response_message(challenge: &Challenge, witness: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(96);
    message.extend_from_slice(DOMAIN_RESPONSE);
    message.extend_from_slice(&challenge.commitment);
    message.extend_from_slice(&challenge.nonce);
    message.extend_from_slice(&witness.to_be_bytes());
    message
}

fn modular_inverse(value: u64, modulus: u64) -> Option<u64> {
    let (mut old_r, mut r) = (value as i128, modulus as i128);
    let (mut old_s, mut s) = (1_i128, 0_i128);
    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_s, s) = (s, old_s - quotient * s);
    }
    if old_r != 1 {
        return None;
    }
    Some(old_s.rem_euclid(modulus as i128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn valid_handshake_is_accepted_once() {
        let now = 1_800_000_000;
        let client = identity();
        let challenge = Challenge::generate(now);
        let response = challenge.respond(&client).expect("response");
        let mut verifier = Verifier::new(30);
        verifier.verify(&challenge, &response, &client.verifying_key(), now + 1).unwrap();
        assert_eq!(
            verifier.verify(&challenge, &response, &client.verifying_key(), now + 1),
            Err(DraError::Replay)
        );
    }

    #[test]
    fn each_registered_rule_family_round_trips() {
        let now = 1_800_000_000;
        let client = identity();
        for kind in [RuleKind::Affine, RuleKind::ScaledOffset] {
            let challenge = Challenge::generate_with_rule(now, kind);
            let response = challenge.respond(&client).expect("response");
            let mut verifier = Verifier::new(30);
            verifier.verify(&challenge, &response, &client.verifying_key(), now + 1).unwrap();
        }
    }

    #[test]
    fn changing_rule_kind_invalidates_commitment() {
        let now = 1_800_000_000;
        let client = identity();
        let challenge = Challenge::generate_with_rule(now, RuleKind::Affine);
        let response = challenge.respond(&client).unwrap();
        let mut tampered = challenge.clone();
        tampered.rule.kind = RuleKind::ScaledOffset;
        let mut verifier = Verifier::new(30);
        assert_eq!(
            verifier.verify(&tampered, &response, &client.verifying_key(), now + 1),
            Err(DraError::InvalidCommitment)
        );
    }

    #[test]
    fn wrong_identity_is_rejected() {
        let now = 1_800_000_000;
        let client = identity();
        let attacker = identity();
        let challenge = Challenge::generate(now);
        let response = challenge.respond(&client).unwrap();
        let mut verifier = Verifier::new(30);
        assert_eq!(
            verifier.verify(&challenge, &response, &attacker.verifying_key(), now + 1),
            Err(DraError::InvalidSignature)
        );
    }

    #[test]
    fn tampered_rule_is_rejected() {
        let now = 1_800_000_000;
        let client = identity();
        let challenge = Challenge::generate(now);
        let response = challenge.respond(&client).unwrap();
        let mut tampered = challenge.clone();
        tampered.rule.y = (tampered.rule.y + 1) % MODULUS;
        let mut verifier = Verifier::new(30);
        assert_eq!(
            verifier.verify(&tampered, &response, &client.verifying_key(), now + 1),
            Err(DraError::InvalidCommitment)
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let now = 1_800_000_000;
        let client = identity();
        let challenge = Challenge::generate(now);
        let response = challenge.respond(&client).unwrap();
        let mut verifier = Verifier::new(5);
        assert_eq!(
            verifier.verify(&challenge, &response, &client.verifying_key(), now + 6),
            Err(DraError::ExpiredChallenge)
        );
    }

    #[test]
    fn modified_witness_is_rejected() {
        let now = 1_800_000_000;
        let client = identity();
        let challenge = Challenge::generate(now);
        let mut response = challenge.respond(&client).unwrap();
        response.witness = (response.witness + 1) % MODULUS;
        let mut verifier = Verifier::new(30);
        assert_eq!(
            verifier.verify(&challenge, &response, &client.verifying_key(), now + 1),
            Err(DraError::InvalidRuleProof)
        );
    }
}
