use dynamic_rule_agreement::{unix_time_now, Challenge, Verifier};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = unix_time_now()?;
    let client_identity = SigningKey::generate(&mut OsRng);
    let challenge = Challenge::generate(now);
    let response = challenge.respond(&client_identity)?;

    let mut verifier = Verifier::new(60);
    verifier.verify(
        &challenge,
        &response,
        &client_identity.verifying_key(),
        now,
    )?;

    println!("DRA demo: handshake accepted");
    println!("protocol version: {}", challenge.version);
    println!("nonce: {}", hex::encode(challenge.nonce));
    println!(
        "rule: {}*x + {} = {} (mod {})",
        challenge.rule.a,
        challenge.rule.b,
        challenge.rule.y,
        dynamic_rule_agreement::MODULUS
    );
    println!("commitment: {}", hex::encode(challenge.commitment));
    println!("NOTE: the equation is a toy consistency layer; Ed25519 authenticates the client.");
    Ok(())
}
