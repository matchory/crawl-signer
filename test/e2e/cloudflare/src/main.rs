//! Verifies the Web Bot Auth signature of a request with Cloudflare's own
//! verifier. Reads the end-to-end origin's JSON answer, which echoes the
//! request's host and headers, on stdin; the argument is the signing key's
//! public part, base64url without padding. Exits 0 if the signature verifies.

use std::io::Read;
use std::process::ExitCode;

use serde_json::Value;
use web_bot_auth::{
    WebBotAuthVerifier,
    components::{CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParameters},
    keyring::{JSONWebKeySet, KeyRing},
    message_signatures::SignedMessage,
};

struct Request {
    host: String,
    headers: Value,
}

impl SignedMessage for Request {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        match name {
            CoveredComponent::Derived(DerivedComponent::Authority { .. }) => {
                vec![self.host.to_lowercase()]
            }
            CoveredComponent::HTTP(HTTPField { name, parameters }) => {
                let values = self
                    .headers
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                    .flat_map(|(_, v)| v.as_array().cloned().unwrap_or_default())
                    .filter_map(|v| v.as_str().map(String::from));
                // The crate leaves component parameters to the message: with
                // key=, the value is that dictionary member's (RFC 9421 2.1.2).
                // A plain split suffices for the members this test sends.
                match parameters.0.iter().find_map(|p| match p {
                    HTTPFieldParameters::Key(k) => Some(k.clone()),
                    _ => None,
                }) {
                    Some(key) => values
                        .flat_map(|v| {
                            v.split(',')
                                .filter_map(|m| m.trim().strip_prefix(&format!("{key}=")).map(String::from))
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                    None => values.collect(),
                }
            }
            _ => vec![],
        }
    }
}

fn run() -> Result<(), String> {
    let x = std::env::args().nth(1).ok_or("usage: wba-verify <x> < answer.json")?;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).map_err(|e| e.to_string())?;
    let answer: Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let request = Request {
        host: answer["host"].as_str().ok_or("answer has no host")?.to_string(),
        headers: answer["headers"].clone(),
    };

    let jwks: JSONWebKeySet = serde_json::from_value(serde_json::json!({
        "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": x }]
    }))
    .map_err(|e| e.to_string())?;
    let mut keyring = KeyRing::default();
    if let Some(Some(err)) = keyring.import_jwks(jwks).into_iter().next() {
        return Err(format!("import key: {err:?}"));
    }

    let verifier = WebBotAuthVerifier::parse(&request).map_err(|e| format!("parse: {e:?}"))?;
    verifier.verify(&keyring, None).map_err(|e| format!("verify: {e:?}"))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("valid");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
