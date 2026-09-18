use anyhow::Context;
use plain_bitnames_types::{
    AuthorizedTransaction, FilledTransaction, authorization,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct LegacyCase {
    name: String,
    filled: FilledTransaction,
    canonical_hex: String,
    transaction_hex: String,
    authorized_hex: String,
    signature_hex: String,
    txid: String,
}

fn cases(prefix: &str) -> anyhow::Result<Vec<LegacyCase>> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/v0.17.11.json"))?;
    fixture["transactions"]
        .as_array()
        .context("The fixture has no transactions")?
        .iter()
        .filter(|value| value["name"].as_str().unwrap().starts_with(prefix))
        .map(|value| serde_json::from_value(value.clone()).map_err(Into::into))
        .collect()
}

fn check_transaction_bytes(prefix: &str) -> anyhow::Result<()> {
    let cases = cases(prefix)?;
    assert_eq!(cases.len(), 2);
    for case in cases {
        let transaction = &case.filled.transaction;
        assert_eq!(
            const_hex::encode(transaction.canonical_encoding()),
            case.canonical_hex,
            "{}",
            case.name,
        );
        assert_eq!(
            const_hex::encode(bincode::serialize(transaction)?),
            case.transaction_hex,
            "{}",
            case.name,
        );
        assert_eq!(transaction.txid().to_string(), case.txid, "{}", case.name);
    }
    Ok(())
}

#[test]
fn legacy_registration_bytes() -> anyhow::Result<()> {
    check_transaction_bytes("registration_")
}

#[test]
fn legacy_update_bytes() -> anyhow::Result<()> {
    check_transaction_bytes("update_")
}

#[test]
fn legacy_registration_signatures() -> anyhow::Result<()> {
    check_transaction_signatures("registration_")
}

#[test]
fn legacy_update_signatures() -> anyhow::Result<()> {
    check_transaction_signatures("update_")
}

fn check_transaction_signatures(prefix: &str) -> anyhow::Result<()> {
    let key = authorization::SigningKey::from_bytes(&[7; 32]);
    for case in cases(prefix)? {
        let bytes = const_hex::decode(&case.authorized_hex)?;
        let authorized: AuthorizedTransaction = bincode::deserialize(&bytes)?;
        authorization::verify_authorized_transaction(&authorized)?;
        assert_eq!(bincode::serialize(&authorized)?, bytes, "{}", case.name);
        let signature = authorization::sign_tx(&key, &case.filled.transaction)?;
        assert_eq!(
            const_hex::encode(signature.0.to_bytes()),
            case.signature_hex,
            "{}",
            case.name,
        );
    }
    Ok(())
}
