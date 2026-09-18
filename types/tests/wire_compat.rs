use anyhow::Context;
use plain_bitnames_types::{
    AuthorizedTransaction, FilledTransaction, VerifyingKey, authorization,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct LegacyCase {
    name: String,
    filled: FilledTransaction,
    canonical_hex: String,
    transaction_hex: String,
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
fn registration_signatures() -> anyhow::Result<()> {
    check_transaction_signatures("registration_")
}

#[test]
fn update_signatures() -> anyhow::Result<()> {
    check_transaction_signatures("update_")
}

fn check_transaction_signatures(prefix: &str) -> anyhow::Result<()> {
    let mut rng = rand::rng();
    let ctxt = authorization::BatchVerificationContext::new(&mut rng);
    let key = authorization::SigningKey::new(&mut rng);
    let address = authorization::get_address(&VerifyingKey::from(&key));
    for case in cases(prefix)? {
        let transaction = case.filled.transaction;
        let n_inputs = transaction.inputs.len();
        let keys = vec![(address, &key); n_inputs];
        let authorized =
            authorization::authorize(&mut rng, &keys, transaction)?;
        authorization::verify_authorized_transaction(&ctxt, &authorized)?;
        let bytes = bincode::serialize(&authorized)?;
        let decoded: AuthorizedTransaction = bincode::deserialize(&bytes)?;
        assert_eq!(bincode::serialize(&decoded)?, bytes, "{}", case.name);
        authorization::verify_authorized_transaction(&ctxt, &decoded)?;
    }
    Ok(())
}
