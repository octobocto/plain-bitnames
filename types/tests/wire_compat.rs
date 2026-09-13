use anyhow::Context;
use plain_bitnames_types::{
    AuthorizedTransaction, Body, FilledTransaction, Header, Verify as _,
    authorization,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct LegacyCase {
    name: String,
    filled: FilledTransaction,
    canonical_hex: String,
    transaction_hex: String,
    authorized_hex: String,
    body_hex: String,
    header_hex: String,
    signature_hex: String,
    txid: String,
    merkle_root: String,
    block_hash: String,
}

#[derive(Deserialize)]
struct AlphanetBlock {
    height: u32,
    hash: String,
    header: Header,
    body: Body,
    filled: Vec<FilledTransaction>,
    body_hex: String,
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

#[test]
fn legacy_registration_blocks() -> anyhow::Result<()> {
    check_block_bodies("registration_")
}

#[test]
fn legacy_update_blocks() -> anyhow::Result<()> {
    check_block_bodies("update_")
}

fn check_block_bodies(prefix: &str) -> anyhow::Result<()> {
    for case in cases(prefix)? {
        let body_bytes = const_hex::decode(&case.body_hex)?;
        let body: Body = bincode::deserialize(&body_bytes)?;
        let header: Header =
            bincode::deserialize(&const_hex::decode(&case.header_hex)?)?;
        let merkle_root =
            Body::compute_merkle_root(&body.coinbase, &[case.filled])?;
        assert_eq!(merkle_root, header.merkle_root, "{}", case.name);
        assert_eq!(merkle_root.to_string(), case.merkle_root, "{}", case.name);
        assert_eq!(header.hash().to_string(), case.block_hash, "{}", case.name);
        assert_eq!(bincode::serialize(&body)?, body_bytes, "{}", case.name);
        authorization::Authorization::verify_body(&body)?;
    }
    Ok(())
}

#[test]
fn alphanet_registration_blocks() -> anyhow::Result<()> {
    let blocks: Vec<AlphanetBlock> =
        serde_json::from_str(include_str!("fixtures/alphanet-v0.17.11.json"))?;
    assert_eq!(
        blocks.iter().map(|block| block.height).collect::<Vec<_>>(),
        [36, 57],
    );
    for block in blocks {
        let bytes = const_hex::decode(&block.body_hex)?;
        let body: Body = bincode::deserialize(&bytes)?;
        assert_eq!(bincode::serialize(&block.body)?, bytes);
        assert_eq!(body.transactions.len(), block.filled.len());
        for (transaction, filled) in body.transactions.iter().zip(&block.filled)
        {
            assert_eq!(
                transaction.canonical_encoding(),
                filled.transaction.canonical_encoding(),
            );
            assert_eq!(transaction.inputs.len(), filled.spent_utxos.len());
        }
        assert_eq!(
            Body::compute_merkle_root(&body.coinbase, &block.filled)?,
            block.header.merkle_root,
            "Block {}",
            block.height,
        );
        assert_eq!(block.header.hash().to_string(), block.hash);
        authorization::Authorization::verify_body(&body)?;
    }
    Ok(())
}
