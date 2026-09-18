use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::Path,
    time::Duration,
};

use anyhow::Context;
use heed::types::SerdeBincode;
use sneed::DatabaseUnique;

use super::{Error, Node};
use crate::{
    types::{
        AuthorizedTransaction, FilledOutput, FilledTransaction, Network,
        OutPoint, OutPointKey, Transaction, Txid,
        authorization::{self, SigningKey},
        proto::mainchain::ValidatorClient,
    },
    wallet::Wallet,
};

pub(super) async fn node(
    runtime: &tokio::runtime::Runtime,
    path: &Path,
) -> anyhow::Result<(Node, SocketAddr)> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = socket.local_addr()?;
    drop(socket);
    let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1")
        .connect_lazy();
    let node = Node::new(
        HashSet::new(),
        address,
        path,
        ValidatorClient::new(channel),
        None,
        None,
        Network::Regtest,
        HashSet::new(),
        &mut rand::rng(),
        runtime,
        #[cfg(feature = "zmq")]
        (Ipv4Addr::LOCALHOST, 0).into(),
    )
    .await?;
    Ok((node, address))
}

pub(super) fn transaction(
    nodes: &[&Node],
    path: &Path,
) -> anyhow::Result<AuthorizedTransaction> {
    let wallet = Wallet::new(&path.join("wallet"))?;
    wallet.set_seed(&[2; 64])?;
    let address = wallet.get_new_address()?;
    let outpoint = OutPoint::Regular {
        txid: [1; 32].into(),
        vout: 0,
    };
    let output = FilledOutput::new_bitcoin_value(
        address,
        bitcoin::Amount::from_sat(1_000),
    );
    wallet.put_utxos(&HashMap::from([(outpoint, output.clone())]))?;
    for node in nodes {
        let mut rwtxn = node.env.write_txn()?;
        let utxos =
            DatabaseUnique::<OutPointKey, SerdeBincode<FilledOutput>>::create(
                &node.env, &mut rwtxn, "utxos",
            )?;
        utxos.put(&mut rwtxn, &OutPointKey::from(&outpoint), &output)?;
        rwtxn.commit()?;
    }
    Ok(wallet.authorize(
        rand::rng(),
        Transaction::new(
            vec![outpoint],
            vec![
                FilledOutput::new_bitcoin_value(
                    address,
                    bitcoin::Amount::from_sat(900),
                )
                .into(),
            ],
        ),
    )?)
}

pub(super) async fn wait_for_transaction(
    node: &Node,
    txid: Txid,
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if node.get_authorized_transaction(txid)?.is_some() {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("The peer did not receive the transaction")?
}

#[test]
fn mempool_restart_keeps_signed_bytes() -> anyhow::Result<()> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../types/tests/fixtures/v0.17.11.json"
    ))?;
    let filled: FilledTransaction =
        serde_json::from_value(fixture["transactions"][0]["filled"].clone())?;
    let mut rng = rand::rng();
    let key = SigningKey::new(&mut rng);
    let address = authorization::get_address(&(&key).into());
    let keys = vec![(address, &key); filled.transaction.inputs.len()];
    let transaction =
        authorization::authorize(&mut rng, &keys, filled.transaction)?;
    let bytes = bincode::serialize(&transaction)?;
    let txid = transaction.transaction.txid();
    let path = temp_dir::TempDir::new()?;
    for restart in [false, true] {
        let mut options = heed::EnvOpenOptions::new();
        options.max_dbs(crate::mempool::MemPool::NUM_DBS);
        options.map_size(10 * 1024 * 1024);
        let env = unsafe { sneed::Env::open(&options, path.path()) }?;
        let mempool = crate::mempool::MemPool::new(&env)?;
        if restart {
            let rotxn = env.read_txn()?;
            let stored = mempool
                .transactions
                .try_get(&rotxn, &txid)?
                .context("The transaction did not survive the restart")?;
            assert_eq!(bincode::serialize(&stored)?, bytes);
        } else {
            let mut rwtxn = env.write_txn()?;
            mempool.put(&mut rwtxn, &transaction)?;
            rwtxn.commit()?;
        }
    }
    Ok(())
}

#[test]
fn duplicate_submission_keeps_signed_bytes() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let path = temp_dir::TempDir::new()?;
        let (node, _) = node(&runtime, path.path()).await?;
        let transaction = transaction(&[&node], path.path())?;
        let txid = transaction.transaction.txid();
        let bytes = bincode::serialize(&transaction)?;
        let first = node.broadcast_transaction(&transaction)?;
        let second = node.broadcast_transaction(&transaction)?;
        node.submit_transaction(&transaction)?;
        assert_eq!(first.txid, txid);
        assert_eq!(second.txid, txid);
        assert_eq!(first.peer_count, 0);
        assert_eq!(second.peer_count, 0);
        assert_eq!(node.get_all_transactions()?.len(), 1);
        let exported = node
            .get_authorized_transaction(txid)?
            .context("The transaction is absent")?;
        assert_eq!(bincode::serialize(&exported)?, bytes);
        assert_eq!(node.rebroadcast_transaction(txid)?.peer_count, 0);
        assert!(node.get_authorized_transaction([7; 32].into())?.is_none());
        assert!(matches!(
            node.rebroadcast_transaction([7; 32].into()),
            Err(Error::MemPool(crate::mempool::Error::MissingTransaction(_)))
        ));
        Ok(())
    })
}

#[test]
fn conflicting_inputs_and_invalid_signatures_fail() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let path = temp_dir::TempDir::new()?;
        let (node, _) = node(&runtime, path.path()).await?;
        let transaction = transaction(&[&node], path.path())?;
        let wallet = Wallet::new(&path.path().join("wallet"))?;
        let mut repeated_input = transaction.transaction.clone();
        repeated_input.inputs.push(repeated_input.inputs[0]);
        let repeated_input = wallet.authorize(rand::rng(), repeated_input)?;
        assert!(matches!(
            node.broadcast_transaction(&repeated_input),
            Err(Error::MemPool(crate::mempool::Error::UtxoDoubleSpent))
        ));
        node.broadcast_transaction(&transaction)?;
        let mut conflict = transaction.transaction.clone();
        conflict.memo = vec![1];
        let conflict = wallet.authorize(rand::rng(), conflict)?;
        assert!(matches!(
            node.broadcast_transaction(&conflict),
            Err(Error::MemPool(crate::mempool::Error::UtxoDoubleSpent))
        ));
        let mut invalid = transaction.clone();
        invalid.authorizations[0].signature =
            conflict.authorizations[0].signature;
        assert!(matches!(
            node.broadcast_transaction(&invalid),
            Err(Error::State(_))
        ));
        assert_eq!(node.get_all_transactions()?.len(), 1);
        assert_eq!(
            bincode::serialize(&node.get_all_transactions()?[0])?,
            bincode::serialize(&transaction)?
        );
        Ok(())
    })
}

#[test]
fn connection_relays_a_transaction_without_peers() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let first_path = temp_dir::TempDir::new()?;
        let second_path = temp_dir::TempDir::new()?;
        let (first, _) = node(&runtime, first_path.path()).await?;
        let (second, second_address) =
            node(&runtime, second_path.path()).await?;
        let transaction = transaction(&[&first, &second], first_path.path())?;
        let txid = transaction.transaction.txid();
        let result = first.broadcast_transaction(&transaction)?;
        assert_eq!(result.peer_count, 0);
        assert!(second.get_authorized_transaction(txid)?.is_none());
        first.connect_peer(second_address.into())?;
        wait_for_transaction(&second, txid).await?;
        assert_eq!(
            bincode::serialize(&second.get_authorized_transaction(txid)?)?,
            bincode::serialize(&Some(transaction.clone()))?
        );
        let result = first.broadcast_transaction(&transaction)?;
        assert_eq!(result.peer_count, 1);
        assert_eq!(first.get_all_transactions()?.len(), 1);
        assert_eq!(second.get_all_transactions()?.len(), 1);
        second.remove_from_mempool(txid)?;
        first.rebroadcast_transaction(txid)?;
        wait_for_transaction(&second, txid).await?;
        assert_eq!(second.get_all_transactions()?.len(), 1);
        Ok(())
    })
}
