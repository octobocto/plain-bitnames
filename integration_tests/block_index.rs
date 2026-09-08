//! Test that a node reports the index of a block it connected

use bip300301_enforcer_integration_tests::{
    integration_test::{
        activate_sidechain, deposit, fund_enforcer, propose_sidechain,
    },
    setup::{
        Mode, Network, PostSetup as EnforcerPostSetup,
        PreSetup as EnforcerPreSetup, SetupOpts as EnforcerSetupOpts,
        Sidechain as _,
    },
    util::{
        AbortOnDrop, AsyncTrial, BinPaths as EnforcerBinPaths,
        TestFailureCollector, TestFileRegistry,
    },
};
use bitcoin::Amount;
use futures::{
    FutureExt as _, StreamExt as _, channel::mpsc, future::BoxFuture,
};
use plain_bitnames_app_rpc_api::{
    node::RpcClient as _, wallet::RpcClient as _,
};
use tokio::time::sleep;
use tracing::Instrument as _;

use crate::{
    setup::{Init, PostSetup},
    util::BinPaths,
};

const DEPOSIT_AMOUNT: Amount = Amount::from_sat(21_000_000);
const DEPOSIT_FEE: Amount = Amount::from_sat(1_000_000);
const TRANSFER_AMOUNT: u64 = 1_000_000;
const TRANSFER_FEE: u64 = 1_000;

/// Initial setup for the test
async fn setup(
    enforcer_bin_paths: &EnforcerBinPaths,
    res_tx: mpsc::UnboundedSender<anyhow::Result<()>>,
) -> anyhow::Result<EnforcerPostSetup> {
    let enforcer_pre_setup =
        EnforcerPreSetup::new(enforcer_bin_paths, Network::Regtest)?;
    let mut enforcer_post_setup = {
        let setup_opts: EnforcerSetupOpts = Default::default();
        enforcer_pre_setup
            .setup(Mode::Mempool, setup_opts, res_tx.clone())
            .await?
    };
    let () = propose_sidechain::<PostSetup>(&mut enforcer_post_setup).await?;
    let () = activate_sidechain::<PostSetup>(&mut enforcer_post_setup).await?;
    let () = fund_enforcer::<PostSetup>(&mut enforcer_post_setup).await?;
    Ok(enforcer_post_setup)
}

async fn block_index_task(
    bin_paths: BinPaths,
    res_tx: mpsc::UnboundedSender<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let mut enforcer_post_setup =
        setup(&bin_paths.others, res_tx.clone()).await?;
    let mut sidechain = PostSetup::setup(
        Init {
            bitnames_app: bin_paths.bitnames()?.clone(),
            data_dir_suffix: None,
        },
        &enforcer_post_setup,
        res_tx,
    )
    .await?;
    tracing::info!("Setup bitnames node successfully");

    let deposit_address = sidechain.get_deposit_address().await?;
    let () = deposit(
        &mut enforcer_post_setup,
        &mut sidechain,
        &deposit_address,
        DEPOSIT_AMOUNT,
        DEPOSIT_FEE,
    )
    .await?;
    tracing::info!("Deposited to sidechain successfully");

    let dest = sidechain.rpc_client.get_new_address().await?;
    let txid = sidechain
        .rpc_client
        .create_transfer(dest, TRANSFER_AMOUNT, TRANSFER_FEE, None)
        .await?;
    let () = sidechain.bmm_single(&mut enforcer_post_setup).await?;

    tracing::debug!("Checking that a height names the block it connected");
    let height = sidechain.rpc_client.getblockcount().await?;
    let block_hash = sidechain.rpc_client.get_block_hash(height).await?;
    anyhow::ensure!(
        block_hash
            == sidechain.rpc_client.get_best_sidechain_block_hash().await?
    );
    let block_hash =
        block_hash.ok_or_else(|| anyhow::anyhow!("no block at {height}"))?;

    tracing::debug!("Checking that a height above the tip names no block");
    anyhow::ensure!(
        sidechain
            .rpc_client
            .get_block_hash(height + 1)
            .await?
            .is_none()
    );

    tracing::debug!("Checking that the index names every transaction");
    let block = sidechain.rpc_client.get_block(block_hash).await?;
    let index = sidechain.rpc_client.get_block_index(block_hash).await?;
    anyhow::ensure!(index.txs.len() == block.body.transactions.len());
    anyhow::ensure!(index.txs.len() == 1);
    for (entry, tx) in index.txs.iter().zip(&block.body.transactions) {
        anyhow::ensure!(entry.txid == tx.txid());
        anyhow::ensure!(entry.size == tx.canonical_size());
        anyhow::ensure!(entry.size > 0);
        anyhow::ensure!(
            entry.raw == const_hex::encode(tx.canonical_encoding())
        );
    }
    anyhow::ensure!(index.txs[0].txid == txid);

    tracing::debug!("Checking that a block without a deposit lists none");
    anyhow::ensure!(index.deposits.is_empty());
    anyhow::ensure!(index.bundle_spends.is_empty());

    tracing::debug!("Checking that the deposit block lists its deposit");
    let mut deposits = Vec::new();
    for deposit_height in 0..height {
        let Some(hash) =
            sidechain.rpc_client.get_block_hash(deposit_height).await?
        else {
            anyhow::bail!("no block at {deposit_height}");
        };
        let index = sidechain.rpc_client.get_block_index(hash).await?;
        deposits.extend(index.deposits);
    }
    anyhow::ensure!(deposits.len() == 1);
    anyhow::ensure!(deposits[0].output.address.to_string() == deposit_address);

    drop(sidechain);
    tracing::info!(
        "Removing {}",
        enforcer_post_setup.directories.base_dir.path().display()
    );
    drop(enforcer_post_setup.tasks);
    // Wait for tasks to die
    sleep(std::time::Duration::from_secs(1)).await;
    enforcer_post_setup.directories.base_dir.cleanup()?;
    Ok(())
}

async fn block_index(bin_paths: BinPaths) -> anyhow::Result<()> {
    let (res_tx, mut res_rx) = mpsc::unbounded();
    let _test_task: AbortOnDrop<()> = tokio::task::spawn({
        let res_tx = res_tx.clone();
        async move {
            let res = block_index_task(bin_paths, res_tx.clone()).await;
            let _send_err: Result<(), _> = res_tx.unbounded_send(res);
        }
        .in_current_span()
    })
    .into();
    res_rx.next().await.ok_or_else(|| {
        anyhow::anyhow!("Unexpected end of test task result stream")
    })?
}

pub fn block_index_trial(
    bin_paths: BinPaths,
    file_registry: TestFileRegistry,
    failure_collector: TestFailureCollector,
) -> AsyncTrial<BoxFuture<'static, anyhow::Result<()>>> {
    AsyncTrial::new(
        "block_index",
        block_index(bin_paths).boxed(),
        file_registry,
        failure_collector,
    )
}
