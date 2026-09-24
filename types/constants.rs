use std::sync::LazyLock;

use hex_literal::hex;

use crate::VerifyingKey;

/// authorized pubkey that can make batch icann registration txs
const BATCH_ICANN_VERIFYING_KEY_BYTES: [u8; VerifyingKey::BYTE_LEN] =
    // FIXME: choose a real key
    hex!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

/// `None` while the placeholder bytes are not a valid key, so no batch ICANN
/// registration is valid.
pub static BATCH_ICANN_VERIFYING_KEY: LazyLock<Option<VerifyingKey>> =
    LazyLock::new(|| {
        VerifyingKey::try_from(&BATCH_ICANN_VERIFYING_KEY_BYTES).ok()
    });
