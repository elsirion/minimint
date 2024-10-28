use std::io::Cursor;

use fedimint_client::module::init::recovery::RecoveryFromHistoryCommon;
use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{impl_db_lookup, impl_db_record, Amount};
use fedimint_mint_common::Nonce;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::backup::recovery::MintRecoveryState;
use crate::oob::{MintOOBStateMachine, MintOOBStateMachineV1, MintOOBStates, MintOOBStatesV1};
use crate::{MintClientStateMachines, SpendableNoteUndecoded};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Note = 0x20,
    NextECashNoteIndex = 0x2a,
    CancelledOOBSpend = 0x2b,
    RecoveryState = 0x2c,
    RecoveryFinalized = 0x2d,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NoteKey {
    pub amount: Amount,
    pub nonce: Nonce,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NoteKeyPrefix;

impl_db_record!(
    key = NoteKey,
    value = SpendableNoteUndecoded,
    db_prefix = DbKeyPrefix::Note,
);
impl_db_lookup!(key = NoteKey, query_prefix = NoteKeyPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct NextECashNoteIndexKey(pub Amount);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextECashNoteIndexKeyPrefix;

impl_db_record!(
    key = NextECashNoteIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextECashNoteIndex,
);
impl_db_lookup!(
    key = NextECashNoteIndexKey,
    query_prefix = NextECashNoteIndexKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecoveryStateKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RestoreStateKeyPrefix;

impl_db_record!(
    key = RecoveryStateKey,
    value = (MintRecoveryState, RecoveryFromHistoryCommon),
    db_prefix = DbKeyPrefix::RecoveryState,
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecoveryFinalizedKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryFinalizedKeyPrefix;

impl_db_record!(
    key = RecoveryFinalizedKey,
    value = bool,
    db_prefix = DbKeyPrefix::RecoveryFinalized,
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct CancelledOOBSpendKey(pub OperationId);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct CancelledOOBSpendKeyPrefix;

impl_db_record!(
    key = CancelledOOBSpendKey,
    value = (),
    db_prefix = DbKeyPrefix::CancelledOOBSpend,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = CancelledOOBSpendKey,
    query_prefix = CancelledOOBSpendKeyPrefix,
);

pub async fn migrate_to_v1(
    dbtx: &mut DatabaseTransaction<'_>,
) -> anyhow::Result<Option<(Vec<(Vec<u8>, OperationId)>, Vec<(Vec<u8>, OperationId)>)>> {
    // between v0 and v1, we changed the format of `MintRecoveryState`, and instead
    // of migrating it, we can just delete it, so the recovery will just start
    // again, ignoring any existing state from before the migration
    dbtx.remove_entry(&RecoveryStateKey).await;

    Ok(None)
}

/// Maps all `Unreachable` states in the state machine to `OutputDone`
pub(crate) fn migrate_state_to_v2(
    operation_id: OperationId,
    cursor: &mut Cursor<&[u8]>,
) -> anyhow::Result<Option<(Vec<u8>, OperationId)>> {
    let decoders = ModuleDecoderRegistry::default();

    let mint_client_state_machine_variant = u16::consensus_decode(cursor, &decoders)?;

    let bytes = match mint_client_state_machine_variant {
        2 => {
            let old_state = MintOOBStateMachineV1::consensus_decode(cursor, &decoders)?;

            let new_state = match old_state.state {
                MintOOBStatesV1::Created(created) => MintOOBStates::Created(created),
                MintOOBStatesV1::UserRefund(refund) => MintOOBStates::UserRefund(refund),
                MintOOBStatesV1::TimeoutRefund(refund) => MintOOBStates::TimeoutRefund(refund),
            };
            MintClientStateMachines::OOB(MintOOBStateMachine {
                operation_id: old_state.operation_id,
                state: new_state,
            })
            .consensus_encode_to_vec()
        }
        _ => return Ok(None),
    };
    Ok(Some((bytes, operation_id)))
}
