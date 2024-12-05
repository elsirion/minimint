use std::collections::HashMap;

use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::{ PublicKey};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_client::recurring::RecurringPaymentProtocol;
use futures::stream::StreamExt;

async fn load_federation_clients(db: &Database) -> Vec<FederationId> {
    let mut dbtx = db.begin_transaction_nc().await;
    dbtx.find_by_prefix(&FederationClientPrefix)
        .await
        .map(|(k, _)| k.federation_id)
        .collect::<Vec<FederationId>>()
        .await
}

pub async fn load_federation_client_databases(db: &Database) -> HashMap<FederationId, Database> {
    load_federation_clients(db)
        .await
        .into_iter()
        .map(|federation_id| {
            let client_db_prefix = federation_db_prefix(federation_id);
            let client_db = db.with_prefix(client_db_prefix);
            (federation_id, client_db)
        })
        .collect()
}

fn federation_db_prefix(federation_id: FederationId) -> Vec<u8> {
    let mut client_db_prefix = Vec::with_capacity(33);
    client_db_prefix.push(DbKeyPrefix::ClientDB as u8);
    client_db_prefix.extend_from_slice(&federation_id.0[..]);
    client_db_prefix
}

pub async fn add_federation_database(db: &Database, federation_id: FederationId) -> Database {
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(&FederationClientKey { federation_id }, &())
        .await;
    dbtx.commit_tx().await;

    db.with_prefix(federation_db_prefix(federation_id))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum DbKeyPrefix {
    ClientList = 0x00,
    ClientDB = 0x01,
    PaymentCodes = 0x02,
    PaymentCodeNextInvoiceIndex = 0x03,
    PaymentCodeInvoices = 0x04,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct FederationClientKey {
    pub federation_id: FederationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct FederationClientPrefix;

impl_db_record!(
    key = FederationClientKey,
    value = (),
    db_prefix = DbKeyPrefix::ClientList,
);
impl_db_lookup!(
    key = FederationClientKey,
    query_prefix = FederationClientPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeKey {
    pub payment_code: PublicKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodePrefix;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum PaymentCodeVariant {
    Lnurl { meta: String },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeEntry {
    pub federation_id: FederationId,
    pub protocol: RecurringPaymentProtocol,
    pub payment_code: String,
    pub variant: PaymentCodeVariant,
}

impl_db_record!(
    key = PaymentCodeKey,
    value = PaymentCodeEntry,
    db_prefix = DbKeyPrefix::PaymentCodes,
);
impl_db_lookup!(key = PaymentCodeKey, query_prefix = PaymentCodePrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeNextInvoiceIndexKey {
    pub payment_code_id: PublicKey,
}

impl_db_record!(
    key = PaymentCodeNextInvoiceIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::PaymentCodeNextInvoiceIndex,
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeInvoiceKey {
    pub payment_code_id: PublicKey,
    pub index: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeInvoicePrefix {
    payment_code_id: PublicKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeInvoiceEntry {
    pub operation_id: OperationId,
}

impl_db_record!(
    key = PaymentCodeInvoiceKey,
    value = PaymentCodeInvoiceEntry,
    db_prefix = DbKeyPrefix::PaymentCodeInvoices,
);
impl_db_lookup!(
    key = PaymentCodeInvoiceKey,
    query_prefix = PaymentCodeInvoicePrefix
);
