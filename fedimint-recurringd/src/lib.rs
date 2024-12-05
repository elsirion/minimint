//TODO:remove
#![allow(dead_code, unused_variables)]

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::{Client, ClientHandleArc, ClientModuleInstance};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped, IRawDatabase};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::secp256k1::hashes::sha256;
use fedimint_core::secp256k1::{All, Secp256k1};
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, BitcoinHash};
use fedimint_ln_client::recurring::{
    PaymentCodeId, RecurringPaymentError, RecurringPaymentProtocol,
};
use fedimint_ln_client::{LightningClientModule, LnReceiveState};
use futures::StreamExt;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Sha256};
use lnurl::lnurl::LnUrl;
use tokio::sync::RwLock;

use crate::db::{
    add_federation_database, load_federation_client_databases, PaymentCodeEntry,
    PaymentCodeInvoiceEntry, PaymentCodeInvoiceKey, PaymentCodeKey, PaymentCodeNextInvoiceIndexKey,
    PaymentCodeVariant,
};

mod db;

#[derive(Clone)]
pub struct RecurringInvoiceServer {
    db: Database,
    clients: Arc<RwLock<HashMap<FederationId, ClientHandleArc>>>,
    base_url: SafeUrl,
    secp_ctx: Secp256k1<All>,
}

impl RecurringInvoiceServer {
    pub async fn new(db: impl IRawDatabase + 'static, base_url: SafeUrl) -> anyhow::Result<Self> {
        let db = Database::new(db, Default::default());

        let mut clients = HashMap::<_, ClientHandleArc>::new();

        for (federation_id, db) in load_federation_client_databases(&db).await {
            let client = Client::builder(db)
                .await?
                .open(Self::default_secret())
                .await?;
            clients.insert(federation_id, Arc::new(client));
        }

        Ok(Self {
            db,
            clients: Arc::new(RwLock::new(clients)),
            base_url,
            secp_ctx: Default::default(),
        })
    }

    /// We don't want to hold any money or sign anything ourselves, we only use
    /// the client with externally supplied key material and to track
    /// ongoing progress of other users' receives.
    fn default_secret() -> DerivableSecret {
        DerivableSecret::new_root(&[], &[])
    }

    pub async fn register_federation(
        &self,
        invite_code: &InviteCode,
    ) -> Result<(), RecurringPaymentError> {
        let federation_id = invite_code.federation_id();

        // We lock to prevent parallel join attempts
        // TODO: lock per federation
        let mut clients = self.clients.write().await;
        if clients.contains_key(&federation_id) {
            return Err(RecurringPaymentError::FederationAlreadyRegistered(
                federation_id,
            ));
        }

        let db = add_federation_database(&self.db, invite_code.federation_id()).await;
        let client = Client::builder(db)
            .await?
            .open(Self::default_secret())
            .await?;
        clients.insert(federation_id, Arc::new(client));

        Ok(())
    }

    pub async fn register_recurring_payment_code(
        &self,
        federation_id: FederationId,
        payment_code_id: PaymentCodeId,
        protocol: RecurringPaymentProtocol,
    ) -> Result<String, RecurringPaymentError> {
        if protocol != RecurringPaymentProtocol::LNURL {
            return Err(RecurringPaymentError::UnsupportedProtocol(protocol));
        }

        // TODO: support BOLT12
        let payment_code = self.create_lnurl(payment_code_id);

        let mut dbtx = self.db.begin_transaction().await;
        if dbtx
            .insert_entry(
                &PaymentCodeKey {
                    payment_code: payment_code_id.0,
                },
                &PaymentCodeEntry {
                    federation_id,
                    protocol,
                    payment_code: payment_code.clone(),
                    variant: PaymentCodeVariant::Lnurl {
                        // TODO: put useful info here
                        meta: "[]".to_string(),
                    },
                },
            )
            .await
            .is_some()
        {
            return Err(RecurringPaymentError::PaymentCodeAlreadyExists(
                payment_code_id,
            ));
        }
        dbtx.commit_tx().await;

        Ok(payment_code)
    }

    fn create_lnurl(&self, payment_code_id: PaymentCodeId) -> String {
        let lnurl = LnUrl::from_url(
            self.base_url
                .join("paycodes") // TODO: use a constant
                .expect("join works")
                .join(&payment_code_id.to_string())
                .expect("join works")
                .to_string(),
        );
        lnurl.encode()
    }

    pub async fn create_bolt11_invoice(
        &self,
        payment_code_id: PaymentCodeId,
        amount: Amount,
    ) -> Result<Bolt11Invoice, RecurringPaymentError> {
        // Invoices are valid for one day by default, might become dynamic with BOLT12
        // support
        const DEFAULT_EXPIRY_TIME: u64 = 60 * 60 * 24;

        let payment_code = self
            .db
            .begin_transaction_nc()
            .await
            .get_value(&PaymentCodeKey {
                payment_code: payment_code_id.0,
            })
            .await
            .ok_or(RecurringPaymentError::UnknownPaymentCode(payment_code_id))?;
        let invoice_index = self.get_next_invoice_index(payment_code_id).await;

        let federation_client = self
            .get_federation_client(payment_code.federation_id)
            .await?;
        let federation_client_ln_module = federation_client
            .get_first_module::<LightningClientModule>()
            .map_err(|_| RecurringPaymentError::NoLightningModuleFound)?;

        let gateway = federation_client_ln_module
            .get_gateway(None, false)
            .await?
            .ok_or(RecurringPaymentError::NoGatewayFound)?;

        let lnurl_meta = match payment_code.variant {
            PaymentCodeVariant::Lnurl { meta } => meta,
        };
        let meta_hash = Sha256(sha256::Hash::hash(lnurl_meta.as_bytes()));
        let description = Bolt11InvoiceDescription::Hash(&meta_hash);

        // TODO: ideally creating the invoice would take a dbtx as argument so we don't
        // get holes in our used indexes in case this function fails/is cancelled
        let (operation_id, invoice, _preimage) = federation_client_ln_module
            .create_bolt11_invoice_for_user_tweaked(
                amount,
                description,
                Some(DEFAULT_EXPIRY_TIME),
                payment_code_id.0,
                invoice_index,
                serde_json::Value::Null,
                Some(gateway),
            )
            .await?;

        let mut dbtx = self.db.begin_transaction().await;
        dbtx.insert_new_entry(
            &PaymentCodeInvoiceKey {
                payment_code_id: payment_code_id.0,
                index: invoice_index,
            },
            &PaymentCodeInvoiceEntry { operation_id },
        )
        .await;
        dbtx.commit_tx().await;

        await_invoice_confirmed(&federation_client_ln_module, operation_id).await?;

        Ok(invoice)
    }

    async fn get_federation_client(
        &self,
        federation_id: FederationId,
    ) -> Result<ClientHandleArc, RecurringPaymentError> {
        self.clients
            .read()
            .await
            .get(&federation_id)
            .cloned()
            .ok_or(RecurringPaymentError::UnknownFederationId(federation_id))
    }

    async fn get_next_invoice_index(&self, payment_code_id: PaymentCodeId) -> u64 {
        self.db
            .autocommit(
                |dbtx, _| {
                    Box::pin(async move {
                        let next_index = dbtx
                            .get_value(&PaymentCodeNextInvoiceIndexKey {
                                payment_code_id: payment_code_id.0,
                            })
                            .await
                            .map(|index| index + 1)
                            .unwrap_or(0);
                        dbtx.insert_entry(
                            &PaymentCodeNextInvoiceIndexKey {
                                payment_code_id: payment_code_id.0,
                            },
                            &next_index,
                        )
                        .await;
                        Result::<_, ()>::Ok(next_index)
                    })
                },
                None,
            )
            .await
            .expect("Loops forever and never returns errors internally")
    }
}

async fn await_invoice_confirmed(
    ln_module: &ClientModuleInstance<'_, LightningClientModule>,
    operation_id: OperationId,
) -> Result<(), RecurringPaymentError> {
    let mut operation_updated = ln_module
        .subscribe_ln_receive(operation_id)
        .await?
        .into_stream();

    while let Some(update) = operation_updated.next().await {
        if matches!(update, LnReceiveState::AwaitingFunds) {
            return Ok(());
        }
    }

    Err(RecurringPaymentError::Other(anyhow!(
        "BOLT11 invoice not confirmed"
    )))
}
