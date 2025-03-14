use std::collections::BTreeMap;
use std::path::PathBuf;

use erased_serde::Serialize;
use fedimint_core::config::ServerModuleGenRegistry;
use fedimint_core::db::notifications::Notifications;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersionKey, SingleUseDatabaseTransaction};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::DynServerModuleGen;
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{push_db_key_items, push_db_pair_items, push_db_pair_items_no_serde};
use fedimint_ln_server::LightningGen;
use fedimint_mint_server::MintGen;
use fedimint_rocksdb::RocksDbReadOnly;
use fedimint_server::config::io::read_server_config;
use fedimint_server::config::ServerConfig;
use fedimint_server::db as ConsensusRange;
use fedimint_wallet_server::WalletGen;
use futures::StreamExt;
use mint_client::db as ClientRange;
use mint_client::ln::db as ClientLightningRange;
use mint_client::mint::db as ClientMintRange;
use mint_client::wallet::db as ClientWalletRange;
use strum::IntoEnumIterator;

#[derive(Debug, serde::Serialize)]
struct SerdeWrapper(#[serde(with = "hex::serde")] Vec<u8>);

impl SerdeWrapper {
    fn from_encodable<T: Encodable>(e: T) -> SerdeWrapper {
        let mut bytes = vec![];
        e.consensus_encode(&mut bytes)
            .expect("Write to vec can't fail");
        SerdeWrapper(bytes)
    }
}

/// Structure to hold the deserialized structs from the database.
/// Also includes metadata on which sections of the database to read.
pub struct DatabaseDump<'a> {
    serialized: BTreeMap<String, Box<dyn Serialize>>,
    read_only: DatabaseTransaction<'a>,
    modules: Vec<String>,
    prefixes: Vec<String>,
    cfg: Option<ServerConfig>,
    module_inits: ServerModuleGenRegistry,
}

impl<'a> DatabaseDump<'a> {
    pub fn new(
        cfg_dir: PathBuf,
        data_dir: String,
        password: String,
        modules: Vec<String>,
        prefixes: Vec<String>,
    ) -> DatabaseDump<'a> {
        let read_only = match RocksDbReadOnly::open_read_only(data_dir) {
            Ok(db) => db,
            Err(_) => {
                panic!("Error reading RocksDB database. Quitting...");
            }
        };
        let single_use = SingleUseDatabaseTransaction::new(read_only);

        // leak here is OK, it only happens once.
        let notifications = Box::leak(Box::new(Notifications::new()));
        if modules.contains(&"client".to_string()) {
            let dbtx = DatabaseTransaction::new(
                Box::new(single_use),
                ModuleDecoderRegistry::default(),
                notifications,
            );
            return DatabaseDump {
                serialized: BTreeMap::new(),
                read_only: dbtx,
                modules,
                prefixes,
                cfg: None,
                module_inits: Default::default(),
            };
        }

        let module_inits = ServerModuleGenRegistry::from(vec![
            DynServerModuleGen::from(WalletGen),
            DynServerModuleGen::from(MintGen),
            DynServerModuleGen::from(LightningGen),
        ]);

        let cfg = read_server_config(&password, cfg_dir).unwrap();
        let decoders = module_inits.decoders(cfg.iter_module_instances()).unwrap();
        let dbtx = DatabaseTransaction::new(Box::new(single_use), decoders, notifications);

        DatabaseDump {
            serialized: BTreeMap::new(),
            read_only: dbtx,
            modules,
            prefixes,
            cfg: Some(cfg),
            module_inits,
        }
    }
}

impl<'a> DatabaseDump<'a> {
    /// Prints the contents of the BTreeMap to a pretty JSON string
    fn print_database(&self) {
        let json = serde_json::to_string_pretty(&self.serialized).unwrap();
        println!("{json}");
    }

    /// Iterates through all the specified ranges in the database and retrieves
    /// the data for each range. Prints serialized contents at the end.
    pub async fn dump_database(&mut self) {
        if self.modules.is_empty() || self.modules.contains(&"consensus".to_string()) {
            self.retrieve_consensus_data().await;
        }

        let cfg = &self.cfg;
        if let Some(cfg) = cfg {
            for (module_id, module_cfg) in &cfg.consensus.modules {
                let kind = module_cfg.kind();

                let Some(init) = self.module_inits.get(kind) else {
                    panic!("Detected configuration for unsupported module kind: {kind}")
                };

                if !self.modules.is_empty() && !self.modules.contains(&kind.to_string()) {
                    continue;
                }

                let mut isolated_dbtx = self.read_only.with_module_prefix(*module_id);
                let mut module_serialized = init
                    .dump_database(&mut isolated_dbtx, self.prefixes.clone())
                    .await
                    .collect::<BTreeMap<String, _>>();

                let db_version = isolated_dbtx.get_value(&DatabaseVersionKey).await;
                if let Some(db_version) = db_version {
                    module_serialized.insert("Version".to_string(), Box::new(db_version));
                } else {
                    module_serialized
                        .insert("Version".to_string(), Box::new("Not Specified".to_string()));
                }

                self.serialized
                    .insert(format!("{kind}-{module_id}"), Box::new(module_serialized));
            }
        }

        // TODO: When the client is modularized, these don't need to be hardcoded
        // anymore
        if !self.modules.is_empty() && self.modules.contains(&"client".to_string()) {
            self.retrieve_client_data().await;
            self.retrieve_ln_client_data().await;
            self.retrieve_mint_client_data().await;
            self.retrieve_wallet_client_data().await;
        }

        self.print_database();
    }

    /// Iterates through each of the prefixes within the consensus range and
    /// retrieves the corresponding data.
    async fn retrieve_consensus_data(&mut self) {
        let mut consensus: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        let dbtx = &mut self.read_only;
        let prefix_names = &self.prefixes;

        let filtered_prefixes = ConsensusRange::DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });
        for table in filtered_prefixes {
            match table {
                ConsensusRange::DbKeyPrefix::AcceptedTransaction => {
                    push_db_pair_items_no_serde!(
                        dbtx,
                        ConsensusRange::AcceptedTransactionKeyPrefix,
                        ConsensusRange::AcceptedTransactionKey,
                        fedimint_server::consensus::AcceptedTransaction,
                        consensus,
                        "Accepted Transactions"
                    );
                }
                ConsensusRange::DbKeyPrefix::DropPeer => {
                    push_db_key_items!(
                        dbtx,
                        ConsensusRange::DropPeerKeyPrefix,
                        ConsensusRange::DropPeerKey,
                        consensus,
                        "Dropped Peers"
                    );
                }
                ConsensusRange::DbKeyPrefix::RejectedTransaction => {
                    push_db_pair_items!(
                        dbtx,
                        ConsensusRange::RejectedTransactionKeyPrefix,
                        ConsensusRange::RejectedTransactionKey,
                        String,
                        consensus,
                        "Rejected Transactions"
                    );
                }
                ConsensusRange::DbKeyPrefix::EpochHistory => {
                    push_db_pair_items_no_serde!(
                        dbtx,
                        ConsensusRange::EpochHistoryKeyPrefix,
                        ConsensusRange::EpochHistoryKey,
                        fedimint_core::epoch::EpochHistory,
                        consensus,
                        "Epoch History"
                    );
                }
                ConsensusRange::DbKeyPrefix::LastEpoch => {
                    let last_epoch = dbtx.get_value(&ConsensusRange::LastEpochKey).await;
                    if let Some(last_epoch) = last_epoch {
                        consensus.insert("LastEpoch".to_string(), Box::new(last_epoch));
                    }
                }
                ConsensusRange::DbKeyPrefix::ClientConfigSignature => {
                    push_db_pair_items!(
                        dbtx,
                        ConsensusRange::ClientConfigSignatureKeyPrefix,
                        ConsensusRange::ClientConfigSignatureKey,
                        fedimint_core::epoch::SerdeSignature,
                        consensus,
                        "Client Config Signature"
                    );
                }
                ConsensusRange::DbKeyPrefix::ConsensusUpgrade => {
                    let shutdown = dbtx.get_value(&ConsensusRange::ConsensusUpgradeKey).await;
                    if let Some(shutdown) = shutdown {
                        consensus.insert("ShutdownSignal".to_string(), Box::new(shutdown));
                    }
                }
                // Module is a global prefix for all module data
                ConsensusRange::DbKeyPrefix::Module => {}
            }
        }

        self.serialized
            .insert("Consensus".to_string(), Box::new(consensus));
    }

    /// Iterates through each of the prefixes within the lightning client range
    /// and retrieves the corresponding data.
    async fn retrieve_ln_client_data(&mut self) {
        let mut ln_client: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        let dbtx = &mut self.read_only;
        let prefix_names = &self.prefixes;
        let filtered_prefixes = ClientLightningRange::DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });
        for table in filtered_prefixes {
            match table {
                ClientLightningRange::DbKeyPrefix::ConfirmedInvoice => {
                    push_db_pair_items!(
                        dbtx,
                        ClientLightningRange::ConfirmedInvoiceKeyPrefix,
                        ClientLightningRange::ConfirmedInvoiceKey,
                        mint_client::ln::incoming::ConfirmedInvoice,
                        ln_client,
                        "Confirmed Invoices"
                    );
                }
                ClientLightningRange::DbKeyPrefix::LightningGateway => {
                    push_db_pair_items!(
                        dbtx,
                        ClientLightningRange::LightningGatewayKeyPrefix,
                        ClientLightningRange::LightningGatewayKey,
                        fedimint_ln_server::common::LightningGateway,
                        ln_client,
                        "Lightning Gateways"
                    );
                }
                ClientLightningRange::DbKeyPrefix::OutgoingContractAccount => {
                    push_db_pair_items!(
                        dbtx,
                        ClientLightningRange::OutgoingContractAccountKeyPrefix,
                        ClientLightningRange::OutgoingContractAccountKey,
                        mint_client::ln::outgoing::OutgoingContractAccount,
                        ln_client,
                        "Outgoing Contract Accounts"
                    );
                }
                ClientLightningRange::DbKeyPrefix::OutgoingPayment => {
                    push_db_pair_items!(
                        dbtx,
                        ClientLightningRange::OutgoingPaymentKeyPrefix,
                        ClientLightningRange::OutgoingPaymentKey,
                        mint_client::ln::outgoing::OutgoingContractData,
                        ln_client,
                        "Outgoing Payments"
                    );
                }
                ClientLightningRange::DbKeyPrefix::OutgoingPaymentClaim => {
                    push_db_key_items!(
                        dbtx,
                        ClientLightningRange::OutgoingPaymentClaimKeyPrefix,
                        ClientLightningRange::OutgoingPaymentClaimKey,
                        ln_client,
                        "Outgoing Payment Claims"
                    );
                }
            }
        }

        self.serialized
            .insert("Client Lightning".to_string(), Box::new(ln_client));
    }

    /// Iterates through each of the prefixes within the mint client range and
    /// retrieves the corresponding data.
    async fn retrieve_mint_client_data(&mut self) {
        let mut mint_client: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        let dbtx = &mut self.read_only;
        let prefix_names = &self.prefixes;
        let filtered_prefixes = ClientMintRange::DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });
        for table in filtered_prefixes {
            match table {
                ClientMintRange::DbKeyPrefix::Note => {
                    push_db_pair_items!(
                        dbtx,
                        ClientMintRange::NoteKeyPrefix,
                        ClientMintRange::NoteKey,
                        mint_client::mint::SpendableNote,
                        mint_client,
                        "Notes"
                    );
                }
                ClientMintRange::DbKeyPrefix::OutputFinalizationData => {
                    push_db_pair_items!(
                        dbtx,
                        ClientMintRange::OutputFinalizationKeyPrefix,
                        ClientMintRange::OutputFinalizationKey,
                        mint_client::mint::NoteIssuanceRequests,
                        mint_client,
                        "Output Finalization"
                    );
                }
                ClientMintRange::DbKeyPrefix::PendingNotes => {
                    push_db_pair_items!(
                        dbtx,
                        ClientMintRange::PendingNotesKeyPrefix,
                        ClientMintRange::PendingNotesKey,
                        fedimint_core::TieredMulti<mint_client::mint::SpendableNote>,
                        mint_client,
                        "Pending Notes"
                    );
                }
                ClientMintRange::DbKeyPrefix::NextECashNoteIndex => {
                    push_db_pair_items!(
                        dbtx,
                        ClientMintRange::NextECashNoteIndexKeyPrefix,
                        ClientMintRange::NextECashNoteIndexKey,
                        u64,
                        mint_client,
                        "Last e-cash note index"
                    );
                }
                ClientMintRange::DbKeyPrefix::NotesPerDenomination => {
                    let notes = dbtx
                        .get_value(&ClientMintRange::NotesPerDenominationKey)
                        .await;
                    if let Some(notes) = notes {
                        mint_client.insert("NotesPerDenomination".to_string(), Box::new(notes));
                    }
                }
            }
        }

        self.serialized
            .insert("Client Mint".to_string(), Box::new(mint_client));
    }

    /// Iterates through each of the prefixes within the wallet client range and
    /// retrieves the corresponding data.
    async fn retrieve_wallet_client_data(&mut self) {
        let mut wallet_client: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        let dbtx = &mut self.read_only;
        let prefix_names = &self.prefixes;
        let filtered_prefixes = ClientWalletRange::DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });
        for table in filtered_prefixes {
            match table {
                ClientWalletRange::DbKeyPrefix::PegIn => {
                    push_db_pair_items!(
                        dbtx,
                        ClientWalletRange::PegInPrefixKey,
                        ClientWalletRange::PegInKey,
                        [u8; 32],
                        wallet_client,
                        "Peg Ins"
                    );
                }
            }
        }

        self.serialized
            .insert("Client Wallet".to_string(), Box::new(wallet_client));
    }

    /// Iterates through each of the prefixes within the client range and
    /// retrieves the corresponding data.
    async fn retrieve_client_data(&mut self) {
        let mut client: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        let prefix_names = &self.prefixes;
        let filtered_prefixes = ClientRange::DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                ClientRange::DbKeyPrefix::ClientSecret => {
                    let secret = self
                        .read_only
                        .get_value(&ClientRange::ClientSecretKey)
                        .await;
                    if let Some(secret) = secret {
                        client.insert("Client Secret".to_string(), Box::new(secret));
                    }
                }
            }
        }

        self.serialized
            .insert("Client".to_string(), Box::new(client));
    }
}
