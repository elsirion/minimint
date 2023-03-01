use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::config::{
    ConfigGenParams, DkgResult, ModuleConfigResponse, ModuleGenParams, ServerModuleConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::{Database, DatabaseTransaction, DatabaseVersion, MigrationMap};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiVersion, ConsensusProposal, CoreConsensusVersion, InputMeta,
    ModuleCommon, ModuleConsensusVersion, ModuleError, ModuleGen, PeerHandle,
    TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::{plugin_types_trait_impl, OutPoint, PeerId, ServerModule};
use futures::{FutureExt, StreamExt};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};
use url::Url;

use crate::config::{DummyClientConfig, DummyConfig, DummyConfigConsensus};
use crate::db::{
    migrate_dummy_db_version_0, BetRoundPrice, BetRoundPriceKey, BetRoundPriceKeyPrefix,
};
use crate::serde_json::Value;

pub mod config;
pub mod db;

const KIND: ModuleKind = ModuleKind::from_static_str("dummy");

// TODO: don't hard code, add config gen params for it
const PRICE_API: &'static str = "https://www.bitstamp.net/api/v2/ticker/btcusd/";

const BET_INTERVAL_SECS: u64 = 60;

/// Dummy module
#[derive(Debug)]
pub struct Dummy {
    pub cfg: DummyConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DummyConsensusItem {
    round: SystemTime,
    current_price_usd_per_btc: u64,
}

#[derive(Debug, Clone)]
pub struct DummyVerificationCache;

#[derive(Debug)]
pub struct DummyConfigGenerator;

#[async_trait]
impl ModuleGen for DummyConfigGenerator {
    const KIND: ModuleKind = KIND;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    fn decoder(&self) -> Decoder {
        <Dummy as ServerModule>::decoder()
    }

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[ModuleConsensusVersion(0)]
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
        _env: &BTreeMap<OsString, OsString>,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        Ok(Dummy::new(cfg.to_typed()?).into())
    }

    fn get_database_migrations(&self) -> MigrationMap {
        let mut migrations = MigrationMap::new();

        migrations.insert(DatabaseVersion(0), move |dbtx| {
            migrate_dummy_db_version_0(dbtx).boxed()
        });

        migrations
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let mint_cfg: BTreeMap<_, DummyConfig> = peers
            .iter()
            .map(|&peer| {
                let config = DummyConfig {
                    consensus: DummyConfigConsensus {
                        price_api: Url::parse(PRICE_API).expect("Is valid URL"),
                    },
                };
                (peer, config)
            })
            .collect();

        mint_cfg
            .into_iter()
            .map(|(k, v)| (k, v.to_erased()))
            .collect()
    }

    async fn distributed_gen(
        &self,
        _peers: &PeerHandle,
        _params: &ConfigGenParams,
    ) -> DkgResult<ServerModuleConfig> {
        let server = DummyConfig {
            consensus: DummyConfigConsensus {
                price_api: Url::parse(PRICE_API).expect("Is valid URL"),
            },
        };

        Ok(server.to_erased())
    }

    fn to_config_response(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ModuleConfigResponse> {
        let config = serde_json::from_value::<DummyConfigConsensus>(config)?;

        Ok(ModuleConfigResponse {
            client: config.to_client_config(),
            consensus_hash: config.consensus_hash()?,
        })
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        config.to_typed::<DummyConfig>()?.validate_config(identity)
    }

    fn hash_client_module(&self, config: Value) -> anyhow::Result<sha256::Hash> {
        serde_json::from_value::<DummyClientConfig>(config)?.consensus_hash()
    }

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyConfigGenParams {
    pub important_param: u64,
}

impl ModuleGenParams for DummyConfigGenParams {
    const MODULE_NAME: &'static str = "dummy";
}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct DummyInput;

impl fmt::Display for DummyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyInput")
    }
}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct DummyOutput;

impl fmt::Display for DummyOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutput")
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct DummyOutputOutcome;

impl fmt::Display for DummyOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutputOutcome")
    }
}

impl fmt::Display for DummyConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BTC price={}USD, round={}",
            self.current_price_usd_per_btc,
            self.round.duration_since(UNIX_EPOCH).unwrap().as_secs()
        )
    }
}

pub struct DummyModuleTypes;

impl ModuleCommon for DummyModuleTypes {
    type Input = DummyInput;
    type Output = DummyOutput;
    type OutputOutcome = DummyOutputOutcome;
    type ConsensusItem = DummyConsensusItem;
}

#[async_trait]
impl ServerModule for Dummy {
    type Common = DummyModuleTypes;
    type Gen = DummyConfigGenerator;
    type VerificationCache = DummyVerificationCache;

    fn versions(&self) -> (ModuleConsensusVersion, &[ApiVersion]) {
        (
            ModuleConsensusVersion(0),
            &[ApiVersion { major: 0, minor: 0 }],
        )
    }

    async fn await_consensus_proposal(&self, dbtx: &mut DatabaseTransaction<'_>) {
        let (next_round_time, _) = Dummy::next_bet_time(dbtx).await;
        let wait_duration = next_round_time
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::from_secs(0))
            + Duration::from_secs(1);
        info!("Waiting {}s till next bet round", wait_duration.as_secs());
        tokio::time::sleep(wait_duration).await
    }

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> ConsensusProposal<DummyConsensusItem> {
        let (next_bet_round, first_round) = Dummy::next_bet_time(dbtx).await;
        if first_round || SystemTime::now() >= next_bet_round {
            info!("Contributing price to consensus");
            let module_cis = match self.fetch_price().await {
                Some(price) => {
                    vec![DummyConsensusItem {
                        round: next_bet_round,
                        current_price_usd_per_btc: price,
                    }]
                }
                None => {
                    warn!("Didn't contribute a price although we wanted to");
                    vec![]
                }
            };
            ConsensusProposal::Trigger(module_cis)
        } else {
            ConsensusProposal::Contribute(vec![])
        }
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_items: Vec<(PeerId, DummyConsensusItem)>,
    ) {
        // FIXME: insecure, need to check that we actually expect contributions for that
        // round
        let rounds = consensus_items
            .into_iter()
            .map(|(_peer, ci)| ci)
            .into_group_map_by(|ci| ci.round);

        for (round, cis) in rounds {
            // FIXME: insecure, check that there are at least t contributions

            // Calculate the median, ensures that for >=t contributions the
            // result lies between (inclusive) the contributions of two honest
            // guardians
            let mut prices = cis
                .into_iter()
                .map(|ci| ci.current_price_usd_per_btc)
                .collect::<Vec<_>>();
            prices.sort();
            let price = prices[prices.len() / 2];

            if dbtx
                .insert_new_entry(
                    &BetRoundPriceKey { round },
                    &BetRoundPrice {
                        price_usd_per_btc: price,
                    },
                )
                .await
                .expect("DB error")
                .is_some()
            {
                // FIXME: should never happen, see fixme above
                warn!("Overwriting old bet price");
            }
        }
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a DummyInput> + Send,
    ) -> Self::VerificationCache {
        DummyVerificationCache
    }

    async fn validate_input<'a, 'b>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        _dbtx: &mut DatabaseTransaction<'b>,
        _verification_cache: &Self::VerificationCache,
        _input: &'a DummyInput,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        _interconnect: &'a dyn ModuleInterconect,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b DummyInput,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn validate_output(
        &self,
        _dbtx: &mut DatabaseTransaction,
        _output: &DummyOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a DummyOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        _consensus_peers: &HashSet<PeerId>,
        _dbtx: &mut DatabaseTransaction<'b>,
    ) -> Vec<PeerId> {
        vec![]
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<DummyOutputOutcome> {
        None
    }

    async fn audit(&self, _dbtx: &mut DatabaseTransaction<'_>, _audit: &mut Audit) {}

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![api_endpoint! {
            "/last_bet",
            async |_module: &Dummy, dbtx, _request: ()| -> Option<BetOutcome> {
                Ok(Dummy::last_bet_outcome(dbtx).await)
            }
        }]
    }
}

impl Dummy {
    /// Create new module instance
    pub fn new(cfg: DummyConfig) -> Dummy {
        Dummy { cfg }
    }

    pub async fn next_bet_time(dbtx: &mut DatabaseTransaction<'_>) -> (SystemTime, bool) {
        // TODO: don't query all rounds just to get the next one
        let all_round_times: Vec<SystemTime> = dbtx
            .find_by_prefix(&BetRoundPriceKeyPrefix)
            .await
            .map(|kvres| {
                let (k, _v) = kvres.expect("DB error");
                k.round
            })
            .collect()
            .await;

        let maybe_last_round = all_round_times.into_iter().max();
        let first_round = maybe_last_round.is_none();
        let last_round = maybe_last_round.unwrap_or_else(|| {
            let current_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let theoretical_last_round_timestamp =
                (current_timestamp / BET_INTERVAL_SECS) * BET_INTERVAL_SECS;
            UNIX_EPOCH + Duration::from_secs(theoretical_last_round_timestamp)
        });

        (
            last_round + Duration::from_secs(BET_INTERVAL_SECS),
            first_round,
        )
    }

    pub async fn last_bet_outcome(dbtx: &mut DatabaseTransaction<'_>) -> Option<BetOutcome> {
        let mut all_rounds: Vec<(SystemTime, u64)> = dbtx
            .find_by_prefix(&BetRoundPriceKeyPrefix)
            .await
            .map(|kvres| {
                let (k, v) = kvres.expect("DB error");
                (k.round, v.price_usd_per_btc)
            })
            .collect()
            .await;

        all_rounds.sort_by(|(round1, _), (round2, _)| round1.cmp(round2));

        all_rounds.last().map(|(round, price)| BetOutcome {
            round: *round,
            price_usd_per_btc: *price,
        })
    }

    async fn fetch_price(&self) -> Option<u64> {
        let api_response = reqwest::get(self.cfg.consensus.price_api.clone())
            .await
            .map_err(|err| warn!(%err, "API returned error"))
            .ok()?;

        let value: serde_json::Value = api_response
            .json()
            .await
            .map_err(|err| warn!(%err, "API returned invalid json"))
            .ok()?;

        debug!(?value, "Price API response");

        value.get("last")?.as_str()?.parse().ok()
    }
}

plugin_types_trait_impl!(
    DummyInput,
    DummyOutput,
    DummyOutputOutcome,
    DummyConsensusItem,
    DummyVerificationCache
);

#[derive(Debug, Serialize, Deserialize)]
pub struct BetOutcome {
    round: SystemTime,
    price_usd_per_btc: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum DummyError {
    #[error("Something went wrong")]
    SomethingDummyWentWrong,
}
