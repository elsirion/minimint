mod db;

use crate::db::{
    BetResolutionKey, BetResolutionKeyPrefix, BetResolutionProposalKey,
    BetResolutionProposalKeyPrefix, ResolvedBet, UserBetKey, UserBetKeyPrefix,
};
use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_api::config::GenerateConfig;
use fedimint_api::db::batch::BatchTx;
use fedimint_api::db::{Database, DatabaseTransaction};
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::module::__reexports::serde_json;
use fedimint_api::module::audit::Audit;
use fedimint_api::module::interconnect::ModuleInterconect;
use fedimint_api::module::{
    api_endpoint, ApiEndpoint, ApiError, FederationModule, TransactionItemAmount,
};
use fedimint_api::net::peers::AnyPeerConnections;
use fedimint_api::{Amount, InputMeta, NumPeers, OutPoint, PeerId};
use rand::{CryptoRng, RngCore};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use tracing::warn;

pub struct TabconfModule {
    db: Database,
    cfg: TabconfConfig,
}

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct TabconfConfig {
    pub our_id: PeerId,
    pub peers: Vec<PeerId>,
    pub bet_size: Amount,
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct PlaceBet {
    pub resolve_consensus_height: u64,
    pub predicted_moscow_time: u64,
    pub pub_key: XOnlyPublicKey,
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct RedeemPrize {
    pub resolve_consensus_height: u64,
    pub amount: Amount,
}

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct BetResolutionProposal {
    consensus_height: u64,
    moscow_time: u64,
}

impl TabconfModule {
    pub fn new(cfg: TabconfConfig, db: Database) -> Self {
        TabconfModule { db, cfg }
    }

    fn last_resolved_bet_height(&self) -> u64 {
        self.db
            .find_by_prefix(&BetResolutionKeyPrefix)
            .map(|res| res.expect("DB error").0.resolve_consensus_height)
            .max()
            .unwrap_or(0)
    }

    async fn should_resolve(&self, interconnect: &dyn ModuleInterconect) -> bool {
        let consensus_block_height = block_height(interconnect).await as u64;
        let last_resolved_consensus_block_height = self.last_resolved_bet_height();

        if last_resolved_consensus_block_height == consensus_block_height {
            return false;
        }

        let we_proposed = self
            .db
            .get_value(&BetResolutionProposalKey {
                resolve_consensus_height: consensus_block_height,
                peer: self.cfg.our_id,
            })
            .expect("DB error")
            .is_none();

        we_proposed
    }

    fn propose_resolution(&self) -> BetResolutionProposal {
        unimplemented!()
    }

    fn get_bet_resolution(&self, consensus_height: u64) -> Option<ResolvedBet> {
        self.db
            .get_value(&BetResolutionKey {
                resolve_consensus_height: consensus_height,
            })
            .expect("DB error")
    }
}

#[async_trait(?Send)]
impl FederationModule for TabconfModule {
    type Error = anyhow::Error;
    type TxInput = RedeemPrize;
    type TxOutput = PlaceBet;
    type TxOutputOutcome = ();
    type ConsensusItem = BetResolutionProposal;
    type VerificationCache = ();

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal<'a>(
        &'a self,
        _interconnect: &dyn ModuleInterconect,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
        // Wait forever since there is no functionality yet that should trigger a new epoch
        std::future::pending().await
    }

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal<'a>(
        &'a self,
        interconnect: &dyn ModuleInterconect,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem> {
        if self.should_resolve(interconnect) {
            vec![self.propose_resolution()]
        } else {
            vec![]
        }
    }

    /// This function is called once before transaction processing starts. All module consensus
    /// items of this round are supplied as `consensus_items`. The batch will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the results are available
    /// when processing transactions.
    async fn begin_consensus_epoch<'a>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'a>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
        for (peer, ci) in consensus_items {
            if dbtx
                .get_value(&BetResolutionKey {
                    resolve_consensus_height: ci.consensus_height,
                })
                .expect("DB error")
                .is_some()
            {
                warn!(?peer, "Bet already resolved");
                continue;
            }

            if dbtx
                .get_value(&BetResolutionProposalKey {
                    resolve_consensus_height: ci.consensus_height,
                    peer,
                })
                .expect("DB error")
                .is_some()
            {
                warn!(?peer, "Peer already contributed to bet resolution");
                continue;
            }

            dbtx.insert_entry(
                &BetResolutionProposalKey {
                    resolve_consensus_height: ci.consensus_height,
                    peer,
                },
                &ci,
            )
        }

        let height_to_resolve = self.last_resolved_bet_height() + 1;
        let mut resolution_proposals = dbtx
            .find_by_prefix(&BetResolutionProposalKeyPrefix {
                resolve_consensus_height: height_to_resolve,
            })
            .map(|res| res.expect("DB error").1.moscow_time)
            .collect::<Vec<_>>();

        if resolution_proposals.len() >= self.cfg.peers.max_evil() {
            resolution_proposals.sort();
            let consensus_moscow_time = resolution_proposals[resolution_proposals.len() / 2];

            let user_proposals = dbtx
                .find_by_prefix(&UserBetKeyPrefix {
                    resolve_consensus_height: height_to_resolve,
                })
                .map(|res| {
                    let (key, value) = res.expect("DB error");
                    let error = key.moscow_time.abs_diff(consensus_moscow_time);
                    (error, key.moscow_time, value)
                })
                .collect::<Vec<_>>();

            dbtx.insert_entry(
                &BetResolutionKey {
                    resolve_consensus_height: height_to_resolve,
                },
                ResolvedBet {
                    winner: (),
                    user_moscow_time: 0,
                    consensus_moscow_time,
                    prize: Amount {},
                    paid_out: false,
                },
            )
        }
    }

    /// Some modules may have slow to verify inputs that would block transaction processing. If the
    /// slow part of verification can be modeled as a pure function not involving any system state
    /// we can build a lookup table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a Self::TxInput> + Send,
    ) -> Self::VerificationCache {
    }

    /// Validate a transaction input before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_input<'a>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        _verification_cache: &Self::VerificationCache,
        input: &'a Self::TxInput,
    ) -> Result<InputMeta<'a>, Self::Error> {
        let resolved_bet = self
            .db
            .get_value(&BetResolutionKey {
                resolve_consensus_height: input.resolve_consensus_height,
            })
            .expect("DB error")
            .ok_or(anyhow!("Bet not resolved yet or doesn't exist!"))?;

        if resolved_bet.paid_out {
            return Err(anyhow!("Prize has already been claimed"));
        }

        if resolved_bet.prize != input.amount {
            return Err(anyhow!(
                "Prize is {}, tried to claim {}",
                resolved_bet.prize,
                input.amount
            ));
        }

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.amount,
                fee: Amount::ZERO,
            },
            puk_keys: Box::new(std::iter::once(resolved_bet.winner)),
        })
    }

    /// Try to spend a transaction input. On success all necessary updates will be part of the
    /// database `batch`. On failure (e.g. double spend) the batch is reset and the operation will
    /// take no effect.
    ///
    /// This function may only be called after `begin_consensus_epoch` and before
    /// `end_consensus_epoch`. Data is only written to the database once all transaction have been
    /// processed.
    fn apply_input<'a, 'b>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        mut batch: BatchTx<'a>,
        input: &'b Self::TxInput,
        verification_cache: &Self::VerificationCache,
    ) -> Result<InputMeta<'b>, Self::Error> {
        // We always want to verify inputs, but apart from that there's nothing to do yet
        let meta = self.validate_input(interconnect, verification_cache, input)?;

        let bet_key = BetResolutionKey {
            resolve_consensus_height: input.resolve_consensus_height,
        };
        let mut resolved_bet = self
            .db
            .get_value(&bet_key)
            .expect("DB error")
            .ok_or(anyhow!("Bet not resolved yet or doesn't exist!"))?;
        resolved_bet.paid_out = true;
        batch.append_insert(bet_key, resolved_bet);

        batch.commit();
        Ok(meta)
    }

    /// Validate a transaction output before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_output(
        &self,
        output: &Self::TxOutput,
    ) -> Result<TransactionItemAmount, Self::Error> {
        if self
            .db
            .get_value(&UserBetKey {
                resolve_consensus_height: output.resolve_consensus_height,
                moscow_time: output.predicted_moscow_time,
            })
            .expect("DB error")
            .is_some()
        {
            return Err(anyhow!(
                "A bet already exists at this price, please choose another one"
            ));
        }

        // TODO: make sure block height is in the future

        Ok(TransactionItemAmount {
            amount: self.cfg.bet_size,
            fee: Amount::ZERO,
        })
    }

    /// Try to create an output (e.g. issue coins, peg-out BTC, …). On success all necessary updates
    /// to the database will be part of the `batch`. On failure (e.g. double spend) the batch is
    /// reset and the operation will take no effect.
    ///
    /// The supplied `out_point` identifies the operation (e.g. a peg-out or coin issuance) and can
    /// be used to retrieve its outcome later using `output_status`.
    ///
    /// This function may only be called after `begin_consensus_epoch` and before
    /// `end_consensus_epoch`. Data is only written to the database once all transactions have been
    /// processed.
    fn apply_output<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        output: &'a Self::TxOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, Self::Error> {
        // We always want to verify outputs, but apart from that there's nothing to do yet
        let amount = self.validate_output(output)?;

        batch.append_insert(
            UserBetKey {
                resolve_consensus_height: output.resolve_consensus_height,
                moscow_time: output.predicted_moscow_time,
            },
            output.pub_key,
        );

        batch.commit();
        Ok(amount)
    }

    /// This function is called once all transactions have been processed and changes were written
    /// to the database. This allows running finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and returns a list of peers
    /// to drop if any are misbehaving.
    async fn end_consensus_epoch<'a>(
        &'a self,
        _consensus_peers: &HashSet<PeerId>,
        _batch: BatchTx<'a>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<PeerId> {
        // Nothing to do, so we also don't need to drop peers
        vec![]
    }

    /// Retrieve the current status of the output. Depending on the module this might contain data
    /// needed by the client to access funds or give an estimate of when funds will be available.
    /// Returns `None` if the output is unknown, **NOT** if it is just not ready yet.
    fn output_status(&self, _out_point: OutPoint) -> Option<Self::TxOutputOutcome> {
        // We don't process outputs yet
        None
    }

    /// Queries the database and returns all assets and liabilities of the module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has occurred in the database
    /// and consensus should halt.
    fn audit(&self, _audit: &mut Audit) {
        // We don't represent value in this module yet
    }

    /// Defines the prefix for API endpoints defined by the module.
    ///
    /// E.g. if the module's base path is `foo` and it defines API endpoints `bar` and `baz` then
    /// these endpoints will be reachable under `/foo/bar` and `/foo/baz`.
    fn api_base_name(&self) -> &'static str {
        "tabconf"
    }

    /// Returns a list of custom API endpoints defined by the module. These are made available both
    /// to users as well as to other modules. They thus should be deterministic, only dependant on
    /// their input and the current epoch.
    fn api_endpoints(&self) -> &'static [ApiEndpoint<Self>] {
        &[api_endpoint! {
            "/bet",
            async |module: &TabconfModule, consensus_height: u64| -> ResolvedBet {
                module.get_bet_resolution(consensus_height).ok_or_else(|| ApiError {
                    code: 404,
                    message: "Bet not resolved or unknown".to_string()
                })
            }
        }]
    }
}

#[async_trait(?Send)]
impl GenerateConfig for TabconfConfig {
    type Params = Amount;
    type ClientConfig = Self;
    type ConfigMessage = ();
    type ConfigError = ();

    fn trusted_dealer_gen(
        peers: &[PeerId],
        params: &Self::Params,
        _rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let cfg = TabconfConfig { bet_size: *params };
        (peers.iter().map(|&peer| (peer, cfg)).collect(), cfg)
    }

    fn to_client_config(&self) -> Self::ClientConfig {
        self.clone()
    }

    fn validate_config(&self, _identity: &PeerId) {}

    async fn distributed_gen(
        _connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        _our_id: &PeerId,
        _peers: &[PeerId],
        params: &Self::Params,
        _rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError> {
        let cfg = TabconfConfig { bet_size: *params };
        Ok((cfg, cfg))
    }
}

async fn block_height(interconnect: &dyn ModuleInterconect) -> u32 {
    // This is a future because we are normally reading from a network socket. But for internal
    // calls the data is available instantly in one go, so we can just block on it.
    let body = interconnect
        .call("wallet", "/block_height".to_owned(), Default::default())
        .await
        .expect("Wallet module not present or malfunctioning!");

    serde_json::from_value(body).expect("Malformed block height response from wallet module!")
}

#[cfg(test)]
mod tests {
    use crate::db::ResolvedBet;
    use crate::{BetResolutionKey, RedeemPrize, TabconfConfig, TabconfModule};
    use fedimint_api::module::testing::FakeFed;
    use fedimint_api::Amount;
    use rand::thread_rng;
    use secp256k1::KeyPair;

    #[tokio::test]
    async fn test_claim_prize() {
        let mut fed = FakeFed::<TabconfModule, TabconfConfig>::new(
            1,
            |cfg, db| async move { TabconfModule { db, cfg } },
            &Amount::from_sat(42),
        )
        .await;

        let ctx = secp256k1::Secp256k1::new();
        let sk = KeyPair::new(&ctx, &mut thread_rng());

        fed.patch_dbs(|db| {
            db.insert_entry(
                &BetResolutionKey {
                    resolve_consensus_height: 100,
                },
                &ResolvedBet {
                    winner: sk.x_only_public_key().0,
                    user_moscow_time: 5000,
                    consensus_moscow_time: 4000,
                    prize: Amount::from_sat(420),
                    paid_out: false,
                },
            )
            .unwrap();
        });

        // Fail on unknown bet
        assert!(fed
            .verify_input_hack(&RedeemPrize {
                resolve_consensus_height: 101,
                amount: Amount::from_sat(420),
            })
            .is_err());

        // Fail on wrong amount
        assert!(fed
            .verify_input_hack(&RedeemPrize {
                resolve_consensus_height: 100,
                amount: Amount::from_sat(421),
            })
            .is_err());

        let good_output = RedeemPrize {
            resolve_consensus_height: 100,
            amount: Amount::from_sat(420),
        };
        let input = fed.verify_input_hack(&good_output).unwrap();

        assert_eq!(input.amount.amount, Amount::from_sat(420));
        assert_eq!(input.amount.fee, Amount::ZERO);
        assert_eq!(input.keys, vec![sk.x_only_public_key().0]);

        fed.consensus_round(&[good_output.clone()], &[]).await;

        assert!(fed.verify_input_hack(&good_output).is_err());
    }
}
