use crate::tiered::TieredMultiZip;
use crate::Tiered;
use async_trait::async_trait;
use bincode::serialize;
use fedimint_api::config::{dkg, DkgError, DkgMessage, GenerateConfig};
use fedimint_api::net::peers::AnyPeerConnections;
use fedimint_api::{Amount, PeerId};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::iter::FromIterator;
use tbs::{
    dealer_keygen, Aggregatable, AggregatePublicKey, PublicKeyShare, Scalar, SecretKeyShare,
};
use threshold_crypto::group::Curve;
use threshold_crypto::group::GroupEncoding;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{G1Affine, G1Projective};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    pub tbs_sks: Tiered<tbs::SecretKeyShare>,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub fee_consensus: FeeConsensus,
    pub threshold: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MintClientConfig {
    pub tbs_pks: Tiered<AggregatePublicKey>,
    pub fee_consensus: FeeConsensus,
}

#[async_trait(?Send)]
impl GenerateConfig for MintConfig {
    type Params = [Amount];
    type ClientConfig = MintClientConfig;
    type ConfigMessage = DkgMessage;
    type ConfigError = DkgError;

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        _rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let tbs_threshold = peers.len() - max_evil;

        let tbs_keys = params
            .iter()
            .map(|&amount| {
                let (tbs_pk, tbs_pks, tbs_sks) = dealer_keygen(tbs_threshold, peers.len());
                (amount, (tbs_pk, tbs_pks, tbs_sks))
            })
            .collect::<HashMap<_, _>>();

        let mint_cfg = peers
            .iter()
            .map(|&peer| {
                let config = MintConfig {
                    threshold: tbs_threshold,
                    tbs_sks: params
                        .iter()
                        .map(|amount| (*amount, tbs_keys[amount].2[peer.to_usize()]))
                        .collect(),
                    peer_tbs_pks: peers
                        .iter()
                        .map(|&key_peer| {
                            let keys = params
                                .iter()
                                .map(|amount| (*amount, tbs_keys[amount].1[key_peer.to_usize()]))
                                .collect();
                            (key_peer, keys)
                        })
                        .collect(),
                    fee_consensus: FeeConsensus::default(),
                };
                (peer, config)
            })
            .collect();

        let client_cfg = MintClientConfig {
            tbs_pks: tbs_keys
                .into_iter()
                .map(|(amount, (pk, _, _))| (amount, pk))
                .collect(),
            fee_consensus: FeeConsensus::default(),
        };

        (mint_cfg, client_cfg)
    }

    fn to_client_config(&self) -> Self::ClientConfig {
        let pub_key: HashMap<Amount, AggregatePublicKey> = TieredMultiZip::new(
            self.peer_tbs_pks
                .iter()
                .map(|(_, keys)| keys.iter())
                .collect(),
        )
        .map(|(amt, keys)| {
            // TODO: avoid this through better aggregation API allowing references or
            let keys = keys.into_iter().copied().collect::<Vec<_>>();
            (amt, keys.aggregate(self.threshold))
        })
        .collect();
        MintClientConfig {
            tbs_pks: Tiered::from_iter(pub_key.into_iter()),
            fee_consensus: self.fee_consensus.clone(),
        }
    }

    fn validate_config(&self, identity: &PeerId) {
        let sks: BTreeMap<Amount, PublicKeyShare> = self
            .tbs_sks
            .iter()
            .map(|(amount, sk)| (amount, sk.to_pub_key_share()))
            .collect();
        let pks: BTreeMap<Amount, PublicKeyShare> =
            self.peer_tbs_pks.get(identity).unwrap().as_map().clone();
        assert_eq!(sks, pks, "Mint private key doesn't match pubkey share");
    }

    async fn distributed_gen(
        connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError> {
        let mut amounts_keys = HashMap::new();
        for amount in params {
            let keys = dkg(connections, our_id, peers, max_evil, &mut rng).await?;
            amounts_keys.insert(*amount, keys);
        }

        let server = MintConfig {
            tbs_sks: amounts_keys
                .iter()
                .map(|(amount, keys)| {
                    let mut bytes: [u8; 32] = [0; 32];
                    let vec = serialize(&SerdeSecret(&keys.secret_key_share)).unwrap();
                    bytes.copy_from_slice(&vec);
                    let sks = SecretKeyShare(Scalar::from_bytes(&bytes).unwrap());
                    tracing::warn!(
                        "A {:?}",
                        keys.secret_key_share.public_key_share().to_bytes()
                    );

                    (*amount, sks)
                })
                .collect(),
            peer_tbs_pks: peers
                .iter()
                .map(|peer| {
                    (
                        *peer,
                        amounts_keys
                            .iter()
                            .map(|(amount, keys)| {
                                let idx = peer.to_usize();
                                tracing::warn!("B idx {:?}", idx);
                                tracing::warn!("B thres {:?}", keys.public_key_set.threshold());
                                let bytes = keys.public_key_set.public_key_share(idx).to_bytes();
                                tracing::warn!("B bytes {:?}", bytes);
                                let pks =
                                    PublicKeyShare(G1Affine::from_compressed(&bytes).unwrap());

                                (*amount, pks)
                            })
                            .collect::<Tiered<PublicKeyShare>>(),
                    )
                })
                .collect(),
            fee_consensus: Default::default(),
            threshold: 0,
        };

        let client = MintClientConfig {
            tbs_pks: amounts_keys
                .iter()
                .map(|(amount, keys)| {
                    let bytes = keys.public_key_set.public_key().to_bytes();
                    let pk = AggregatePublicKey(G1Affine::from_compressed(&bytes).unwrap());

                    (*amount, pk)
                })
                .collect(),
            fee_consensus: Default::default(),
        };

        Ok((server, client))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub coin_issuance_abs: fedimint_api::Amount,
    pub coin_spend_abs: fedimint_api::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            coin_issuance_abs: fedimint_api::Amount::ZERO,
            coin_spend_abs: fedimint_api::Amount::ZERO,
        }
    }
}
