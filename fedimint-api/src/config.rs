use crate::net::peers::AnyPeerConnections;
use crate::rand::Rand07Compat;
use crate::PeerId;
use async_trait::async_trait;
use hbbft::crypto::group::Curve;
use hbbft::crypto::group::GroupEncoding;
use hbbft::crypto::poly::Commitment;
use hbbft::crypto::{G1Affine, IntoScalar};
use hbbft::crypto::{
    G1Projective, G2Affine, G2Projective, PublicKey, PublicKeySet, SecretKey, SecretKeyShare,
};
use hbbft::sync_key_gen::{Ack, AckOutcome, Part, PartOutcome, SyncKeyGen};
use hbbft::PubKeyMap;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::borrow::BorrowMut;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ops::Mul;
use std::ops::{Add, AddAssign};
use std::sync::Arc;
use tbs::hash::hash_bytes_to_curve;
use tbs::poly::Poly;
use tbs::Scalar;
use tracing::warn;

/// Part of a config that needs to be generated to bootstrap a new federation.
#[async_trait(?Send)]
pub trait GenerateConfig: Sized {
    type Params: ?Sized;
    type ClientConfig;
    type ConfigMessage;
    type ConfigError;

    /// Function that generates the config of all peers locally. This is only meant to be used for
    /// testing as the generating machine would be a single point of failure/compromise.
    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig);

    fn to_client_config(&self) -> Self::ClientConfig;

    /// Asserts that the public keys in the config are and panics otherwise (no way to recover)
    fn validate_config(&self, identity: &PeerId);

    async fn distributed_gen(
        connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError>;
}

struct DkgRunner {
    peers: Vec<PeerId>,
    our_id: PeerId,
    coefficients: usize,
    f1_poly: Poly<Scalar, Scalar>,
    f2_poly: Poly<Scalar, Scalar>,
    commitments: BTreeMap<PeerId, Vec<G1Projective>>,
    sk_shares: BTreeMap<PeerId, Scalar>,
    pk_shares: BTreeMap<PeerId, Vec<G1Projective>>,
}

impl DkgRunner {
    pub fn new(
        our_id: &PeerId,
        peers: &[PeerId],
        max_evil: usize,
        rng: &mut impl rand07::RngCore,
    ) -> (Self, DkgStep) {
        let degree = peers.len() - max_evil - 1;
        let f1_poly: Poly<Scalar, Scalar> = Poly::random(degree, rng);
        let f2_poly: Poly<Scalar, Scalar> = Poly::random(degree, rng);

        // broadcast our commitment to the polynomials
        let commit: Vec<G1Projective> = f1_poly
            .coefficients()
            .map(|c| Self::gen_g() * c)
            .zip(f2_poly.coefficients().map(|c| Self::gen_h() * c))
            .map(|(g, h)| g + h)
            .collect();

        let mut dkg = DkgRunner {
            peers: peers.clone().to_vec(),
            our_id: our_id.clone(),
            coefficients: degree + 1,
            f1_poly,
            f2_poly,
            commitments: Default::default(),
            sk_shares: Default::default(),
            pk_shares: Default::default(),
        };

        let step = DkgStep {
            messages: dkg.broadcast(DkgMessage::Commit(commit)),
            keys: None,
        };

        (dkg, step)
    }

    pub fn step(&mut self, peer: PeerId, msg: DkgMessage) -> DkgStep {
        let mut step = DkgStep::default();

        match msg {
            DkgMessage::Commit(commit) => {
                assert_eq!(self.coefficients, commit.len(), "wrong degree from {}", peer);
                if self.commitments.insert(peer, commit).is_some() {
                    panic!("{} sent us two commitments!", peer);
                }

                // once everyone has made commitments, send out shares
                if self.commitments.len() == self.peers.len() {
                    for peer in &self.peers {
                        let s1 = self.f1_poly.evaluate(scalar(peer));
                        let s2 = self.f2_poly.evaluate(scalar(peer));
                        step.messages
                            .push((peer.clone(), DkgMessage::Share(s1, s2)));
                    }
                }
            }
            // Pedersen-VSS verifies the shares match the commitments
            DkgMessage::Share(s1, s2) => {
                let share_product = (Self::gen_g() * s1) + (Self::gen_h() * s2);
                let commitment = self
                    .commitments
                    .get(&peer)
                    .expect(&format!("{} sent share before commit", peer));
                let commit_product: G1Projective = commitment
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| *commit * scalar(&self.our_id).pow(&[idx as u64, 0, 0, 0]))
                    .sum();

                assert_eq!(share_product, commit_product, "bad commit from {}", peer);
                self.sk_shares.insert(peer, s1);

                if self.sk_shares.len() == self.peers.len() {
                    let extract = self
                        .f1_poly
                        .coefficients()
                        .map(|c| Self::gen_g() * c)
                        .collect();
                    step.messages
                        .append(&mut self.broadcast(DkgMessage::Extract(extract)));
                }
            }
            // Feldman-VSS exposes the public key shares
            DkgMessage::Extract(extract) => {
                let share = self
                    .sk_shares
                    .get(&peer)
                    .expect(&format!("{} sent extract before share", peer));
                let share_product = Self::gen_g() * share;
                let extract_product: G1Projective = extract
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| *commit * scalar(&self.our_id).pow(&[idx as u64, 0, 0, 0]))
                    .sum();

                assert_eq!(share_product, extract_product, "bad extract from {}", peer);
                assert_eq!(self.coefficients, extract.len(), "wrong degree from {}", peer);
                self.pk_shares.insert(peer, extract);

                if self.pk_shares.len() == self.peers.len() {
                    let pks: Vec<G1Projective> = (0..self.coefficients).map(|idx|{
                        self.pk_shares.values().map(|shares| {
                            Commitment::from(shares.clone()).evaluate(idx)
                        }).sum::<G1Projective>()
                    }).collect();

                    let mut pks2 = hbbft::crypto::poly::Poly::zero().commitment();
                    for (_, pk) in &self.pk_shares {
                        pks2 += Commitment::from(pk.clone());
                    }
                    let sks = self.sk_shares.values().cloned().sum();

                    warn!("SK {} {:?}", self.our_id, Self::gen_g() * sks);
                    warn!("PK2 {:?}", self.peers.iter().map(|p| pks2.evaluate(scalar(p))).collect::<Vec<_>>());
                    warn!("PK1 {:?}", pks);

                    step.keys = Some(DkgKeys {
                        public_key_set: pks2,
                        secret_key_share: sks,
                    });
                }
            }
        }

        step
    }

    fn broadcast(&self, msg: DkgMessage) -> Vec<(PeerId, DkgMessage)> {
        self.peers.iter().map(|peer| (*peer, msg.clone())).collect()
    }

    fn gen_g() -> G1Projective {
        G1Projective::generator()
    }

    /// Get a second generator by hashing the first one to the curve
    fn gen_h() -> G1Projective {
        hash_bytes_to_curve::<G1Projective>(&Self::gen_g().to_bytes().as_ref()[..])
    }
}

pub fn scalar(peer: &PeerId) -> Scalar {
    Scalar::from(peer.to_usize() as u64 + 1)
}

pub async fn dkg(
    connections: &mut AnyPeerConnections<DkgMessage>,
    our_id: &PeerId,
    peers: &[PeerId],
    max_evil: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<DkgKeys, DkgError> {
    // let mut rng = Rand07Compat(rng);
    // let (mut dkg, mut step) = DkgRunner::new(our_id, peers, max_evil, &mut rng);
    //
    // loop {
    //     if let Some(keys) = step.keys {
    //         return Ok(keys);
    //     }
    //
    //     for msg in step.messages {
    //         connections.send(peers, msg).await;
    //     }
    //
    //     let (peer, msg) = connections.receive().await;
    //     step = dkg.step(peer, msg, &mut rng)?;
    // }
    todo!()
}

#[derive(Debug, Default, Clone)]
pub struct DkgStep {
    pub messages: Vec<(PeerId, DkgMessage)>,
    pub keys: Option<DkgKeys>,
}

#[derive(Debug, Clone)]
pub struct DkgKeys {
    pub public_key_set: Commitment,
    pub secret_key_share: Scalar,
}

impl DkgKeys {
    // compatible with threshold_crypto lib
    pub fn threshold_crypto(mut self) -> (PublicKeySet, SecretKeyShare) {
        (
            PublicKeySet::from(self.public_key_set),
            SecretKeyShare::from_mut(&mut self.secret_key_share),
        )
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum DkgMessage {
    Commit(Vec<G1Projective>),
    Share(Scalar, Scalar),
    Extract(Vec<G1Projective>),
}

#[derive(Debug)]
pub enum DkgError {
    UnexpectedMessage(PeerId, DkgMessage),
    Hbbft(hbbft::sync_key_gen::Error),
    NoSecretKey,
}

#[cfg(test)]
mod tests {
    use crate::config::{scalar, DkgKeys, DkgRunner};
    use crate::PeerId;
    use fedimint_api::config::DkgStep;
    use hbbft::crypto::poly::Poly;
    use hbbft::crypto::G1Affine;
    use rand07::rngs::OsRng;
    use std::collections::{HashMap, VecDeque};
    use std::ops::Mul;
    use tracing::warn;

    #[test_log::test]
    fn test_dkg() {
        let mut rng = OsRng::default();
        let num_peers = 4;
        let max_evil = 1;
        let peers = (0..num_peers as u16).map(PeerId::from).collect::<Vec<_>>();

        let mut steps: VecDeque<(PeerId, DkgStep)> = VecDeque::new();
        let mut dkgs: HashMap<PeerId, DkgRunner> = HashMap::new();
        let mut keys: HashMap<PeerId, DkgKeys> = HashMap::new();

        for peer in &peers {
            let (dkg, step) = DkgRunner::new(&peer, &peers, max_evil, &mut rng);
            dkgs.insert(peer.clone(), dkg);
            steps.push_back((peer.clone(), step));
        }

        while keys.len() < peers.len() {
            while let Some((send_peer, step)) = steps.pop_front() {
                for (receive_peer, msg) in &step.messages {
                    let receive_dkg = dkgs.get_mut(&receive_peer).unwrap();
                    let step = receive_dkg.step(send_peer.clone(), msg.clone());

                    if step.messages.len() > 0 {
                        steps.push_back((receive_peer.clone(), step.clone()))
                    }

                    if let Some(step_keys) = step.keys {
                        keys.insert(receive_peer.clone(), step_keys);
                    }
                }
            }
        }

        for (peer, keys) in keys {
            let (pk, sk) = keys.threshold_crypto();
            if pk.public_key_share(scalar(&peer)) == sk.public_key_share() {
                warn!("OK");
            } else {
                warn!("BAD");
            }
            // assert_eq!(pk.public_key_share(scalar(&peer)), sk.public_key_share());
        }
        assert!(false);
    }
}
