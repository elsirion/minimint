use fedimint_api::rand::Rand07Compat;
pub use fedimint_core::config::*;

use crate::net::peers::{ConnectionConfig, NetworkConfig};
use fedimint_api::config::{dkg, DkgError, DkgMessage, GenerateConfig};
use fedimint_api::PeerId;
use fedimint_core::modules::ln::config::LightningModuleConfig;
use fedimint_core::modules::mint::config::MintConfig;
use fedimint_core::modules::wallet::config::WalletConfig;
use hbbft::crypto::serde_impl::SerdeSecret;
use rand::{CryptoRng, RngCore};
use url::Url;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::fedimint_api::net::peers::PeerConnections;
use crate::net::connect::Connector;
use crate::net::connect::TlsConfig;
use crate::{ReconnectPeerConnections, TlsTcpConnector};
use async_trait::async_trait;
use fedimint_api::net::peers::AnyPeerConnections;
use hbbft::crypto::{PublicKey, SecretKey};
use hbbft::sync_key_gen;
use hbbft::sync_key_gen::{Ack, AckOutcome, Part, PartOutcome, SyncKeyGen};
use itertools::Either;
use rand::distributions::Standard;
use serde::de::DeserializeOwned;
use tokio_rustls::rustls;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub identity: PeerId,
    pub hbbft_bind_addr: String,
    pub api_bind_addr: String,
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
    #[serde(with = "serde_tls_key")]
    pub tls_key: rustls::PrivateKey,

    pub peers: BTreeMap<PeerId, Peer>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_pk_set: hbbft::crypto::PublicKeySet,

    #[serde(with = "serde_binary_human_readable")]
    pub epoch_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
    #[serde(with = "serde_binary_human_readable")]
    pub epoch_pk_set: hbbft::crypto::PublicKeySet,

    pub wallet: WalletConfig,
    pub mint: MintConfig,
    pub ln: LightningModuleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub hbbft: ConnectionConfig,
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
    /// The peer's websocket network address and port (e.g. `ws://10.42.0.10:5000`)
    pub api_addr: Url,
}

#[derive(Debug, Clone)]
/// network config for a server
pub struct ServerConfigParams {
    pub tls: TlsConfig,
    pub hbbft: NetworkConfig,
    pub api: NetworkConfig,
    pub hbbft_dkg: NetworkConfig,
    pub epoch_dkg: NetworkConfig,
    pub wallet_dkg: NetworkConfig,
    pub lightning_dkg: NetworkConfig,
    pub mint_dkg: NetworkConfig,
    pub amount_tiers: Vec<fedimint_api::Amount>,
}

#[async_trait(?Send)]
impl GenerateConfig for ServerConfig {
    type Params = HashMap<PeerId, ServerConfigParams>;
    type ClientConfig = ClientConfig;
    type ConfigMessage = DkgMessage;
    type ConfigError = DkgError;

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let netinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut Rand07Compat(&mut rng))
            .expect("Could not generate HBBFT netinfo");
        let epochinfo =
            hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut Rand07Compat(&mut rng))
                .expect("Could not generate HBBFT netinfo");

        let amount_tiers = &params[&PeerId::from(0)].amount_tiers;
        let (wallet_server_cfg, wallet_client_cfg) =
            WalletConfig::trusted_dealer_gen(peers, max_evil, &(), &mut rng);
        let (mint_server_cfg, mint_client_cfg) =
            MintConfig::trusted_dealer_gen(peers, max_evil, amount_tiers, &mut rng);
        let (ln_server_cfg, ln_client_cfg) =
            LightningModuleConfig::trusted_dealer_gen(peers, max_evil, &(), &mut rng);

        let server_config = netinfo
            .iter()
            .map(|(&id, netinf)| {
                let epoch_keys = epochinfo.get(&id).unwrap();
                let config = ServerConfig {
                    identity: id,
                    hbbft_bind_addr: params[&id].hbbft.bind_addr.clone(),
                    api_bind_addr: params[&id].api.bind_addr.clone(),
                    tls_cert: params[&id].tls.our_certificate.clone(),
                    tls_key: params[&id].tls.our_private_key.clone(),
                    peers: params[&id].peers(),
                    hbbft_sks: SerdeSecret(netinf.secret_key_share().unwrap().clone()),
                    hbbft_pk_set: netinf.public_key_set().clone(),
                    epoch_sks: SerdeSecret(epoch_keys.secret_key_share().unwrap().clone()),
                    epoch_pk_set: epoch_keys.public_key_set().clone(),
                    wallet: wallet_server_cfg[&id].clone(),
                    mint: mint_server_cfg[&id].clone(),
                    ln: ln_server_cfg[&id].clone(),
                };
                (id, config)
            })
            .collect();

        let client_config = ClientConfig {
            max_evil,
            api_endpoints: params[&PeerId::from(0)].api.urls("ws://"),
            mint: mint_client_cfg,
            wallet: wallet_client_cfg,
            ln: ln_client_cfg,
        };

        (server_config, client_config)
    }

    fn to_client_config(&self) -> Self::ClientConfig {
        let api_endpoints: Vec<Url> = self
            .peers
            .iter()
            .map(|(_, peer)| peer.api_addr.clone())
            .collect();
        let max_evil = hbbft::util::max_faulty(self.peers.len());
        ClientConfig {
            api_endpoints,
            max_evil,
            mint: self.mint.to_client_config(),
            wallet: self.wallet.to_client_config(),
            ln: self.ln.to_client_config(),
        }
    }

    fn validate_config(&self, identity: &PeerId) {
        assert_eq!(
            self.epoch_sks.public_key_share(),
            self.epoch_pk_set.public_key_share(identity.to_usize()),
            "Epoch private key doesn't match pubkey share"
        );
        assert_eq!(
            self.hbbft_sks.public_key_share(),
            self.hbbft_pk_set.public_key_share(identity.to_usize()),
            "HBBFT private key doesn't match pubkey share"
        );
        assert_eq!(
            self.peers.keys().max().copied().map(|id| id.to_usize()),
            Some(self.peers.len() - 1),
            "Peer ids are not indexed from 0"
        );
        assert_eq!(
            self.peers.keys().min().copied(),
            Some(PeerId::from(0)),
            "Peer ids are not indexed from 0"
        );

        self.mint.validate_config(identity);
        self.ln.validate_config(identity);
        self.wallet.validate_config(identity);
    }

    async fn distributed_gen(
        connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError> {
        let params = params[&our_id].clone();
        let mut epoch = connect(params.epoch_dkg.clone(), params.tls.clone()).await;
        let hbbft_keys = dkg(connections, our_id, peers, max_evil, &mut rng).await?;
        let epoch_keys = dkg(&mut epoch, our_id, peers, max_evil, &mut rng).await?;

        let mut wallet = connect(params.wallet_dkg.clone(), params.tls.clone()).await;
        let (wallet_server_cfg, wallet_client_cfg) =
            WalletConfig::distributed_gen(&mut wallet, our_id, peers, max_evil, &(), &mut rng)
                .await
                .expect("wallet error");

        let mut ln = connect(params.lightning_dkg.clone(), params.tls.clone()).await;
        let (ln_server_cfg, ln_client_cfg) =
            LightningModuleConfig::distributed_gen(&mut ln, our_id, peers, max_evil, &(), &mut rng)
                .await?;

        let mut mint = connect(params.mint_dkg.clone(), params.tls.clone()).await;
        let param = &params.amount_tiers;
        let (mint_server_cfg, mint_client_cfg) =
            MintConfig::distributed_gen(&mut mint, our_id, peers, max_evil, param, &mut rng)
                .await?;
        warn!("COOLLLLLLLLLLLLLLLLLLLL");

        let server = ServerConfig {
            identity: our_id.clone(),
            hbbft_bind_addr: params.hbbft.bind_addr.clone(),
            api_bind_addr: params.api.bind_addr.clone(),
            tls_cert: params.tls.our_certificate.clone(),
            tls_key: params.tls.our_private_key.clone(),
            peers: params.peers(),
            hbbft_sks: SerdeSecret(hbbft_keys.secret_key_share),
            hbbft_pk_set: hbbft_keys.public_key_set,
            epoch_sks: SerdeSecret(epoch_keys.secret_key_share),
            epoch_pk_set: epoch_keys.public_key_set,
            wallet: wallet_server_cfg,
            mint: mint_server_cfg,
            ln: ln_server_cfg,
        };

        let client = ClientConfig {
            api_endpoints: params.api.urls("ws://"),
            mint: mint_client_cfg,
            wallet: wallet_client_cfg,
            ln: ln_client_cfg,
            max_evil,
        };

        Ok((server, client))
    }
}

impl ServerConfig {
    pub fn network_config(&self) -> NetworkConfig {
        NetworkConfig {
            identity: self.identity,
            bind_addr: self.hbbft_bind_addr.clone(),
            peers: self
                .peers
                .iter()
                .map(|(&id, peer)| (id, peer.hbbft.clone()))
                .collect(),
        }
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            our_certificate: self.tls_cert.clone(),
            our_private_key: self.tls_key.clone(),
            peer_certs: self
                .peers
                .iter()
                .map(|(peer, cfg)| (*peer, cfg.tls_cert.clone()))
                .collect(),
        }
    }

    pub fn get_incoming_count(&self) -> u16 {
        self.identity.into()
    }

    /// how many peers can be evil without breaking consensus
    pub fn max_faulty(&self) -> usize {
        hbbft::util::max_faulty(self.peers.len())
    }

    /// how many peers are required for consensus
    pub fn threshold(&self) -> usize {
        hbbft::util::max_faulty(self.peers.len()) * 2 + 1
    }

    pub fn fee_consensus(&self) -> fedimint_core::config::FeeConsensus {
        fedimint_core::config::FeeConsensus {
            wallet: self.wallet.fee_consensus.clone(),
            mint: self.mint.fee_consensus.clone(),
            ln: self.ln.fee_consensus.clone(),
        }
    }
}

impl ServerConfigParams {
    pub fn peers(&self) -> BTreeMap<PeerId, Peer> {
        self.hbbft
            .peers
            .iter()
            .map(|(peer, hbbft)| {
                (
                    *peer,
                    Peer {
                        hbbft: hbbft.clone(),
                        tls_cert: self.tls.peer_certs[peer].clone(),
                        api_addr: Url::parse(&format!("ws://{}", self.api.peers[peer].address))
                            .expect("Could not parse URL"),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    }

    /// config for servers running on different ports on a local network
    pub fn gen_local(
        peers: &[PeerId],
        amount_tiers: Vec<fedimint_api::Amount>,
        base_port: u16,
    ) -> HashMap<PeerId, ServerConfigParams> {
        let keys: HashMap<PeerId, (rustls::Certificate, rustls::PrivateKey)> = peers
            .iter()
            .map(|peer| {
                let (cert, key) = gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap();
                (*peer, (cert, key))
            })
            .collect::<HashMap<_, _>>();

        let certs: HashMap<PeerId, rustls::Certificate> = keys
            .iter()
            .map(|(peer, (cert, _))| (*peer, cert.clone()))
            .collect::<HashMap<_, _>>();

        let tls_config: HashMap<PeerId, TlsConfig> = keys
            .iter()
            .map(|(peer, (cert, key))| {
                (
                    *peer,
                    TlsConfig {
                        our_certificate: cert.clone(),
                        our_private_key: key.clone(),
                        peer_certs: certs.clone(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        let port = base_port as usize;
        peers
            .iter()
            .map(|peer| {
                (
                    *peer,
                    ServerConfigParams {
                        tls: tls_config.get(peer).expect("exists").clone(),
                        hbbft: Self::gen_local_network(peers, peer, port),
                        api: Self::gen_local_network(peers, peer, port + peers.len()),
                        hbbft_dkg: Self::gen_local_network(peers, peer, port + peers.len() * 2),
                        epoch_dkg: Self::gen_local_network(peers, peer, port + peers.len() * 3),
                        wallet_dkg: Self::gen_local_network(peers, peer, port + peers.len() * 4),
                        lightning_dkg: Self::gen_local_network(peers, peer, port + peers.len() * 5),
                        mint_dkg: Self::gen_local_network(peers, peer, port + peers.len() * 6),
                        amount_tiers: amount_tiers.clone(),
                    },
                )
            })
            .collect()
    }

    fn gen_local_network(peers: &[PeerId], our_id: &PeerId, base_port: usize) -> NetworkConfig {
        NetworkConfig {
            identity: our_id.clone(),
            bind_addr: format!("127.0.0.1:{}", base_port + our_id.to_usize()),
            peers: peers
                .iter()
                .map(|peer| {
                    (*peer, {
                        ConnectionConfig {
                            address: format!("127.0.0.1:{}", base_port + peer.to_usize()),
                        }
                    })
                })
                .collect(),
        }
    }
}

pub async fn connect<T>(network: NetworkConfig, certs: TlsConfig) -> AnyPeerConnections<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync + 'static,
{
    let connector = TlsTcpConnector::new(certs).to_any();
    ReconnectPeerConnections::new(network, connector)
        .await
        .to_any()
}

pub(crate) fn gen_cert_and_key(
    name: &str,
) -> Result<(rustls::Certificate, rustls::PrivateKey), anyhow::Error> {
    let keypair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let keypair_ser = keypair.serialize_der();
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]);

    params.key_pair = Some(keypair);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = rcgen::IsCa::SelfSignedOnly;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);

    let cert = rcgen::Certificate::from_params(params)?;

    Ok((
        rustls::Certificate(cert.serialize_der()?),
        rustls::PrivateKey(keypair_ser),
    ))
}

mod serde_tls_cert {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::borrow::Cow;
    use tokio_rustls::rustls;

    pub fn serialize<S>(cert: &rustls::Certificate, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(&cert.0);
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::Certificate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str.as_ref()).map_err(|_e| D::Error::custom("Invalid hex"))?;
        Ok(rustls::Certificate(bytes))
    }
}

mod serde_tls_key {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::borrow::Cow;
    use tokio_rustls::rustls;

    pub fn serialize<S>(key: &rustls::PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(&key.0);
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str.as_ref()).map_err(|_e| D::Error::custom("Invalid hex"))?;
        Ok(rustls::PrivateKey(bytes))
    }
}
