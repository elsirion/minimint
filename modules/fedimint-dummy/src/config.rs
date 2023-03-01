use fedimint_core::config::{
    ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::Encodable;
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::PeerId;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::KIND;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyConfig {
    /// Contains all configuration that needs to be the same for every
    /// federation member
    pub consensus: DummyConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable)]
pub struct DummyConfigConsensus {
    pub price_api: Url,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable)]
pub struct DummyClientConfig {
    pub price_api: Url,
}

impl TypedClientModuleConfig for DummyClientConfig {
    fn kind(&self) -> fedimint_core::core::ModuleKind {
        KIND
    }
}

impl TypedServerModuleConsensusConfig for DummyConfigConsensus {
    fn to_client_config(&self) -> ClientModuleConfig {
        ClientModuleConfig::new(
            KIND,
            serde_json::to_value(&DummyClientConfig {
                price_api: self.price_api.clone(),
            })
            .expect("Serialization can't fail"),
        )
    }
}

impl TypedServerModuleConfig for DummyConfig {
    type Local = ();
    type Private = ();
    type Consensus = DummyConfigConsensus;

    fn from_parts(
        _local: Self::Local,
        _private: Self::Private,
        consensus: Self::Consensus,
    ) -> Self {
        Self { consensus }
    }

    fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus) {
        (KIND, (), (), self.consensus)
    }

    fn validate_config(&self, _identity: &PeerId) -> anyhow::Result<()> {
        Ok(())
    }
}
