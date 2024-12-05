// TODO: move to separate crate for sharing with LNv2
pub mod api;

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Uniquely identifies a payment code, also happens to be the public key all
/// payment code invoice pub keys will be derived from.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
)]
pub struct PaymentCodeId(pub PublicKey);

impl Display for PaymentCodeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PaymentCodeId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(PublicKey::from_str(s)?))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Hash,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
)]
pub enum RecurringPaymentProtocol {
    LNURL,
    BOLT12,
}

#[derive(Debug, Error)]
pub enum RecurringPaymentError {
    #[error("Unsupported protocol: {0:?}")]
    UnsupportedProtocol(RecurringPaymentProtocol),
    #[error("Unknown federation ID: {0}")]
    UnknownFederationId(FederationId),
    #[error("Unknown payment code: {0:?}")]
    UnknownPaymentCode(PaymentCodeId),
    #[error("No compatible lightning module found")]
    NoLightningModuleFound,
    #[error("No gateway found")]
    NoGatewayFound,
    #[error("Payment code already exists: {0:?}")]
    PaymentCodeAlreadyExists(PaymentCodeId),
    #[error("Federation already registered: {0}")]
    FederationAlreadyRegistered(FederationId),
    #[error("Error registering with recurring payment service: {0}")]
    Other(#[from] anyhow::Error),
}
