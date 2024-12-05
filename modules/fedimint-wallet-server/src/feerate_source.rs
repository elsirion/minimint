use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Feerate};
use fedimint_logging::LOG_MODULE_WALLET;
use fedimint_wallet_common::CONFIRMATION_TARGET;
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{Ctx, Native, RcIter};
use jaq_json::Val;
use tracing::{debug, trace};

#[apply(async_trait_maybe_send!)]
pub trait FeeRateSource: Send + Sync {
    fn name(&self) -> String;
    async fn fetch(&self) -> Result<Feerate>;
}

#[apply(async_trait_maybe_send!)]
impl FeeRateSource for DynBitcoindRpc {
    fn name(&self) -> String {
        self.get_bitcoin_rpc_config().kind
    }

    async fn fetch(&self) -> Result<Feerate> {
        self.get_fee_rate(CONFIRMATION_TARGET)
            .await?
            .ok_or_else(|| anyhow!("bitcoind did not return any feerate"))
    }
}

pub struct FetchJson {
    filter: jaq_core::Filter<Native<Val>>,
    source_url: SafeUrl,
}

impl FetchJson {
    pub fn from_str(source_str: &str) -> Result<Self> {
        let (source_url, code) = {
            let (url, code) = match source_str.split_once('#') {
                Some(val) => val,
                None => (source_str, "."),
            };

            (SafeUrl::parse(url)?, code)
        };

        debug!(target: LOG_MODULE_WALLET, url = %source_url, code = %code, "Setting fee rate json source");
        let program = File { code, path: () };

        let loader = Loader::new([]);
        let arena = Arena::default();
        let modules = loader.load(&arena, program).map_err(|errs| {
            anyhow!(
                "Error parsing jq filter for {source_url}: {}",
                errs.into_iter()
                    .fold(String::new(), |acc, new| if acc.is_empty() {
                        format!("{:?}", new.1)
                    } else {
                        format!("{acc}\n{:?}", new.1)
                    })
            )
        })?;

        let filter = jaq_core::Compiler::<_, Native<_>>::default()
            .compile(modules)
            .map_err(|errs| anyhow!("Failed to compile program: {:?}", errs))?;

        Ok(Self { filter, source_url })
    }
}

#[apply(async_trait_maybe_send!)]
impl FeeRateSource for FetchJson {
    fn name(&self) -> String {
        self.source_url
            .host()
            .map_or_else(|| "host-not-available".to_string(), |h| h.to_string())
    }

    async fn fetch(&self) -> Result<Feerate> {
        let json_resp: serde_json::Value = reqwest::get(self.source_url.clone().to_unsafe())
            .await?
            .json()
            .await?;

        trace!(target: LOG_MODULE_WALLET, name = %self.name(), resp = ?json_resp, "Got json response");

        let inputs = RcIter::new(core::iter::empty());

        let mut out = self
            .filter
            .run((Ctx::new([], &inputs), Val::from(json_resp)));

        let val = out
            .next()
            .ok_or_else(|| anyhow!("Missing value after applying filter"))?
            .map_err(|e| anyhow!("Jaq err: {e}"))?;

        let rate = match val {
            Val::Float(rate) => rate,
            #[allow(clippy::cast_precision_loss)]
            Val::Int(rate) => rate as f64,
            Val::Num(rate) => FromStr::from_str(&rate)?,
            _ => {
                bail!("Value returned by feerate source has invalid type: {val:?}");
            }
        };
        debug!(target: LOG_MODULE_WALLET, name = %self.name(), rate_sats_vb = %rate, "Got fee rate");

        if rate <= 0.0 {
            bail!("Fee rate returned by source not positive: {rate}")
        }

        if 10_000.0 <= rate {
            bail!("Fee rate returned by source too large: {rate}")
        }

        Ok(Feerate {
            // just checked that it's not negative
            #[allow(clippy::cast_sign_loss)]
            sats_per_kvb: (rate * 1000.0).floor() as u64,
        })
    }
}
