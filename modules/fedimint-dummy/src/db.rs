use std::time::SystemTime;

use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

/// Example function that will migrate the Dummy Module's database from
/// version 0 to version 1. This function selects all of the ExampleKeyV0
/// and inserts a new String to construct ExampleKeys, deletes the old
/// ExampleKeyV0, then inserts the new ExampleKeys.
pub async fn migrate_dummy_db_version_0<'a, 'b>(
    _dbtx: &'b mut DatabaseTransaction<'a>,
) -> Result<(), anyhow::Error> {
    Ok(())
}

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    BetRoundPrice = 0x80,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct BetRoundPriceKey {
    pub round: SystemTime,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct BetRoundPrice {
    pub price_usd_per_btc: u64,
}

#[derive(Debug, Encodable, Decodable)]
pub struct BetRoundPriceKeyPrefix;

impl_db_record!(
    key = BetRoundPriceKey,
    value = BetRoundPrice,
    db_prefix = DbKeyPrefix::BetRoundPrice,
);

impl_db_lookup!(
    key = BetRoundPriceKey,
    query_prefix = BetRoundPriceKeyPrefix
);
