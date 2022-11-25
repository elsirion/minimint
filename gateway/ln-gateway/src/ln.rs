use async_trait::async_trait;
use fedimint_api::Amount;
use fedimint_server::modules::ln::contracts::Preimage;
use secp256k1::PublicKey;

#[async_trait]
pub trait LnRpc: Send + Sync + 'static {
    /// Get the public key of the lightning node
    async fn pubkey(&self) -> Result<PublicKey, LightningError>;

    /// Attempt to pay an invoice and block till it succeeds, fails or times out
    async fn pay(
        &self,
        invoice: lightning_invoice::Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<Preimage, LightningError>;
}

#[derive(Debug)]
pub struct LightningError(pub Option<i32>);
