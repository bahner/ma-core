//! Iroh transport backend.

pub mod channel;
mod endpoint;

use crate::error::Result;

pub(crate) async fn new_endpoint(
    secret_bytes: [u8; 32],
    ipv6: bool,
) -> Result<endpoint::IrohEndpoint> {
    endpoint::IrohEndpoint::new(secret_bytes, ipv6).await
}
