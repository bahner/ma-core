//! IPFS-relaterte APIs.
//!
//! Plattformuavhengig:
//! - `gateway_resolver` — DID-dokument-henting via HTTP gateway (fungerer på wasm og native).
//!
//! For Kubo-spesifikke operasjoner (RPC write/pin/publish), se `crate::kubo`.

pub mod gateway_resolver;

pub use gateway_resolver::{DidDocumentResolver, IpfsGatewayResolver};
