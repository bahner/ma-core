//! Service trait for ma endpoint protocol handlers.
//!
//! A `Service` is analogous to an entry in `/etc/services`: a named protocol
//! on a ma endpoint. Register services on an `MaEndpoint` to handle incoming
//! connections on their protocol.

/// Trait that all ma services must implement.
///
/// Each service declares its protocol identifier and provides a handler for
/// incoming connections. Built-in services ship with ma-core; applications
/// add custom services via this trait.
///
/// # Examples
///
/// ```
/// use ma_core::Service;
///
/// struct MyService;
///
/// impl Service for MyService {
///     fn protocol(&self) -> &[u8] { b"/ma/my-service/0.0.1" }
/// }
/// ```
pub trait Service: Send + Sync {
    /// The protocol identifier for this service.
    fn protocol(&self) -> &[u8];
}

// ─── Well-known protocol constants (ma-core scope) ──────────────────────────

pub const INBOX_PROTOCOL_ID: &str = "/ma/inbox/0.0.1";
pub const RPC_PROTOCOL_ID: &str = "/ma/rpc/0.0.1";
pub const IPFS_PROTOCOL_ID: &str = "/ma/ipfs/0.0.1";

/// The well-known broadcast topic / protocol string.
pub const BROADCAST_TOPIC: &str = "/ma/broadcast/0.0.1";

// ─── Message types (routing / dispatch category) ────────────────────────────

pub const MESSAGE_TYPE_BROADCAST: &str = "application/x-ma-broadcast";
pub const MESSAGE_TYPE_CHAT: &str = "application/x-ma-chat";
pub const MESSAGE_TYPE_EMOTE: &str = "application/x-ma-emote";
pub const MESSAGE_TYPE_MESSAGE: &str = "application/x-ma-message";
pub const MESSAGE_TYPE_IPFS_REQUEST: &str = "application/x-ma-ipfs-request";
pub const MESSAGE_TYPE_IPFS_STORE: &str = "application/x-ma-ipfs-store";
pub const MESSAGE_TYPE_DOC: &str = "application/x-ma-doc";
pub const MESSAGE_TYPE_RPC: &str = "application/x-ma-rpc";
pub const MESSAGE_TYPE_RPC_REPLY: &str = "application/x-ma-rpc-reply";

// ─── Content types (inner payload format) ───────────────────────────────────

pub const CONTENT_TYPE_CBOR: &str = "application/cbor";
