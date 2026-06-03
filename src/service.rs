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
pub const CRUD_PROTOCOL_ID: &str = "/ma/crud/0.0.1";

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

// ─── CRUD message types (/ma/crud/0.0.1) ────────────────────────────────────
//
// Operation is encoded in the CBOR payload, not the message type:
//   GET:    [":get",    ":path"]
//   SET:    [":path",   value]        value = scalar or "/ipfs/…", "/ipns/…", "/ipld/…"
//   DELETE: [":delete", ":path"]

pub const MESSAGE_TYPE_CRUD: &str = "application/x-ma-crud";
pub const MESSAGE_TYPE_CRUD_REPLY: &str = "application/x-ma-crud-reply";

// ─── Content types (inner payload format) ───────────────────────────────────

pub const CONTENT_TYPE_CBOR: &str = "application/cbor";
/// CBOR term — either a bare atom (`:ok`, `:pong`) or a tuple (CBOR array whose first element
/// is a dispatchable atom, e.g. `[:ok, data]` or `[:error, reason]`).
/// Used as `contentType` for RPC and CRUD messages.
pub const CONTENT_TYPE_TERM: &str = "application/x-ma-term";
/// Raw CBOR data payload — e.g. an `EntityNode` struct or a `Vec<String>` names list.
/// The `+cbor` suffix follows RFC 6838 §4.2.8 structured-syntax conventions.
pub const CONTENT_TYPE_TERM_CBOR: &str = "application/x-ma-term+cbor";
/// CID pointer — the CBOR payload is a text string holding a `CIDv1` that
/// addresses a DAG-CBOR node in IPFS.  Receivers should fetch and decode it.
pub const CONTENT_TYPE_TERM_DAG_CBOR: &str = "application/x-ma-term+dag-cbor";
/// Inline YAML string — the CBOR payload is a text string containing a
/// UTF-8 YAML document.  Suitable for config values (scalars, sequences,
/// mappings) that do not need to be stored as separate IPFS objects.
pub const CONTENT_TYPE_TERM_YAML: &str = "application/x-ma-term+yaml";
