//! Transport-agnostic send handle to a remote ma service.
//!
//! An `Outbox` wraps the transport details and exposes a single `send()`
//! method. Outboxes are lightweight and meant to be kept alive for the
//! duration of a session — `ma-core` manages the underlying connections.
//!
//! `send()` takes a [`Message`], validates it,
//! serializes to CBOR, and transmits. Malformed or expired messages
//! are rejected before anything hits the wire.
//!
//! Requires the `iroh` feature.
//!
//! ```ignore
//! let mut outbox = ep.outbox(&resolver, "did:ma:k51qzi5uqu5d…", INBOX_PROTOCOL_ID).await?;
//! outbox.send(&message).await?;
//! // Keep the outbox alive — no need to close it.
//! ```

use crate::error::{Error, Result};
use crate::Message;
use async_trait::async_trait;

#[async_trait]
pub(crate) trait OutboxWire: Send + std::fmt::Debug {
    async fn send_payload(&mut self, payload: &[u8]) -> Result<()>;
    fn close_box(self: Box<Self>);
}

/// A transport-agnostic write handle to a remote service.
///
/// The caller doesn't need to know the underlying transport.
#[derive(Debug)]
pub struct Outbox {
    inner: Option<Box<dyn OutboxWire>>,
    did: String,
    protocol: String,
}

impl Outbox {
    /// Create an outbox backed by a transport implementation.
    pub(crate) fn from_transport<T>(transport: T, did: String, protocol: String) -> Self
    where
        T: OutboxWire + 'static,
    {
        Self {
            inner: Some(Box::new(transport)),
            did,
            protocol,
        }
    }

    /// Send a ma message to the remote service.
    ///
    /// Validates the message headers, serializes to CBOR, and transmits.
    ///
    /// # Errors
    /// Returns an error if validation, serialization, or transport send fails.
    pub async fn send(&mut self, message: &Message) -> Result<()> {
        message.headers().validate()?;
        let cbor = message.encode()?;
        match self.inner.as_mut() {
            Some(transport) => transport.send_payload(&cbor).await,
            None => Err(Error::ConnectionClosed("outbox is closed".to_string())),
        }
    }

    /// The DID this outbox delivers to.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The protocol this outbox is connected to.
    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Close the outbox gracefully.
    pub fn close(mut self) {
        if let Some(transport) = self.inner.take() {
            transport.close_box();
        }
    }
}
