//! DID document publishing to IPFS/IPNS.
//!
//! Provides request/response types, validation, and (with the `kubo` feature)
//! the [`IpfsDidPublisher`] for publishing signed DID documents via the
//! `ma/ipfs/0.0.1` service.

use crate::{Did, Document, Message};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub const MA_IPNS_ALIAS_HASH_PREFIX: &str = "ma-";

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use web_time::Duration;

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use crate::kubo::{
    dag_put, import_key, list_keys, name_publish_with_retry, wait_for_api, IpnsPublishOptions,
};
#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
use reqwest::Url;

use crate::service::CONTENT_TYPE_IPFS_REQUEST;

// ── Unified wire format ──────────────────────────────────────────────────────

/// Unified CBOR payload for all `application/x-ma-ipfs-request` messages
/// on `/ma/ipfs/0.0.1`. The `kind` field selects the operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum IpfsRequestPayload {
    /// Publish a signed DID document to IPFS/IPNS on behalf of the sender.
    DidDocumentPublish {
        /// dag-cbor encoded signed [`Document`].
        document: Vec<u8>,
        /// Raw 32-byte IPNS signing key (Ed25519 seed). Must be zeroized by receiver.
        ipns_secret_key: Vec<u8>,
    },
    /// Store arbitrary content on IPFS; receiver replies with the resulting CID.
    Store {
        content: Vec<u8>,
        content_type: String,
    },
}

fn encode_ipfs_request_payload(payload: &IpfsRequestPayload) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(payload, &mut buf)
        .map_err(|e| anyhow!("failed to encode IPFS request payload as CBOR: {}", e))?;
    Ok(buf)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpfsPublishDidResponse {
    pub ok: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
}

pub struct ValidatedIpfsPublish {
    pub document_bytes: Vec<u8>,
    pub ipns_secret_key: Vec<u8>,
    pub document: Document,
    pub document_did: Did,
}

/// Validated store request.
pub struct ValidatedIpfsStore {
    pub content: Vec<u8>,
    pub content_type: String,
    pub sender_did: String,
    pub msg_id: String,
}

/// Unified validated IPFS request — returned by [`validate_ipfs_request`].
pub enum ValidatedIpfsRequest {
    DidDocumentPublish(ValidatedIpfsPublish),
    Store(ValidatedIpfsStore),
}

/// Build CBOR content bytes for `application/x-ma-ipfs-request` (did-document-publish kind).
///
/// The returned bytes are the payload to place in `Message.content` when
/// sending to `/ma/ipfs/0.0.1`.
pub fn generate_ipfs_publish_request(
    did_document: &Document,
    ipns_secret_key: &[u8],
) -> Result<Vec<u8>> {
    let document_bytes = did_document
        .encode()
        .map_err(|e| anyhow!("failed to encode DID document as dag-cbor: {}", e))?;
    encode_ipfs_request_payload(&IpfsRequestPayload::DidDocumentPublish {
        document: document_bytes,
        ipns_secret_key: ipns_secret_key.to_vec(),
    })
}

/// Build a signed `application/x-ma-ipfs-request` message (store kind).
///
/// Returns the complete signed [`Message`] ready to send on `/ma/ipfs/0.0.1`.
pub fn generate_ipfs_store_request(
    sender_did: &str,
    publisher_did: &str,
    content: Vec<u8>,
    content_type: &str,
    signing_key: &crate::SigningKey,
) -> Result<Message> {
    let payload = encode_ipfs_request_payload(&IpfsRequestPayload::Store {
        content,
        content_type: content_type.to_string(),
    })?;
    Message::new(sender_did, publisher_did, CONTENT_TYPE_IPFS_REQUEST, payload, signing_key)
        .map_err(|e| anyhow!("failed to build ipfs-store message: {}", e))
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
#[derive(Clone, Debug)]
pub struct IpfsDidPublisher {
    kubo_url: String,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
impl IpfsDidPublisher {
    pub fn new(kubo_url: impl AsRef<str>) -> Result<Self> {
        let kubo_url = normalize_kubo_url(kubo_url.as_ref())?;
        Ok(Self { kubo_url })
    }

    pub fn kubo_url(&self) -> &str {
        &self.kubo_url
    }

    pub async fn publish_signed_message(
        &self,
        message_cbor: &[u8],
    ) -> Result<IpfsPublishDidResponse> {
        handle_ipfs_publish(&self.kubo_url, message_cbor).await
    }

    pub async fn publish_document(
        &self,
        did_document: &[u8],
        ipns_private_key: &[u8],
    ) -> Result<Option<String>> {
        publish_did_document_to_kubo(&self.kubo_url, did_document, ipns_private_key).await
    }

    pub async fn wait_until_ready(&self, attempts: u32) -> Result<()> {
        wait_for_api(&self.kubo_url, attempts).await
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
fn normalize_kubo_url(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("kubo_url must not be empty"));
    }

    let parsed =
        Url::parse(trimmed).map_err(|e| anyhow!("invalid kubo_url '{}': {}", trimmed, e))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(anyhow!(
            "kubo_url must use http or https scheme, got '{}'",
            scheme
        ));
    }

    if parsed.host_str().is_none() {
        return Err(anyhow!("kubo_url must include a host"));
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(anyhow!(
            "kubo_url must not include query params or fragments"
        ));
    }

    let mut base = format!("{}://{}", scheme, parsed.host_str().unwrap_or_default());
    if let Some(port) = parsed.port() {
        base.push(':');
        base.push_str(&port.to_string());
    }

    let mut path = parsed.path().trim_end_matches('/').to_string();
    if path.ends_with("/api/v0") {
        path.truncate(path.len() - "/api/v0".len());
    }
    if !path.is_empty() && path != "/" {
        if !path.starts_with('/') {
            base.push('/');
        }
        base.push_str(&path);
    }

    Ok(base)
}

/// Validate a full did-document-publish request from raw message CBOR bytes.
///
/// Used internally by [`IpfsDidPublisher::publish_signed_message`].
pub fn validate_ipfs_publish_request(message_cbor: &[u8]) -> Result<ValidatedIpfsPublish> {
    let message =
        Message::decode(message_cbor).map_err(|e| anyhow!("invalid signed message: {}", e))?;
    match validate_ipfs_request(&message)? {
        ValidatedIpfsRequest::DidDocumentPublish(v) => Ok(v),
        ValidatedIpfsRequest::Store(_) => Err(anyhow!(
            "expected did-document-publish kind on /ma/ipfs/0.0.1, got store"
        )),
    }
}

/// Validate any `application/x-ma-ipfs-request` message, dispatching on `kind`.
///
/// For `did-document-publish`: verifies the DID document signature and that
/// the sender IPNS matches the document DID. Returns a [`ValidatedIpfsPublish`].
///
/// For `store`: extracts content and sender identity. Returns a [`ValidatedIpfsStore`].
pub fn validate_ipfs_request(message: &Message) -> Result<ValidatedIpfsRequest> {
    if message.content_type != CONTENT_TYPE_IPFS_REQUEST {
        return Err(anyhow!(
            "expected {} on /ma/ipfs/0.0.1, got {}",
            CONTENT_TYPE_IPFS_REQUEST,
            message.content_type
        ));
    }

    let payload: IpfsRequestPayload = ciborium::de::from_reader(message.content.as_slice())
        .map_err(|e| anyhow!("invalid IPFS request payload: {}", e))?;

    match payload {
        IpfsRequestPayload::DidDocumentPublish {
            document: document_bytes,
            ipns_secret_key,
        } => {
            let sender_did = Did::try_from(message.from.as_str())
                .map_err(|e| anyhow!("invalid sender did '{}': {}", message.from, e))?;

            let document = Document::decode(&document_bytes)
                .map_err(|e| anyhow!("invalid DID document dag-cbor: {}", e))?;
            document
                .validate()
                .map_err(|e| anyhow!("invalid DID document: {}", e))?;
            document
                .verify()
                .map_err(|e| anyhow!("DID document signature verification failed: {}", e))?;

            let document_did = Did::try_from(document.id.as_str())
                .map_err(|e| anyhow!("invalid document DID '{}': {}", document.id, e))?;

            if document_did.ipns != sender_did.ipns {
                return Err(anyhow!(
                    "sender IPNS '{}' does not match document IPNS '{}'",
                    sender_did.ipns,
                    document_did.ipns
                ));
            }

            message
                .verify_with_document(&document)
                .map_err(|e| anyhow!("request signature verification failed: {}", e))?;

            Ok(ValidatedIpfsRequest::DidDocumentPublish(ValidatedIpfsPublish {
                document_bytes,
                ipns_secret_key,
                document,
                document_did,
            }))
        }
        IpfsRequestPayload::Store {
            content,
            content_type,
        } => Ok(ValidatedIpfsRequest::Store(ValidatedIpfsStore {
            content,
            content_type,
            sender_did: message.from.clone(),
            msg_id: message.id.clone(),
        })),
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub async fn publish_did_document_to_kubo(
    kubo_url: &str,
    did_document: &[u8],
    ipns_private_key: &[u8],
) -> Result<Option<String>> {
    let document = Document::decode(did_document)
        .map_err(|e| anyhow!("invalid DID document dag-cbor: {}", e))?;
    let document_did = Did::try_from(document.id.as_str())
        .map_err(|e| anyhow!("invalid document DID '{}': {}", document.id, e))?;
    let document_ipns_id = document_did.ipns.clone();

    // Deterministic key name derived from the DID IPNS identity.
    // Same DID always maps to the same Kubo key name — idempotent, no cleanup needed.
    let hash = blake3::hash(document_ipns_id.as_bytes());
    let key_name = format!("{}{}", MA_IPNS_ALIAS_HASH_PREFIX, &hash.to_hex()[..16]);

    let existing_key = list_keys(kubo_url)
        .await?
        .into_iter()
        .find(|k| k.name == key_name);

    if let Some(existing) = existing_key {
        if existing.id.trim() != document_ipns_id {
            return Err(anyhow!(
                "existing key '{}' has IPNS id '{}' but document DID IPNS is '{}'",
                key_name,
                existing.id,
                document_ipns_id
            ));
        }
    } else {
        if ipns_private_key.is_empty() {
            return Err(anyhow!(
                "ipns_private_key is required when key is not present in Kubo"
            ));
        }

        let raw_key: [u8; 32] = ipns_private_key
            .try_into()
            .map_err(|_| anyhow!("ipns_private_key must be 32 bytes"))?;
        let keypair = libp2p_identity::Keypair::ed25519_from_bytes(raw_key)
            .map_err(|e| anyhow!("invalid ipns key: {}", e))?;
        let protobuf_key = keypair
            .to_protobuf_encoding()
            .map_err(|e| anyhow!("failed to encode ipns key: {}", e))?;
        let imported = import_key(kubo_url, &key_name, protobuf_key).await?;
        if imported.id.trim() != document_ipns_id {
            return Err(anyhow!(
                "imported key IPNS id '{}' does not match document DID IPNS '{}'",
                imported.id,
                document_ipns_id
            ));
        }
    }

    let published_cid = dag_put(kubo_url, &document).await?;
    let ipns_options = IpnsPublishOptions::default();
    name_publish_with_retry(
        kubo_url,
        &key_name,
        &published_cid,
        &ipns_options,
        3,
        Duration::from_secs(1),
    )
    .await?;

    Ok(Some(published_cid))
}

#[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
pub async fn handle_ipfs_publish(
    kubo_url: &str,
    message_cbor: &[u8],
) -> Result<IpfsPublishDidResponse> {
    let validated = validate_ipfs_publish_request(message_cbor)?;

    let cid = publish_did_document_to_kubo(
        kubo_url,
        &validated.document_bytes,
        &validated.ipns_secret_key,
    )
    .await?;

    Ok(IpfsPublishDidResponse {
        ok: true,
        message: "did document published via ma/ipfs/0.0.1".to_string(),
        did: Some(validated.document_did.id()),
        cid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_identity_from_secret, Did, SigningKey};

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    use super::normalize_kubo_url;

    fn test_identity(seed: u8) -> crate::GeneratedIdentity {
        generate_identity_from_secret([seed; 32]).expect("identity")
    }

    fn test_signing_key(identity: &crate::GeneratedIdentity) -> SigningKey {
        let sign_url = Did::new_url(&identity.subject_url.ipns, None::<String>).expect("did url");
        let private_key: [u8; 32] = hex::decode(&identity.signing_private_key_hex)
            .expect("decode key")
            .try_into()
            .expect("private key bytes");
        SigningKey::from_private_key_bytes(sign_url, private_key).expect("signing key")
    }

    #[test]
    fn generate_request_embeds_cbor_document_and_private_key() {
        let identity = test_identity(21);
        let payload =
            generate_ipfs_publish_request(&identity.document, b"secret-key").expect("payload");
        let request: IpfsRequestPayload =
            ciborium::de::from_reader(payload.as_slice()).expect("decode request");

        match request {
            IpfsRequestPayload::DidDocumentPublish { document, ipns_secret_key } => {
                assert_eq!(document, identity.document.encode().expect("document bytes"));
                assert_eq!(ipns_secret_key, b"secret-key".to_vec());
            }
            _ => panic!("expected DidDocumentPublish variant"),
        }
    }

    #[test]
    fn validate_ipfs_publish_request_accepts_signed_request() {
        let identity = test_identity(22);
        let signing_key = test_signing_key(&identity);
        let payload =
            generate_ipfs_publish_request(&identity.document, b"private-key").expect("payload");
        let message = Message::new(
            identity.document.id.clone(),
            String::new(),
            CONTENT_TYPE_IPFS_REQUEST,
            payload,
            &signing_key,
        )
        .expect("message");
        let encoded = message.encode().expect("message cbor");

        let validated = validate_ipfs_publish_request(&encoded).expect("validated request");
        assert_eq!(validated.document, identity.document);
        assert_eq!(validated.ipns_secret_key, b"private-key".to_vec());
    }

    #[test]
    fn validate_ipfs_publish_request_rejects_wrong_content_type() {
        let identity = test_identity(23);
        let signing_key = test_signing_key(&identity);
        let payload =
            generate_ipfs_publish_request(&identity.document, b"private-key").expect("payload");
        let message = Message::new(
            identity.document.id.clone(),
            String::new(),
            "application/x-test",
            payload,
            &signing_key,
        )
        .expect("message");
        let encoded = message.encode().expect("message cbor");

        let err = validate_ipfs_publish_request(&encoded)
            .err()
            .expect("wrong content type");
        assert!(err
            .to_string()
            .contains("expected application/x-ma-ipfs-request"));
    }

    #[test]
    fn validate_ipfs_publish_request_rejects_ipns_mismatch() {
        let sender_identity = test_identity(24);
        let document_identity = test_identity(25);
        let signing_key = test_signing_key(&sender_identity);
        let payload = generate_ipfs_publish_request(&document_identity.document, b"private-key")
            .expect("payload");
        let message = Message::new(
            sender_identity.document.id.clone(),
            String::new(),
            CONTENT_TYPE_IPFS_REQUEST,
            payload,
            &signing_key,
        )
        .expect("message");
        let encoded = message.encode().expect("message cbor");

        let err = validate_ipfs_publish_request(&encoded)
            .err()
            .expect("ipns mismatch");
        assert!(err.to_string().contains("does not match document IPNS"));
    }

    #[test]
    fn validate_ipfs_publish_request_rejects_invalid_document_bytes() {
        let identity = test_identity(26);
        let signing_key = test_signing_key(&identity);
        let payload = encode_ipfs_request_payload(&IpfsRequestPayload::DidDocumentPublish {
            document: b"not dag-cbor".to_vec(),
            ipns_secret_key: b"private-key".to_vec(),
        })
        .expect("encode request");
        let message = Message::new(
            identity.document.id.clone(),
            String::new(),
            CONTENT_TYPE_IPFS_REQUEST,
            payload,
            &signing_key,
        )
        .expect("message");
        let encoded = message.encode().expect("message cbor");

        let err = validate_ipfs_publish_request(&encoded)
            .err()
            .expect("invalid document");
        assert!(err.to_string().contains("invalid IPFS request payload") || err.to_string().contains("invalid DID document dag-cbor"));
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn normalizes_trailing_slash() {
        assert_eq!(
            normalize_kubo_url("http://127.0.0.1:5001/").expect("normalize url"),
            "http://127.0.0.1:5001"
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn strips_api_v0_suffix() {
        assert_eq!(
            normalize_kubo_url("http://127.0.0.1:5001/api/v0").expect("normalize url"),
            "http://127.0.0.1:5001"
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn keeps_custom_base_path() {
        assert_eq!(
            normalize_kubo_url("http://localhost:5001/kubo").expect("normalize url"),
            "http://localhost:5001/kubo"
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn rejects_empty_url() {
        assert!(normalize_kubo_url("   ").is_err());
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "kubo"))]
    #[test]
    fn rejects_non_http_scheme() {
        assert!(normalize_kubo_url("ftp://127.0.0.1:5001").is_err());
    }
}
