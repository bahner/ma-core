use cid::Cid;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ipld_core::ipld::Ipld;
use serde::{Deserialize, Serialize};
use web_time::{SystemTime, UNIX_EPOCH};

use crate::{
    did::Did,
    error::{MaError, MaResult as Result},
    key::{EncryptionKey, SigningKey, ED25519_PUB_CODEC, EDDSA_SIG_CODEC, X25519_PUB_CODEC},
    multiformat::{
        public_key_multibase_decode, signature_multibase_decode, signature_multibase_encode,
    },
};

pub const DEFAULT_DID_CONTEXT: &[&str] = &["https://www.w3.org/ns/did/v1.1"];
pub const DEFAULT_PROOF_TYPE: &str = "MultiformatSignature2023";
pub const DEFAULT_PROOF_PURPOSE: &str = "assertionMethod";

/// Returns the current UTC time as an ISO 8601 string with millisecond precision.
pub fn now_iso_utc() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        // Use chrono for ISO formatting on wasm
        use chrono::prelude::*;
        let now = js_sys::Date::new_0().get_time();
        let secs = (now / 1000.0) as i64;
        let nsecs = ((now % 1000.0) * 1_000_000.0) as u32;
        let dt = Utc.timestamp_opt(secs, nsecs).unwrap();
        return dt.to_rfc3339_opts(SecondsFormat::Millis, true);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        unix_millis_to_iso(duration.as_secs(), duration.subsec_millis())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn unix_millis_to_iso(secs: u64, millis: u32) -> String {
    // Howard Hinnant's civil_from_days algorithm.
    let z = (secs / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let tod = secs % 86400;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60,
        millis,
    )
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

impl VerificationMethod {
    pub fn new(
        id: impl AsRef<str>,
        controller: impl Into<String>,
        key_type: impl Into<String>,
        fragment: impl AsRef<str>,
        public_key_multibase: impl Into<String>,
    ) -> Result<Self> {
        let base_id = id
            .as_ref()
            .split('#')
            .next()
            .ok_or(MaError::MissingIdentifier)?;

        let method = Self {
            id: format!("{base_id}#{}", fragment.as_ref()),
            key_type: key_type.into(),
            controller: controller.into(),
            public_key_multibase: public_key_multibase.into(),
        };
        method.validate()?;
        Ok(method)
    }

    pub fn fragment(&self) -> Result<String> {
        let did = Did::try_from(self.id.as_str())?;
        did.fragment.ok_or(MaError::MissingFragment)
    }

    pub fn validate(&self) -> Result<()> {
        Did::validate_url(&self.id)?;

        if self.key_type.is_empty() {
            return Err(MaError::VerificationMethodMissingType);
        }

        if self.controller.is_empty() {
            return Err(MaError::EmptyController);
        }

        Did::validate(&self.controller)?;

        if self.public_key_multibase.is_empty() {
            return Err(MaError::EmptyPublicKeyMultibase);
        }

        public_key_multibase_decode(&self.public_key_multibase)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl Proof {
    pub fn new(proof_value: impl Into<String>, verification_method: impl Into<String>) -> Self {
        Self {
            proof_type: DEFAULT_PROOF_TYPE.to_string(),
            verification_method: verification_method.into(),
            proof_purpose: DEFAULT_PROOF_PURPOSE.to_string(),
            proof_value: proof_value.into(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.proof_value.is_empty()
    }
}

fn is_valid_rfc3339_utc(value: &str) -> bool {
    let trimmed = value.trim();
    // Strict enough for ISO-8601 UTC produced by current implementations.
    if !trimmed.ends_with('Z') {
        return false;
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    let expected_punct = [
        (4usize, b'-'),
        (7usize, b'-'),
        (10usize, b'T'),
        (13usize, b':'),
        (16usize, b':'),
    ];
    if expected_punct
        .iter()
        .any(|(idx, punct)| bytes.get(*idx).copied() != Some(*punct))
    {
        return false;
    }
    let core_digits = [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    if core_digits.iter().any(|idx| {
        !bytes
            .get(*idx)
            .copied()
            .unwrap_or_default()
            .is_ascii_digit()
    }) {
        return false;
    }
    let tail = &trimmed[19..trimmed.len() - 1];
    if tail.is_empty() {
        return true;
    }
    if let Some(frac) = tail.strip_prefix('.') {
        return !frac.is_empty() && frac.chars().all(|ch| ch.is_ascii_digit());
    }
    false
}

/// A `did:ma:` DID document.
///
/// Contains verification methods, proof, and optional extension data.
/// Documents are signed with Ed25519 over a BLAKE3 hash of the dag-cbor-serialized
/// payload (all fields except `proof`).
///
/// # Examples
///
/// ```
/// use ma_core::{generate_identity_from_secret, Document};
///
/// let id = generate_identity_from_secret([7u8; 32]).unwrap();
///
/// // Verify the signature
/// id.document.verify().unwrap();
///
/// // Validate structural correctness
/// id.document.validate().unwrap();
///
/// // Round-trip through JSON
/// let json = id.document.marshal().unwrap();
/// let restored = Document::unmarshal(&json).unwrap();
/// assert_eq!(id.document, restored);
///
/// // Round-trip through CBOR
/// let cbor = id.document.to_cbor().unwrap();
/// let restored = Document::from_cbor(&cbor).unwrap();
/// assert_eq!(id.document, restored);
/// ```
///
/// # Extension namespace
///
/// The `ma` field is an opaque IPLD value for application-defined
/// extension data. did-ma does not interpret or validate its contents.
/// Using [`Ipld`] gives native support for CID links and dag-cbor/dag-json
/// round-tripping.
///
/// ```
/// use std::collections::BTreeMap;
/// use ipld_core::ipld::Ipld;
/// use ma_core::{Did, Document};
///
/// let did = Did::new_url("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr", None::<String>).unwrap();
/// let mut doc = Document::new(&did, &did);
/// let ma = Ipld::Map(BTreeMap::from([
///     ("type".into(), Ipld::String("agent".into())),
///     ("services".into(), Ipld::Map(BTreeMap::new())),
/// ]));
/// doc.set_ma(ma);
/// assert!(doc.ma.is_some());
/// doc.clear_ma();
/// assert!(doc.ma.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub controller: Vec<String>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "keyAgreement")]
    pub key_agreement: Vec<String>,
    pub proof: Proof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ma: Option<Ipld>,
}

impl Document {
    pub fn new(identity: &Did, controller: &Did) -> Self {
        let now = now_iso_utc();
        Self {
            context: DEFAULT_DID_CONTEXT
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            id: identity.base_id(),
            controller: vec![controller.base_id()],
            verification_method: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            proof: Proof::default(),
            identity: None,
            created_at: now.clone(),
            updated_at: now,
            ma: None,
        }
    }

    /// Set the opaque `ma` extension namespace.
    pub fn set_ma(&mut self, ma: Ipld) {
        match &ma {
            Ipld::Null => self.ma = None,
            Ipld::Map(m) if m.is_empty() => self.ma = None,
            _ => self.ma = Some(ma),
        }
    }

    /// Clear the `ma` extension namespace.
    pub fn clear_ma(&mut self) {
        self.ma = None;
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        serde_ipld_dagcbor::to_vec(self).map_err(|error| MaError::CborEncode(error.to_string()))
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        serde_ipld_dagcbor::from_slice(bytes)
            .map_err(|error| MaError::CborDecode(error.to_string()))
    }

    pub fn marshal(&self) -> Result<String> {
        self.to_json()
    }

    pub fn unmarshal(s: &str) -> Result<Self> {
        Self::from_json(s)
    }

    fn to_json(&self) -> Result<String> {
        let bytes = serde_ipld_dagjson::to_vec(self)
            .map_err(|error| MaError::JsonEncode(error.to_string()))?;
        String::from_utf8(bytes).map_err(|error| MaError::JsonEncode(error.to_string()))
    }

    fn from_json(s: &str) -> Result<Self> {
        serde_ipld_dagjson::from_slice(s.as_bytes())
            .map_err(|error| MaError::JsonDecode(error.to_string()))
    }

    pub fn add_controller(&mut self, controller: impl Into<String>) -> Result<()> {
        let controller = controller.into();
        Did::validate(&controller)?;
        if !self.controller.contains(&controller) {
            self.controller.push(controller);
        }
        Ok(())
    }

    pub fn add_verification_method(&mut self, method: VerificationMethod) -> Result<()> {
        method.validate()?;
        let duplicate = self.verification_method.iter().any(|existing| {
            existing.id == method.id || existing.public_key_multibase == method.public_key_multibase
        });

        if !duplicate {
            self.verification_method.push(method);
        }

        Ok(())
    }

    pub fn get_verification_method_by_id(&self, method_id: &str) -> Result<&VerificationMethod> {
        self.verification_method
            .iter()
            .find(|method| method.id == method_id)
            .ok_or_else(|| MaError::UnknownVerificationMethod(method_id.to_string()))
    }

    pub fn set_identity(&mut self, identity: impl Into<String>) -> Result<()> {
        let identity = identity.into();
        Cid::try_from(identity.as_str()).map_err(|_| MaError::InvalidIdentity)?;
        self.identity = Some(identity);
        Ok(())
    }

    /// Update the `updatedAt` timestamp to the current time.
    pub fn touch(&mut self) {
        self.updated_at = now_iso_utc();
    }

    pub fn assertion_method_public_key(&self) -> Result<VerifyingKey> {
        let assertion_id = self
            .assertion_method
            .first()
            .ok_or_else(|| MaError::UnknownVerificationMethod("assertionMethod".to_string()))?;
        let vm = self.get_verification_method_by_id(assertion_id)?;
        let (codec, public_key_bytes) = public_key_multibase_decode(&vm.public_key_multibase)?;
        if codec != ED25519_PUB_CODEC {
            return Err(MaError::InvalidMulticodec {
                expected: ED25519_PUB_CODEC,
                actual: codec,
            });
        }

        let key_len = public_key_bytes.len();
        let bytes: [u8; 32] =
            public_key_bytes
                .try_into()
                .map_err(|_| MaError::InvalidKeyLength {
                    expected: 32,
                    actual: key_len,
                })?;

        VerifyingKey::from_bytes(&bytes).map_err(|_| MaError::Crypto)
    }

    pub fn key_agreement_public_key_bytes(&self) -> Result<[u8; 32]> {
        let agreement_id = self
            .key_agreement
            .first()
            .ok_or_else(|| MaError::UnknownVerificationMethod("keyAgreement".to_string()))?;
        let vm = self.get_verification_method_by_id(agreement_id)?;
        let (codec, public_key_bytes) = public_key_multibase_decode(&vm.public_key_multibase)?;
        if codec != X25519_PUB_CODEC {
            return Err(MaError::InvalidMulticodec {
                expected: X25519_PUB_CODEC,
                actual: codec,
            });
        }

        let key_len = public_key_bytes.len();
        public_key_bytes
            .try_into()
            .map_err(|_| MaError::InvalidKeyLength {
                expected: 32,
                actual: key_len,
            })
    }

    pub fn payload_document(&self) -> Self {
        let mut payload = self.clone();
        payload.proof = Proof::default();
        payload
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>> {
        self.payload_document().to_cbor()
    }

    pub fn payload_hash(&self) -> Result<[u8; 32]> {
        Ok(blake3::hash(&self.payload_bytes()?).into())
    }

    pub fn sign(
        &mut self,
        signing_key: &SigningKey,
        verification_method: &VerificationMethod,
    ) -> Result<()> {
        if signing_key.public_key_multibase != verification_method.public_key_multibase {
            return Err(MaError::InvalidPublicKeyMultibase);
        }

        let signature = signing_key.sign(&self.payload_hash()?);
        let proof_value = signature_multibase_encode(EDDSA_SIG_CODEC, &signature)?;
        self.proof = Proof::new(proof_value, verification_method.id.clone());
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        if self.proof.is_empty() {
            return Err(MaError::MissingProof);
        }

        let (codec, sig_bytes) = signature_multibase_decode(&self.proof.proof_value)?;
        if codec != EDDSA_SIG_CODEC {
            return Err(MaError::InvalidDocumentSignature);
        }
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| MaError::InvalidDocumentSignature)?;
        let public_key = self.assertion_method_public_key()?;
        public_key
            .verify(&self.payload_hash()?, &signature)
            .map_err(|_| MaError::InvalidDocumentSignature)
    }

    pub fn validate(&self) -> Result<()> {
        if self.context.is_empty() {
            return Err(MaError::EmptyContext);
        }

        Did::validate(&self.id)?;

        if self.controller.is_empty() {
            return Err(MaError::EmptyController);
        }

        for controller in &self.controller {
            Did::validate(controller)?;
        }

        if let Some(identity) = &self.identity {
            Cid::try_from(identity.as_str()).map_err(|_| MaError::InvalidIdentity)?;
        }

        if !is_valid_rfc3339_utc(&self.created_at) {
            return Err(MaError::InvalidCreatedAt(self.created_at.clone()));
        }

        if !is_valid_rfc3339_utc(&self.updated_at) {
            return Err(MaError::InvalidUpdatedAt(self.updated_at.clone()));
        }

        for method in &self.verification_method {
            method.validate()?;
        }

        if self.assertion_method.is_empty() {
            return Err(MaError::UnknownVerificationMethod(
                "assertionMethod".to_string(),
            ));
        }

        if self.key_agreement.is_empty() {
            return Err(MaError::UnknownVerificationMethod(
                "keyAgreement".to_string(),
            ));
        }

        Ok(())
    }
}

impl TryFrom<&EncryptionKey> for VerificationMethod {
    type Error = MaError;

    fn try_from(value: &EncryptionKey) -> Result<Self> {
        let fragment = value.did.fragment.clone().ok_or(MaError::MissingFragment)?;
        VerificationMethod::new(
            value.did.base_id(),
            value.did.base_id(),
            value.key_type.clone(),
            fragment,
            value.public_key_multibase.clone(),
        )
    }
}

impl TryFrom<&SigningKey> for VerificationMethod {
    type Error = MaError;

    fn try_from(value: &SigningKey) -> Result<Self> {
        let fragment = value.did.fragment.clone().ok_or(MaError::MissingFragment)?;
        VerificationMethod::new(
            value.did.base_id(),
            value.did.base_id(),
            value.key_type.clone(),
            fragment,
            value.public_key_multibase.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn set_ma_stores_opaque_value() {
        let root = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            None::<String>,
        )
        .expect("valid test did");
        let mut document = Document::new(&root, &root);

        let ma = Ipld::Map(BTreeMap::from([(
            "type".into(),
            Ipld::String("agent".into()),
        )]));
        document.set_ma(ma.clone());
        assert_eq!(document.ma.as_ref(), Some(&ma));
    }

    #[test]
    fn clear_ma_removes_value() {
        let root = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            None::<String>,
        )
        .expect("valid test did");
        let mut document = Document::new(&root, &root);

        document.set_ma(Ipld::Map(BTreeMap::from([(
            "type".into(),
            Ipld::String("agent".into()),
        )])));
        assert!(document.ma.is_some());
        document.clear_ma();
        assert!(document.ma.is_none());
    }

    #[test]
    fn set_ma_null_clears() {
        let root = Did::new_url(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
            None::<String>,
        )
        .expect("valid test did");
        let mut document = Document::new(&root, &root);

        document.set_ma(Ipld::Map(BTreeMap::from([(
            "type".into(),
            Ipld::String("agent".into()),
        )])));
        document.set_ma(Ipld::Null);
        assert!(document.ma.is_none());
    }

    #[test]
    fn validate_accepts_opaque_ma() {
        let identity = crate::identity::generate_identity(
            "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr",
        )
        .expect("generate identity");
        let mut document = identity.document;
        document.set_ma(Ipld::Map(BTreeMap::from([
            ("type".into(), Ipld::String("bahner".into())),
            ("custom".into(), Ipld::Integer(42)),
        ])));
        document
            .validate()
            .expect("validate should accept any ma value");
    }
}
