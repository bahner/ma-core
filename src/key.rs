use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    did::Did,
    error::{MaError, MaResult as Result},
    multiformat::{public_key_multibase_decode, public_key_multibase_encode},
};

pub const ASSERTION_METHOD_KEY_TYPE: &str = "Multikey";
pub const KEY_AGREEMENT_KEY_TYPE: &str = "Multikey";

// https://github.com/multiformats/multicodec/blob/master/table.csv
pub const CODEC_X25519_PUB: u64 = 0xec;
pub const CODEC_ED25519_PUB: u64 = 0xed;
pub const CODEC_EDDSA_SIG: u64 = 0xd0ed;

/// Ed25519 signing key for document proofs and message signatures.
///
/// # Examples
///
/// ```
/// use ma_core::{Did, SigningKey};
///
/// let did = Did::new_url("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr", None::<String>).unwrap();
/// let key = SigningKey::generate(did).unwrap();
///
/// let signature = key.sign(b"hello world");
/// assert!(!signature.is_empty());
///
/// // Export and reimport private key bytes
/// let bytes = key.private_key_bytes();
/// let did2 = Did::new_url("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr", None::<String>).unwrap();
/// let restored = SigningKey::from_private_key_bytes(did2, bytes).unwrap();
/// assert_eq!(key.public_key_multibase, restored.public_key_multibase);
/// ```
#[derive(Clone)]
pub struct SigningKey {
    pub did: Did,
    pub key_type: String,
    secret_key: Ed25519SigningKey,
    pub public_key_multibase: String,
}

impl SigningKey {
    pub fn generate(did: Did) -> Result<Self> {
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let public_key_multibase =
            public_key_multibase_encode(CODEC_ED25519_PUB, signing_key.verifying_key().as_bytes());

        Ok(Self {
            did,
            key_type: ASSERTION_METHOD_KEY_TYPE.to_string(),
            secret_key: signing_key,
            public_key_multibase,
        })
    }

    #[must_use]
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.secret_key.sign(data).to_bytes().to_vec()
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.secret_key.verifying_key()
    }

    #[must_use]
    pub fn private_key_bytes(&self) -> [u8; ed25519_dalek::SECRET_KEY_LENGTH] {
        self.secret_key.to_bytes()
    }

    pub fn from_private_key_bytes(
        did: Did,
        private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    ) -> Result<Self> {
        let signing_key = Ed25519SigningKey::from_bytes(&private_key);
        let public_key_multibase =
            public_key_multibase_encode(CODEC_ED25519_PUB, signing_key.verifying_key().as_bytes());

        Ok(Self {
            did,
            key_type: ASSERTION_METHOD_KEY_TYPE.to_string(),
            secret_key: signing_key,
            public_key_multibase,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Did::validate(&self.did.id())?;

        if self.key_type != ASSERTION_METHOD_KEY_TYPE {
            return Err(MaError::InvalidKeyType);
        }

        let (codec, key_bytes) = public_key_multibase_decode(&self.public_key_multibase)?;
        if codec != CODEC_ED25519_PUB {
            return Err(MaError::InvalidMulticodec {
                expected: CODEC_ED25519_PUB,
                actual: codec,
            });
        }

        if key_bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(MaError::InvalidKeyLength {
                expected: ed25519_dalek::PUBLIC_KEY_LENGTH,
                actual: key_bytes.len(),
            });
        }

        Ok(())
    }
}

/// X25519 encryption key for envelope key agreement.
///
/// Used to compute shared secrets via Diffie-Hellman for encrypting
/// and decrypting [`Envelope`](crate::Envelope) payloads.
///
/// # Examples
///
/// ```
/// use ma_core::{Did, EncryptionKey};
///
/// let did = Did::new_url("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr", None::<String>).unwrap();
/// let key = EncryptionKey::generate(did).unwrap();
///
/// // Export and reimport
/// let bytes = key.private_key_bytes();
/// let did2 = Did::new_url("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr", None::<String>).unwrap();
/// let restored = EncryptionKey::from_private_key_bytes(did2, bytes).unwrap();
/// assert_eq!(key.public_key_multibase, restored.public_key_multibase);
/// ```
#[derive(Clone)]
pub struct EncryptionKey {
    pub did: Did,
    pub key_type: String,
    private_key: StaticSecret,
    pub public_key: X25519PublicKey,
    pub public_key_multibase: String,
}

impl EncryptionKey {
    pub fn generate(did: Did) -> Result<Self> {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        let public_key_multibase =
            public_key_multibase_encode(CODEC_X25519_PUB, public_key.as_bytes());

        Ok(Self {
            did,
            key_type: KEY_AGREEMENT_KEY_TYPE.to_string(),
            private_key,
            public_key,
            public_key_multibase,
        })
    }

    #[must_use]
    pub fn shared_secret(&self, other: &X25519PublicKey) -> [u8; 32] {
        self.private_key.diffie_hellman(other).to_bytes()
    }

    #[must_use]
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    pub fn from_private_key_bytes(did: Did, private_key: [u8; 32]) -> Result<Self> {
        let private_key = StaticSecret::from(private_key);
        let public_key = X25519PublicKey::from(&private_key);
        let public_key_multibase =
            public_key_multibase_encode(CODEC_X25519_PUB, public_key.as_bytes());

        Ok(Self {
            did,
            key_type: KEY_AGREEMENT_KEY_TYPE.to_string(),
            private_key,
            public_key,
            public_key_multibase,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Did::validate(&self.did.id())?;

        if self.key_type != KEY_AGREEMENT_KEY_TYPE {
            return Err(MaError::InvalidKeyType);
        }

        let (codec, key_bytes) = public_key_multibase_decode(&self.public_key_multibase)?;
        if codec != CODEC_X25519_PUB {
            return Err(MaError::InvalidMulticodec {
                expected: CODEC_X25519_PUB,
                actual: codec,
            });
        }

        if key_bytes.len() != 32 {
            return Err(MaError::InvalidKeyLength {
                expected: 32,
                actual: key_bytes.len(),
            });
        }

        Ok(())
    }
}
