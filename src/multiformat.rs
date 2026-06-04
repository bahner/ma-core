use unsigned_varint::{decode, encode};

use crate::error::{MaError, MaResult as Result};

// Well-known multicodec codec identifiers for payload encoding.
// Key/signature codecs live in key.rs.
// Source: https://github.com/multiformats/multicodec/blob/master/table.csv
pub const CODEC_IDENTITY: u64 = 0x00;
pub const CODEC_RAW: u64 = 0x55;
pub const CODEC_CBOR: u64 = 0x51;
pub const CODEC_DAG_CBOR: u64 = 0x71;
pub const CODEC_DAG_JSON: u64 = 0x0129;
pub const CODEC_JSON: u64 = 0x0200;

pub fn multibase_encode(data: &[u8]) -> String {
    multibase::encode(multibase::Base::Base58Btc, data)
}

pub fn multibase_decode(input: &str) -> Result<Vec<u8>> {
    multibase::decode(input)
        .map(|(_, data)| data)
        .map_err(|_| MaError::InvalidPublicKeyMultibase)
}

pub fn multicodec_encode(codec: u64, payload: &[u8]) -> Vec<u8> {
    let mut buffer = encode::u64_buffer();
    let prefix = encode::u64(codec, &mut buffer);
    let mut out = prefix.to_vec();
    out.extend_from_slice(payload);
    out
}

pub fn multicodec_decode(encoded: &[u8]) -> Result<(u64, Vec<u8>)> {
    let (codec, remainder) =
        decode::u64(encoded).map_err(|_| MaError::InvalidPublicKeyMultibase)?;
    if remainder.is_empty() {
        return Err(MaError::InvalidPublicKeyMultibase);
    }
    Ok((codec, remainder.to_vec()))
}

pub fn public_key_multibase_encode(codec: u64, public_key: &[u8]) -> String {
    multibase_encode(&multicodec_encode(codec, public_key))
}

pub fn public_key_multibase_decode(input: &str) -> Result<(u64, Vec<u8>)> {
    let decoded = multibase_decode(input)?;
    multicodec_decode(&decoded)
}

pub fn signature_multibase_encode(codec: u64, signature: &[u8]) -> String {
    multibase_encode(&multicodec_encode(codec, signature))
}

pub fn signature_multibase_decode(input: &str) -> Result<(u64, Vec<u8>)> {
    let decoded = multibase_decode(input)?;
    multicodec_decode(&decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicodec_round_trip_dag_cbor() {
        let payload = b"hello dag-cbor";
        let encoded = multicodec_encode(CODEC_DAG_CBOR, payload);
        let (codec, decoded) = multicodec_decode(&encoded).unwrap();
        assert_eq!(codec, CODEC_DAG_CBOR);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn multicodec_round_trip_identity() {
        let payload = b"raw bytes";
        let encoded = multicodec_encode(CODEC_IDENTITY, payload);
        let (codec, decoded) = multicodec_decode(&encoded).unwrap();
        assert_eq!(codec, CODEC_IDENTITY);
        assert_eq!(decoded.as_slice(), payload);
    }

    #[test]
    fn multicodec_round_trip_large_codec_varint() {
        // CODEC_DAG_JSON (0x0129) requires a 2-byte varint — exercises multi-byte encoding.
        let payload = b"json payload";
        let encoded = multicodec_encode(CODEC_DAG_JSON, payload);
        let (codec, decoded) = multicodec_decode(&encoded).unwrap();
        assert_eq!(codec, CODEC_DAG_JSON);
        assert_eq!(decoded.as_slice(), payload);
    }

    #[test]
    fn multicodec_decode_empty_payload_fails() {
        // A valid varint prefix with no payload following it should be rejected.
        let mut buf = unsigned_varint::encode::u64_buffer();
        let prefix = unsigned_varint::encode::u64(CODEC_CBOR, &mut buf);
        assert!(multicodec_decode(prefix).is_err());
    }

    #[test]
    fn multicodec_decode_empty_slice_fails() {
        assert!(multicodec_decode(&[]).is_err());
    }

    #[test]
    fn multibase_round_trip() {
        let data = b"test data 12345";
        let encoded = multibase_encode(data);
        assert!(
            encoded.starts_with('z'),
            "base58btc multibase prefix is 'z'"
        );
        let decoded = multibase_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn multibase_decode_invalid_input_fails() {
        assert!(multibase_decode("!!!not-valid!!!").is_err());
    }

    #[test]
    fn public_key_multibase_round_trip() {
        // Use the Ed25519 public key codec (0xed).
        let codec = 0xed_u64;
        let key_bytes = [42u8; 32];
        let encoded = public_key_multibase_encode(codec, &key_bytes);
        let (decoded_codec, decoded_bytes) = public_key_multibase_decode(&encoded).unwrap();
        assert_eq!(decoded_codec, codec);
        assert_eq!(decoded_bytes.as_slice(), &key_bytes);
    }

    #[test]
    fn signature_multibase_round_trip() {
        // Use the EdDSA signature codec (0xd0ed).
        let codec = 0xd0ed_u64;
        let sig_bytes = [99u8; 64];
        let encoded = signature_multibase_encode(codec, &sig_bytes);
        let (decoded_codec, decoded_bytes) = signature_multibase_decode(&encoded).unwrap();
        assert_eq!(decoded_codec, codec);
        assert_eq!(decoded_bytes.as_slice(), &sig_bytes);
    }

    #[test]
    fn multicodec_encode_prepends_prefix_bytes() {
        // CODEC_IDENTITY = 0x00 → single zero byte prefix.
        let payload = b"x";
        let encoded = multicodec_encode(CODEC_IDENTITY, payload);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(&encoded[1..], payload);
    }
}
