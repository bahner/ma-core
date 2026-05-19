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
