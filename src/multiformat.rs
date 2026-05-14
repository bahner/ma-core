use unsigned_varint::{decode, encode};

use crate::error::{MaError, MaResult as Result};

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
