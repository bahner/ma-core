use std::sync::OnceLock;

pub const NAME: &str = "ma";
pub const PROPER_NAME: &str = "間";
pub const VERSION: &str = "0.0.1";

#[must_use]
pub fn rendezvous() -> String {
    format!("/{NAME}/{VERSION}")
}

static BLAKE3_CONTENT_LABEL: OnceLock<String> = OnceLock::new();

pub fn blake3_content_label() -> &'static str {
    BLAKE3_CONTENT_LABEL.get_or_init(rendezvous).as_str()
}

pub const BLAKE3_HEADERS_LABEL: &str = NAME;
pub const BLAKE3_SUM_SIZE: usize = 32;
