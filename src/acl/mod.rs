//! Capability-based access control for ma identities.
//!
//! An [`AclMap`] maps principal strings to [`CapabilityEntry`] values.
//! Deny always wins over allow; a wildcard deny closes access to everyone.
//!
//! # Capabilities
//!
//! Capabilities are plain strings. Built-in system capabilities:
//!
//! | Capability | Meaning |
//! |------------|---------|
//! | `"rpc"`    | Send RPC messages via `/ma/rpc/0.0.1` |
//! | `"ipfs"`   | Publish DID documents via `/ma/ipfs/0.0.1` |
//! | `"read"`   | Read entities, config, and namespace contents |
//! | `"create"` | Create new namespaces or entities |
//! | `"update"` | Update existing namespaces or entities |
//! | `"delete"` | Delete namespaces or entities |
//! | `"owner"`  | Full access at this level (semantics enforced by caller) |
//!
//! Entity and namespace ACLs may also use arbitrary capability strings that
//! correspond to verb names or sub-namespace names.
//!
//! # Principal key forms
//!
//! Valid keys in an [`AclMap`] (and in YAML) are exactly:
//!
//! | Form | Meaning |
//! |------|---------|
//! | `"*"` | Wildcard — matches any caller |
//! | `"did:ma:<identity>"` | Bare DID — a remote runtime identity (no fragment) |
//! | `"#<local>"` | Local entity identifier |
//! | `"group:<handle>.<name>"` | Named group of principals |
//!
//! DID-URLs with fragments (`did:ma:foo#bar`) are **not** valid keys.
//! Use [`is_valid_acl_key`] to validate keys before inserting them.
//!
//! # YAML format
//!
//! ```yaml
//! acl:
//!   "*": [rpc, create]        # everyone: RPC + create
//!   "did:ma:alice": [owner]   # alice: full access
//!   "did:ma:bob": [rpc, read] # bob: read-only RPC
//!   "did:ma:eve":             # null / absent → explicit deny
//! ```
//!
//! # Example
//!
//! ```rust
//! # use ma_core::{AclMap, CapabilityEntry, check_cap, CAP_RPC};
//! let mut acl = AclMap::new();
//! acl.insert("*".to_string(), CapabilityEntry::from_caps(["rpc"]));
//! acl.insert("did:ma:Qmevil".to_string(), CapabilityEntry::Deny);
//! assert!(check_cap(&acl, "did:ma:Qmgood", CAP_RPC).is_ok());
//! assert!(check_cap(&acl, "did:ma:Qmevil", CAP_RPC).is_err());
//! ```

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "acl")]
use crate::{Error, Result};

// ── Capability constants ───────────────────────────────────────────────────────

/// Send RPC messages via `/ma/rpc/0.0.1`.
pub const CAP_RPC: &str = "rpc";
/// Publish DID documents via `/ma/ipfs/0.0.1`.
pub const CAP_IPFS: &str = "ipfs";
/// Read entities, config, and namespace contents.
pub const CAP_READ: &str = "read";
/// Create new namespaces or entities.
pub const CAP_CREATE: &str = "create";
/// Update existing namespaces or entities.
pub const CAP_UPDATE: &str = "update";
/// Delete namespaces or entities.
pub const CAP_DELETE: &str = "delete";
/// Full access at this level — semantics are enforced by the caller, not by [`check_cap`].
pub const CAP_OWNER: &str = "owner";

// ── CapabilityEntry ────────────────────────────────────────────────────────────

/// Capability set for a principal in an [`AclMap`].
///
/// Serialises as a YAML sequence of capability strings (`["rpc", "create"]`)
/// or `null` for an explicit deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityEntry {
    /// Explicit deny. Wins over any wildcard allow for the same principal.
    Deny,
    /// Allow the listed capabilities. An empty set behaves like `Deny`.
    Allow(BTreeSet<String>),
}

impl CapabilityEntry {
    /// Construct an `Allow` entry from an iterator of capability name strings.
    pub fn from_caps<I, S>(caps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Allow(caps.into_iter().map(Into::into).collect())
    }

    /// Return `true` if this entry grants `cap`.
    pub fn has(&self, cap: &str) -> bool {
        match self {
            Self::Deny => false,
            Self::Allow(caps) => caps.contains(cap),
        }
    }

    /// Return `true` if this is an explicit deny.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

impl Serialize for CapabilityEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Deny => serializer.serialize_none(),
            Self::Allow(caps) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(caps.len()))?;
                for cap in caps {
                    seq.serialize_element(cap)?;
                }
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CapabilityEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let opt: Option<Vec<String>> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(Self::Deny),
            Some(v) if v.is_empty() => Ok(Self::Deny),
            Some(v) => Ok(Self::Allow(v.into_iter().collect())),
        }
    }
}

// ── AclMap ─────────────────────────────────────────────────────────────────────

/// Capability-based access control map.
///
/// Keys are principal strings — exactly one of:
/// - `"*"` — wildcard
/// - `"did:ma:<identity>"` — bare DID, no fragment
/// - `"#<local>"` — local entity identifier
/// - `"group:<handle>.<name>"` — named group of principals
///
/// DID-URLs with fragments (`did:ma:foo#bar`) are **not** valid keys;
/// use [`is_valid_acl_key`] to validate before inserting.
pub type AclMap = HashMap<String, CapabilityEntry>;

// ── check_cap ──────────────────────────────────────────────────────────────────

/// Check whether `caller` has capability `cap` in `acl`.
///
/// 1. Normalise `caller` to a bare identity (strip fragment from DID-URLs).
/// 2. Look up the normalised caller directly — if found, apply and stop.
/// 3. Fall back to the `"*"` wildcard entry.
/// 4. Explicit deny → `Err`; capability absent → `Err`; no entry → `Err`.
///
/// The `"owner"` capability is just a string — callers that need owner-bypass
/// semantics must call `check_cap(acl, caller, CAP_OWNER)` explicitly.
#[cfg(feature = "acl")]
pub fn check_cap(acl: &AclMap, caller: &str, cap: &str) -> Result<()> {
    let normalized = normalize_principal(caller);
    if let Some(direct) = acl.get(normalized) {
        return match direct {
            CapabilityEntry::Deny => Err(Error::Acl(format!("operation denied for {caller}"))),
            CapabilityEntry::Allow(caps) if caps.contains(cap) => Ok(()),
            CapabilityEntry::Allow(_) => Err(Error::Acl(format!(
                "capability '{cap}' denied for {caller}"
            ))),
        };
    }

    match acl.get("*") {
        None => Err(Error::Acl(format!("no ACL entry for {caller}"))),
        Some(CapabilityEntry::Deny) => Err(Error::Acl(format!("operation denied for {caller}"))),
        Some(CapabilityEntry::Allow(caps)) if caps.contains(cap) => Ok(()),
        Some(CapabilityEntry::Allow(_)) => Err(Error::Acl(format!(
            "capability '{cap}' denied for {caller}"
        ))),
    }
}

/// Return `true` if `key` is a valid [`AclMap`] principal key.
///
/// Valid forms:
/// - `"*"` — wildcard
/// - `"did:ma:<identity>"` — bare DID, no fragment
/// - `"#<local>"` — local entity identifier
/// - `"group:<handle>.<name>"` — named group (`<handle>` and `<name>` non-empty)
pub fn is_valid_acl_key(key: &str) -> bool {
    key == "*"
        || (key.starts_with("did:") && !key.contains('#'))
        || (key.starts_with('#') && key.len() > 1)
        || is_valid_group_key(key)
}

/// Return `true` if `key` is a valid group principal (`group:<handle>.<name>`).
fn is_valid_group_key(key: &str) -> bool {
    if let Some(rest) = key.strip_prefix("group:") {
        if let Some(dot) = rest.find('.') {
            let handle = &rest[..dot];
            let name = &rest[dot + 1..];
            return !handle.is_empty() && !name.is_empty();
        }
    }
    false
}

/// Validate all keys in an [`AclMap`], returning a descriptive error for the
/// first invalid key found.
///
/// Call this immediately after loading an ACL from YAML or any external source.
#[cfg(feature = "acl")]
pub fn validate_acl_map(acl: &AclMap) -> Result<()> {
    for key in acl.keys() {
        if !is_valid_acl_key(key) {
            return Err(Error::Acl(format!(
                "invalid ACL key {key:?}: must be \"*\", a bare DID (\"did:ma:\u{2026}\"), \
                 a local entity (\"#name\"), or a group (\"group:<handle>.<name>\")"
            )));
        }
    }
    Ok(())
}

/// Normalise a caller identity for [`AclMap`] lookup.
///
/// - `did:ma:foo#bar` → `did:ma:foo` (strips fragment from DID-URLs)
/// - `#local` → `#local` (local entity, passed through)
/// - `*` → `*` (wildcard, passed through)
pub fn normalize_principal(did: &str) -> &str {
    if did.starts_with("did:") {
        if let Some(pos) = did.find('#') {
            return &did[..pos];
        }
    }
    did
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(caps: &[&str]) -> CapabilityEntry {
        CapabilityEntry::from_caps(caps.iter().copied())
    }

    fn m(entries: &[(&str, CapabilityEntry)]) -> AclMap {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn wildcard_rpc_allows_rpc() {
        let acl = m(&[("*", allow(&[CAP_RPC]))]);
        assert!(check_cap(&acl, "did:ma:alice", CAP_RPC).is_ok());
    }

    #[test]
    fn wildcard_rpc_denies_ipfs() {
        let acl = m(&[("*", allow(&[CAP_RPC]))]);
        assert!(check_cap(&acl, "did:ma:alice", CAP_IPFS).is_err());
    }

    #[test]
    fn explicit_deny_wins_over_wildcard_allow() {
        let acl = m(&[
            ("*", allow(&[CAP_RPC, CAP_IPFS])),
            ("did:ma:bandit", CapabilityEntry::Deny),
        ]);
        assert!(check_cap(&acl, "did:ma:bandit", CAP_RPC).is_err());
    }

    #[test]
    fn exact_match_restricts_below_wildcard() {
        let acl = m(&[
            ("*", allow(&[CAP_RPC, CAP_IPFS])),
            ("did:ma:bob", allow(&[CAP_RPC])),
        ]);
        assert!(check_cap(&acl, "did:ma:bob", CAP_RPC).is_ok());
        assert!(check_cap(&acl, "did:ma:bob", CAP_IPFS).is_err());
    }

    #[test]
    fn did_url_caller_is_normalized() {
        let acl = m(&[("did:ma:alice", allow(&[CAP_RPC, CAP_IPFS]))]);
        assert!(check_cap(&acl, "did:ma:alice#sign", CAP_RPC).is_ok());
    }

    #[test]
    fn no_entry_default_deny() {
        assert!(check_cap(&AclMap::new(), "did:ma:anyone", CAP_RPC).is_err());
    }

    #[test]
    fn wildcard_deny_blocks_all() {
        let acl = m(&[("*", CapabilityEntry::Deny)]);
        assert!(check_cap(&acl, "did:ma:anyone", CAP_RPC).is_err());
    }

    #[test]
    fn local_entity_key_allowed() {
        let acl = m(&[("#agent", allow(&[CAP_RPC]))]);
        assert!(check_cap(&acl, "#agent", CAP_RPC).is_ok());
        assert!(check_cap(&acl, "#other", CAP_RPC).is_err());
    }

    #[test]
    fn arbitrary_capability_works() {
        let acl = m(&[("did:ma:alice", allow(&["emote", "reply"]))]);
        assert!(check_cap(&acl, "did:ma:alice", "emote").is_ok());
        assert!(check_cap(&acl, "did:ma:alice", "reply").is_ok());
        assert!(check_cap(&acl, "did:ma:alice", "admin").is_err());
    }

    #[test]
    fn owner_capability_is_just_a_string() {
        // "owner" semantics (implies all) are the caller's responsibility
        let acl = m(&[("did:ma:alice", allow(&[CAP_OWNER]))]);
        assert!(check_cap(&acl, "did:ma:alice", CAP_OWNER).is_ok());
        assert!(check_cap(&acl, "did:ma:alice", CAP_RPC).is_err());
    }

    #[test]
    fn normalize_strips_fragment() {
        assert_eq!(normalize_principal("did:ma:foo#bar"), "did:ma:foo");
        assert_eq!(normalize_principal("did:ma:foo"), "did:ma:foo");
        assert_eq!(normalize_principal("#local"), "#local");
        assert_eq!(normalize_principal("*"), "*");
    }

    #[test]
    fn valid_acl_keys() {
        assert!(is_valid_acl_key("*"));
        assert!(is_valid_acl_key("did:ma:Qmfoo"));
        assert!(is_valid_acl_key("#agent"));
        assert!(is_valid_acl_key("group:alice.venner"));
        assert!(is_valid_acl_key("group:runtime.admins"));
        assert!(!is_valid_acl_key("did:ma:Qmfoo#sign"));
        assert!(!is_valid_acl_key("#"));
        assert!(!is_valid_acl_key(""));
        assert!(!is_valid_acl_key("group:noname"));
        assert!(!is_valid_acl_key("group:.nohandle"));
        assert!(!is_valid_acl_key("group:handle."));
    }

    #[cfg(feature = "acl")]
    #[test]
    fn capability_serde_roundtrip() {
        let acl: AclMap = [
            (
                "*".to_string(),
                CapabilityEntry::from_caps(["rpc", "create"]),
            ),
            ("did:ma:bandit".to_string(), CapabilityEntry::Deny),
        ]
        .into_iter()
        .collect();
        let yaml = serde_yaml::to_string(&acl).unwrap();
        let roundtrip: AclMap = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(acl, roundtrip);
    }

    #[cfg(feature = "acl")]
    #[test]
    fn yaml_null_deserializes_to_deny() {
        let yaml = "'did:ma:x': ~\n'*':\n- rpc\n- create\n";
        let acl: AclMap = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(acl.get("did:ma:x"), Some(&CapabilityEntry::Deny));
        assert_eq!(
            acl.get("*"),
            Some(&CapabilityEntry::from_caps(["rpc", "create"]))
        );
    }
}
