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
//! | `"*"`      | Wildcard — grants **all** capabilities at this level |
//!
//! Entity and namespace ACLs may also use arbitrary capability strings that
//! correspond to verb names or sub-namespace names.
//!
//! # Key forms in an [`AclMap`]
//!
//! An `AclMap` supports two kinds of entries:
//!
//! **Principal entries** — key identifies *who*:
//!
//! | Form | Meaning |
//! |------|---------|
//! | `"*"` | Wildcard — matches any caller |
//! | `"did:ma:<identity>"` | Bare DID (no fragment) |
//! | `"#<local>"` | Local entity identifier |
//! | `"group:<handle>.<name>"` | Named group of principals |
//!
//! **Capability-grant entries** — key identifies *what*, value lists *who*:
//!
//! Plain words (e.g. `"fortune"`, `"admin"`) as keys map a capability name
//! to a comma-separated list of group/DID references.
//! These are resolved by the runtime's async ACL checker; [`check_cap`] skips them.
//!
//! # YAML format
//!
//! ```yaml
//! acl:
//!   "*": [rpc, create]                     # everyone: RPC + create
//!   "did:ma:alice": ["*"]                   # alice: all capabilities
//!   "did:ma:bob": [rpc, read]              # bob: restricted
//!   "did:ma:eve":                          # null / absent → explicit deny
//!   fortune: "group:carlotta.friends,did:ma:dave"  # cap-grant entry
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

/// Deliver messages to an endpoint's inbox (`/ma/inbox/0.0.1`).
pub const CAP_INBOX: &str = "inbox";
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

// ── CapabilityEntry ────────────────────────────────────────────────────────────

/// Capability set for a principal in an [`AclMap`], or a grantee list for a
/// capability-grant entry.
///
/// Serialises as:
/// - `null` → [`Deny`](CapabilityEntry::Deny)
/// - YAML sequence → [`Allow`](CapabilityEntry::Allow)
/// - comma-separated string → [`Grant`](CapabilityEntry::Grant)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityEntry {
    /// Explicit deny. Wins over any wildcard allow for the same principal.
    Deny,
    /// Allow the listed capabilities. `["*"]` grants all capabilities.
    Allow(BTreeSet<String>),
    /// Capability-grant entry: the listed group/DID refs may use this capability.
    /// Stored as a comma-separated string in YAML.
    /// Resolved lazily by the runtime's async ACL checker; [`check_cap`] skips these.
    Grant(Vec<String>),
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
    /// `"*"` in the capability set grants any capability.
    pub fn has(&self, cap: &str) -> bool {
        match self {
            Self::Deny | Self::Grant(_) => false,
            Self::Allow(caps) => caps.contains(cap) || caps.contains("*"),
        }
    }

    /// Return `true` if this is an explicit deny.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }

    /// Return the grantee refs if this is a [`Grant`](Self::Grant) entry.
    pub fn grantees(&self) -> Option<&[String]> {
        if let Self::Grant(refs) = self {
            Some(refs)
        } else {
            None
        }
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
            Self::Grant(refs) => serializer.serialize_str(&refs.join(",")),
        }
    }
}

impl<'de> Deserialize<'de> for CapabilityEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Str(String),
            Seq(Vec<String>),
        }
        let opt: Option<Raw> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(Self::Deny),
            Some(Raw::Seq(v)) if v.is_empty() => Ok(Self::Deny),
            Some(Raw::Seq(v)) => Ok(Self::Allow(v.into_iter().collect())),
            Some(Raw::Str(s)) => {
                let refs: Vec<String> = s
                    .split(',')
                    .map(|r| r.trim().to_string())
                    .filter(|r| !r.is_empty())
                    .collect();
                if refs.is_empty() {
                    Ok(Self::Deny)
                } else {
                    Ok(Self::Grant(refs))
                }
            }
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
/// 1. Normalise `caller` (strip fragment from DID-URLs).
/// 2. Look up the normalised caller directly — if a principal entry, apply and stop.
/// 3. Fall back to the `"*"` wildcard principal entry.
/// 4. Explicit deny → `Err`; capability absent → `Err`; no entry → `Err`.
///
/// [`Grant`](CapabilityEntry::Grant) entries (capability→grantees) are **skipped**;
/// they are resolved by the runtime's async `acl_check` via lazy IPFS lookups.
///
/// A `"*"` item inside an `Allow` set grants **all** capabilities.
#[cfg(feature = "acl")]
pub fn check_cap(acl: &AclMap, caller: &str, cap: &str) -> Result<()> {
    let normalized = normalize_principal(caller);
    if let Some(direct) = acl.get(normalized) {
        match direct {
            CapabilityEntry::Deny => {
                return Err(Error::Acl(format!("operation denied for {caller}")));
            }
            CapabilityEntry::Allow(caps) if caps.contains(cap) || caps.contains("*") => {
                return Ok(());
            }
            CapabilityEntry::Allow(_) => {
                return Err(Error::Acl(format!(
                    "capability '{cap}' denied for {caller}"
                )));
            }
            CapabilityEntry::Grant(_) => {
                // Capability-grant entry under a principal key — should not
                // happen in practice. Ignore and fall through to wildcard.
            }
        }
    }

    match acl.get("*") {
        Some(CapabilityEntry::Grant(_)) | None => {
            Err(Error::Acl(format!("no ACL entry for {caller}")))
        }
        Some(CapabilityEntry::Deny) => Err(Error::Acl(format!("operation denied for {caller}"))),
        Some(CapabilityEntry::Allow(caps)) if caps.contains(cap) || caps.contains("*") => Ok(()),
        Some(CapabilityEntry::Allow(_)) => Err(Error::Acl(format!(
            "capability '{cap}' denied for {caller}"
        ))),
    }
}

/// Return `true` if `key` is a valid [`AclMap`] key.
///
/// Two kinds of keys are valid:
/// - **Principal keys**: `"*"`, `"did:ma:<id>"`, `"#<local>"`, `"group:<h>.<n>"`
/// - **Capability-grant keys**: any non-empty word not matching a principal key
///   (e.g. `"fortune"`, `"admin"`, `"emote"`)
pub fn is_valid_acl_key(key: &str) -> bool {
    !key.is_empty()
}

/// Return `true` if `key` is a principal key (identifies *who*).
pub fn is_principal_key(key: &str) -> bool {
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
                "invalid ACL key {key:?}: key must be non-empty"
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
    fn wildcard_cap_grants_all_capabilities() {
        let acl = m(&[("did:ma:alice", allow(&["*"]))]);
        assert!(check_cap(&acl, "did:ma:alice", CAP_RPC).is_ok());
        assert!(check_cap(&acl, "did:ma:alice", CAP_IPFS).is_ok());
        assert!(check_cap(&acl, "did:ma:alice", "emote").is_ok());
        assert!(check_cap(&acl, "did:ma:alice", "admin").is_ok());
    }

    #[test]
    fn grant_entry_is_skipped_by_check_cap() {
        let mut acl = AclMap::new();
        acl.insert("*".to_string(), allow(&[CAP_RPC]));
        acl.insert(
            "fortune".to_string(),
            CapabilityEntry::Grant(vec!["group:carlotta.friends".to_string()]),
        );
        assert!(check_cap(&acl, "did:ma:anyone", CAP_RPC).is_ok());
        assert!(check_cap(&acl, "did:ma:anyone", "fortune").is_err());
    }

    #[test]
    fn grant_entry_serde_round_trip() {
        let entry = CapabilityEntry::Grant(vec![
            "group:carlotta.friends".to_string(),
            "did:ma:alice".to_string(),
        ]);
        let yaml = serde_yaml::to_string(&entry).expect("serialize");
        assert!(yaml.contains("group:carlotta.friends"));
        let round: CapabilityEntry = serde_yaml::from_str(yaml.trim()).expect("deserialize");
        assert_eq!(round, entry);
    }

    #[test]
    fn owner_capability_is_just_a_string() {
        // "owner" still works as a plain capability string
        let acl = m(&[("did:ma:alice", allow(&["owner"]))]);
        assert!(check_cap(&acl, "did:ma:alice", "owner").is_ok());
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
        // capability-grant keys (plain words)
        assert!(is_valid_acl_key("fortune"));
        assert!(is_valid_acl_key("admin"));
        assert!(is_valid_acl_key("emote"));
        assert!(!is_valid_acl_key(""));
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
