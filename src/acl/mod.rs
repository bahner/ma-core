//! Operation-level access control for ma identities.
//!
//! An [`AclMap`] maps principal strings to [`Permissions`].
//! Deny always wins over allow; a wildcard deny closes access to everyone.
//!
//! # Permission bits
//!
//! | Letter | Bit | Meaning |
//! |--------|-----|---------|
//! | `r`    |  4  | Read — list metadata, read config, fetch entities |
//! | `w`    |  2  | Write — mutate entities/config; required for `/ma/ipfs/0.0.1` |
//! | `x`    |  1  | Execute — invoke entity verbs; required for `/ma/rpc/0.0.1` |
//!
//! # YAML format
//!
//! ```yaml
//! acl:
//!   "*": "rwx"          # everyone: full access
//!   "did:ma:bob": "rx"  # read + execute, no write
//!   "did:ma:eve":       # null / absent → explicit deny
//! ```
//!
//! # Example
//!
//! ```rust
//! # use ma_core::{AclMap, Permissions, check_op, PERM_X};
//! let mut acl = AclMap::new();
//! acl.insert("*".to_string(), Permissions::Allow(PERM_X));
//! acl.insert("did:ma:Qmevil".to_string(), Permissions::Deny);
//! assert!(check_op(&acl, "did:ma:Qmgood", PERM_X).is_ok());
//! assert!(check_op(&acl, "did:ma:Qmevil", PERM_X).is_err());
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "acl")]
use crate::{Error, Result};

// ── Permission bits ────────────────────────────────────────────────────────────

/// Read permission: list metadata, read config, fetch entities.
pub const PERM_R: u8 = 0b100;
/// Write permission: mutate entities and config; required for `/ma/ipfs/0.0.1`.
pub const PERM_W: u8 = 0b010;
/// Execute permission: invoke entity verbs; required for `/ma/rpc/0.0.1`.
pub const PERM_X: u8 = 0b001;
/// All permissions combined.
pub const PERM_RWX: u8 = 0b111;

// ── Permissions type ───────────────────────────────────────────────────────────

/// Permission value for a principal in an [`AclMap`].
///
/// Serialises as a permission string (`"rwx"`, `"rx"`, `"x"`, …) or YAML
/// `null` for deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permissions {
    /// Explicit deny. Wins over any wildcard allow for the same principal.
    Deny,
    /// Allow with the given `r`/`w`/`x` bits.
    Allow(u8),
}

impl Permissions {
    /// Return `true` if this permission grants all bits in `required`.
    pub const fn grants(self, required: u8) -> bool {
        match self {
            Self::Allow(p) => p & required == required,
            Self::Deny => false,
        }
    }

    /// Return `true` if this is an explicit deny.
    pub fn is_deny(self) -> bool {
        self == Self::Deny
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny => write!(f, "-"),
            Self::Allow(p) => {
                if p & PERM_R != 0 {
                    write!(f, "r")?;
                }
                if p & PERM_W != 0 {
                    write!(f, "w")?;
                }
                if p & PERM_X != 0 {
                    write!(f, "x")?;
                }
                Ok(())
            }
        }
    }
}

impl FromStr for Permissions {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, anyhow::Error> {
        if s.is_empty() {
            return Ok(Self::Deny);
        }
        let mut bits = 0u8;
        for ch in s.chars() {
            match ch {
                'r' => bits |= PERM_R,
                'w' => bits |= PERM_W,
                'x' => bits |= PERM_X,
                other => {
                    return Err(anyhow::anyhow!(
                        "unknown permission character '{other}' in '{s}'"
                    ));
                }
            }
        }
        if bits == 0 {
            return Err(anyhow::anyhow!("permission string '{s}' has no valid bits"));
        }
        Ok(Self::Allow(bits))
    }
}

impl Serialize for Permissions {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Deny => serializer.serialize_none(),
            Self::Allow(_) => serializer.serialize_str(&self.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(Self::Deny),
            Some(s) if s.is_empty() => Ok(Self::Deny),
            Some(s) => s.parse::<Permissions>().map_err(serde::de::Error::custom),
        }
    }
}

// ── AclMap ─────────────────────────────────────────────────────────────────────

/// Operation-level access control map.
///
/// Keys are principal strings: `"*"` (wildcard) or `"did:ma:…"` (bare
/// identity). Values are [`Permissions`].
pub type AclMap = BTreeMap<String, Permissions>;

// ── check_op ───────────────────────────────────────────────────────────────────

/// Check whether `caller` has `required` permission bits in `acl`.
///
/// 1. Normalise `caller` to a bare identity (strip fragment from DID-URLs).
/// 2. Look up the normalised caller directly — if found, apply and stop.
/// 3. Fall back to the `"*"` wildcard entry.
/// 4. Explicit deny → `Err`; missing required bits → `Err`; no entry → `Err`.
///
/// Owner bypass is the caller's responsibility.
#[cfg(feature = "acl")]
pub fn check_op(acl: &AclMap, caller: &str, required: u8) -> Result<()> {
    let normalized = normalize_principal(caller);
    if let Some(direct) = acl.get(normalized) {
        return if direct.is_deny() {
            Err(Error::Acl(format!("operation denied for {caller}")))
        } else if direct.grants(required) {
            Ok(())
        } else {
            Err(Error::Acl(format!("permission denied for {caller}")))
        };
    }

    match acl.get("*") {
        None => Err(Error::Acl(format!("no ACL entry for {caller}"))),
        Some(e) if e.is_deny() => Err(Error::Acl(format!("operation denied for {caller}"))),
        Some(e) if e.grants(required) => Ok(()),
        Some(_) => Err(Error::Acl(format!("permission denied for {caller}"))),
    }
}

/// Strip fragment from DID-URLs for principal normalisation.
///
/// `did:ma:foo#bar` → `did:ma:foo`. Non-DID strings (like `"*"`) are returned
/// unchanged.
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

    fn m(entries: &[(&str, &str)]) -> AclMap {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.parse().expect("valid permissions")))
            .collect()
    }

    #[test]
    fn wildcard_exec_allows_execute() {
        let acl = m(&[("*", "x")]);
        assert!(check_op(&acl, "did:ma:alice", PERM_X).is_ok());
    }

    #[test]
    fn wildcard_exec_denies_write() {
        let acl = m(&[("*", "x")]);
        assert!(check_op(&acl, "did:ma:alice", PERM_W).is_err());
    }

    #[test]
    fn explicit_deny_wins_over_wildcard_allow() {
        let acl = m(&[("*", "rwx"), ("did:ma:bandit", "")]);
        assert!(check_op(&acl, "did:ma:bandit", PERM_X).is_err());
    }

    #[test]
    fn exact_match_restricts_below_wildcard() {
        let acl = m(&[("*", "rwx"), ("did:ma:bob", "r")]);
        assert!(check_op(&acl, "did:ma:bob", PERM_R).is_ok());
        assert!(check_op(&acl, "did:ma:bob", PERM_X).is_err());
    }

    #[test]
    fn did_url_caller_is_normalized() {
        let acl = m(&[("did:ma:alice", "rwx")]);
        assert!(check_op(&acl, "did:ma:alice#sign", PERM_X).is_ok());
    }

    #[test]
    fn no_entry_default_deny() {
        assert!(check_op(&AclMap::new(), "did:ma:anyone", PERM_X).is_err());
    }

    #[test]
    fn wildcard_deny_blocks_all() {
        let acl = m(&[("*", "")]);
        assert!(check_op(&acl, "did:ma:anyone", PERM_X).is_err());
    }

    #[test]
    fn normalize_strips_fragment() {
        assert_eq!(normalize_principal("did:ma:foo#bar"), "did:ma:foo");
        assert_eq!(normalize_principal("did:ma:foo"), "did:ma:foo");
        assert_eq!(normalize_principal("*"), "*");
    }

    #[test]
    fn permissions_display() {
        assert_eq!(Permissions::Allow(PERM_RWX).to_string(), "rwx");
        assert_eq!(Permissions::Allow(PERM_R | PERM_X).to_string(), "rx");
        assert_eq!(Permissions::Allow(PERM_X).to_string(), "x");
        assert_eq!(Permissions::Deny.to_string(), "-");
    }

    #[test]
    fn permissions_from_str() {
        assert_eq!(
            "rwx".parse::<Permissions>().unwrap(),
            Permissions::Allow(PERM_RWX)
        );
        assert_eq!(
            "rx".parse::<Permissions>().unwrap(),
            Permissions::Allow(PERM_R | PERM_X)
        );
        assert_eq!(
            "x".parse::<Permissions>().unwrap(),
            Permissions::Allow(PERM_X)
        );
        assert_eq!("".parse::<Permissions>().unwrap(), Permissions::Deny);
        assert!("z".parse::<Permissions>().is_err());
    }

    #[cfg(feature = "acl")]
    #[test]
    fn permissions_serde_roundtrip() {
        let acl: AclMap = [
            ("*".to_string(), Permissions::Allow(PERM_RWX)),
            ("did:ma:bandit".to_string(), Permissions::Deny),
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
        // YAML tilde (~) is canonical null
        let yaml = "'did:ma:x': ~\n'*': rwx\n";
        let acl: AclMap = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(acl.get("did:ma:x"), Some(&Permissions::Deny));
        assert_eq!(acl.get("*"), Some(&Permissions::Allow(PERM_RWX)));
    }
}
