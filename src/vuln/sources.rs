//! Source catalog — where attacker-controllable input enters the
//! binary.
//!
//! v1.0 ships ~12 source families across 7 trust boundaries
//! (`TrustBoundary` enum). Each source is identified by its
//! `kind` string AND a list of `apis` it's recognized as. Chain
//! discovery matches sources by comparing the import / api-flow
//! `normalized_api` against `Source::apis`.
//!
//! Trust boundary determines the `source_trust_weight` in scoring
//! (`scoring.rs`): `RemoteUnauth` is the most dangerous (weight 1.0)
//! down to `InternalOnly` (weight 0.0 — internal sources don't
//! produce attacker-controlled chains).

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// How "attacker-reachable" a source's data is. Used by the scoring
/// formula to weight findings. v1.0 distinguishes 7 bands; v1.1 may
/// introduce per-authentication-tier variants (e.g. `RemoteWithMfa`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustBoundary {
    /// Remote network, no authentication required.
    RemoteUnauth,
    /// Remote network, after authentication.
    RemoteAuth,
    /// Local untrusted process / unprivileged user / sandbox.
    LocalUnprivileged,
    /// Local elevated user.
    LocalPrivileged,
    /// Configuration file or registry entry.
    ConfigFile,
    /// Plugin / extension / COM-server hosted code.
    PluginInput,
    /// Internal-only data path (no attacker reach in v1 threat model).
    InternalOnly,
}

impl TrustBoundary {
    /// Numeric weight used by the scoring formula.
    pub fn weight(&self) -> f32 {
        match self {
            Self::RemoteUnauth => 1.0,
            Self::RemoteAuth => 0.8,
            Self::LocalUnprivileged => 0.6,
            Self::PluginInput => 0.55,
            Self::LocalPrivileged => 0.4,
            Self::ConfigFile => 0.3,
            Self::InternalOnly => 0.0,
        }
    }
}

/// A category of input entry point. Concrete `apis` resolve sources
/// at graph-build time — when an `ApiFlowRecord` or `ImportRecord`
/// matches one of these strings, the corresponding source is wired
/// into the chain.
///
/// `Serialize` only — `Source` is a `&'static`-backed catalog entry,
/// never deserialized from external JSON. The emit path goes through
/// `Source::to_owned_view` which converts to plain `String` fields
/// for the LLM consumer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Source {
    pub kind: &'static str,
    pub trust: TrustBoundary,
    /// Concrete API names this source maps to. Case-insensitive
    /// substring match.
    pub apis: &'static [&'static str],
    /// Free-form human-readable description for the LLM consumer.
    pub description: &'static str,
}

/// Read-only registry of every v1.0 source. Indexed by `kind` for
/// fast lookup; iterator preserves declaration order so the source
/// list serialization is stable.
pub struct SourceCatalog {
    sources: &'static [Source],
}

impl SourceCatalog {
    pub fn v1_0() -> Self {
        Self {
            sources: V1_0_SOURCES,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Source> {
        self.sources.iter()
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    pub fn lookup(&self, kind: &str) -> Option<&Source> {
        self.sources.iter().find(|s| s.kind == kind)
    }

    /// Find the source(s) whose `apis` list contains `api` as a
    /// case-insensitive substring. Returns the most-trusted match
    /// (highest weight) when multiple apply.
    pub fn match_api(&self, api: &str) -> Option<&Source> {
        let lower = api.to_lowercase();
        let mut best: Option<&Source> = None;
        for s in self.sources {
            if s.apis
                .iter()
                .any(|name| lower.contains(&name.to_lowercase()))
            {
                let prefer = match best {
                    Some(b) => s.trust.weight() > b.trust.weight(),
                    None => true,
                };
                if prefer {
                    best = Some(s);
                }
            }
        }
        best
    }
}

/// The v1.0 source registry. 12 source families.
pub const V1_0_SOURCES: &[Source] = &[
    Source {
        kind: "network_recv",
        trust: TrustBoundary::RemoteUnauth,
        // NOTE: bare "read" is intentionally omitted — too short a
        // substring, matches Windows ReadFile and other unrelated
        // APIs. POSIX `read(fd)` on a socket is a rare pattern for
        // binary-target analysis; v1 trades that coverage for fewer
        // false positives in the chain query.
        apis: &["recv", "recvfrom", "WSARecv", "WSARecvFrom"],
        description: "Bytes from a network socket.",
    },
    Source {
        kind: "network_accept_then_recv",
        trust: TrustBoundary::RemoteUnauth,
        apis: &["accept", "WSAAccept"],
        description: "Accepted connection that subsequently reads attacker bytes.",
    },
    Source {
        kind: "file_read",
        trust: TrustBoundary::LocalUnprivileged,
        apis: &["ReadFile", "fread", "fgets", "ReadFileEx", "_read"],
        description: "Bytes from an attacker-supplied file (e.g. document, archive).",
    },
    Source {
        kind: "argv",
        trust: TrustBoundary::LocalUnprivileged,
        apis: &[
            "GetCommandLine",
            "GetCommandLineA",
            "GetCommandLineW",
            "CommandLineToArgv",
        ],
        description: "Command-line arguments under attacker control.",
    },
    Source {
        kind: "environment_variable",
        trust: TrustBoundary::LocalUnprivileged,
        apis: &["GetEnvironmentVariable", "getenv", "_wgetenv"],
        description: "Environment variable value.",
    },
    Source {
        kind: "ioctl_input_buffer",
        trust: TrustBoundary::LocalUnprivileged,
        apis: &["DeviceIoControl", "NtDeviceIoControlFile"],
        description: "IOCTL input buffer (user → driver crossing).",
    },
    Source {
        kind: "registry_value",
        trust: TrustBoundary::ConfigFile,
        apis: &["RegQueryValueEx", "RegGetValue", "RegEnumValue"],
        description: "Registry value read from a config-controlled hive.",
    },
    Source {
        kind: "ipc_pipe",
        trust: TrustBoundary::LocalUnprivileged,
        apis: &["ReadFile/pipe", "NtReadFile", "TransactNamedPipe"],
        description: "Bytes from a named-pipe or anonymous-pipe IPC channel.",
    },
    Source {
        kind: "com_server_ingress",
        trust: TrustBoundary::PluginInput,
        apis: &["CoCreateInstance", "DllGetClassObject"],
        description: "Inbound COM call from an untrusted client into a server method.",
    },
    Source {
        kind: "rpc_inbound",
        trust: TrustBoundary::RemoteAuth,
        apis: &["RpcServerListen", "NdrServerCall"],
        description: "Authenticated RPC method call.",
    },
    Source {
        kind: "url_or_uri",
        trust: TrustBoundary::RemoteUnauth,
        apis: &["InternetReadFile", "WinHttpReadData", "HttpQueryInfo"],
        description: "HTTP / URI body downloaded from a remote endpoint.",
    },
    Source {
        kind: "dns_response",
        trust: TrustBoundary::RemoteUnauth,
        apis: &["DnsQuery", "getaddrinfo", "gethostbyname"],
        description: "Result of a DNS query (attacker-controllable via spoofing / redirection).",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_0_has_12_sources() {
        assert_eq!(SourceCatalog::v1_0().len(), 12);
    }

    #[test]
    fn trust_weight_orders_remote_unauth_highest() {
        assert!(TrustBoundary::RemoteUnauth.weight() > TrustBoundary::RemoteAuth.weight());
        assert!(TrustBoundary::RemoteAuth.weight() > TrustBoundary::LocalUnprivileged.weight());
        assert!(
            TrustBoundary::LocalUnprivileged.weight() > TrustBoundary::LocalPrivileged.weight()
        );
        assert!(TrustBoundary::LocalPrivileged.weight() > TrustBoundary::ConfigFile.weight());
        assert_eq!(TrustBoundary::InternalOnly.weight(), 0.0);
    }

    #[test]
    fn lookup_by_kind_returns_canonical_entry() {
        let cat = SourceCatalog::v1_0();
        let s = cat.lookup("network_recv").unwrap();
        assert_eq!(s.trust, TrustBoundary::RemoteUnauth);
        assert!(s.apis.contains(&"recv"));
    }

    #[test]
    fn lookup_returns_none_for_unknown_kind() {
        let cat = SourceCatalog::v1_0();
        assert!(cat.lookup("not_a_thing").is_none());
    }

    #[test]
    fn match_api_finds_network_recv_for_lowercase_substring() {
        let cat = SourceCatalog::v1_0();
        let s = cat.match_api("recv").unwrap();
        assert_eq!(s.kind, "network_recv");
        let s = cat.match_api("WSARecv").unwrap();
        assert_eq!(s.kind, "network_recv");
    }

    #[test]
    fn match_api_returns_most_trusted_when_multiple_overlap() {
        let cat = SourceCatalog::v1_0();
        // "ReadFile" appears in file_read (LocalUnpriv) AND
        // ipc_pipe's "ReadFile/pipe" wouldn't match a bare "ReadFile"
        // because the substring includes "/pipe". But both sources
        // share a common token. Verify the file_read entry wins (it's
        // listed first; weights are equal at LocalUnprivileged).
        let s = cat.match_api("ReadFile").unwrap();
        assert_eq!(s.kind, "file_read");
    }

    #[test]
    fn trust_boundary_round_trips_through_json() {
        let s = serde_json::to_string(&TrustBoundary::RemoteAuth).unwrap();
        assert_eq!(s, "\"remote_auth\"");
        let back: TrustBoundary = serde_json::from_str(&s).unwrap();
        assert_eq!(back, TrustBoundary::RemoteAuth);
    }

    #[test]
    fn iter_preserves_declaration_order() {
        let cat = SourceCatalog::v1_0();
        let kinds: Vec<&str> = cat.iter().map(|s| s.kind).collect();
        assert_eq!(kinds[0], "network_recv");
        assert_eq!(kinds[1], "network_accept_then_recv");
        // Last should be the dns_response entry (declared last).
        assert_eq!(*kinds.last().unwrap(), "dns_response");
    }
}
