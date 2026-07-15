//! Independently researched UDP capability and disposition ledger.
//!
//! This is deliberately separate from any owner-controlled comparison against
//! third-party probe data. It contains only project identifiers, primary
//! sources, implemented catalogue IDs, and explicit project dispositions.

use core::fmt;

use crate::{DISCOVERY_OPERATION_REGISTRY, UDP_PROBE_CATALOGUE};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpCapabilityDisposition {
    Equivalent,
    Superseded,
    UnsafeOptIn,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityImplementation {
    UdpProbe(u16),
    DiscoveryOperation(u16),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpCapabilityEntry {
    pub project_id: &'static str,
    pub category: &'static str,
    pub disposition: UdpCapabilityDisposition,
    pub implementations: &'static [CapabilityImplementation],
    pub primary_source_url: &'static str,
    pub evidence: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpCapabilityLedgerError {
    EmptyField,
    DuplicateProjectId,
    MissingImplementedProbe,
    BlockedProbeIsImplemented,
    UnknownProbeId,
    UnknownDiscoveryOperationId,
    DuplicateProbeCoverage,
    DuplicateDiscoveryOperationCoverage,
    UncoveredCatalogueProbe,
    UncoveredDiscoveryOperation,
    InsecurePrimarySource,
    ExternalComparisonReference,
}

impl fmt::Display for UdpCapabilityLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid UDP capability ledger: {self:?}")
    }
}

impl std::error::Error for UdpCapabilityLedgerError {}

macro_rules! capability {
    ($id:literal, $category:literal, $disposition:ident, [$($probe:literal),*], $source:literal, $evidence:literal) => {
        UdpCapabilityEntry {
            project_id: $id,
            category: $category,
            disposition: UdpCapabilityDisposition::$disposition,
            implementations: &[$(CapabilityImplementation::UdpProbe($probe)),*],
            primary_source_url: $source,
            evidence: $evidence,
        }
    };
}

macro_rules! discovery_capability {
    ($id:literal, $category:literal, $disposition:ident, [$($operation:literal),*], $source:literal, $evidence:literal) => {
        UdpCapabilityEntry {
            project_id: $id,
            category: $category,
            disposition: UdpCapabilityDisposition::$disposition,
            implementations: &[$(CapabilityImplementation::DiscoveryOperation($operation)),*],
            primary_source_url: $source,
            evidence: $evidence,
        }
    };
}

/// Shippable project-owned capability ledger. No Nmap identifiers, names,
/// payloads, patterns, or source-derived mappings occur in this table.
pub static UDP_CAPABILITY_LEDGER: &[UdpCapabilityEntry] = &[
    capability!(
        "dns-root-a",
        "directory",
        Equivalent,
        [1],
        "https://www.rfc-editor.org/rfc/rfc1035",
        "typed builder/parser and dual-stack responder"
    ),
    capability!(
        "ntp-client",
        "time",
        Equivalent,
        [2],
        "https://www.rfc-editor.org/rfc/rfc5905",
        "typed transaction-correlated exchange"
    ),
    capability!(
        "snmpv3-engine",
        "device-management",
        Equivalent,
        [3],
        "https://www.rfc-editor.org/rfc/rfc3414",
        "credential-free engine discovery"
    ),
    capability!(
        "rpcbind-null",
        "directory",
        Equivalent,
        [4],
        "https://www.rfc-editor.org/rfc/rfc5531",
        "typed ONC RPC NULL exchange"
    ),
    capability!(
        "stun-binding",
        "nat-traversal",
        Equivalent,
        [5],
        "https://www.rfc-editor.org/rfc/rfc8489",
        "96-bit transaction-correlated exchange"
    ),
    capability!(
        "coap-empty",
        "device-management",
        Equivalent,
        [6],
        "https://www.rfc-editor.org/rfc/rfc7252",
        "empty confirmable exchange"
    ),
    capability!(
        "asf-rmcp",
        "device-management",
        Equivalent,
        [7],
        "https://www.dmtf.org/sites/default/files/standards/documents/DSP0136_3.0.1.pdf",
        "tag-correlated presence exchange"
    ),
    capability!(
        "memcached-version",
        "database",
        Equivalent,
        [8],
        "https://github.com/memcached/memcached/blob/master/doc/protocol.txt",
        "framed low-impact version exchange"
    ),
    capability!(
        "pcp-announce",
        "nat-traversal",
        Equivalent,
        [9],
        "https://www.rfc-editor.org/rfc/rfc6887",
        "mapping-free ANNOUNCE exchange"
    ),
    capability!(
        "netbios-node-status",
        "directory",
        UnsafeOptIn,
        [10],
        "https://www.rfc-editor.org/rfc/rfc1002",
        "sensitive node-name response is explicit opt-in"
    ),
    capability!(
        "nfs-v3-null",
        "database",
        Equivalent,
        [11],
        "https://www.rfc-editor.org/rfc/rfc1813",
        "typed NFS NULL exchange"
    ),
    capability!(
        "sip-options",
        "remote-control",
        UnsafeOptIn,
        [12],
        "https://www.rfc-editor.org/rfc/rfc3261",
        "bounded server-identification response"
    ),
    capability!(
        "ssdp-unicast",
        "device-management",
        UnsafeOptIn,
        [13],
        "https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf",
        "unicast-only discovery with impact consent"
    ),
    capability!(
        "l2tp-control",
        "vpn-tunnel",
        UnsafeOptIn,
        [14],
        "https://www.rfc-editor.org/rfc/rfc2661",
        "bounded stateful SCCRQ/SCCRP exchange"
    ),
    capability!(
        "snmpv1-system-description",
        "device-management",
        UnsafeOptIn,
        [15],
        "https://www.rfc-editor.org/rfc/rfc1157",
        "public-community authentication and read require consent"
    ),
    capability!(
        "memcached-statistics",
        "database",
        UnsafeOptIn,
        [16],
        "https://github.com/memcached/memcached/blob/master/doc/protocol.txt",
        "amplifying metadata read requires consent"
    ),
    capability!(
        "udp-echo",
        "historical",
        Equivalent,
        [17],
        "https://www.rfc-editor.org/rfc/rfc862",
        "exact token echo"
    ),
    capability!(
        "daytime",
        "historical",
        Equivalent,
        [18],
        "https://www.rfc-editor.org/rfc/rfc867",
        "finite text signature"
    ),
    capability!(
        "quote-of-the-day",
        "historical",
        UnsafeOptIn,
        [19],
        "https://www.rfc-editor.org/rfc/rfc865",
        "legacy profile and amplification consent"
    ),
    capability!(
        "character-generator",
        "historical",
        UnsafeOptIn,
        [20],
        "https://www.rfc-editor.org/rfc/rfc864",
        "legacy profile and amplification consent"
    ),
    capability!(
        "active-users",
        "historical",
        UnsafeOptIn,
        [21],
        "https://www.rfc-editor.org/rfc/rfc866",
        "sensitive amplifying legacy query"
    ),
    capability!(
        "network-status",
        "historical",
        UnsafeOptIn,
        [22],
        "https://www.rfc-editor.org/rfc/rfc869",
        "sensitive amplifying legacy query"
    ),
    capability!(
        "ripv2-table",
        "network-discovery",
        UnsafeOptIn,
        [23],
        "https://www.rfc-editor.org/rfc/rfc2453",
        "bounded full-table request with consent"
    ),
    capability!(
        "xdmcp-query",
        "remote-control",
        UnsafeOptIn,
        [24],
        "https://www.x.org/releases/X11R7.7/doc/libXdmcp/xdmcp.html",
        "legacy display-manager status query"
    ),
    capability!(
        "source-engine-info",
        "game-discovery",
        UnsafeOptIn,
        [25],
        "https://developer.valvesoftware.com/wiki/Server_queries",
        "bounded A2S_INFO identification"
    ),
    capability!(
        "raknet-ping",
        "game-discovery",
        UnsafeOptIn,
        [26],
        "https://github.com/facebookarchive/RakNet/blob/master/Help/Protocol.html",
        "timestamp-correlated unconnected pong"
    ),
    capability!(
        "bacnet-who-is",
        "building-industrial",
        UnsafeOptIn,
        [27],
        "https://bacnet.org/",
        "unicast Who-Is only; no target expansion"
    ),
    capability!(
        "ethernet-ip-identity",
        "building-industrial",
        UnsafeOptIn,
        [28],
        "https://www.odva.org/technology-standards/key-technologies/ethernet-ip/",
        "sender-context-correlated identity list"
    ),
    capability!(
        "knxnet-ip-search",
        "building-industrial",
        UnsafeOptIn,
        [29],
        "https://support.knx.org/hc/en-us/articles/360018876560-KNXnet-IP",
        "unicast IPv4 search with actual HPAI"
    ),
    capability!(
        "bittorrent-dht-ping",
        "peer-to-peer",
        UnsafeOptIn,
        [30],
        "https://www.bittorrent.org/beps/bep_0005.html",
        "bounded KRPC ping with state consent"
    ),
    capability!(
        "dns-chaos-version",
        "directory",
        UnsafeOptIn,
        [31],
        "https://bind9.readthedocs.io/en/latest/reference.html",
        "legacy sensitive version query"
    ),
    capability!(
        "ntp-control-readvar",
        "time",
        UnsafeOptIn,
        [32],
        "https://www.rfc-editor.org/rfc/rfc9327",
        "legacy amplifying mode-6 read"
    ),
    capability!(
        "slp-service-agent",
        "directory",
        UnsafeOptIn,
        [33],
        "https://www.rfc-editor.org/rfc/rfc2608",
        "bounded unicast service-agent request"
    ),
    discovery_capability!(
        "mdns-dns-sd",
        "directory",
        UnsafeOptIn,
        [1],
        "https://www.rfc-editor.org/rfc/rfc6762",
        "legacy-unicast link discovery preserves per-interface service entities; fixed-port browse remains no-go pending daemon coexistence proof"
    ),
    discovery_capability!(
        "tftp-read",
        "historical",
        UnsafeOptIn,
        [8],
        "https://www.rfc-editor.org/rfc/rfc1350",
        "collision-resistant sentinel read with first-valid transfer-port pinning and cleanup"
    ),
    discovery_capability!(
        "ws-discovery",
        "device-management",
        UnsafeOptIn,
        [3],
        "https://docs.oasis-open.org/ws-dd/discovery/1.1/wsdd-discovery-1.1-spec.html",
        "bounded SOAP-over-UDP Probe and correlated ProbeMatches parsing"
    ),
    discovery_capability!(
        "llmnr-query",
        "directory",
        UnsafeOptIn,
        [4],
        "https://www.rfc-editor.org/rfc/rfc4795",
        "bounded explicitly named link-local resolution operation"
    ),
    discovery_capability!(
        "nat-pmp-external-address",
        "nat-traversal",
        UnsafeOptIn,
        [5],
        "https://www.rfc-editor.org/rfc/rfc6886",
        "non-mutating external-address request to an exact gateway target"
    ),
    discovery_capability!(
        "rpcbind-getaddr",
        "directory",
        UnsafeOptIn,
        [7],
        "https://www.rfc-editor.org/rfc/rfc1833",
        "bounded GETADDR evidence with same-target derived endpoint policy"
    ),
    capability!(
        "kerberos-kdc-error",
        "authentication",
        Blocked,
        [],
        "https://www.rfc-editor.org/rfc/rfc4120",
        "no credential-free synthetic principal contract was accepted without ASN.1 and identity ambiguity"
    ),
    capability!(
        "dhcp-inform",
        "network-discovery",
        Blocked,
        [],
        "https://www.rfc-editor.org/rfc/rfc2131",
        "fixed source and broadcast ownership are not represented by the current API"
    ),
    capability!(
        "ike",
        "vpn-tunnel",
        Blocked,
        [],
        "https://www.rfc-editor.org/rfc/rfc7296",
        "cryptographic SA construction awaits dependency and binary-size review"
    ),
    capability!(
        "dtls",
        "vpn-tunnel",
        Blocked,
        [],
        "https://www.rfc-editor.org/rfc/rfc9147",
        "specification-valid discovery requires reviewed cryptographic handshake state"
    ),
    discovery_capability!(
        "quic",
        "vpn-tunnel",
        UnsafeOptIn,
        [9],
        "https://www.rfc-editor.org/rfc/rfc9000",
        "reserved-version minimum datagram with exact reversed connection-ID correlation"
    ),
    capability!(
        "openvpn",
        "vpn-tunnel",
        Blocked,
        [],
        "https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/",
        "no accepted stable public discovery-wire contract"
    ),
    capability!(
        "radius",
        "authentication",
        Blocked,
        [],
        "https://www.rfc-editor.org/rfc/rfc2865",
        "useful responses require a shared secret and authentication semantics"
    ),
    capability!(
        "cldap-root-dse",
        "directory",
        Blocked,
        [],
        "https://www.rfc-editor.org/rfc/rfc4511",
        "UDP transport and amplification-safe discovery contract are not standardized by LDAPv3"
    ),
    discovery_capability!(
        "sql-browser",
        "database",
        UnsafeOptIn,
        [6],
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/",
        "bounded direct enumeration with one entity per returned instance"
    ),
    capability!(
        "ubiquiti-discovery",
        "device-management",
        Blocked,
        [],
        "https://help.ui.com/",
        "no accepted stable public wire specification"
    ),
    capability!(
        "pcanywhere-status",
        "remote-control",
        Blocked,
        [],
        "https://www.broadcom.com/",
        "no accepted stable public wire specification"
    ),
    capability!(
        "wireguard-handshake",
        "vpn-tunnel",
        Blocked,
        [],
        "https://www.wireguard.com/protocol/",
        "identity-bound authenticated handshake is not a service-discovery request"
    ),
];

/// Validates unique project dispositions and exact coverage of every compiled
/// catalogue probe.
///
/// # Errors
///
/// Returns a deterministic ledger invariant violation.
pub fn validate_udp_capability_ledger(
    entries: &[UdpCapabilityEntry],
) -> Result<(), UdpCapabilityLedgerError> {
    let mut covered = vec![false; usize::from(u16::MAX) + 1];
    let mut covered_discovery = vec![false; usize::from(u16::MAX) + 1];
    for (index, entry) in entries.iter().enumerate() {
        if entry.project_id.is_empty()
            || entry.category.is_empty()
            || entry.primary_source_url.is_empty()
            || entry.evidence.is_empty()
        {
            return Err(UdpCapabilityLedgerError::EmptyField);
        }
        if !entry.primary_source_url.starts_with("https://") {
            return Err(UdpCapabilityLedgerError::InsecurePrimarySource);
        }
        if [
            entry.project_id,
            entry.category,
            entry.primary_source_url,
            entry.evidence,
        ]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains("nmap"))
        {
            return Err(UdpCapabilityLedgerError::ExternalComparisonReference);
        }
        if entries[..index]
            .iter()
            .any(|prior| prior.project_id == entry.project_id)
        {
            return Err(UdpCapabilityLedgerError::DuplicateProjectId);
        }
        if entry.disposition == UdpCapabilityDisposition::Blocked
            && !entry.implementations.is_empty()
        {
            return Err(UdpCapabilityLedgerError::BlockedProbeIsImplemented);
        }
        if entry.disposition != UdpCapabilityDisposition::Blocked
            && entry.implementations.is_empty()
        {
            return Err(UdpCapabilityLedgerError::MissingImplementedProbe);
        }
        for implementation in entry.implementations {
            match implementation {
                CapabilityImplementation::UdpProbe(probe_id) => {
                    let slot = usize::from(*probe_id);
                    if !UDP_PROBE_CATALOGUE
                        .iter()
                        .any(|descriptor| descriptor.id.get() == *probe_id)
                    {
                        return Err(UdpCapabilityLedgerError::UnknownProbeId);
                    }
                    if covered[slot] {
                        return Err(UdpCapabilityLedgerError::DuplicateProbeCoverage);
                    }
                    covered[slot] = true;
                }
                CapabilityImplementation::DiscoveryOperation(operation_id) => {
                    let slot = usize::from(*operation_id);
                    if !DISCOVERY_OPERATION_REGISTRY
                        .iter()
                        .any(|descriptor| descriptor.id.get() == *operation_id)
                    {
                        return Err(UdpCapabilityLedgerError::UnknownDiscoveryOperationId);
                    }
                    if covered_discovery[slot] {
                        return Err(UdpCapabilityLedgerError::DuplicateDiscoveryOperationCoverage);
                    }
                    covered_discovery[slot] = true;
                }
            }
        }
    }
    if UDP_PROBE_CATALOGUE
        .iter()
        .any(|descriptor| !covered[usize::from(descriptor.id.get())])
    {
        return Err(UdpCapabilityLedgerError::UncoveredCatalogueProbe);
    }
    if DISCOVERY_OPERATION_REGISTRY
        .iter()
        .any(|descriptor| !covered_discovery[usize::from(descriptor.id.get())])
    {
        return Err(UdpCapabilityLedgerError::UncoveredDiscoveryOperation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_ledger_is_complete_and_separate_from_external_comparisons() {
        validate_udp_capability_ledger(UDP_CAPABILITY_LEDGER).unwrap();
        assert_eq!(
            UDP_CAPABILITY_LEDGER
                .iter()
                .filter(|entry| entry.disposition == UdpCapabilityDisposition::Blocked)
                .count(),
            10
        );
        assert!(UDP_CAPABILITY_LEDGER.iter().all(|entry| {
            !entry.project_id.to_ascii_lowercase().contains("nmap")
                && !entry.category.to_ascii_lowercase().contains("nmap")
                && !entry
                    .primary_source_url
                    .to_ascii_lowercase()
                    .contains("nmap")
                && !entry.evidence.to_ascii_lowercase().contains("nmap")
        }));
    }

    #[test]
    fn malformed_ledgers_fail_closed() {
        let duplicate = [UDP_CAPABILITY_LEDGER[0], UDP_CAPABILITY_LEDGER[0]];
        assert_eq!(
            validate_udp_capability_ledger(&duplicate),
            Err(UdpCapabilityLedgerError::DuplicateProjectId)
        );
        let mut blocked = *UDP_CAPABILITY_LEDGER
            .iter()
            .find(|entry| entry.disposition == UdpCapabilityDisposition::Blocked)
            .unwrap();
        blocked.implementations = &[CapabilityImplementation::UdpProbe(1)];
        assert_eq!(
            validate_udp_capability_ledger(&[blocked]),
            Err(UdpCapabilityLedgerError::BlockedProbeIsImplemented)
        );
        let mut insecure = UDP_CAPABILITY_LEDGER[0];
        insecure.primary_source_url = "http://example.invalid/";
        assert_eq!(
            validate_udp_capability_ledger(&[insecure]),
            Err(UdpCapabilityLedgerError::InsecurePrimarySource)
        );
        let mut external_comparison = UDP_CAPABILITY_LEDGER[0];
        external_comparison.evidence = "derived from Nmap";
        assert_eq!(
            validate_udp_capability_ledger(&[external_comparison]),
            Err(UdpCapabilityLedgerError::ExternalComparisonReference)
        );
    }
}
