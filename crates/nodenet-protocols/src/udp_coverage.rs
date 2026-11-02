//! Versioned Phase 59–69 UDP coverage and admission registry.
//!
//! This registry describes roadmap candidates and support dimensions. It is
//! deliberately separate from the exact compiled-implementation ledger and
//! contains no third-party scanner identifiers, payloads, or fingerprints.

use core::fmt;

use crate::{
    CapabilityImplementation, DISCOVERY_OPERATION_REGISTRY, UDP_PROBE_CATALOGUE, UdpProbeRisk,
    UdpProbeRiskSet,
};

pub const UDP_COVERAGE_REGISTRY_VERSION: &str = "1.1.0";
pub const MAX_UDP_COVERAGE_CANDIDATES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpCoverageDisposition {
    Research,
    Implemented,
    NoGo,
    Excluded,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpCoverageExecutionModel {
    None,
    TargetPort,
    Discovery,
    Conversation,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpCoveragePolicy {
    Safe,
    OptIn,
    Excluded,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpCoverageRisk {
    ManagementDisclosure = 0,
    TopologyDisclosure = 1,
    Amplification = 2,
    StatefulParticipation = 3,
    LegacyFragility = 4,
    ThreatSignature = 5,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct UdpCoverageRiskSet(u8);

impl UdpCoverageRiskSet {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !0x3f == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, risk: UdpCoverageRisk) -> bool {
        self.0 & (1 << risk as u8) != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpCoverageDimension {
    Request = 0,
    Correlation = 1,
    TypedEvidence = 2,
    ProjectResponder = 3,
    ProductFingerprint = 4,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct UdpCoverageDimensionSet(u8);

impl UdpCoverageDimensionSet {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !0x1f == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, dimension: UdpCoverageDimension) -> bool {
        self.0 & (1 << dimension as u8) != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpCoverageEntry {
    pub id: u16,
    pub project_id: &'static str,
    pub phase: u8,
    pub family: &'static str,
    pub disposition: UdpCoverageDisposition,
    pub execution_model: UdpCoverageExecutionModel,
    pub policy: UdpCoveragePolicy,
    pub risks: UdpCoverageRiskSet,
    /// Exact runtime consent names required before this implementation can run.
    pub required_consents: UdpProbeRiskSet,
    pub dimensions: UdpCoverageDimensionSet,
    pub implementation: Option<CapabilityImplementation>,
    pub primary_source_url: &'static str,
    pub rationale: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpCoverageResourceContract {
    pub maximum_candidates: u16,
    pub maximum_compiled_variants: u16,
    pub maximum_physical_queries: u16,
    pub maximum_response_bytes: u32,
    pub maximum_metadata_bytes: u32,
    pub maximum_returned_endpoints: u16,
    pub maximum_state_lifetime_ms: u32,
}

pub const UDP_COVERAGE_RESOURCE_CONTRACT: UdpCoverageResourceContract =
    UdpCoverageResourceContract {
        maximum_candidates: 64,
        maximum_compiled_variants: 256,
        maximum_physical_queries: 1_024,
        maximum_response_bytes: 4_096,
        maximum_metadata_bytes: 65_536,
        maximum_returned_endpoints: 1_024,
        maximum_state_lifetime_ms: 60_000,
    };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpCoverageRegistryError {
    TooManyCandidates,
    NonSequentialId,
    DuplicateProjectId,
    InvalidPhase,
    EmptyField,
    InsecurePrimarySource,
    ExternalComparisonReference,
    InvalidFinalDisposition,
    MissingImplementation,
    UnexpectedImplementation,
    UnknownImplementation,
    DuplicateImplementation,
    MissingImplementedDimension,
    InvalidPolicy,
    InvalidThreatExclusion,
    InvalidResourceContract,
    InvalidImplementationContract,
    MissingResponderEvidence,
    InvalidConsentContract,
}

impl fmt::Display for UdpCoverageRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid UDP coverage registry: {self:?}")
    }
}

impl std::error::Error for UdpCoverageRegistryError {}

const IMPLEMENTED_DIMENSIONS: u8 = (1 << UdpCoverageDimension::Request as u8)
    | (1 << UdpCoverageDimension::Correlation as u8)
    | (1 << UdpCoverageDimension::TypedEvidence as u8)
    | (1 << UdpCoverageDimension::ProjectResponder as u8);

const EMPTY_CONSENTS: UdpProbeRiskSet = match UdpProbeRiskSet::from_bits(0) {
    Some(value) => value,
    None => panic!("valid empty consent set"),
};
const HIGH_AMPLIFICATION_SENSITIVE_CONSENTS: UdpProbeRiskSet = match UdpProbeRiskSet::from_bits(
    (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
) {
    Some(value) => value,
    None => panic!("valid RIPv1/game/voice consent set"),
};

const VERIFIED_RESPONDER_IMPLEMENTATIONS: &[CapabilityImplementation] = &[
    CapabilityImplementation::UdpProbe(7),
    CapabilityImplementation::DiscoveryOperation(10),
    CapabilityImplementation::UdpProbe(35),
    CapabilityImplementation::UdpProbe(36),
    CapabilityImplementation::UdpProbe(37),
];

const fn risks(bits: u8) -> UdpCoverageRiskSet {
    match UdpCoverageRiskSet::from_bits(bits) {
        Some(value) => value,
        None => panic!("invalid UDP coverage risks"),
    }
}

const fn dimensions(bits: u8) -> UdpCoverageDimensionSet {
    match UdpCoverageDimensionSet::from_bits(bits) {
        Some(value) => value,
        None => panic!("invalid UDP coverage dimensions"),
    }
}

macro_rules! implemented {
    ($id:literal, $project:literal, $phase:literal, $family:literal, $model:ident, $policy:ident, $risks:expr, $implementation:expr, $consents:expr, $fingerprint:expr, $source:literal, $rationale:literal) => {
        UdpCoverageEntry {
            id: $id,
            project_id: $project,
            phase: $phase,
            family: $family,
            disposition: UdpCoverageDisposition::Implemented,
            execution_model: UdpCoverageExecutionModel::$model,
            policy: UdpCoveragePolicy::$policy,
            risks: risks($risks),
            required_consents: $consents,
            dimensions: dimensions(
                IMPLEMENTED_DIMENSIONS
                    | if $fingerprint {
                        1 << UdpCoverageDimension::ProductFingerprint as u8
                    } else {
                        0
                    },
            ),
            implementation: Some($implementation),
            primary_source_url: $source,
            rationale: $rationale,
        }
    };
}

macro_rules! no_go {
    ($id:literal, $project:literal, $phase:literal, $family:literal, $source:literal, $rationale:literal) => {
        UdpCoverageEntry {
            id: $id,
            project_id: $project,
            phase: $phase,
            family: $family,
            disposition: UdpCoverageDisposition::NoGo,
            execution_model: UdpCoverageExecutionModel::None,
            policy: UdpCoveragePolicy::Excluded,
            risks: risks(0),
            required_consents: EMPTY_CONSENTS,
            dimensions: dimensions(0),
            implementation: None,
            primary_source_url: $source,
            rationale: $rationale,
        }
    };
}

macro_rules! excluded {
    ($id:literal, $project:literal, $phase:literal, $family:literal, $source:literal, $rationale:literal) => {
        UdpCoverageEntry {
            id: $id,
            project_id: $project,
            phase: $phase,
            family: $family,
            disposition: UdpCoverageDisposition::Excluded,
            execution_model: UdpCoverageExecutionModel::None,
            policy: UdpCoveragePolicy::Excluded,
            risks: risks(1 << UdpCoverageRisk::ThreatSignature as u8),
            required_consents: EMPTY_CONSENTS,
            dimensions: dimensions(0),
            implementation: None,
            primary_source_url: $source,
            rationale: $rationale,
        }
    };
}

/// Final Phase 59–68 candidate decisions. Runtime implementations resolve to
/// exact compiled IDs; unsupported and excluded rows cannot schedule work.
pub static UDP_COVERAGE_REGISTRY: &[UdpCoverageEntry] = &[
    implemented!(
        1,
        "asf-rmcp-presence",
        60,
        "remote-management",
        TargetPort,
        Safe,
        1 << UdpCoverageRisk::ManagementDisclosure as u8,
        CapabilityImplementation::UdpProbe(7),
        EMPTY_CONSENTS,
        false,
        "https://www.dmtf.org/sites/default/files/standards/documents/DSP0136.pdf",
        "tag-correlated non-mutating ASF presence exchange"
    ),
    no_go!(
        2,
        "ipmi-channel-auth-capabilities",
        60,
        "remote-management",
        "https://www.intel.com/content/www/us/en/products/docs/servers/ipmi/ipmi-home.html",
        "current public primary contract and disclosure-safe live responder were not established"
    ),
    no_go!(
        3,
        "apple-remote-desktop-discovery",
        60,
        "remote-management",
        "https://support.apple.com/guide/remote-desktop/welcome/mac",
        "vendor documentation does not define a stable public UDP discovery contract"
    ),
    no_go!(
        4,
        "citrix-discovery",
        60,
        "remote-management",
        "https://docs.citrix.com/",
        "vendor documentation does not define a stable public credential-free UDP discovery contract"
    ),
    no_go!(
        5,
        "ibm-db2-das-discovery",
        61,
        "database",
        "https://www.ibm.com/docs/en/db2/11.5.x",
        "no stable public vendor wire contract was found for the legacy DAS exchange"
    ),
    no_go!(
        6,
        "sap-sql-anywhere-discovery",
        61,
        "database",
        "https://help.sap.com/docs/SAP_SQL_Anywhere",
        "no stable public vendor wire contract and independent responder were available"
    ),
    implemented!(
        7,
        "ripv1-routing-table",
        62,
        "routing",
        Discovery,
        OptIn,
        (1 << UdpCoverageRisk::TopologyDisclosure as u8)
            | (1 << UdpCoverageRisk::Amplification as u8)
            | (1 << UdpCoverageRisk::LegacyFragility as u8),
        CapabilityImplementation::DiscoveryOperation(10),
        HIGH_AMPLIFICATION_SENSITIVE_CONSENTS,
        false,
        "https://www.rfc-editor.org/rfc/rfc1058",
        "bounded explicit-target whole-table request with strict version-one parsing"
    ),
    no_go!(
        8,
        "beckhoff-ads-discovery",
        62,
        "industrial",
        "https://infosys.beckhoff.com/content/1033/tc3_grundlagen/6917981195.html",
        "vendor material establishes discovery presence but not a complete independently testable wire contract"
    ),
    no_go!(
        9,
        "quake1-server-info",
        63,
        "game-server",
        "https://github.com/id-Software/Quake",
        "the legacy query lacks an accepted correlation and modern responder contract"
    ),
    implemented!(
        10,
        "quake2-status",
        63,
        "game-server",
        TargetPort,
        OptIn,
        (1 << UdpCoverageRisk::Amplification as u8) | (1 << UdpCoverageRisk::LegacyFragility as u8),
        CapabilityImplementation::UdpProbe(35),
        HIGH_AMPLIFICATION_SENSITIVE_CONSENTS,
        false,
        "https://github.com/yquake2/yquake2",
        "bounded out-of-band status request and print response"
    ),
    implemented!(
        11,
        "quake3-info",
        63,
        "game-server",
        TargetPort,
        OptIn,
        1 << UdpCoverageRisk::Amplification as u8,
        CapabilityImplementation::UdpProbe(36),
        HIGH_AMPLIFICATION_SENSITIVE_CONSENTS,
        true,
        "https://github.com/id-Software/Quake-III-Arena",
        "challenge-correlated getinfo response with bounded server fields"
    ),
    no_go!(
        12,
        "quake3-master-servers",
        63,
        "game-master",
        "https://github.com/id-Software/Quake-III-Arena",
        "master enumeration requires a dedicated derived-endpoint discovery runtime and live authority matrix"
    ),
    no_go!(
        13,
        "ut2k-server-ping",
        63,
        "game-server",
        "https://www.epicgames.com/",
        "no current authoritative public wire contract and project responder were established"
    ),
    no_go!(
        14,
        "all-seeing-eye-server",
        63,
        "game-server",
        "https://www.ubisoft.com/",
        "obsolete proprietary protocol lacks an authoritative public wire contract"
    ),
    no_go!(
        15,
        "freelancer-server-status",
        63,
        "game-server",
        "https://www.microsoft.com/",
        "legacy proprietary exchange lacks an authoritative public wire contract"
    ),
    no_go!(
        16,
        "teamspeak2-discovery",
        64,
        "voice",
        "https://www.teamspeak.com/en/downloads/",
        "legacy proprietary handshake lacks a stable public wire contract"
    ),
    no_go!(
        17,
        "teamspeak3-discovery",
        64,
        "voice",
        "https://www.teamspeak.com/en/downloads/",
        "multi-step proprietary initialization was not independently specified or bounded"
    ),
    implemented!(
        18,
        "mumble-extended-ping",
        64,
        "voice",
        TargetPort,
        OptIn,
        1 << UdpCoverageRisk::Amplification as u8,
        CapabilityImplementation::UdpProbe(37),
        HIGH_AMPLIFICATION_SENSITIVE_CONSENTS,
        true,
        "https://github.com/mumble-voip/mumble",
        "timestamp-correlated legacy extended ping with typed version and capacity fields"
    ),
    no_go!(
        19,
        "ventrilo-status",
        64,
        "voice",
        "https://www.ventrilo.com/",
        "encrypted proprietary status protocol lacks a stable public wire contract"
    ),
    no_go!(
        20,
        "squeezecenter-discovery",
        64,
        "media",
        "https://github.com/LMS-Community/slimserver",
        "discovery format and privacy-safe typed result were not established from a stable contract"
    ),
    no_go!(
        21,
        "vuze-dht-ping",
        65,
        "dht",
        "https://github.com/BiglySoftware/BiglyBT",
        "protocol-specific ephemeral identity and read-only participation contract remain unproven"
    ),
    no_go!(
        22,
        "edonkey-kademlia-ping",
        65,
        "dht",
        "https://github.com/irwir/eMule",
        "protocol-specific ephemeral identity and non-participating ping contract remain unproven"
    ),
    no_go!(
        23,
        "afs-rx-ping",
        66,
        "legacy-enterprise",
        "https://docs.openafs.org/doxygen-test/chap5.html",
        "minimum read-only Rx conversation and independent responder were not completed"
    ),
    no_go!(
        24,
        "amanda-noop",
        66,
        "legacy-enterprise",
        "https://github.com/zmanda/amanda",
        "source-defined exchange lacks a frozen independently authored wire contract and responder"
    ),
    no_go!(
        25,
        "dce-rpc-connectionless",
        66,
        "legacy-enterprise",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/",
        "safe endpoint query, fragmentation bounds, and live legacy responder were not established"
    ),
    no_go!(
        26,
        "vxworks-wdb-ping",
        66,
        "legacy-enterprise",
        "https://www.windriver.com/products/vxworks",
        "vendor documentation does not expose a stable non-mutating public wire contract"
    ),
    no_go!(
        27,
        "vxworks-wdb-connect",
        66,
        "legacy-enterprise",
        "https://www.windriver.com/products/vxworks",
        "debugger attachment semantics cross the target-mutation boundary"
    ),
    no_go!(
        28,
        "kerberos-kdc-error",
        67,
        "authentication",
        "https://www.rfc-editor.org/rfc/rfc4120",
        "a fabricated principal is authentication-shaped, identity-ambiguous, and likely logged"
    ),
    no_go!(
        29,
        "dhcp-information-query",
        67,
        "network-configuration",
        "https://www.rfc-editor.org/rfc/rfc2131",
        "host-namespace fixed-port and lease semantics remain outside scanner ownership"
    ),
    no_go!(
        30,
        "ike-discovery",
        67,
        "cryptographic",
        "https://www.rfc-editor.org/rfc/rfc7296",
        "SA negotiation creates cryptographic CPU and state without a discovery-only contract"
    ),
    no_go!(
        31,
        "dtls-discovery",
        67,
        "cryptographic",
        "https://www.rfc-editor.org/rfc/rfc9147",
        "a valid response requires a complete reviewed cryptographic handshake state machine"
    ),
    no_go!(
        32,
        "openvpn-discovery",
        67,
        "cryptographic",
        "https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/",
        "no stable credential-free public discovery wire contract exists"
    ),
    no_go!(
        33,
        "radius-access",
        67,
        "authentication",
        "https://www.rfc-editor.org/rfc/rfc2865",
        "Access-Request is an authentication attempt and useful validation requires a shared secret"
    ),
    no_go!(
        34,
        "cldap-root-dse",
        67,
        "directory",
        "https://www.rfc-editor.org/rfc/rfc4511",
        "LDAPv3 does not standardize an amplification-safe UDP discovery transport"
    ),
    no_go!(
        35,
        "ubiquiti-discovery",
        67,
        "remote-management",
        "https://help.ui.com/",
        "no stable public vendor wire contract exists"
    ),
    no_go!(
        36,
        "pcanywhere-status",
        67,
        "remote-management",
        "https://www.broadcom.com/",
        "obsolete proprietary remote-control protocol lacks a stable public wire contract"
    ),
    no_go!(
        37,
        "wireguard-initiation",
        67,
        "cryptographic",
        "https://www.wireguard.com/protocol/",
        "identity-bound authenticated initiation is not a service-discovery exchange"
    ),
    excluded!(
        38,
        "backorifice-signature",
        68,
        "threat",
        "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "active command-and-control signatures are outside ordinary network discovery"
    ),
    excluded!(
        39,
        "trinoo-signature",
        68,
        "threat",
        "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "active command-and-control signatures are outside ordinary network discovery"
    ),
    excluded!(
        40,
        "andromouse-signature",
        68,
        "threat",
        "https://github.com/justokay/AndroMouse",
        "active remote-control signatures are outside ordinary network discovery"
    ),
    excluded!(
        41,
        "airhid-signature",
        68,
        "threat",
        "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "active remote-input signatures are outside ordinary network discovery"
    ),
];

/// Validates final dispositions, support dimensions, implementation identity,
/// primary-source hygiene, and global resource ceilings.
///
/// # Errors
///
/// Returns the first deterministic registry violation.
#[allow(
    clippy::too_many_lines,
    reason = "the final registry audit is intentionally kept as one ordered fail-closed pass"
)]
pub fn validate_udp_coverage_registry(
    entries: &[UdpCoverageEntry],
    resources: UdpCoverageResourceContract,
) -> Result<(), UdpCoverageRegistryError> {
    if entries.len() > MAX_UDP_COVERAGE_CANDIDATES
        || entries.len() > usize::from(resources.maximum_candidates)
    {
        return Err(UdpCoverageRegistryError::TooManyCandidates);
    }
    if resources.maximum_candidates == 0
        || resources.maximum_compiled_variants == 0
        || UDP_PROBE_CATALOGUE.len() >= usize::from(resources.maximum_compiled_variants)
        || resources.maximum_compiled_variants as usize > crate::MAX_UDP_CATALOGUE_VARIANTS
        || resources.maximum_physical_queries == 0
        || resources.maximum_response_bytes == 0
        || resources.maximum_response_bytes as usize > crate::MAX_UDP_RESPONSE_BYTES
        || resources.maximum_metadata_bytes == 0
        || resources.maximum_returned_endpoints == 0
        || resources.maximum_state_lifetime_ms == 0
        || resources.maximum_state_lifetime_ms > 60_000
    {
        return Err(UdpCoverageRegistryError::InvalidResourceContract);
    }
    if crate::validate_udp_probe_catalogue(UDP_PROBE_CATALOGUE).is_err()
        || crate::validate_discovery_operation_registry(DISCOVERY_OPERATION_REGISTRY).is_err()
    {
        return Err(UdpCoverageRegistryError::InvalidImplementationContract);
    }

    for (index, entry) in entries.iter().enumerate() {
        if usize::from(entry.id) != index + 1 {
            return Err(UdpCoverageRegistryError::NonSequentialId);
        }
        if entry.project_id.is_empty()
            || entry.family.is_empty()
            || entry.primary_source_url.is_empty()
            || entry.rationale.is_empty()
        {
            return Err(UdpCoverageRegistryError::EmptyField);
        }
        if !(60..=68).contains(&entry.phase) {
            return Err(UdpCoverageRegistryError::InvalidPhase);
        }
        if !entry.primary_source_url.starts_with("https://") {
            return Err(UdpCoverageRegistryError::InsecurePrimarySource);
        }
        if entries[..index]
            .iter()
            .any(|prior| prior.project_id == entry.project_id)
        {
            return Err(UdpCoverageRegistryError::DuplicateProjectId);
        }
        if [
            entry.project_id,
            entry.family,
            entry.primary_source_url,
            entry.rationale,
        ]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains("nmap"))
        {
            return Err(UdpCoverageRegistryError::ExternalComparisonReference);
        }
        if entry.disposition == UdpCoverageDisposition::Research {
            return Err(UdpCoverageRegistryError::InvalidFinalDisposition);
        }

        match entry.disposition {
            UdpCoverageDisposition::Implemented => {
                let Some(implementation) = entry.implementation else {
                    return Err(UdpCoverageRegistryError::MissingImplementation);
                };
                if entry.execution_model == UdpCoverageExecutionModel::None
                    || entry.policy == UdpCoveragePolicy::Excluded
                {
                    return Err(UdpCoverageRegistryError::InvalidPolicy);
                }
                if entry.dimensions.bits() & IMPLEMENTED_DIMENSIONS != IMPLEMENTED_DIMENSIONS {
                    return Err(UdpCoverageRegistryError::MissingImplementedDimension);
                }
                match implementation {
                    CapabilityImplementation::UdpProbe(id) => {
                        let Some(probe) = UDP_PROBE_CATALOGUE
                            .iter()
                            .find(|probe| probe.id.get() == id)
                        else {
                            return Err(UdpCoverageRegistryError::UnknownImplementation);
                        };
                        if entry.required_consents != probe.risks {
                            return Err(UdpCoverageRegistryError::InvalidConsentContract);
                        }
                        if entry.execution_model != UdpCoverageExecutionModel::TargetPort
                            || probe.request_builder_id != id
                            || probe.response_parser_id != id
                            || probe.maximum_response_bytes
                                >= usize::try_from(resources.maximum_response_bytes)
                                    .unwrap_or(usize::MAX)
                            || crate::MAX_UDP_SERVICE_METADATA_BYTES
                                >= usize::try_from(resources.maximum_metadata_bytes)
                                    .unwrap_or(usize::MAX)
                            || probe.maximum_state_lifetime_ms
                                >= resources.maximum_state_lifetime_ms
                            || resources.maximum_physical_queries <= 1
                        {
                            return Err(UdpCoverageRegistryError::InvalidImplementationContract);
                        }
                    }
                    CapabilityImplementation::DiscoveryOperation(id) => {
                        let Some(operation) = DISCOVERY_OPERATION_REGISTRY
                            .iter()
                            .find(|operation| operation.id.get() == id)
                        else {
                            return Err(UdpCoverageRegistryError::UnknownImplementation);
                        };
                        let maximum_physical_queries = match id {
                            1 => 256,
                            7 => 2,
                            _ => 1,
                        };
                        if entry.required_consents != operation.required_risks {
                            return Err(UdpCoverageRegistryError::InvalidConsentContract);
                        }
                        if entry.execution_model != UdpCoverageExecutionModel::Discovery
                            || operation.request_builder_id != id
                            || operation.response_parser_id != id
                            || operation.maximum_response_bytes
                                >= usize::try_from(resources.maximum_response_bytes)
                                    .unwrap_or(usize::MAX)
                            || operation.maximum_metadata_bytes_per_query
                                >= resources.maximum_metadata_bytes
                            || operation.maximum_entities_per_query
                                >= resources.maximum_returned_endpoints
                            || operation.response_window_ms >= resources.maximum_state_lifetime_ms
                            || maximum_physical_queries >= resources.maximum_physical_queries
                        {
                            return Err(UdpCoverageRegistryError::InvalidImplementationContract);
                        }
                    }
                }
                if entries[..index]
                    .iter()
                    .any(|prior| prior.implementation == Some(implementation))
                {
                    return Err(UdpCoverageRegistryError::DuplicateImplementation);
                }
                if !VERIFIED_RESPONDER_IMPLEMENTATIONS.contains(&implementation) {
                    return Err(UdpCoverageRegistryError::MissingResponderEvidence);
                }
            }
            UdpCoverageDisposition::NoGo => {
                if entry.implementation.is_some() {
                    return Err(UdpCoverageRegistryError::UnexpectedImplementation);
                }
                if entry.execution_model != UdpCoverageExecutionModel::None
                    || entry.policy != UdpCoveragePolicy::Excluded
                    || entry.dimensions.bits() != 0
                    || entry.required_consents.bits() != 0
                {
                    return Err(UdpCoverageRegistryError::InvalidPolicy);
                }
            }
            UdpCoverageDisposition::Excluded => {
                if entry.implementation.is_some()
                    || entry.execution_model != UdpCoverageExecutionModel::None
                    || entry.policy != UdpCoveragePolicy::Excluded
                    || entry.dimensions.bits() != 0
                    || entry.required_consents.bits() != 0
                    || !entry.risks.contains(UdpCoverageRisk::ThreatSignature)
                {
                    return Err(UdpCoverageRegistryError::InvalidThreatExclusion);
                }
            }
            UdpCoverageDisposition::Research => unreachable!("rejected above"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_registry_is_complete_and_final() {
        validate_udp_coverage_registry(UDP_COVERAGE_REGISTRY, UDP_COVERAGE_RESOURCE_CONTRACT)
            .unwrap();
        assert_eq!(UDP_COVERAGE_REGISTRY.len(), 41);
        assert_eq!(
            UDP_COVERAGE_REGISTRY
                .iter()
                .filter(|entry| entry.disposition == UdpCoverageDisposition::Implemented)
                .count(),
            5
        );
        assert_eq!(
            UDP_COVERAGE_REGISTRY
                .iter()
                .filter(|entry| entry.disposition == UdpCoverageDisposition::Excluded)
                .count(),
            4
        );
        assert!(UDP_COVERAGE_REGISTRY.iter().all(|entry| {
            !entry.project_id.to_ascii_lowercase().contains("nmap")
                && !entry.rationale.to_ascii_lowercase().contains("nmap")
        }));
    }

    #[test]
    fn malformed_registry_rows_fail_closed() {
        let mut missing = UDP_COVERAGE_REGISTRY[0];
        missing.implementation = None;
        assert_eq!(
            validate_udp_coverage_registry(&[missing], UDP_COVERAGE_RESOURCE_CONTRACT),
            Err(UdpCoverageRegistryError::MissingImplementation)
        );

        let mut threat = UDP_COVERAGE_REGISTRY[37];
        threat.risks = UdpCoverageRiskSet::default();
        assert_eq!(
            validate_udp_coverage_registry(&[threat], UDP_COVERAGE_RESOURCE_CONTRACT),
            Err(UdpCoverageRegistryError::NonSequentialId)
        );
        threat.id = 1;
        assert_eq!(
            validate_udp_coverage_registry(&[threat], UDP_COVERAGE_RESOURCE_CONTRACT),
            Err(UdpCoverageRegistryError::InvalidThreatExclusion)
        );

        let mut external = UDP_COVERAGE_REGISTRY[1];
        external.id = 1;
        external.rationale = "copied from nmap";
        assert_eq!(
            validate_udp_coverage_registry(&[external], UDP_COVERAGE_RESOURCE_CONTRACT),
            Err(UdpCoverageRegistryError::ExternalComparisonReference)
        );
    }

    #[test]
    fn implementation_resources_and_consents_fail_closed() {
        for resources in [
            UdpCoverageResourceContract {
                maximum_compiled_variants: 37,
                ..UDP_COVERAGE_RESOURCE_CONTRACT
            },
            UdpCoverageResourceContract {
                maximum_physical_queries: 1,
                ..UDP_COVERAGE_RESOURCE_CONTRACT
            },
            UdpCoverageResourceContract {
                maximum_response_bytes: 1_400,
                ..UDP_COVERAGE_RESOURCE_CONTRACT
            },
            UdpCoverageResourceContract {
                maximum_metadata_bytes: 32_768,
                ..UDP_COVERAGE_RESOURCE_CONTRACT
            },
            UdpCoverageResourceContract {
                maximum_returned_endpoints: 250,
                ..UDP_COVERAGE_RESOURCE_CONTRACT
            },
            UdpCoverageResourceContract {
                maximum_state_lifetime_ms: 3_000,
                ..UDP_COVERAGE_RESOURCE_CONTRACT
            },
        ] {
            assert!(matches!(
                validate_udp_coverage_registry(UDP_COVERAGE_REGISTRY, resources),
                Err(UdpCoverageRegistryError::InvalidResourceContract
                    | UdpCoverageRegistryError::InvalidImplementationContract)
            ));
        }

        let mut consent_drift = UDP_COVERAGE_REGISTRY[10];
        consent_drift.id = 1;
        consent_drift.required_consents = EMPTY_CONSENTS;
        assert_eq!(
            validate_udp_coverage_registry(&[consent_drift], UDP_COVERAGE_RESOURCE_CONTRACT),
            Err(UdpCoverageRegistryError::InvalidConsentContract)
        );
    }
}
