use core::fmt;

use sha2::{Digest, Sha256};

use crate::MAX_UDP_REQUEST_BYTES;

pub const UDP_PROBE_CATALOGUE_VERSION: &str = "1.4.1";
pub const UDP_PROBE_CATALOGUE_SHA256_HEX: &str =
    "90c1589cd264385c6931cd6ed9efdc216f352239790a9026830bfe98cffe5e56";
pub const MAX_UDP_CATALOGUE_VARIANTS: usize = 256;
pub const MAX_UDP_CORRELATION_FIELDS: usize = 8;
pub const MAX_UDP_RESPONSE_BYTES: usize = 65_527;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UdpProbeId(u16);

impl UdpProbeId {
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UdpServiceFamilyId(u16);

impl UdpServiceFamilyId {
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpProbeProfile {
    Safe,
    Comprehensive,
    Legacy,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpProbeRisk {
    HighAmplification = 0,
    StatefulHandshake = 1,
    FixedSourcePort = 2,
    MulticastOrBroadcast = 3,
    AuthenticationAttempt = 4,
    SensitiveRead = 5,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct UdpProbeRiskSet(u8);

impl UdpProbeRiskSet {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !0x3f == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn contains(self, risk: UdpProbeRisk) -> bool {
        self.0 & (1 << risk as u8) != 0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpAddressFamilies {
    Ipv4,
    Ipv6,
    Both,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpResponseEndpointPolicy {
    RequestTupleOnly,
    SameAddressAnyPort,
    AnyUnicastEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UdpSourcePortConstraint {
    Ephemeral,
    Fixed(u16),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum UdpCorrelationFieldKind {
    TransactionU16,
    TransactionU32,
    TokenU64,
    ExactBytes,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpCorrelationField {
    pub offset: u16,
    pub length: u16,
    pub kind: UdpCorrelationFieldKind,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpPortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpProbeProvenance {
    pub primary_source: &'static str,
    pub source_url: &'static str,
    pub specification: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpProbeDescriptor {
    pub id: UdpProbeId,
    pub service_family: UdpServiceFamilyId,
    pub name: &'static str,
    pub profile: UdpProbeProfile,
    pub minimum_intensity: u8,
    pub risks: UdpProbeRiskSet,
    pub address_families: UdpAddressFamilies,
    pub ports: &'static [UdpPortRange],
    pub response_endpoint: UdpResponseEndpointPolicy,
    pub source_port: UdpSourcePortConstraint,
    pub request_builder_id: u16,
    pub response_parser_id: u16,
    /// Smallest request size used for conservative amplification accounting.
    pub minimum_request_bytes: usize,
    /// Largest request size the builder may produce.
    pub request_template_bytes: usize,
    pub maximum_response_bytes: usize,
    /// Maximum typed-parser input accepted from one response datagram.
    pub maximum_parser_bytes: usize,
    /// Ceiling of `maximum_response_bytes / request_template_bytes`, rounded up.
    pub maximum_amplification_ratio: u16,
    /// Longest permitted live state for a materially stateful request.
    pub maximum_state_lifetime_ms: u32,
    pub correlation: &'static [UdpCorrelationField],
    pub provenance: UdpProbeProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpCatalogueError {
    TooManyVariants,
    NonDeterministicOrder,
    DuplicateProbeId,
    EmptyName,
    InvalidPortRange,
    NonDeterministicPortOrder,
    UnknownRequestBuilder,
    UnknownResponseParser,
    UnsafeSafeProfile,
    InvalidSourcePort,
    OversizedRequestTemplate,
    InvalidRequestBounds,
    UnboundedResponse,
    OversizedResponse,
    InvalidParserBudget,
    InvalidAmplificationRatio,
    MissingAmplificationRisk,
    InvalidStateLifetime,
    TooManyCorrelationFields,
    InvalidCorrelationField,
    MissingProvenance,
    InsecureProvenance,
    ExternalComparisonReference,
}

impl fmt::Display for UdpCatalogueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid UDP probe catalogue: {self:?}")
    }
}

impl std::error::Error for UdpCatalogueError {}

const REGISTERED_REQUEST_BUILDERS: [u16; 37] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
];
const REGISTERED_RESPONSE_PARSERS: [u16; 37] = REGISTERED_REQUEST_BUILDERS;
const EMPTY_RISKS: UdpProbeRiskSet = match UdpProbeRiskSet::from_bits(0) {
    Some(value) => value,
    None => unreachable!(),
};
const fn probe_id(value: u16) -> UdpProbeId {
    match UdpProbeId::new(value) {
        Some(value) => value,
        None => panic!("zero probe id"),
    }
}
const fn family_id(value: u16) -> UdpServiceFamilyId {
    match UdpServiceFamilyId::new(value) {
        Some(value) => value,
        None => panic!("zero family id"),
    }
}

const DNS_PORTS: &[UdpPortRange] = &[UdpPortRange { start: 53, end: 53 }];
const NTP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 123,
    end: 123,
}];
const SNMP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 161,
    end: 161,
}];
const RPCBIND_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 111,
    end: 111,
}];
const STUN_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 3478,
    end: 3478,
}];
const COAP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 5683,
    end: 5683,
}];
const ASF_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 623,
    end: 623,
}];
const MEMCACHED_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 11_211,
    end: 11_211,
}];
const NETBIOS_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 137,
    end: 137,
}];
const NFS_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 2049,
    end: 2049,
}];
const SIP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 5060,
    end: 5060,
}];
const SSDP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 1900,
    end: 1900,
}];
const L2TP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 1701,
    end: 1701,
}];
const PCP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 5351,
    end: 5351,
}];
const ECHO_PORTS: &[UdpPortRange] = &[UdpPortRange { start: 7, end: 7 }];
const DAYTIME_PORTS: &[UdpPortRange] = &[UdpPortRange { start: 13, end: 13 }];
const QOTD_PORTS: &[UdpPortRange] = &[UdpPortRange { start: 17, end: 17 }];
const CHARGEN_PORTS: &[UdpPortRange] = &[UdpPortRange { start: 19, end: 19 }];
const SYSTAT_PORTS: &[UdpPortRange] = &[UdpPortRange { start: 11, end: 11 }];
const NETSTAT_PORTS: &[UdpPortRange] = &[UdpPortRange { start: 15, end: 15 }];
const RIP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 520,
    end: 520,
}];
const XDMCP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 177,
    end: 177,
}];
const SOURCE_ENGINE_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 27_015,
    end: 27_015,
}];
const RAKNET_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 19_132,
    end: 19_133,
}];
const BACNET_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 47_808,
    end: 47_808,
}];
const ENIP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 44_818,
    end: 44_818,
}];
const KNX_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 3_671,
    end: 3_671,
}];
const DHT_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 6_881,
    end: 6_881,
}];
const SLP_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 427,
    end: 427,
}];
const QUAKE2_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 27_910,
    end: 27_910,
}];
const QUAKE3_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 27_960,
    end: 27_960,
}];
const MUMBLE_PORTS: &[UdpPortRange] = &[UdpPortRange {
    start: 64_738,
    end: 64_738,
}];
const TX16: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 0,
    length: 2,
    kind: UdpCorrelationFieldKind::TransactionU16,
}];
const TX32: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 0,
    length: 4,
    kind: UdpCorrelationFieldKind::TransactionU32,
}];
const TX64: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 24,
    length: 8,
    kind: UdpCorrelationFieldKind::TokenU64,
}];
const TX96: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 8,
    length: 12,
    kind: UdpCorrelationFieldKind::ExactBytes,
}];
const COAP_TX: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 2,
    length: 2,
    kind: UdpCorrelationFieldKind::TransactionU16,
}];
const ASF_TX: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 9,
    length: 1,
    kind: UdpCorrelationFieldKind::ExactBytes,
}];
const OFFSET4_TX16: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 4,
    length: 2,
    kind: UdpCorrelationFieldKind::TransactionU16,
}];
const OFFSET1_TX64: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 1,
    length: 8,
    kind: UdpCorrelationFieldKind::TokenU64,
}];
const OFFSET2_TX16: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 2,
    length: 2,
    kind: UdpCorrelationFieldKind::TransactionU16,
}];
const OFFSET10_TX16: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 10,
    length: 2,
    kind: UdpCorrelationFieldKind::TransactionU16,
}];
const OFFSET12_TX64: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 12,
    length: 8,
    kind: UdpCorrelationFieldKind::TokenU64,
}];
const OFFSET4_TX64: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 4,
    length: 8,
    kind: UdpCorrelationFieldKind::TokenU64,
}];
const OFFSET28_EXACT16: &[UdpCorrelationField] = &[UdpCorrelationField {
    offset: 28,
    length: 16,
    kind: UdpCorrelationFieldKind::ExactBytes,
}];
const NO_TX: &[UdpCorrelationField] = &[];

const fn probe_risks(bits: u8) -> UdpProbeRiskSet {
    match UdpProbeRiskSet::from_bits(bits) {
        Some(value) => value,
        None => panic!("invalid risk bits"),
    }
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "the preceding bound proves the successful branch fits u16"
)]
const fn amplification_ratio(maximum: usize, request: usize) -> u16 {
    let value = maximum.div_ceil(request);
    if value > u16::MAX as usize {
        u16::MAX
    } else {
        value as u16
    }
}

macro_rules! safe_probe {
    ($id:literal, $name:literal, $ports:ident, $minimum:literal, $size:literal, $maximum:literal, $correlation:ident, $source:literal, $spec:literal) => {
        UdpProbeDescriptor {
            id: probe_id($id),
            service_family: family_id($id),
            name: $name,
            profile: UdpProbeProfile::Safe,
            minimum_intensity: 0,
            risks: EMPTY_RISKS,
            address_families: UdpAddressFamilies::Both,
            ports: $ports,
            response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
            source_port: UdpSourcePortConstraint::Ephemeral,
            request_builder_id: $id,
            response_parser_id: $id,
            minimum_request_bytes: $minimum,
            request_template_bytes: $size,
            maximum_response_bytes: $maximum,
            maximum_parser_bytes: $maximum,
            maximum_amplification_ratio: amplification_ratio($maximum, $minimum),
            maximum_state_lifetime_ms: 0,
            correlation: $correlation,
            provenance: UdpProbeProvenance {
                primary_source: "RFC Editor / protocol owner",
                source_url: $source,
                specification: $spec,
            },
        }
    };
}

macro_rules! extended_probe {
    ($id:literal, $family:literal, $name:literal, $profile:ident, $intensity:literal, $risks:expr, $families:ident, $ports:ident, $minimum:literal, $request:literal, $response:literal, $lifetime:literal, $correlation:ident, $owner:literal, $source:literal, $spec:literal) => {
        UdpProbeDescriptor {
            id: probe_id($id),
            service_family: family_id($family),
            name: $name,
            profile: UdpProbeProfile::$profile,
            minimum_intensity: $intensity,
            risks: probe_risks($risks),
            address_families: UdpAddressFamilies::$families,
            ports: $ports,
            response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
            source_port: UdpSourcePortConstraint::Ephemeral,
            request_builder_id: $id,
            response_parser_id: $id,
            minimum_request_bytes: $minimum,
            request_template_bytes: $request,
            maximum_response_bytes: $response,
            maximum_parser_bytes: $response,
            maximum_amplification_ratio: amplification_ratio($response, $minimum),
            maximum_state_lifetime_ms: $lifetime,
            correlation: $correlation,
            provenance: UdpProbeProvenance {
                primary_source: $owner,
                source_url: $source,
                specification: $spec,
            },
        }
    };
}

pub static UDP_PROBE_CATALOGUE: &[UdpProbeDescriptor] = &[
    safe_probe!(
        1,
        "dns-root-a-edns",
        DNS_PORTS,
        128,
        128,
        512,
        TX16,
        "https://www.rfc-editor.org/rfc/rfc1035",
        "RFC 1035 section 4; RFC 6891 section 6; RFC 7830 section 4"
    ),
    safe_probe!(
        2,
        "ntp-client",
        NTP_PORTS,
        48,
        48,
        512,
        TX64,
        "https://www.rfc-editor.org/rfc/rfc5905",
        "RFC 5905 section 7.3"
    ),
    safe_probe!(
        3,
        "snmpv3-engine-discovery",
        SNMP_PORTS,
        64,
        96,
        1024,
        TX32,
        "https://www.rfc-editor.org/rfc/rfc3414",
        "RFC 3414 section 4"
    ),
    safe_probe!(
        4,
        "rpcbind-null",
        RPCBIND_PORTS,
        40,
        40,
        1024,
        TX32,
        "https://www.rfc-editor.org/rfc/rfc5531",
        "RFC 5531 sections 8 and 9; rpcbind program 100000 v2 NULL"
    ),
    safe_probe!(
        5,
        "stun-binding",
        STUN_PORTS,
        20,
        20,
        1024,
        TX96,
        "https://www.rfc-editor.org/rfc/rfc8489",
        "RFC 8489 sections 5 and 6"
    ),
    safe_probe!(
        6,
        "coap-empty-con",
        COAP_PORTS,
        4,
        4,
        256,
        COAP_TX,
        "https://www.rfc-editor.org/rfc/rfc7252",
        "RFC 7252 sections 3 and 4.2"
    ),
    safe_probe!(
        7,
        "asf-rmcp-presence",
        ASF_PORTS,
        12,
        12,
        256,
        ASF_TX,
        "https://www.dmtf.org/sites/default/files/standards/documents/DSP0136_3.0.1.pdf",
        "DMTF DSP0136 ASF RMCP presence ping"
    ),
    safe_probe!(
        8,
        "memcached-version",
        MEMCACHED_PORTS,
        17,
        17,
        512,
        TX16,
        "https://github.com/memcached/memcached/blob/master/doc/protocol.txt",
        "memcached UDP framing and text protocol version command"
    ),
    safe_probe!(
        9,
        "pcp-announce",
        PCP_PORTS,
        24,
        24,
        256,
        NO_TX,
        "https://www.rfc-editor.org/rfc/rfc6887",
        "RFC 6887 sections 7 and 14.1"
    ),
    UdpProbeDescriptor {
        id: probe_id(10),
        service_family: family_id(10),
        name: "netbios-node-status",
        profile: UdpProbeProfile::Comprehensive,
        minimum_intensity: 3,
        risks: probe_risks(1 << UdpProbeRisk::SensitiveRead as u8),
        address_families: UdpAddressFamilies::Ipv4,
        ports: NETBIOS_PORTS,
        response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
        source_port: UdpSourcePortConstraint::Ephemeral,
        request_builder_id: 10,
        response_parser_id: 10,
        minimum_request_bytes: 50,
        request_template_bytes: 50,
        maximum_response_bytes: 1_024,
        maximum_parser_bytes: 1_024,
        maximum_amplification_ratio: 21,
        maximum_state_lifetime_ms: 0,
        correlation: TX16,
        provenance: UdpProbeProvenance {
            primary_source: "RFC Editor",
            source_url: "https://www.rfc-editor.org/rfc/rfc1002",
            specification: "RFC 1002 sections 4.2.17 and 4.2.18",
        },
    },
    UdpProbeDescriptor {
        id: probe_id(11),
        service_family: family_id(11),
        name: "nfs-v3-null",
        profile: UdpProbeProfile::Comprehensive,
        minimum_intensity: 1,
        risks: EMPTY_RISKS,
        address_families: UdpAddressFamilies::Both,
        ports: NFS_PORTS,
        response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
        source_port: UdpSourcePortConstraint::Ephemeral,
        request_builder_id: 11,
        response_parser_id: 11,
        minimum_request_bytes: 40,
        request_template_bytes: 40,
        maximum_response_bytes: 256,
        maximum_parser_bytes: 256,
        maximum_amplification_ratio: 7,
        maximum_state_lifetime_ms: 0,
        correlation: TX32,
        provenance: UdpProbeProvenance {
            primary_source: "RFC Editor",
            source_url: "https://www.rfc-editor.org/rfc/rfc1813",
            specification: "RFC 1813 NFS_PROGRAM v3 NFSPROC3_NULL; RFC 5531 RPC framing",
        },
    },
    UdpProbeDescriptor {
        id: probe_id(12),
        service_family: family_id(12),
        name: "sip-options",
        profile: UdpProbeProfile::Comprehensive,
        minimum_intensity: 4,
        risks: probe_risks(1 << UdpProbeRisk::SensitiveRead as u8),
        address_families: UdpAddressFamilies::Both,
        ports: SIP_PORTS,
        response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
        source_port: UdpSourcePortConstraint::Ephemeral,
        request_builder_id: 12,
        response_parser_id: 12,
        minimum_request_bytes: 256,
        request_template_bytes: 512,
        maximum_response_bytes: 1_024,
        maximum_parser_bytes: 1_024,
        maximum_amplification_ratio: 4,
        maximum_state_lifetime_ms: 0,
        correlation: NO_TX,
        provenance: UdpProbeProvenance {
            primary_source: "RFC Editor",
            source_url: "https://www.rfc-editor.org/rfc/rfc3261",
            specification: "RFC 3261 sections 11, 17.1.3, and 20",
        },
    },
    UdpProbeDescriptor {
        id: probe_id(13),
        service_family: family_id(13),
        name: "ssdp-unicast-all",
        profile: UdpProbeProfile::Comprehensive,
        minimum_intensity: 4,
        risks: probe_risks(
            (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        ),
        address_families: UdpAddressFamilies::Both,
        ports: SSDP_PORTS,
        response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
        source_port: UdpSourcePortConstraint::Ephemeral,
        request_builder_id: 13,
        response_parser_id: 13,
        minimum_request_bytes: 128,
        request_template_bytes: 256,
        maximum_response_bytes: 4_096,
        maximum_parser_bytes: 4_096,
        maximum_amplification_ratio: 32,
        maximum_state_lifetime_ms: 0,
        correlation: NO_TX,
        provenance: UdpProbeProvenance {
            primary_source: "UPnP Forum",
            source_url: "https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf",
            specification: "UPnP Device Architecture 1.1 section 1.3.2 unicast M-SEARCH",
        },
    },
    UdpProbeDescriptor {
        id: probe_id(14),
        service_family: family_id(14),
        name: "l2tp-sccrq",
        profile: UdpProbeProfile::Comprehensive,
        minimum_intensity: 6,
        risks: probe_risks(1 << UdpProbeRisk::StatefulHandshake as u8),
        address_families: UdpAddressFamilies::Both,
        ports: L2TP_PORTS,
        response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
        source_port: UdpSourcePortConstraint::Ephemeral,
        request_builder_id: 14,
        response_parser_id: 14,
        minimum_request_bytes: 67,
        request_template_bytes: 128,
        maximum_response_bytes: 1_024,
        maximum_parser_bytes: 1_024,
        maximum_amplification_ratio: 16,
        maximum_state_lifetime_ms: 10_000,
        correlation: OFFSET4_TX16,
        provenance: UdpProbeProvenance {
            primary_source: "RFC Editor",
            source_url: "https://www.rfc-editor.org/rfc/rfc2661",
            specification: "RFC 2661 sections 3.1, 4.4, 6.1, and 6.2",
        },
    },
    UdpProbeDescriptor {
        id: probe_id(15),
        service_family: family_id(15),
        name: "snmpv1-public-sysdescr",
        profile: UdpProbeProfile::Comprehensive,
        minimum_intensity: 7,
        risks: probe_risks(
            (1 << UdpProbeRisk::AuthenticationAttempt as u8)
                | (1 << UdpProbeRisk::SensitiveRead as u8),
        ),
        address_families: UdpAddressFamilies::Both,
        ports: SNMP_PORTS,
        response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
        source_port: UdpSourcePortConstraint::Ephemeral,
        request_builder_id: 15,
        response_parser_id: 15,
        minimum_request_bytes: 40,
        request_template_bytes: 64,
        maximum_response_bytes: 1_024,
        maximum_parser_bytes: 1_024,
        maximum_amplification_ratio: 26,
        maximum_state_lifetime_ms: 0,
        correlation: NO_TX,
        provenance: UdpProbeProvenance {
            primary_source: "RFC Editor",
            source_url: "https://www.rfc-editor.org/rfc/rfc1157",
            specification: "RFC 1157 sections 4.1.2 and 4.1.4; MIB-II sysDescr.0",
        },
    },
    UdpProbeDescriptor {
        id: probe_id(16),
        service_family: family_id(8),
        name: "memcached-statistics",
        profile: UdpProbeProfile::Comprehensive,
        minimum_intensity: 7,
        risks: probe_risks(
            (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        ),
        address_families: UdpAddressFamilies::Both,
        ports: MEMCACHED_PORTS,
        response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
        source_port: UdpSourcePortConstraint::Ephemeral,
        request_builder_id: 16,
        response_parser_id: 16,
        minimum_request_bytes: 15,
        request_template_bytes: 15,
        maximum_response_bytes: 4_096,
        maximum_parser_bytes: 4_096,
        maximum_amplification_ratio: 274,
        maximum_state_lifetime_ms: 0,
        correlation: TX16,
        provenance: UdpProbeProvenance {
            primary_source: "memcached project",
            source_url: "https://github.com/memcached/memcached/blob/master/doc/protocol.txt",
            specification: "memcached UDP framing and text statistics command",
        },
    },
    extended_probe!(
        17,
        17,
        "udp-echo",
        Legacy,
        1,
        0,
        Both,
        ECHO_PORTS,
        16,
        16,
        16,
        0,
        NO_TX,
        "RFC Editor",
        "https://www.rfc-editor.org/rfc/rfc862",
        "RFC 862 UDP Echo"
    ),
    extended_probe!(
        18,
        18,
        "daytime",
        Legacy,
        2,
        0,
        Both,
        DAYTIME_PORTS,
        1,
        1,
        1_024,
        0,
        NO_TX,
        "RFC Editor",
        "https://www.rfc-editor.org/rfc/rfc867",
        "RFC 867 UDP Daytime"
    ),
    extended_probe!(
        19,
        19,
        "quote-of-the-day",
        Legacy,
        3,
        1 << UdpProbeRisk::HighAmplification as u8,
        Both,
        QOTD_PORTS,
        1,
        1,
        1_024,
        0,
        NO_TX,
        "RFC Editor",
        "https://www.rfc-editor.org/rfc/rfc865",
        "RFC 865 UDP Quote of the Day"
    ),
    extended_probe!(
        20,
        20,
        "character-generator",
        Legacy,
        9,
        1 << UdpProbeRisk::HighAmplification as u8,
        Both,
        CHARGEN_PORTS,
        1,
        1,
        4_096,
        0,
        NO_TX,
        "RFC Editor",
        "https://www.rfc-editor.org/rfc/rfc864",
        "RFC 864 UDP Character Generator"
    ),
    extended_probe!(
        21,
        21,
        "active-users",
        Legacy,
        8,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        SYSTAT_PORTS,
        1,
        1,
        4_096,
        0,
        NO_TX,
        "RFC Editor",
        "https://www.rfc-editor.org/rfc/rfc866",
        "RFC 866 UDP Active Users"
    ),
    extended_probe!(
        22,
        22,
        "network-status",
        Legacy,
        8,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        NETSTAT_PORTS,
        1,
        1,
        4_096,
        0,
        NO_TX,
        "RFC Editor",
        "https://www.rfc-editor.org/rfc/rfc869",
        "RFC 869 UDP Network Status"
    ),
    extended_probe!(
        23,
        23,
        "ripv2-routing-table",
        Comprehensive,
        8,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Ipv4,
        RIP_PORTS,
        24,
        24,
        504,
        0,
        NO_TX,
        "RFC Editor",
        "https://www.rfc-editor.org/rfc/rfc2453",
        "RFC 2453 sections 3.4 and 3.9.1"
    ),
    extended_probe!(
        24,
        24,
        "xdmcp-query",
        Legacy,
        6,
        1 << UdpProbeRisk::SensitiveRead as u8,
        Both,
        XDMCP_PORTS,
        7,
        7,
        1_024,
        0,
        NO_TX,
        "X.Org Foundation",
        "https://www.x.org/releases/X11R7.7/doc/libXdmcp/xdmcp.html",
        "XDMCP Query/Willing/Unwilling"
    ),
    extended_probe!(
        25,
        25,
        "source-engine-info",
        Comprehensive,
        5,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        SOURCE_ENGINE_PORTS,
        25,
        25,
        4_096,
        0,
        NO_TX,
        "Valve Developer Community",
        "https://developer.valvesoftware.com/wiki/Server_queries",
        "A2S_INFO request and response"
    ),
    extended_probe!(
        26,
        26,
        "raknet-unconnected-ping",
        Comprehensive,
        5,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        RAKNET_PORTS,
        33,
        33,
        1_024,
        0,
        OFFSET1_TX64,
        "Open-source RakNet protocol documentation",
        "https://github.com/facebookarchive/RakNet/blob/master/Help/Protocol.html",
        "RakNet unconnected ping/pong"
    ),
    extended_probe!(
        27,
        27,
        "bacnet-who-is",
        Comprehensive,
        6,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        BACNET_PORTS,
        8,
        8,
        1_476,
        0,
        NO_TX,
        "ASHRAE BACnet Committee",
        "https://bacnet.org/",
        "ANSI/ASHRAE 135 BACnet/IP BVLC and Who-Is/I-Am"
    ),
    extended_probe!(
        28,
        28,
        "ethernet-ip-list-identity",
        Comprehensive,
        5,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        ENIP_PORTS,
        24,
        24,
        4_096,
        0,
        OFFSET12_TX64,
        "ODVA",
        "https://www.odva.org/technology-standards/key-technologies/ethernet-ip/",
        "EtherNet/IP encapsulation ListIdentity"
    ),
    extended_probe!(
        29,
        29,
        "knxnet-ip-search",
        Comprehensive,
        6,
        1 << UdpProbeRisk::SensitiveRead as u8,
        Ipv4,
        KNX_PORTS,
        14,
        14,
        1_024,
        0,
        NO_TX,
        "KNX Association",
        "https://support.knx.org/hc/en-us/articles/360018876560-KNXnet-IP",
        "KNXnet/IP Search Request/Response and HPAI"
    ),
    extended_probe!(
        30,
        30,
        "bittorrent-dht-ping",
        Comprehensive,
        6,
        1 << UdpProbeRisk::StatefulHandshake as u8,
        Both,
        DHT_PORTS,
        55,
        80,
        512,
        10_000,
        NO_TX,
        "BitTorrent project",
        "https://www.bittorrent.org/beps/bep_0005.html",
        "BEP 5 KRPC ping query"
    ),
    extended_probe!(
        31,
        1,
        "dns-chaos-version",
        Legacy,
        8,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        DNS_PORTS,
        30,
        30,
        4_096,
        0,
        TX16,
        "ISC BIND / RFC Editor",
        "https://bind9.readthedocs.io/en/latest/reference.html",
        "BIND CHAOS-class version.bind TXT convention; RFC 1035 framing"
    ),
    extended_probe!(
        32,
        2,
        "ntp-control-read-variables",
        Legacy,
        9,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        NTP_PORTS,
        12,
        12,
        4_096,
        0,
        OFFSET2_TX16,
        "RFC Editor / NTP project",
        "https://www.rfc-editor.org/rfc/rfc9327",
        "RFC 9327 mode 6 control message framing and READVAR"
    ),
    extended_probe!(
        33,
        33,
        "slp-service-agent",
        Comprehensive,
        7,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        SLP_PORTS,
        52,
        64,
        4_096,
        0,
        OFFSET10_TX16,
        "RFC Editor",
        "https://www.rfc-editor.org/rfc/rfc2608",
        "RFC 2608 Service Request/Reply for service-agent"
    ),
    extended_probe!(
        34,
        34,
        "ripv1-routing-table",
        Legacy,
        8,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Ipv4,
        RIP_PORTS,
        24,
        24,
        504,
        0,
        NO_TX,
        "RFC Editor",
        "https://www.rfc-editor.org/rfc/rfc1058",
        "RFC 1058 sections 3.4 and 3.4.1"
    ),
    extended_probe!(
        35,
        35,
        "quake2-status",
        Legacy,
        7,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        QUAKE2_PORTS,
        10,
        10,
        1_400,
        0,
        NO_TX,
        "Yamagi Quake II project",
        "https://github.com/yquake2/yquake2",
        "connectionless status command and print response"
    ),
    extended_probe!(
        36,
        36,
        "quake3-info",
        Comprehensive,
        6,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        QUAKE3_PORTS,
        28,
        28,
        1_041,
        0,
        OFFSET28_EXACT16,
        "id Software",
        "https://github.com/id-Software/Quake-III-Arena",
        "challenge-correlated getinfo/infoResponse exchange"
    ),
    extended_probe!(
        37,
        37,
        "mumble-extended-ping",
        Comprehensive,
        6,
        (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
        Both,
        MUMBLE_PORTS,
        12,
        12,
        24,
        0,
        OFFSET4_TX64,
        "Mumble project",
        "https://github.com/mumble-voip/mumble",
        "legacy extended UDP ping with opaque timestamp echo"
    ),
];

/// Validates descriptor bounds, stable ordering, provenance, and component IDs.
///
/// # Errors
///
/// Returns the first deterministic catalogue contract violation.
#[allow(
    clippy::too_many_lines,
    reason = "one ordered validation pass keeps descriptor invariants deterministic"
)]
pub fn validate_udp_probe_catalogue(
    descriptors: &[UdpProbeDescriptor],
) -> Result<(), UdpCatalogueError> {
    if descriptors.len() > MAX_UDP_CATALOGUE_VARIANTS {
        return Err(UdpCatalogueError::TooManyVariants);
    }
    let mut prior_id = None;
    for descriptor in descriptors {
        if descriptor.name.is_empty() {
            return Err(UdpCatalogueError::EmptyName);
        }
        if let Some(prior) = prior_id {
            if descriptor.id == prior {
                return Err(UdpCatalogueError::DuplicateProbeId);
            }
            if descriptor.id < prior {
                return Err(UdpCatalogueError::NonDeterministicOrder);
            }
        }
        prior_id = Some(descriptor.id);
        if !REGISTERED_REQUEST_BUILDERS.contains(&descriptor.request_builder_id) {
            return Err(UdpCatalogueError::UnknownRequestBuilder);
        }
        if !REGISTERED_RESPONSE_PARSERS.contains(&descriptor.response_parser_id) {
            return Err(UdpCatalogueError::UnknownResponseParser);
        }
        if descriptor.minimum_intensity > 9 {
            return Err(UdpCatalogueError::UnsafeSafeProfile);
        }
        if descriptor.profile == UdpProbeProfile::Safe && !descriptor.risks.is_empty() {
            return Err(UdpCatalogueError::UnsafeSafeProfile);
        }
        if matches!(descriptor.source_port, UdpSourcePortConstraint::Fixed(0)) {
            return Err(UdpCatalogueError::InvalidSourcePort);
        }
        if matches!(descriptor.source_port, UdpSourcePortConstraint::Fixed(_))
            && !descriptor.risks.contains(UdpProbeRisk::FixedSourcePort)
        {
            return Err(UdpCatalogueError::InvalidSourcePort);
        }
        if descriptor.request_template_bytes > MAX_UDP_REQUEST_BYTES {
            return Err(UdpCatalogueError::OversizedRequestTemplate);
        }
        if descriptor.minimum_request_bytes == 0
            || descriptor.minimum_request_bytes > descriptor.request_template_bytes
        {
            return Err(UdpCatalogueError::InvalidRequestBounds);
        }
        if descriptor.maximum_response_bytes == 0 {
            return Err(UdpCatalogueError::UnboundedResponse);
        }
        if descriptor.maximum_response_bytes > MAX_UDP_RESPONSE_BYTES {
            return Err(UdpCatalogueError::OversizedResponse);
        }
        if descriptor.maximum_parser_bytes == 0
            || descriptor.maximum_parser_bytes > descriptor.maximum_response_bytes
        {
            return Err(UdpCatalogueError::InvalidParserBudget);
        }
        let expected_ratio = descriptor
            .maximum_response_bytes
            .div_ceil(descriptor.minimum_request_bytes);
        if usize::from(descriptor.maximum_amplification_ratio) < expected_ratio {
            return Err(UdpCatalogueError::InvalidAmplificationRatio);
        }
        let amplification_threshold = descriptor
            .minimum_request_bytes
            .saturating_mul(4)
            .max(1_024);
        if descriptor.maximum_response_bytes > amplification_threshold
            && !descriptor.risks.contains(UdpProbeRisk::HighAmplification)
        {
            return Err(UdpCatalogueError::MissingAmplificationRisk);
        }
        let is_stateful = descriptor.risks.contains(UdpProbeRisk::StatefulHandshake);
        if is_stateful != (descriptor.maximum_state_lifetime_ms != 0) {
            return Err(UdpCatalogueError::InvalidStateLifetime);
        }
        if descriptor.profile == UdpProbeProfile::Safe
            && descriptor.maximum_response_bytes > MAX_UDP_REQUEST_BYTES
        {
            return Err(UdpCatalogueError::UnsafeSafeProfile);
        }
        if descriptor.correlation.len() > MAX_UDP_CORRELATION_FIELDS {
            return Err(UdpCatalogueError::TooManyCorrelationFields);
        }
        let mut prior_correlation_end = 0_usize;
        for field in descriptor.correlation {
            let valid_length = match field.kind {
                UdpCorrelationFieldKind::TransactionU16 => field.length == 2,
                UdpCorrelationFieldKind::TransactionU32 => field.length == 4,
                UdpCorrelationFieldKind::TokenU64 => field.length == 8,
                UdpCorrelationFieldKind::ExactBytes => field.length > 0,
            };
            let start = usize::from(field.offset);
            let end = start + usize::from(field.length);
            if !valid_length
                || start < prior_correlation_end
                || end > descriptor.maximum_response_bytes
            {
                return Err(UdpCatalogueError::InvalidCorrelationField);
            }
            prior_correlation_end = end;
        }
        if descriptor.ports.is_empty() {
            return Err(UdpCatalogueError::InvalidPortRange);
        }
        let mut prior_end = None;
        for range in descriptor.ports {
            if range.start == 0 || range.start > range.end {
                return Err(UdpCatalogueError::InvalidPortRange);
            }
            if prior_end.is_some_and(|end| range.start <= end) {
                return Err(UdpCatalogueError::NonDeterministicPortOrder);
            }
            prior_end = Some(range.end);
        }
        let provenance = descriptor.provenance;
        if provenance.primary_source.is_empty()
            || provenance.source_url.is_empty()
            || provenance.specification.is_empty()
        {
            return Err(UdpCatalogueError::MissingProvenance);
        }
        if !provenance.source_url.starts_with("https://") {
            return Err(UdpCatalogueError::InsecureProvenance);
        }
        if [
            descriptor.name,
            provenance.primary_source,
            provenance.source_url,
            provenance.specification,
        ]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains("nmap"))
        {
            return Err(UdpCatalogueError::ExternalComparisonReference);
        }
    }
    Ok(())
}

/// Deterministic SHA-256 over the catalogue's canonical, byte-stable fields.
#[must_use]
pub fn udp_probe_catalogue_sha256(descriptors: &[UdpProbeDescriptor]) -> [u8; 32] {
    let mut hash = Sha256::new();
    put_bytes(&mut hash, UDP_PROBE_CATALOGUE_VERSION.as_bytes());
    put_u32(
        &mut hash,
        u32::try_from(descriptors.len()).unwrap_or(u32::MAX),
    );
    for item in descriptors {
        put_u16(&mut hash, item.id.get());
        put_u16(&mut hash, item.service_family.get());
        put_bytes(&mut hash, item.name.as_bytes());
        hash.update([
            item.profile as u8,
            item.minimum_intensity,
            item.risks.bits(),
            item.address_families as u8,
        ]);
        hash.update([item.response_endpoint as u8]);
        match item.source_port {
            UdpSourcePortConstraint::Ephemeral => hash.update([0, 0, 0]),
            UdpSourcePortConstraint::Fixed(port) => {
                hash.update([1]);
                put_u16(&mut hash, port);
            }
        }
        put_u16(&mut hash, item.request_builder_id);
        put_u16(&mut hash, item.response_parser_id);
        put_u32(
            &mut hash,
            u32::try_from(item.minimum_request_bytes).unwrap_or(u32::MAX),
        );
        put_u32(
            &mut hash,
            u32::try_from(item.request_template_bytes).unwrap_or(u32::MAX),
        );
        put_u32(
            &mut hash,
            u32::try_from(item.maximum_response_bytes).unwrap_or(u32::MAX),
        );
        put_u32(
            &mut hash,
            u32::try_from(item.maximum_parser_bytes).unwrap_or(u32::MAX),
        );
        put_u16(&mut hash, item.maximum_amplification_ratio);
        put_u32(&mut hash, item.maximum_state_lifetime_ms);
        put_u32(
            &mut hash,
            u32::try_from(item.ports.len()).unwrap_or(u32::MAX),
        );
        for range in item.ports {
            put_u16(&mut hash, range.start);
            put_u16(&mut hash, range.end);
        }
        put_u32(
            &mut hash,
            u32::try_from(item.correlation.len()).unwrap_or(u32::MAX),
        );
        for field in item.correlation {
            put_u16(&mut hash, field.offset);
            put_u16(&mut hash, field.length);
            hash.update([field.kind as u8]);
        }
        put_bytes(&mut hash, item.provenance.primary_source.as_bytes());
        put_bytes(&mut hash, item.provenance.source_url.as_bytes());
        put_bytes(&mut hash, item.provenance.specification.as_bytes());
    }
    hash.finalize().into()
}

#[must_use]
pub fn udp_probe_catalogue_sha256_hex(descriptors: &[UdpProbeDescriptor]) -> String {
    let digest = udp_probe_catalogue_sha256(descriptors);
    let mut value = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn put_u16(hash: &mut Sha256, value: u16) {
    hash.update(value.to_le_bytes());
}
fn put_u32(hash: &mut Sha256, value: u32) {
    hash.update(value.to_le_bytes());
}
fn put_bytes(hash: &mut Sha256, value: &[u8]) {
    put_u32(hash, u32::try_from(value.len()).unwrap_or(u32::MAX));
    hash.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORTS: &[UdpPortRange] = &[UdpPortRange { start: 53, end: 53 }];
    const CORRELATION: &[UdpCorrelationField] = &[UdpCorrelationField {
        offset: 0,
        length: 2,
        kind: UdpCorrelationFieldKind::TransactionU16,
    }];

    fn descriptor(id: u16) -> UdpProbeDescriptor {
        UdpProbeDescriptor {
            id: UdpProbeId::new(id).unwrap(),
            service_family: UdpServiceFamilyId::new(1).unwrap(),
            name: "example",
            profile: UdpProbeProfile::Safe,
            minimum_intensity: 7,
            risks: UdpProbeRiskSet::default(),
            address_families: UdpAddressFamilies::Both,
            ports: PORTS,
            response_endpoint: UdpResponseEndpointPolicy::RequestTupleOnly,
            source_port: UdpSourcePortConstraint::Ephemeral,
            request_builder_id: 1,
            response_parser_id: 1,
            minimum_request_bytes: 12,
            request_template_bytes: 12,
            maximum_response_bytes: 512,
            maximum_parser_bytes: 512,
            maximum_amplification_ratio: 43,
            maximum_state_lifetime_ms: 0,
            correlation: CORRELATION,
            provenance: UdpProbeProvenance {
                primary_source: "RFC Editor",
                source_url: "https://www.rfc-editor.org/",
                specification: "RFC example",
            },
        }
    }

    #[test]
    fn production_catalogue_is_valid_and_hash_is_stable() {
        validate_udp_probe_catalogue(UDP_PROBE_CATALOGUE).unwrap();
        let first = udp_probe_catalogue_sha256_hex(UDP_PROBE_CATALOGUE);
        assert_eq!(first, UDP_PROBE_CATALOGUE_SHA256_HEX);
        assert_eq!(first, udp_probe_catalogue_sha256_hex(UDP_PROBE_CATALOGUE));
        assert_eq!(first.len(), 64);
        assert!(UDP_PROBE_CATALOGUE.iter().all(|descriptor| {
            descriptor.provenance.source_url.starts_with("https://")
                && ![
                    descriptor.name,
                    descriptor.provenance.primary_source,
                    descriptor.provenance.source_url,
                    descriptor.provenance.specification,
                ]
                .iter()
                .any(|value| value.to_ascii_lowercase().contains("nmap"))
        }));
    }

    #[test]
    fn malformed_and_non_deterministic_descriptors_are_rejected() {
        let duplicate = [descriptor(1), descriptor(1)];
        assert_eq!(
            validate_udp_probe_catalogue(&duplicate),
            Err(UdpCatalogueError::DuplicateProbeId)
        );
        let reversed = [descriptor(2), descriptor(1)];
        assert_eq!(
            validate_udp_probe_catalogue(&reversed),
            Err(UdpCatalogueError::NonDeterministicOrder)
        );
        let mut unsafe_safe = descriptor(1);
        unsafe_safe.risks = UdpProbeRiskSet::from_bits(1).unwrap();
        assert_eq!(
            validate_udp_probe_catalogue(&[unsafe_safe]),
            Err(UdpCatalogueError::UnsafeSafeProfile)
        );
        let mut oversized = descriptor(1);
        oversized.request_template_bytes = MAX_UDP_REQUEST_BYTES + 1;
        assert_eq!(
            validate_udp_probe_catalogue(&[oversized]),
            Err(UdpCatalogueError::OversizedRequestTemplate)
        );
        let mut unknown_builder = descriptor(1);
        unknown_builder.request_builder_id = 38;
        assert_eq!(
            validate_udp_probe_catalogue(&[unknown_builder]),
            Err(UdpCatalogueError::UnknownRequestBuilder)
        );
        let mut unknown_parser = descriptor(1);
        unknown_parser.response_parser_id = 38;
        assert_eq!(
            validate_udp_probe_catalogue(&[unknown_parser]),
            Err(UdpCatalogueError::UnknownResponseParser)
        );
        let mut invalid_source = descriptor(1);
        invalid_source.source_port = UdpSourcePortConstraint::Fixed(0);
        assert_eq!(
            validate_udp_probe_catalogue(&[invalid_source]),
            Err(UdpCatalogueError::InvalidSourcePort)
        );
        let mut missing_provenance = descriptor(1);
        missing_provenance.provenance.primary_source = "";
        assert_eq!(
            validate_udp_probe_catalogue(&[missing_provenance]),
            Err(UdpCatalogueError::MissingProvenance)
        );
        let mut insecure_provenance = descriptor(1);
        insecure_provenance.provenance.source_url = "http://example.invalid/";
        assert_eq!(
            validate_udp_probe_catalogue(&[insecure_provenance]),
            Err(UdpCatalogueError::InsecureProvenance)
        );
        let mut external_comparison = descriptor(1);
        external_comparison.provenance.specification = "Nmap-derived fixture";
        assert_eq!(
            validate_udp_probe_catalogue(&[external_comparison]),
            Err(UdpCatalogueError::ExternalComparisonReference)
        );
        let mut oversized_response = descriptor(1);
        oversized_response.maximum_response_bytes = MAX_UDP_RESPONSE_BYTES + 1;
        assert_eq!(
            validate_udp_probe_catalogue(&[oversized_response]),
            Err(UdpCatalogueError::OversizedResponse)
        );
        let mut parser_overrun = descriptor(1);
        parser_overrun.maximum_parser_bytes = 513;
        assert_eq!(
            validate_udp_probe_catalogue(&[parser_overrun]),
            Err(UdpCatalogueError::InvalidParserBudget)
        );
        let mut understated_ratio = descriptor(1);
        understated_ratio.maximum_amplification_ratio = 1;
        assert_eq!(
            validate_udp_probe_catalogue(&[understated_ratio]),
            Err(UdpCatalogueError::InvalidAmplificationRatio)
        );
        let mut unclassified_amplification = descriptor(1);
        unclassified_amplification.minimum_request_bytes = 16;
        unclassified_amplification.request_template_bytes = 16;
        unclassified_amplification.maximum_response_bytes = 1_025;
        unclassified_amplification.maximum_parser_bytes = 1_025;
        unclassified_amplification.maximum_amplification_ratio = 65;
        assert_eq!(
            validate_udp_probe_catalogue(&[unclassified_amplification]),
            Err(UdpCatalogueError::MissingAmplificationRisk)
        );
        let mut state_without_lifetime = descriptor(1);
        state_without_lifetime.profile = UdpProbeProfile::Comprehensive;
        state_without_lifetime.risks =
            UdpProbeRiskSet::from_bits(1 << UdpProbeRisk::StatefulHandshake as u8).unwrap();
        assert_eq!(
            validate_udp_probe_catalogue(&[state_without_lifetime]),
            Err(UdpCatalogueError::InvalidStateLifetime)
        );
    }
}
