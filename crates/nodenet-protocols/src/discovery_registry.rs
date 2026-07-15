//! Stable, project-owned discovery operation registry.
//!
//! Discovery operations are intentionally distinct from destination-port UDP
//! probes: one query may create several bounded entity observations and may be
//! link-scoped rather than target-scoped.

use core::fmt;
use core::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::{UdpAddressFamilies, UdpProbeRisk, UdpProbeRiskSet, UdpSourcePortConstraint};

pub const DISCOVERY_OPERATION_REGISTRY_VERSION: &str = "1.0.0";
pub const MAX_DISCOVERY_OPERATIONS: usize = 64;
pub const MAX_DISCOVERY_REQUEST_BYTES: usize = 4_096;
pub const MAX_DISCOVERY_RESPONSE_BYTES: usize = 65_507;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiscoveryOperationId(u16);

impl DiscoveryOperationId {
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
pub enum DiscoveryScopeKind {
    Links,
    Targets,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DiscoveryTransportKind {
    UdpEphemeral,
    UdpFixed,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DiscoveryEvidenceKind {
    Parsed,
    QueryRelated,
    TransactionCorrelated,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DiscoveryEntityKind {
    Service,
    Device,
    Name,
    Gateway,
    DatabaseInstance,
    AuthenticationService,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DiscoveryOperationProvenance {
    pub primary_source: &'static str,
    pub source_url: &'static str,
    pub specification: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DiscoveryOperationDescriptor {
    pub id: DiscoveryOperationId,
    pub name: &'static str,
    pub scope: DiscoveryScopeKind,
    pub families: UdpAddressFamilies,
    pub transport: DiscoveryTransportKind,
    pub source_port: UdpSourcePortConstraint,
    pub destination_port: u16,
    pub ipv4_multicast: Option<[u8; 4]>,
    pub ipv6_multicast: Option<[u8; 16]>,
    pub required_risks: UdpProbeRiskSet,
    pub evidence: DiscoveryEvidenceKind,
    pub entity_kind: DiscoveryEntityKind,
    pub request_builder_id: u16,
    pub response_parser_id: u16,
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: usize,
    pub maximum_entities_per_query: u16,
    pub maximum_metadata_bytes_per_query: u32,
    pub response_window_ms: u32,
    pub permits_kernel_default_ipv4_gateway: bool,
    pub provenance: DiscoveryOperationProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryRegistryError {
    TooManyOperations,
    NonDeterministicOrder,
    DuplicateOperationId,
    EmptyName,
    InvalidScope,
    InvalidDestination,
    InvalidSourcePort,
    InvalidResourceBound,
    InvalidRisk,
    InsecurePrimarySource,
    ExternalComparisonReference,
}

impl fmt::Display for DiscoveryRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid discovery operation registry: {self:?}")
    }
}

impl std::error::Error for DiscoveryRegistryError {}

const MULTICAST_SENSITIVE: UdpProbeRiskSet = match UdpProbeRiskSet::from_bits(
    (1 << UdpProbeRisk::MulticastOrBroadcast as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
) {
    Some(value) => value,
    None => panic!("valid discovery risk set"),
};
const SENSITIVE: UdpProbeRiskSet =
    match UdpProbeRiskSet::from_bits(1 << UdpProbeRisk::SensitiveRead as u8) {
        Some(value) => value,
        None => panic!("valid discovery risk set"),
    };
const HIGH_AMPLIFICATION_SENSITIVE: UdpProbeRiskSet = match UdpProbeRiskSet::from_bits(
    (1 << UdpProbeRisk::HighAmplification as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
) {
    Some(value) => value,
    None => panic!("valid discovery risk set"),
};
const NO_RISKS: UdpProbeRiskSet = match UdpProbeRiskSet::from_bits(0) {
    Some(value) => value,
    None => panic!("valid empty discovery risk set"),
};
const STATEFUL_SENSITIVE: UdpProbeRiskSet = match UdpProbeRiskSet::from_bits(
    (1 << UdpProbeRisk::StatefulHandshake as u8) | (1 << UdpProbeRisk::SensitiveRead as u8),
) {
    Some(value) => value,
    None => panic!("valid discovery risk set"),
};

macro_rules! operation {
    (
        $id:literal, $name:literal, $scope:ident, $families:ident, $transport:ident,
        $source:expr, $port:literal, $v4:expr, $v6:expr, $risks:expr, $evidence:ident,
        $entity:ident, $max_request:literal, $max_response:literal, $max_entities:literal,
        $max_metadata:literal, $window:literal, $gateway:literal, $source_name:literal,
        $source_url:literal, $specification:literal
    ) => {
        DiscoveryOperationDescriptor {
            id: match DiscoveryOperationId::new($id) {
                Some(value) => value,
                None => panic!("nonzero discovery operation identifier"),
            },
            name: $name,
            scope: DiscoveryScopeKind::$scope,
            families: UdpAddressFamilies::$families,
            transport: DiscoveryTransportKind::$transport,
            source_port: $source,
            destination_port: $port,
            ipv4_multicast: $v4,
            ipv6_multicast: $v6,
            required_risks: $risks,
            evidence: DiscoveryEvidenceKind::$evidence,
            entity_kind: DiscoveryEntityKind::$entity,
            request_builder_id: $id,
            response_parser_id: $id,
            maximum_request_bytes: $max_request,
            maximum_response_bytes: $max_response,
            maximum_entities_per_query: $max_entities,
            maximum_metadata_bytes_per_query: $max_metadata,
            response_window_ms: $window,
            permits_kernel_default_ipv4_gateway: $gateway,
            provenance: DiscoveryOperationProvenance {
                primary_source: $source_name,
                source_url: $source_url,
                specification: $specification,
            },
        }
    };
}

/// Implemented discovery operations. IDs are append-only inside one major
/// registry version.
pub static DISCOVERY_OPERATION_REGISTRY: &[DiscoveryOperationDescriptor] = &[
    operation!(
        1,
        "mdns-dns-sd-legacy",
        Links,
        Both,
        UdpEphemeral,
        UdpSourcePortConstraint::Ephemeral,
        5353,
        Some([224, 0, 0, 251]),
        Some([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb]),
        MULTICAST_SENSITIVE,
        TransactionCorrelated,
        Service,
        512,
        9_000,
        512,
        1_048_576,
        3_000,
        false,
        "IETF",
        "https://www.rfc-editor.org/rfc/rfc6762",
        "RFC 6762 and RFC 6763"
    ),
    operation!(
        3,
        "ws-discovery-probe",
        Links,
        Both,
        UdpEphemeral,
        UdpSourcePortConstraint::Ephemeral,
        3702,
        Some([239, 255, 255, 250]),
        Some([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c]),
        MULTICAST_SENSITIVE,
        TransactionCorrelated,
        Device,
        2_048,
        4_096,
        512,
        1_048_576,
        5_000,
        false,
        "OASIS",
        "https://docs.oasis-open.org/ws-dd/discovery/1.1/wsdd-discovery-1.1-spec.html",
        "WS-Discovery 1.1"
    ),
    operation!(
        4,
        "llmnr-query",
        Links,
        Both,
        UdpEphemeral,
        UdpSourcePortConstraint::Ephemeral,
        5355,
        Some([224, 0, 0, 252]),
        Some([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3]),
        MULTICAST_SENSITIVE,
        TransactionCorrelated,
        Name,
        512,
        1_500,
        64,
        65_536,
        2_000,
        false,
        "IETF",
        "https://www.rfc-editor.org/rfc/rfc4795",
        "RFC 4795"
    ),
    operation!(
        5,
        "nat-pmp-external-address",
        Targets,
        Ipv4,
        UdpEphemeral,
        UdpSourcePortConstraint::Ephemeral,
        5351,
        None,
        None,
        SENSITIVE,
        Parsed,
        Gateway,
        2,
        12,
        1,
        1_024,
        2_000,
        true,
        "IETF",
        "https://www.rfc-editor.org/rfc/rfc6886",
        "RFC 6886"
    ),
    operation!(
        6,
        "sql-browser-enumeration",
        Targets,
        Ipv4,
        UdpEphemeral,
        UdpSourcePortConstraint::Ephemeral,
        1434,
        None,
        None,
        HIGH_AMPLIFICATION_SENSITIVE,
        Parsed,
        DatabaseInstance,
        1,
        65_507,
        129,
        1_048_576,
        3_000,
        false,
        "Microsoft",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/",
        "MC-SQLR"
    ),
    operation!(
        7,
        "rpcbind-getaddr",
        Targets,
        Both,
        UdpEphemeral,
        UdpSourcePortConstraint::Ephemeral,
        111,
        None,
        None,
        SENSITIVE,
        TransactionCorrelated,
        Service,
        256,
        4_096,
        32,
        65_536,
        3_000,
        false,
        "IETF",
        "https://www.rfc-editor.org/rfc/rfc1833",
        "RFC 1833 and RFC 5531"
    ),
    operation!(
        8,
        "tftp-sentinel-read",
        Targets,
        Both,
        UdpEphemeral,
        UdpSourcePortConstraint::Ephemeral,
        69,
        None,
        None,
        STATEFUL_SENSITIVE,
        QueryRelated,
        Service,
        512,
        4_096,
        1,
        4_096,
        3_000,
        false,
        "IETF",
        "https://www.rfc-editor.org/rfc/rfc1350",
        "RFC 1350, RFC 2347, RFC 2348, and RFC 2349"
    ),
    operation!(
        9,
        "quic-version-negotiation",
        Targets,
        Both,
        UdpEphemeral,
        UdpSourcePortConstraint::Ephemeral,
        443,
        None,
        None,
        NO_RISKS,
        TransactionCorrelated,
        Service,
        1_200,
        4_096,
        1,
        4_096,
        2_000,
        false,
        "IETF",
        "https://www.rfc-editor.org/rfc/rfc9000",
        "RFC 9000 and RFC 8999"
    ),
];

/// Validates ordering, IDs, destinations, resource bounds, risks, and
/// provenance without allocating from untrusted wire input.
///
/// # Errors
///
/// Returns the first deterministic registry invariant violation.
pub fn validate_discovery_operation_registry(
    operations: &[DiscoveryOperationDescriptor],
) -> Result<(), DiscoveryRegistryError> {
    if operations.len() > MAX_DISCOVERY_OPERATIONS {
        return Err(DiscoveryRegistryError::TooManyOperations);
    }
    for (index, operation) in operations.iter().enumerate() {
        if operation.name.is_empty() {
            return Err(DiscoveryRegistryError::EmptyName);
        }
        if index > 0 && operations[index - 1].id >= operation.id {
            return Err(if operations[index - 1].id == operation.id {
                DiscoveryRegistryError::DuplicateOperationId
            } else {
                DiscoveryRegistryError::NonDeterministicOrder
            });
        }
        if operation.destination_port == 0
            || (operation.scope == DiscoveryScopeKind::Links
                && operation.ipv4_multicast.is_none()
                && operation.ipv6_multicast.is_none())
            || (operation.scope == DiscoveryScopeKind::Targets
                && (operation.ipv4_multicast.is_some() || operation.ipv6_multicast.is_some()))
        {
            return Err(DiscoveryRegistryError::InvalidDestination);
        }
        if operation.transport == DiscoveryTransportKind::UdpFixed
            && !matches!(operation.source_port, UdpSourcePortConstraint::Fixed(_))
        {
            return Err(DiscoveryRegistryError::InvalidSourcePort);
        }
        if operation.maximum_request_bytes == 0
            || operation.maximum_request_bytes > MAX_DISCOVERY_REQUEST_BYTES
            || operation.maximum_response_bytes == 0
            || operation.maximum_response_bytes > MAX_DISCOVERY_RESPONSE_BYTES
            || operation.maximum_entities_per_query == 0
            || operation.maximum_metadata_bytes_per_query == 0
            || operation.response_window_ms == 0
            || operation.response_window_ms > 60_000
        {
            return Err(DiscoveryRegistryError::InvalidResourceBound);
        }
        if operation.scope == DiscoveryScopeKind::Links
            && !operation
                .required_risks
                .contains(UdpProbeRisk::MulticastOrBroadcast)
        {
            return Err(DiscoveryRegistryError::InvalidRisk);
        }
        if operation.permits_kernel_default_ipv4_gateway
            && (operation.scope != DiscoveryScopeKind::Targets
                || operation.families != UdpAddressFamilies::Ipv4)
        {
            return Err(DiscoveryRegistryError::InvalidScope);
        }
        if operation.provenance.primary_source.is_empty()
            || operation.provenance.specification.is_empty()
            || !operation.provenance.source_url.starts_with("https://")
        {
            return Err(DiscoveryRegistryError::InsecurePrimarySource);
        }
        if [
            operation.name,
            operation.provenance.primary_source,
            operation.provenance.source_url,
            operation.provenance.specification,
        ]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains("nmap"))
        {
            return Err(DiscoveryRegistryError::ExternalComparisonReference);
        }
    }
    Ok(())
}

#[must_use]
pub fn discovery_operation_registry_sha256(
    operations: &[DiscoveryOperationDescriptor],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DISCOVERY_OPERATION_REGISTRY_VERSION.as_bytes());
    hash.update([0]);
    for operation in operations {
        hash.update(operation.id.get().to_be_bytes());
        hash.update(operation.name.as_bytes());
        hash.update([0]);
        hash.update([operation.scope as u8]);
        hash.update([operation.families as u8]);
        hash.update([operation.transport as u8]);
        match operation.source_port {
            UdpSourcePortConstraint::Ephemeral => hash.update([0, 0, 0]),
            UdpSourcePortConstraint::Fixed(port) => {
                hash.update([1]);
                hash.update(port.to_be_bytes());
            }
        }
        hash.update(operation.destination_port.to_be_bytes());
        hash.update(operation.ipv4_multicast.unwrap_or_default());
        hash.update(operation.ipv6_multicast.unwrap_or_default());
        hash.update([operation.required_risks.bits()]);
        hash.update([operation.evidence as u8, operation.entity_kind as u8]);
        hash.update(operation.request_builder_id.to_be_bytes());
        hash.update(operation.response_parser_id.to_be_bytes());
        hash.update(operation.maximum_request_bytes.to_be_bytes());
        hash.update(operation.maximum_response_bytes.to_be_bytes());
        hash.update(operation.maximum_entities_per_query.to_be_bytes());
        hash.update(operation.maximum_metadata_bytes_per_query.to_be_bytes());
        hash.update(operation.response_window_ms.to_be_bytes());
        hash.update([u8::from(operation.permits_kernel_default_ipv4_gateway)]);
        hash.update(operation.provenance.primary_source.as_bytes());
        hash.update([0]);
        hash.update(operation.provenance.source_url.as_bytes());
        hash.update([0]);
        hash.update(operation.provenance.specification.as_bytes());
        hash.update([0]);
    }
    hash.finalize().into()
}

#[must_use]
pub fn discovery_operation_registry_sha256_hex(
    operations: &[DiscoveryOperationDescriptor],
) -> String {
    discovery_operation_registry_sha256(operations).iter().fold(
        String::with_capacity(64),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_registry_is_bounded_ordered_and_independently_sourced() {
        validate_discovery_operation_registry(DISCOVERY_OPERATION_REGISTRY).unwrap();
        assert_eq!(DISCOVERY_OPERATION_REGISTRY.len(), 8);
        assert_eq!(
            discovery_operation_registry_sha256_hex(DISCOVERY_OPERATION_REGISTRY).len(),
            64
        );
    }

    #[test]
    fn malformed_registries_fail_closed() {
        let duplicate = [
            DISCOVERY_OPERATION_REGISTRY[0],
            DISCOVERY_OPERATION_REGISTRY[0],
        ];
        assert_eq!(
            validate_discovery_operation_registry(&duplicate),
            Err(DiscoveryRegistryError::DuplicateOperationId)
        );
        let mut unsafe_link = DISCOVERY_OPERATION_REGISTRY[0];
        unsafe_link.required_risks = UdpProbeRiskSet::default();
        assert_eq!(
            validate_discovery_operation_registry(&[unsafe_link]),
            Err(DiscoveryRegistryError::InvalidRisk)
        );
    }
}
