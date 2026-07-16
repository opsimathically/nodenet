//! Bounded same-target derived-endpoint and alternate-port ownership.

use std::collections::BTreeSet;
use std::net::IpAddr;

pub const SCAN_RESULT_SCHEMA_VERSION_DERIVED: u16 = 3;
pub const MAX_DERIVATION_DEPTH: u8 = 2;
pub const MAX_DERIVED_PORTS_PER_PARENT: usize = 32;
pub const MAX_DERIVED_ENDPOINTS_PER_TARGET: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DerivationKind {
    RpcbindGetAddress = 1,
    AdvertisedTcpService = 2,
    SsdpLocation = 3,
    WsDiscoveryXaddr = 4,
    DnsService = 5,
    CoapResource = 6,
    UpnpDescription = 7,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DerivedOperation {
    NfsNull = 1,
    TcpServiceConversation = 2,
    HttpDescription = 3,
    DnsQuery = 4,
    CoapResourceDiscovery = 5,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuthorityRiskSet(u16);

impl AuthorityRiskSet {
    pub const PASSIVE_METADATA: Self = Self(1 << 0);
    pub const PROMISCUOUS_CAPTURE: Self = Self(1 << 1);
    pub const LINK_MULTICAST: Self = Self(1 << 2);
    pub const SERVER_FIRST: Self = Self(1 << 3);
    pub const CLIENT_NEGOTIATION: Self = Self(1 << 4);
    pub const STATEFUL_HANDSHAKE: Self = Self(1 << 5);
    pub const SENSITIVE_READ: Self = Self(1 << 6);
    pub const AUTHENTICATION_ATTEMPT: Self = Self(1 << 7);
    pub const TARGET_MUTATION: Self = Self(1 << 8);

    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedAuthorityRule {
    pub derivation: DerivationKind,
    pub operation: DerivedOperation,
    pub required_risks: AuthorityRiskSet,
    pub same_address_only: bool,
}

pub const DERIVED_AUTHORITY_REGISTRY: [DerivedAuthorityRule; 7] = [
    DerivedAuthorityRule {
        derivation: DerivationKind::RpcbindGetAddress,
        operation: DerivedOperation::NfsNull,
        required_risks: AuthorityRiskSet::SENSITIVE_READ,
        same_address_only: true,
    },
    DerivedAuthorityRule {
        derivation: DerivationKind::AdvertisedTcpService,
        operation: DerivedOperation::TcpServiceConversation,
        required_risks: AuthorityRiskSet::CLIENT_NEGOTIATION,
        same_address_only: true,
    },
    DerivedAuthorityRule {
        derivation: DerivationKind::SsdpLocation,
        operation: DerivedOperation::HttpDescription,
        required_risks: AuthorityRiskSet::SENSITIVE_READ,
        same_address_only: true,
    },
    DerivedAuthorityRule {
        derivation: DerivationKind::WsDiscoveryXaddr,
        operation: DerivedOperation::HttpDescription,
        required_risks: AuthorityRiskSet::SENSITIVE_READ,
        same_address_only: true,
    },
    DerivedAuthorityRule {
        derivation: DerivationKind::DnsService,
        operation: DerivedOperation::DnsQuery,
        required_risks: AuthorityRiskSet::SENSITIVE_READ,
        same_address_only: true,
    },
    DerivedAuthorityRule {
        derivation: DerivationKind::CoapResource,
        operation: DerivedOperation::CoapResourceDiscovery,
        required_risks: AuthorityRiskSet::SENSITIVE_READ,
        same_address_only: true,
    },
    DerivedAuthorityRule {
        derivation: DerivationKind::UpnpDescription,
        operation: DerivedOperation::HttpDescription,
        required_risks: AuthorityRiskSet::SENSITIVE_READ,
        same_address_only: true,
    },
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DerivedWorkRequest {
    pub source_address: IpAddr,
    pub destination_address: IpAddr,
    pub port: u16,
    pub parent_result_id: u64,
    pub derivation: DerivationKind,
    pub operation: DerivedOperation,
    pub depth: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivedAuthorityError {
    AddressOutsideOriginalScope,
    ExcludedAddress,
    CrossAddressNotAuthorized,
    InvalidPort,
    DepthExceeded,
    UnregisteredEdge,
    MissingRiskConsent,
    ForbiddenRisk,
    ParentFanOutExceeded,
    TargetFanOutExceeded,
    TotalFanOutExceeded,
    Duplicate,
}

#[derive(Clone, Debug)]
pub struct DerivedWorkAuthority {
    allowed_targets: BTreeSet<IpAddr>,
    excluded_targets: BTreeSet<IpAddr>,
    allow_risks: AuthorityRiskSet,
    admitted: BTreeSet<DerivedWorkRequest>,
    maximum_total: usize,
}

impl DerivedWorkAuthority {
    #[must_use]
    pub fn new(
        allowed_targets: impl IntoIterator<Item = IpAddr>,
        excluded_targets: impl IntoIterator<Item = IpAddr>,
        allow_risks: AuthorityRiskSet,
        maximum_total: usize,
    ) -> Self {
        Self {
            allowed_targets: allowed_targets.into_iter().collect(),
            excluded_targets: excluded_targets.into_iter().collect(),
            allow_risks,
            admitted: BTreeSet::new(),
            maximum_total: maximum_total.min(MAX_DERIVED_ENDPOINTS_PER_TARGET),
        }
    }

    /// Re-authorizes one evidence-derived child before any I/O.
    ///
    /// # Errors
    ///
    /// Rejects scope/exclusion escape, unregistered transitions, forbidden or
    /// missing risk consent, duplicates, and every graph ceiling.
    pub fn authorize(&mut self, request: DerivedWorkRequest) -> Result<(), DerivedAuthorityError> {
        if !self.allowed_targets.contains(&request.destination_address) {
            return Err(DerivedAuthorityError::AddressOutsideOriginalScope);
        }
        if self.excluded_targets.contains(&request.destination_address) {
            return Err(DerivedAuthorityError::ExcludedAddress);
        }
        if request.port == 0 {
            return Err(DerivedAuthorityError::InvalidPort);
        }
        if request.depth == 0 || request.depth > MAX_DERIVATION_DEPTH {
            return Err(DerivedAuthorityError::DepthExceeded);
        }
        let rule = DERIVED_AUTHORITY_REGISTRY
            .iter()
            .find(|rule| {
                rule.derivation == request.derivation && rule.operation == request.operation
            })
            .ok_or(DerivedAuthorityError::UnregisteredEdge)?;
        if rule.same_address_only && request.source_address != request.destination_address {
            return Err(DerivedAuthorityError::CrossAddressNotAuthorized);
        }
        let forbidden =
            AuthorityRiskSet::AUTHENTICATION_ATTEMPT.union(AuthorityRiskSet::TARGET_MUTATION);
        if rule.required_risks.bits() & forbidden.bits() != 0 {
            return Err(DerivedAuthorityError::ForbiddenRisk);
        }
        if !self.allow_risks.contains(rule.required_risks) {
            return Err(DerivedAuthorityError::MissingRiskConsent);
        }
        if self.admitted.contains(&request) {
            return Err(DerivedAuthorityError::Duplicate);
        }
        if self.admitted.len() >= self.maximum_total {
            return Err(DerivedAuthorityError::TotalFanOutExceeded);
        }
        if self
            .admitted
            .iter()
            .filter(|edge| edge.parent_result_id == request.parent_result_id)
            .count()
            >= MAX_DERIVED_PORTS_PER_PARENT
        {
            return Err(DerivedAuthorityError::ParentFanOutExceeded);
        }
        if self
            .admitted
            .iter()
            .filter(|edge| edge.destination_address == request.destination_address)
            .count()
            >= MAX_DERIVED_ENDPOINTS_PER_TARGET
        {
            return Err(DerivedAuthorityError::TargetFanOutExceeded);
        }
        self.admitted.insert(request);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.admitted.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DerivedEndpoint {
    pub target: IpAddr,
    pub port: u16,
    pub transport: u8,
    pub parent_result_id: u64,
    pub derivation: DerivationKind,
    pub depth: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivationError {
    AddressOutsideOriginalScope,
    InvalidPort,
    DepthExceeded,
    ParentFanOutExceeded,
    TargetFanOutExceeded,
    Duplicate,
}

/// Deterministic graph that only admits same-address endpoints already present
/// in the caller's immutable target allowlist.
#[derive(Clone, Debug)]
pub struct DerivationGraph {
    allowed_targets: BTreeSet<IpAddr>,
    excluded_targets: BTreeSet<IpAddr>,
    edges: BTreeSet<DerivedEndpoint>,
}

impl DerivationGraph {
    #[must_use]
    pub fn new(
        allowed_targets: impl IntoIterator<Item = IpAddr>,
        excluded_targets: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        Self {
            allowed_targets: allowed_targets.into_iter().collect(),
            excluded_targets: excluded_targets.into_iter().collect(),
            edges: BTreeSet::new(),
        }
    }

    /// Adds one checked, deduplicated same-target graph edge.
    ///
    /// # Errors
    ///
    /// Rejects scope escape, invalid ports, duplicate/cyclic work, and every graph ceiling.
    pub fn insert(&mut self, endpoint: DerivedEndpoint) -> Result<(), DerivationError> {
        if !self.allowed_targets.contains(&endpoint.target)
            || self.excluded_targets.contains(&endpoint.target)
        {
            return Err(DerivationError::AddressOutsideOriginalScope);
        }
        if endpoint.port == 0 {
            return Err(DerivationError::InvalidPort);
        }
        if endpoint.depth == 0 || endpoint.depth > MAX_DERIVATION_DEPTH {
            return Err(DerivationError::DepthExceeded);
        }
        if self.edges.contains(&endpoint) {
            return Err(DerivationError::Duplicate);
        }
        let parent_count = self
            .edges
            .iter()
            .filter(|edge| edge.parent_result_id == endpoint.parent_result_id)
            .count();
        if parent_count >= MAX_DERIVED_PORTS_PER_PARENT {
            return Err(DerivationError::ParentFanOutExceeded);
        }
        let target_count = self
            .edges
            .iter()
            .filter(|edge| edge.target == endpoint.target)
            .count();
        if target_count >= MAX_DERIVED_ENDPOINTS_PER_TARGET {
            return Err(DerivationError::TargetFanOutExceeded);
        }
        self.edges.insert(endpoint);
        Ok(())
    }

    pub fn edges(&self) -> impl Iterator<Item = &DerivedEndpoint> {
        self.edges.iter()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateEndpointState {
    AwaitingFirstResponse,
    Pinned(u16),
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateEndpointError {
    WrongTarget,
    WrongInterface,
    InvalidPort,
    CompetingPort,
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlternateEndpointCorrelation {
    target: IpAddr,
    interface_index: Option<u32>,
    state: AlternateEndpointState,
}

impl AlternateEndpointCorrelation {
    #[must_use]
    pub const fn new(target: IpAddr, interface_index: Option<u32>) -> Self {
        Self {
            target,
            interface_index,
            state: AlternateEndpointState::AwaitingFirstResponse,
        }
    }

    /// Pins only after the protocol-specific parser has established structure.
    ///
    /// # Errors
    ///
    /// Rejects wrong targets/interfaces, invalid ports, competing pins, and retired state.
    pub fn accept_structured(
        &mut self,
        source: IpAddr,
        port: u16,
        interface_index: Option<u32>,
    ) -> Result<(), AlternateEndpointError> {
        if source != self.target {
            return Err(AlternateEndpointError::WrongTarget);
        }
        if interface_index != self.interface_index {
            return Err(AlternateEndpointError::WrongInterface);
        }
        if port == 0 {
            return Err(AlternateEndpointError::InvalidPort);
        }
        match self.state {
            AlternateEndpointState::AwaitingFirstResponse => {
                self.state = AlternateEndpointState::Pinned(port);
                Ok(())
            }
            AlternateEndpointState::Pinned(pinned) if pinned == port => Ok(()),
            AlternateEndpointState::Pinned(_) => Err(AlternateEndpointError::CompetingPort),
            AlternateEndpointState::Retired => Err(AlternateEndpointError::Retired),
        }
    }

    pub fn retire(&mut self) {
        self.state = AlternateEndpointState::Retired;
    }

    #[must_use]
    pub const fn state(&self) -> AlternateEndpointState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_never_expands_address_scope_and_deduplicates() {
        let target: IpAddr = "192.0.2.1".parse().unwrap();
        let mut graph = DerivationGraph::new([target], []);
        let edge = DerivedEndpoint {
            target,
            port: 2_049,
            transport: 17,
            parent_result_id: 7,
            derivation: DerivationKind::RpcbindGetAddress,
            depth: 1,
        };
        graph.insert(edge.clone()).unwrap();
        assert_eq!(graph.insert(edge), Err(DerivationError::Duplicate));
        assert_eq!(graph.edges().count(), 1);
        let outside = DerivedEndpoint {
            target: "192.0.2.2".parse().unwrap(),
            port: 2_049,
            transport: 17,
            parent_result_id: 7,
            derivation: DerivationKind::RpcbindGetAddress,
            depth: 1,
        };
        assert_eq!(
            graph.insert(outside),
            Err(DerivationError::AddressOutsideOriginalScope)
        );
    }

    #[test]
    fn alternate_endpoint_pins_first_structured_same_target_tuple() {
        let target: IpAddr = "192.0.2.1".parse().unwrap();
        let mut correlation = AlternateEndpointCorrelation::new(target, Some(2));
        correlation
            .accept_structured(target, 40_000, Some(2))
            .unwrap();
        assert_eq!(
            correlation.accept_structured(target, 40_001, Some(2)),
            Err(AlternateEndpointError::CompetingPort)
        );
        correlation.retire();
        assert_eq!(
            correlation.accept_structured(target, 40_000, Some(2)),
            Err(AlternateEndpointError::Retired)
        );
    }

    #[test]
    fn generalized_authority_rechecks_scope_risk_and_registered_edges() {
        let target: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        let request = DerivedWorkRequest {
            source_address: target,
            destination_address: target,
            port: 443,
            parent_result_id: 9,
            derivation: DerivationKind::AdvertisedTcpService,
            operation: DerivedOperation::TcpServiceConversation,
            depth: 1,
        };
        let mut denied = DerivedWorkAuthority::new([target], [], AuthorityRiskSet::default(), 8);
        assert_eq!(
            denied.authorize(request.clone()),
            Err(DerivedAuthorityError::MissingRiskConsent)
        );
        let mut authority =
            DerivedWorkAuthority::new([target], [], AuthorityRiskSet::CLIENT_NEGOTIATION, 8);
        authority.authorize(request.clone()).unwrap();
        assert_eq!(
            authority.authorize(request.clone()),
            Err(DerivedAuthorityError::Duplicate)
        );
        let mut cross_address = request;
        cross_address.source_address = other;
        assert_eq!(
            authority.authorize(cross_address),
            Err(DerivedAuthorityError::CrossAddressNotAuthorized)
        );
        let outside = DerivedWorkRequest {
            source_address: other,
            destination_address: other,
            port: 443,
            parent_result_id: 10,
            derivation: DerivationKind::AdvertisedTcpService,
            operation: DerivedOperation::TcpServiceConversation,
            depth: 1,
        };
        assert_eq!(
            authority.authorize(outside),
            Err(DerivedAuthorityError::AddressOutsideOriginalScope)
        );
    }
}
