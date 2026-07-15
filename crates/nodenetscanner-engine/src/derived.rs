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
}
