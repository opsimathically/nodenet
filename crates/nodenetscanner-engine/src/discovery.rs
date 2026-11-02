//! Syscall-free discovery planning, fan-out reservations, and aggregation.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use nodenet_protocols::{
    DISCOVERY_OPERATION_REGISTRY, DiscoveryEntityKind, DiscoveryEvidenceKind,
    DiscoveryOperationDescriptor, DiscoveryOperationId, DiscoveryScopeKind, UdpProbeRiskSet,
};

pub const DISCOVERY_SCHEMA_VERSION: u16 = 1;
pub const MAX_DISCOVERY_INTERFACES: usize = 16;
pub const MAX_DISCOVERY_SCOPE_MEMBERS: usize = 65_536;
pub const MAX_DISCOVERY_OPERATIONS_PER_PLAN: usize = 8;
pub const MAX_DISCOVERY_PHYSICAL_QUERIES: usize = 65_536;
pub const MAX_DISCOVERY_RESULTS: usize = 8_192;
pub const MAX_DISCOVERY_METADATA_BYTES: usize = 16 * 1_024 * 1_024;
pub const MAX_DISCOVERY_ENTITY_ADDRESSES: usize = 32;
pub const MAX_DISCOVERY_ENTITY_METADATA_FIELDS: usize = 128;
pub const MAX_DISCOVERY_METADATA_VALUE_BYTES: usize = 1_024;
pub const MAX_DISCOVERY_ENTITY_METADATA_BYTES: usize = 16 * 1_024;
pub const MAX_DISCOVERY_DEADLINE: Duration = Duration::from_mins(1);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DiscoveryAddressFamily {
    Ipv4 = 4,
    Ipv6 = 6,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiscoveryScopeMember {
    Link {
        interface_index: u32,
        family: DiscoveryAddressFamily,
    },
    Target {
        address: IpAddr,
        interface_index: Option<u32>,
    },
    KernelDefaultIpv4Gateway,
}

impl DiscoveryScopeMember {
    fn kind(&self) -> DiscoveryScopeKind {
        match self {
            Self::Link { .. } => DiscoveryScopeKind::Links,
            Self::Target { .. } | Self::KernelDefaultIpv4Gateway => DiscoveryScopeKind::Targets,
        }
    }

    fn supports(&self, descriptor: &DiscoveryOperationDescriptor) -> bool {
        let family_supported = match self {
            Self::Link { family, .. } => match family {
                DiscoveryAddressFamily::Ipv4 => matches!(
                    descriptor.families,
                    nodenet_protocols::UdpAddressFamilies::Ipv4
                        | nodenet_protocols::UdpAddressFamilies::Both
                ),
                DiscoveryAddressFamily::Ipv6 => matches!(
                    descriptor.families,
                    nodenet_protocols::UdpAddressFamilies::Ipv6
                        | nodenet_protocols::UdpAddressFamilies::Both
                ),
            },
            Self::Target { address, .. } => match address {
                IpAddr::V4(_) => matches!(
                    descriptor.families,
                    nodenet_protocols::UdpAddressFamilies::Ipv4
                        | nodenet_protocols::UdpAddressFamilies::Both
                ),
                IpAddr::V6(_) => matches!(
                    descriptor.families,
                    nodenet_protocols::UdpAddressFamilies::Ipv6
                        | nodenet_protocols::UdpAddressFamilies::Both
                ),
            },
            Self::KernelDefaultIpv4Gateway => matches!(
                descriptor.families,
                nodenet_protocols::UdpAddressFamilies::Ipv4
                    | nodenet_protocols::UdpAddressFamilies::Both
            ),
        };
        self.kind() == descriptor.scope
            && family_supported
            && (!matches!(self, Self::KernelDefaultIpv4Gateway)
                || descriptor.permits_kernel_default_ipv4_gateway)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryLimits {
    pub max_results: usize,
    pub max_metadata_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryPlan {
    operations: Vec<DiscoveryOperationId>,
    scope_members: Vec<DiscoveryScopeMember>,
    deadline: Duration,
    limits: DiscoveryLimits,
    allow_risks: UdpProbeRiskSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryPlanError {
    EmptyOperations,
    EmptyScope,
    TooManyOperations,
    TooManyScopeMembers,
    DuplicateOperation,
    DuplicateScopeMember,
    UnknownOperation,
    UnsupportedScope,
    MissingRiskConsent,
    InvalidDeadline,
    InvalidResultLimit,
    InvalidMetadataLimit,
    ProductOverflow,
    TooManyQueries,
}

impl std::fmt::Display for DiscoveryPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid discovery plan: {self:?}")
    }
}

impl std::error::Error for DiscoveryPlanError {}

impl DiscoveryPlan {
    /// Normalizes the complete initial product before any transport admission.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unsupported, over-budget, or unconsented plans.
    pub fn new(
        mut operations: Vec<DiscoveryOperationId>,
        mut scope_members: Vec<DiscoveryScopeMember>,
        deadline: Duration,
        limits: DiscoveryLimits,
        allow_risks: UdpProbeRiskSet,
    ) -> Result<Self, DiscoveryPlanError> {
        if operations.is_empty() {
            return Err(DiscoveryPlanError::EmptyOperations);
        }
        if scope_members.is_empty() {
            return Err(DiscoveryPlanError::EmptyScope);
        }
        if operations.len() > MAX_DISCOVERY_OPERATIONS_PER_PLAN {
            return Err(DiscoveryPlanError::TooManyOperations);
        }
        if scope_members.len() > MAX_DISCOVERY_SCOPE_MEMBERS {
            return Err(DiscoveryPlanError::TooManyScopeMembers);
        }
        operations.sort_unstable();
        if operations.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DiscoveryPlanError::DuplicateOperation);
        }
        scope_members.sort_unstable();
        if scope_members.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DiscoveryPlanError::DuplicateScopeMember);
        }
        if deadline.is_zero() || deadline > MAX_DISCOVERY_DEADLINE {
            return Err(DiscoveryPlanError::InvalidDeadline);
        }
        if limits.max_results == 0 || limits.max_results > MAX_DISCOVERY_RESULTS {
            return Err(DiscoveryPlanError::InvalidResultLimit);
        }
        if limits.max_metadata_bytes == 0
            || limits.max_metadata_bytes > MAX_DISCOVERY_METADATA_BYTES
        {
            return Err(DiscoveryPlanError::InvalidMetadataLimit);
        }
        let product = operations
            .len()
            .checked_mul(scope_members.len())
            .ok_or(DiscoveryPlanError::ProductOverflow)?;
        if product > MAX_DISCOVERY_PHYSICAL_QUERIES {
            return Err(DiscoveryPlanError::TooManyQueries);
        }
        for operation in &operations {
            let descriptor =
                discovery_operation(*operation).ok_or(DiscoveryPlanError::UnknownOperation)?;
            if descriptor.required_risks.bits() & !allow_risks.bits() != 0 {
                return Err(DiscoveryPlanError::MissingRiskConsent);
            }
            if scope_members
                .iter()
                .any(|member| !member.supports(descriptor))
            {
                return Err(DiscoveryPlanError::UnsupportedScope);
            }
        }
        Ok(Self {
            operations,
            scope_members,
            deadline,
            limits,
            allow_risks,
        })
    }

    #[must_use]
    pub fn operations(&self) -> &[DiscoveryOperationId] {
        &self.operations
    }

    #[must_use]
    pub fn scope_members(&self) -> &[DiscoveryScopeMember] {
        &self.scope_members
    }

    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    #[must_use]
    pub const fn limits(&self) -> DiscoveryLimits {
        self.limits
    }

    #[must_use]
    pub const fn allow_risks(&self) -> UdpProbeRiskSet {
        self.allow_risks
    }
}

fn discovery_operation(id: DiscoveryOperationId) -> Option<&'static DiscoveryOperationDescriptor> {
    DISCOVERY_OPERATION_REGISTRY
        .iter()
        .find(|entry| entry.id == id)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryQueryLease {
    rows: usize,
    metadata_bytes: usize,
    settled: bool,
}

impl DiscoveryQueryLease {
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    #[must_use]
    pub const fn metadata_bytes(&self) -> usize {
        self.metadata_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryBudget {
    maximum_rows: usize,
    maximum_metadata_bytes: usize,
    leased_rows: usize,
    leased_metadata_bytes: usize,
    committed_rows: usize,
    committed_metadata_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryBudgetError {
    InsufficientCapacity,
    InvalidSettlement,
    AlreadySettled,
    ArithmeticOverflow,
}

impl DiscoveryBudget {
    #[must_use]
    pub const fn new(limits: DiscoveryLimits) -> Self {
        Self {
            maximum_rows: limits.max_results,
            maximum_metadata_bytes: limits.max_metadata_bytes,
            leased_rows: 0,
            leased_metadata_bytes: 0,
            committed_rows: 0,
            committed_metadata_bytes: 0,
        }
    }

    /// Reserves one query's declared worst-case row and metadata capacity.
    ///
    /// # Errors
    ///
    /// Rejects insufficient capacity and checked arithmetic overflow.
    pub fn try_lease(
        &mut self,
        rows: usize,
        metadata_bytes: usize,
    ) -> Result<DiscoveryQueryLease, DiscoveryBudgetError> {
        let rows_in_use = self
            .leased_rows
            .checked_add(self.committed_rows)
            .and_then(|value| value.checked_add(rows))
            .ok_or(DiscoveryBudgetError::ArithmeticOverflow)?;
        let bytes_in_use = self
            .leased_metadata_bytes
            .checked_add(self.committed_metadata_bytes)
            .and_then(|value| value.checked_add(metadata_bytes))
            .ok_or(DiscoveryBudgetError::ArithmeticOverflow)?;
        if rows_in_use > self.maximum_rows || bytes_in_use > self.maximum_metadata_bytes {
            return Err(DiscoveryBudgetError::InsufficientCapacity);
        }
        self.leased_rows += rows;
        self.leased_metadata_bytes += metadata_bytes;
        Ok(DiscoveryQueryLease {
            rows,
            metadata_bytes,
            settled: false,
        })
    }

    /// Commits used capacity and releases the unused remainder exactly once.
    ///
    /// # Errors
    ///
    /// Rejects double or over-lease settlement and arithmetic invariant failure.
    pub fn settle(
        &mut self,
        lease: &mut DiscoveryQueryLease,
        committed_rows: usize,
        committed_metadata_bytes: usize,
    ) -> Result<(), DiscoveryBudgetError> {
        if lease.settled {
            return Err(DiscoveryBudgetError::AlreadySettled);
        }
        if committed_rows > lease.rows || committed_metadata_bytes > lease.metadata_bytes {
            return Err(DiscoveryBudgetError::InvalidSettlement);
        }
        self.leased_rows = self
            .leased_rows
            .checked_sub(lease.rows)
            .ok_or(DiscoveryBudgetError::InvalidSettlement)?;
        self.leased_metadata_bytes = self
            .leased_metadata_bytes
            .checked_sub(lease.metadata_bytes)
            .ok_or(DiscoveryBudgetError::InvalidSettlement)?;
        self.committed_rows = self
            .committed_rows
            .checked_add(committed_rows)
            .ok_or(DiscoveryBudgetError::ArithmeticOverflow)?;
        self.committed_metadata_bytes = self
            .committed_metadata_bytes
            .checked_add(committed_metadata_bytes)
            .ok_or(DiscoveryBudgetError::ArithmeticOverflow)?;
        lease.settled = true;
        Ok(())
    }

    #[must_use]
    pub const fn committed(&self) -> (usize, usize) {
        (self.committed_rows, self.committed_metadata_bytes)
    }

    #[must_use]
    pub const fn leased(&self) -> (usize, usize) {
        (self.leased_rows, self.leased_metadata_bytes)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiscoveryMetadataField {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryEntityCandidate {
    pub canonical_identity: Vec<u8>,
    pub parent_identity: Option<Vec<u8>>,
    pub operation: DiscoveryOperationId,
    pub entity_kind: DiscoveryEntityKind,
    pub evidence: DiscoveryEvidenceKind,
    pub responder: IpAddr,
    pub interface_index: Option<u32>,
    pub addresses: Vec<IpAddr>,
    pub metadata: Vec<DiscoveryMetadataField>,
    pub complete: bool,
}

impl DiscoveryEntityCandidate {
    fn metadata_bytes(&self) -> Option<usize> {
        self.metadata.iter().try_fold(0_usize, |total, field| {
            total
                .checked_add(field.key.len())?
                .checked_add(field.value.len())
        })
    }

    fn validate(&self) -> bool {
        !self.canonical_identity.is_empty()
            && self.canonical_identity.len() <= MAX_DISCOVERY_METADATA_VALUE_BYTES
            && self.addresses.len() <= MAX_DISCOVERY_ENTITY_ADDRESSES
            && self.metadata.len() <= MAX_DISCOVERY_ENTITY_METADATA_FIELDS
            && self.metadata.iter().all(|field| {
                !field.key.is_empty()
                    && field.key.len() <= MAX_DISCOVERY_METADATA_VALUE_BYTES
                    && field.value.len() <= MAX_DISCOVERY_METADATA_VALUE_BYTES
            })
            && self
                .metadata_bytes()
                .is_some_and(|bytes| bytes <= MAX_DISCOVERY_ENTITY_METADATA_BYTES)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryEntity {
    pub entity_id: u64,
    pub candidate: DiscoveryEntityCandidate,
    pub conflicts: Vec<DiscoveryEntityCandidate>,
    pub duplicate_observations: u64,
    pub ambiguous: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryAggregationCounters {
    pub accepted: u64,
    pub duplicates: u64,
    pub rejected: u64,
    pub conflicts: u64,
    pub truncated: u64,
}

#[derive(Clone, Debug)]
pub struct DiscoveryAggregator {
    entities: BTreeMap<Vec<u8>, Vec<DiscoveryEntityCandidate>>,
    counters: DiscoveryAggregationCounters,
    maximum_entities: usize,
}

impl DiscoveryAggregator {
    #[must_use]
    pub fn new(maximum_entities: usize) -> Self {
        Self {
            entities: BTreeMap::new(),
            counters: DiscoveryAggregationCounters::default(),
            maximum_entities,
        }
    }

    pub fn retain(&mut self, mut candidate: DiscoveryEntityCandidate) {
        if !candidate.validate() {
            self.counters.rejected += 1;
            return;
        }
        candidate.addresses.sort_unstable();
        candidate.addresses.dedup();
        candidate.metadata.sort_unstable();
        candidate.metadata.dedup();
        if let Some(conflicts) = self.entities.get_mut(&candidate.canonical_identity) {
            if conflicts.contains(&candidate) {
                self.counters.duplicates += 1;
                return;
            }
            if conflicts.len() >= MAX_DISCOVERY_ENTITY_METADATA_FIELDS {
                self.counters.truncated += 1;
                return;
            }
            conflicts.push(candidate);
            conflicts.sort_by(candidate_order);
            self.counters.conflicts += 1;
            return;
        }
        if self.entities.len() >= self.maximum_entities {
            self.counters.truncated += 1;
            return;
        }
        self.entities
            .insert(candidate.canonical_identity.clone(), vec![candidate]);
        self.counters.accepted += 1;
    }

    #[must_use]
    pub const fn counters(&self) -> DiscoveryAggregationCounters {
        self.counters
    }

    #[must_use]
    pub fn finish(self) -> Vec<DiscoveryEntity> {
        self.entities
            .into_iter()
            .enumerate()
            .map(|(index, (_, mut candidates))| {
                candidates.sort_by(candidate_order);
                let candidate = candidates.remove(0);
                let duplicate_observations = self.counters.duplicates;
                DiscoveryEntity {
                    entity_id: u64::try_from(index).unwrap_or(u64::MAX) + 1,
                    ambiguous: !candidates.is_empty(),
                    candidate,
                    conflicts: candidates,
                    duplicate_observations,
                }
            })
            .collect()
    }
}

fn candidate_order(
    left: &DiscoveryEntityCandidate,
    right: &DiscoveryEntityCandidate,
) -> std::cmp::Ordering {
    (
        left.operation,
        left.entity_kind as u8,
        left.evidence as u8,
        left.responder,
        &left.addresses,
        &left.metadata,
    )
        .cmp(&(
            right.operation,
            right.entity_kind as u8,
            right.evidence as u8,
            right.responder,
            &right.addresses,
            &right.metadata,
        ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryQuery {
    pub query_id: u64,
    pub operation: DiscoveryOperationId,
    pub scope_member: DiscoveryScopeMember,
}

/// Deterministic initial query programme. Adaptive protocol programmes append
/// checked queries through the same ceiling.
#[derive(Clone, Debug)]
pub struct DiscoveryProgramme {
    pending: VecDeque<DiscoveryQuery>,
    admitted: BTreeSet<u64>,
    next_query_id: u64,
}

impl DiscoveryProgramme {
    #[must_use]
    pub fn from_plan(plan: &DiscoveryPlan) -> Self {
        let mut pending = VecDeque::new();
        let mut next_query_id = 1_u64;
        for operation in plan.operations() {
            for scope_member in plan.scope_members() {
                pending.push_back(DiscoveryQuery {
                    query_id: next_query_id,
                    operation: *operation,
                    scope_member: scope_member.clone(),
                });
                next_query_id += 1;
            }
        }
        Self {
            pending,
            admitted: BTreeSet::new(),
            next_query_id,
        }
    }

    pub fn pop(&mut self) -> Option<DiscoveryQuery> {
        let query = self.pending.pop_front()?;
        self.admitted.insert(query.query_id);
        Some(query)
    }

    /// Appends one adaptive query under the lifetime physical-query ceiling.
    ///
    /// # Errors
    ///
    /// Rejects query identifier/product overflow and excessive physical work.
    pub fn append_adaptive(
        &mut self,
        operation: DiscoveryOperationId,
        scope_member: DiscoveryScopeMember,
    ) -> Result<u64, DiscoveryPlanError> {
        let total = self
            .pending
            .len()
            .checked_add(self.admitted.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(DiscoveryPlanError::ProductOverflow)?;
        if total > MAX_DISCOVERY_PHYSICAL_QUERIES {
            return Err(DiscoveryPlanError::TooManyQueries);
        }
        let query_id = self.next_query_id;
        self.next_query_id = self
            .next_query_id
            .checked_add(1)
            .ok_or(DiscoveryPlanError::ProductOverflow)?;
        self.pending.push_back(DiscoveryQuery {
            query_id,
            operation,
            scope_member,
        });
        Ok(query_id)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodenet_protocols::UdpProbeRisk;

    fn risks(values: &[UdpProbeRisk]) -> UdpProbeRiskSet {
        let mut bits = 0_u8;
        for value in values {
            bits |= 1 << *value as u8;
        }
        UdpProbeRiskSet::from_bits(bits).unwrap()
    }

    #[test]
    fn plan_normalizes_product_and_enforces_risk_and_scope() {
        let plan = DiscoveryPlan::new(
            vec![DiscoveryOperationId::new(1).unwrap()],
            vec![DiscoveryScopeMember::Link {
                interface_index: 2,
                family: DiscoveryAddressFamily::Ipv4,
            }],
            Duration::from_secs(3),
            DiscoveryLimits {
                max_results: 512,
                max_metadata_bytes: 2 * 1_024 * 1_024,
            },
            risks(&[
                UdpProbeRisk::MulticastOrBroadcast,
                UdpProbeRisk::SensitiveRead,
            ]),
        )
        .unwrap();
        let mut programme = DiscoveryProgramme::from_plan(&plan);
        assert_eq!(programme.pop().unwrap().query_id, 1);
        assert!(programme.is_empty());
    }

    #[test]
    fn lifetime_budget_does_not_replenish_committed_rows() {
        let mut budget = DiscoveryBudget::new(DiscoveryLimits {
            max_results: 4,
            max_metadata_bytes: 100,
        });
        let mut lease = budget.try_lease(4, 100).unwrap();
        budget.settle(&mut lease, 3, 80).unwrap();
        assert_eq!(budget.committed(), (3, 80));
        assert!(budget.try_lease(2, 1).is_err());
        let mut final_lease = budget.try_lease(1, 20).unwrap();
        budget.settle(&mut final_lease, 0, 0).unwrap();
        assert_eq!(budget.leased(), (0, 0));
    }

    #[test]
    fn aggregation_is_order_independent_and_retains_conflicts() {
        let candidate = |value: u8| DiscoveryEntityCandidate {
            canonical_identity: b"service".to_vec(),
            parent_identity: None,
            operation: DiscoveryOperationId::new(1).unwrap(),
            entity_kind: DiscoveryEntityKind::Service,
            evidence: DiscoveryEvidenceKind::QueryRelated,
            responder: "192.0.2.1".parse().unwrap(),
            interface_index: Some(2),
            addresses: vec!["192.0.2.1".parse().unwrap()],
            metadata: vec![DiscoveryMetadataField {
                key: b"value".to_vec(),
                value: vec![value],
            }],
            complete: true,
        };
        let mut first = DiscoveryAggregator::new(8);
        first.retain(candidate(2));
        first.retain(candidate(1));
        first.retain(candidate(1));
        let mut second = DiscoveryAggregator::new(8);
        second.retain(candidate(1));
        second.retain(candidate(2));
        assert_eq!(first.finish()[0].conflicts, second.finish()[0].conflicts);
    }
}
