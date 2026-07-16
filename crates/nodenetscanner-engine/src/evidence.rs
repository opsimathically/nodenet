//! Additive, syscall-free evidence records and deterministic retention.

use std::collections::{BTreeMap, BTreeSet};

use nodenet_protocols::{DiscoveryEntityKind, DiscoveryEvidenceKind, EvidenceStrength, IpAddress};

use crate::{
    DiscoveryEntity, EvidenceKind, NetworkState, ProbeFamily, ProbeOutcome, ScanResult,
    TerminalReason,
};

pub const EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const MAX_EVIDENCE_RECORDS: usize = 8_192;
pub const MAX_EVIDENCE_FIELDS: usize = 128;
pub const MAX_EVIDENCE_RELATIONS: usize = 64;
pub const MAX_EVIDENCE_ITEM_BYTES: usize = 1_024;
pub const MAX_EVIDENCE_RECORD_BYTES: usize = 16 * 1_024;
pub const MAX_EVIDENCE_BATCH_BYTES: usize = 16 * 1_024 * 1_024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EvidenceSourceKind {
    ScanResult = 1,
    DiscoveryResult = 2,
    PassiveObservation = 3,
    PathObservation = 4,
    ServiceConversation = 5,
    LocalContext = 6,
    ImportedSensor = 7,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EvidenceEntityKind {
    DeviceCandidate = 1,
    Interface = 2,
    Address = 3,
    Name = 4,
    Service = 5,
    Router = 6,
    Prefix = 7,
    Path = 8,
    Hop = 9,
    Adjacency = 10,
    Classification = 11,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EvidenceRelationKind {
    HasAddress = 1,
    HasName = 2,
    OffersService = 3,
    AttachedToInterface = 4,
    RoutesPrefix = 5,
    NextHop = 6,
    AdvertisedBy = 7,
    DerivedFrom = 8,
    ClassifiedAs = 9,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EvidenceConfidence {
    Weak = 1,
    Structural = 2,
    TransactionCorrelated = 3,
    StrongCorrelated = 4,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EvidenceDisposition {
    Observed = 1,
    Inferred = 2,
    Expired = 3,
    Withdrawn = 4,
    Conflict = 5,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceOrigin {
    pub source: EvidenceSourceKind,
    pub source_schema: u16,
    pub run_id: Vec<u8>,
    pub record_id: u64,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceEntityKey {
    pub kind: EvidenceEntityKind,
    pub canonical: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceField {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceRelation {
    pub kind: EvidenceRelationKind,
    pub target: EvidenceEntityKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecordInput {
    pub origin: EvidenceOrigin,
    pub entity: EvidenceEntityKey,
    pub confidence: EvidenceConfidence,
    pub disposition: EvidenceDisposition,
    pub observed_at_nanos: u64,
    pub expires_at_nanos: Option<u64>,
    pub wall_time_millis: Option<i64>,
    pub fields: Vec<EvidenceField>,
    pub relations: Vec<EvidenceRelation>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceRecord {
    origin: EvidenceOrigin,
    entity: EvidenceEntityKey,
    confidence: EvidenceConfidence,
    disposition: EvidenceDisposition,
    observed_at_nanos: u64,
    expires_at_nanos: Option<u64>,
    wall_time_millis: Option<i64>,
    fields: Vec<EvidenceField>,
    relations: Vec<EvidenceRelation>,
    variable_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceValidationError {
    EmptyRunId,
    ZeroSourceSchema,
    EmptyCanonicalKey,
    TooManyFields,
    TooManyRelations,
    EmptyFieldKey,
    ItemTooLarge,
    RecordTooLarge,
    InvalidExpiry,
    ArithmeticOverflow,
}

impl std::fmt::Display for EvidenceValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid evidence record: {self:?}")
    }
}

impl std::error::Error for EvidenceValidationError {}

impl EvidenceRecord {
    /// Validates and canonicalizes one immutable evidence record.
    ///
    /// # Errors
    ///
    /// Rejects empty identities, malformed time ranges, and every byte/count ceiling.
    pub fn new(mut input: EvidenceRecordInput) -> Result<Self, EvidenceValidationError> {
        if input.origin.run_id.is_empty() {
            return Err(EvidenceValidationError::EmptyRunId);
        }
        if input.origin.source_schema == 0 {
            return Err(EvidenceValidationError::ZeroSourceSchema);
        }
        if input.entity.canonical.is_empty() {
            return Err(EvidenceValidationError::EmptyCanonicalKey);
        }
        if input.fields.len() > MAX_EVIDENCE_FIELDS {
            return Err(EvidenceValidationError::TooManyFields);
        }
        if input.relations.len() > MAX_EVIDENCE_RELATIONS {
            return Err(EvidenceValidationError::TooManyRelations);
        }
        if input.fields.iter().any(|field| field.key.is_empty()) {
            return Err(EvidenceValidationError::EmptyFieldKey);
        }
        if input
            .expires_at_nanos
            .is_some_and(|expires| expires < input.observed_at_nanos)
        {
            return Err(EvidenceValidationError::InvalidExpiry);
        }
        if item_too_large(&input.origin.run_id)
            || item_too_large(&input.entity.canonical)
            || input
                .fields
                .iter()
                .any(|field| item_too_large(&field.key) || item_too_large(&field.value))
            || input
                .relations
                .iter()
                .any(|relation| item_too_large(&relation.target.canonical))
        {
            return Err(EvidenceValidationError::ItemTooLarge);
        }
        input.fields.sort_unstable();
        input.fields.dedup();
        input.relations.sort_unstable();
        input.relations.dedup();
        let base_bytes = input
            .origin
            .run_id
            .len()
            .checked_add(input.entity.canonical.len())
            .ok_or(EvidenceValidationError::ArithmeticOverflow)?;
        let variable_bytes = input
            .fields
            .iter()
            .try_fold(base_bytes, |total, field| {
                total
                    .checked_add(field.key.len())?
                    .checked_add(field.value.len())
            })
            .and_then(|total| {
                input.relations.iter().try_fold(total, |sum, relation| {
                    sum.checked_add(relation.target.canonical.len())
                })
            })
            .ok_or(EvidenceValidationError::ArithmeticOverflow)?;
        if variable_bytes > MAX_EVIDENCE_RECORD_BYTES {
            return Err(EvidenceValidationError::RecordTooLarge);
        }
        Ok(Self {
            origin: input.origin,
            entity: input.entity,
            confidence: input.confidence,
            disposition: input.disposition,
            observed_at_nanos: input.observed_at_nanos,
            expires_at_nanos: input.expires_at_nanos,
            wall_time_millis: input.wall_time_millis,
            fields: input.fields,
            relations: input.relations,
            variable_bytes,
        })
    }

    #[must_use]
    pub const fn origin(&self) -> &EvidenceOrigin {
        &self.origin
    }

    #[must_use]
    pub const fn entity(&self) -> &EvidenceEntityKey {
        &self.entity
    }

    #[must_use]
    pub const fn confidence(&self) -> EvidenceConfidence {
        self.confidence
    }

    #[must_use]
    pub const fn disposition(&self) -> EvidenceDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn observed_at_nanos(&self) -> u64 {
        self.observed_at_nanos
    }

    #[must_use]
    pub const fn expires_at_nanos(&self) -> Option<u64> {
        self.expires_at_nanos
    }

    #[must_use]
    pub const fn wall_time_millis(&self) -> Option<i64> {
        self.wall_time_millis
    }

    #[must_use]
    pub fn fields(&self) -> &[EvidenceField] {
        &self.fields
    }

    #[must_use]
    pub fn relations(&self) -> &[EvidenceRelation] {
        &self.relations
    }

    #[must_use]
    pub const fn variable_bytes(&self) -> usize {
        self.variable_bytes
    }
}

const fn item_too_large(value: &[u8]) -> bool {
    value.len() > MAX_EVIDENCE_ITEM_BYTES
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvidenceLedgerCounters {
    pub accepted: u64,
    pub duplicates: u64,
    pub conflicts: u64,
    pub rejected_capacity: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRetainOutcome {
    Accepted,
    Duplicate,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceLedgerError {
    RecordCapacity,
    ByteCapacity,
    ArithmeticOverflow,
}

#[derive(Clone, Debug)]
pub struct EvidenceLedger {
    records: BTreeMap<EvidenceEntityKey, BTreeSet<EvidenceRecord>>,
    record_count: usize,
    variable_bytes: usize,
    maximum_records: usize,
    maximum_bytes: usize,
    counters: EvidenceLedgerCounters,
}

impl EvidenceLedger {
    /// Creates a bounded ledger without allocating record capacity eagerly.
    ///
    /// # Errors
    ///
    /// Rejects zero or above-contract capacities.
    pub fn new(maximum_records: usize, maximum_bytes: usize) -> Result<Self, EvidenceLedgerError> {
        if maximum_records == 0 || maximum_records > MAX_EVIDENCE_RECORDS {
            return Err(EvidenceLedgerError::RecordCapacity);
        }
        if maximum_bytes == 0 || maximum_bytes > MAX_EVIDENCE_BATCH_BYTES {
            return Err(EvidenceLedgerError::ByteCapacity);
        }
        Ok(Self {
            records: BTreeMap::new(),
            record_count: 0,
            variable_bytes: 0,
            maximum_records,
            maximum_bytes,
            counters: EvidenceLedgerCounters::default(),
        })
    }

    /// Retains one record or reports exact duplicate/conflict disposition.
    ///
    /// # Errors
    ///
    /// Rejects a record that would exceed lifetime row or byte capacity.
    pub fn retain(
        &mut self,
        record: EvidenceRecord,
    ) -> Result<EvidenceRetainOutcome, EvidenceLedgerError> {
        if self
            .records
            .get(record.entity())
            .is_some_and(|records| records.contains(&record))
        {
            self.counters.duplicates = self.counters.duplicates.saturating_add(1);
            return Ok(EvidenceRetainOutcome::Duplicate);
        }
        if self.record_count >= self.maximum_records {
            self.counters.rejected_capacity = self.counters.rejected_capacity.saturating_add(1);
            return Err(EvidenceLedgerError::RecordCapacity);
        }
        let next_bytes = self
            .variable_bytes
            .checked_add(record.variable_bytes())
            .ok_or(EvidenceLedgerError::ArithmeticOverflow)?;
        if next_bytes > self.maximum_bytes {
            self.counters.rejected_capacity = self.counters.rejected_capacity.saturating_add(1);
            return Err(EvidenceLedgerError::ByteCapacity);
        }
        let conflict = self.records.contains_key(record.entity());
        self.variable_bytes = next_bytes;
        self.record_count += 1;
        self.records
            .entry(record.entity().clone())
            .or_default()
            .insert(record);
        if conflict {
            self.counters.conflicts = self.counters.conflicts.saturating_add(1);
            Ok(EvidenceRetainOutcome::Conflict)
        } else {
            self.counters.accepted = self.counters.accepted.saturating_add(1);
            Ok(EvidenceRetainOutcome::Accepted)
        }
    }

    #[must_use]
    pub const fn counters(&self) -> EvidenceLedgerCounters {
        self.counters
    }

    #[must_use]
    pub const fn usage(&self) -> (usize, usize) {
        (self.record_count, self.variable_bytes)
    }

    #[must_use]
    pub fn finish(self) -> Vec<EvidenceRecord> {
        self.records
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect()
    }
}

/// Projects one retained scan result into an additive address observation.
///
/// # Errors
///
/// Returns evidence validation failures without changing the source result.
pub fn adapt_scan_result(
    run_id: &[u8],
    record_id: u64,
    result: &ScanResult,
) -> Result<EvidenceRecord, EvidenceValidationError> {
    let mut canonical = Vec::with_capacity(21);
    match result.probe.target.address {
        IpAddress::V4(address) => {
            canonical.push(4);
            canonical.extend_from_slice(&address.octets());
        }
        IpAddress::V6(address) => {
            canonical.push(6);
            canonical.extend_from_slice(&address.octets());
        }
    }
    canonical.extend_from_slice(
        &result
            .probe
            .target
            .scope
            .map_or(0, super::TargetScope::get)
            .to_be_bytes(),
    );
    let fields = vec![
        numeric_field(b"scan.probe", probe_family_code(result.probe.family)),
        numeric_field(b"scan.outcome", probe_outcome_code(result.outcome)),
        numeric_field(b"scan.reason", terminal_reason_code(result.terminal_reason)),
        numeric_field(
            b"scan.networkState",
            result.outcome.network_state().map_or(0, network_state_code),
        ),
        EvidenceField {
            key: b"scan.port".to_vec(),
            value: result
                .probe
                .port
                .map_or(0, nodenet_protocols::ProbePort::get)
                .to_be_bytes()
                .to_vec(),
        },
    ];
    EvidenceRecord::new(EvidenceRecordInput {
        origin: EvidenceOrigin {
            source: EvidenceSourceKind::ScanResult,
            source_schema: if result.udp.is_some() { 2 } else { 1 },
            run_id: run_id.to_vec(),
            record_id,
        },
        entity: EvidenceEntityKey {
            kind: EvidenceEntityKind::Address,
            canonical,
        },
        confidence: result
            .evidence_strength
            .map_or(EvidenceConfidence::Weak, evidence_confidence),
        disposition: EvidenceDisposition::Observed,
        observed_at_nanos: result.terminal_at.as_micros().saturating_mul(1_000),
        expires_at_nanos: None,
        wall_time_millis: None,
        fields,
        relations: Vec::new(),
    })
}

/// Projects one retained discovery entity into additive service/device/name evidence.
///
/// # Errors
///
/// Returns evidence validation failures without changing the source entity.
pub fn adapt_discovery_entity(
    run_id: &[u8],
    entity: &DiscoveryEntity,
) -> Result<EvidenceRecord, EvidenceValidationError> {
    let candidate = &entity.candidate;
    let mut fields = Vec::with_capacity(candidate.metadata.len() + 3);
    fields.push(numeric_field(
        b"discovery.operation",
        u64::from(candidate.operation.get()),
    ));
    fields.push(EvidenceField {
        key: b"discovery.responder".to_vec(),
        value: ip_bytes(candidate.responder),
    });
    fields.push(numeric_field(
        b"discovery.ambiguous",
        u64::from(entity.ambiguous),
    ));
    fields.extend(candidate.metadata.iter().map(|field| EvidenceField {
        key: field.key.clone(),
        value: field.value.clone(),
    }));
    EvidenceRecord::new(EvidenceRecordInput {
        origin: EvidenceOrigin {
            source: EvidenceSourceKind::DiscoveryResult,
            source_schema: crate::DISCOVERY_SCHEMA_VERSION,
            run_id: run_id.to_vec(),
            record_id: entity.entity_id,
        },
        entity: EvidenceEntityKey {
            kind: discovery_entity_kind(candidate.entity_kind),
            canonical: candidate.canonical_identity.clone(),
        },
        confidence: discovery_confidence(candidate.evidence),
        disposition: if entity.ambiguous {
            EvidenceDisposition::Conflict
        } else {
            EvidenceDisposition::Observed
        },
        observed_at_nanos: 0,
        expires_at_nanos: None,
        wall_time_millis: None,
        fields,
        relations: Vec::new(),
    })
}

fn numeric_field(key: &[u8], value: u64) -> EvidenceField {
    EvidenceField {
        key: key.to_vec(),
        value: value.to_be_bytes().to_vec(),
    }
}

fn ip_bytes(address: std::net::IpAddr) -> Vec<u8> {
    match address {
        std::net::IpAddr::V4(value) => {
            let mut bytes = vec![4];
            bytes.extend_from_slice(&value.octets());
            bytes
        }
        std::net::IpAddr::V6(value) => {
            let mut bytes = vec![6];
            bytes.extend_from_slice(&value.octets());
            bytes
        }
    }
}

const fn discovery_entity_kind(kind: DiscoveryEntityKind) -> EvidenceEntityKind {
    match kind {
        DiscoveryEntityKind::Name => EvidenceEntityKind::Name,
        DiscoveryEntityKind::Service
        | DiscoveryEntityKind::DatabaseInstance
        | DiscoveryEntityKind::AuthenticationService => EvidenceEntityKind::Service,
        DiscoveryEntityKind::Gateway => EvidenceEntityKind::Router,
        DiscoveryEntityKind::Device => EvidenceEntityKind::DeviceCandidate,
        DiscoveryEntityKind::Route => EvidenceEntityKind::Prefix,
    }
}

const fn discovery_confidence(kind: DiscoveryEvidenceKind) -> EvidenceConfidence {
    match kind {
        DiscoveryEvidenceKind::Parsed => EvidenceConfidence::Structural,
        DiscoveryEvidenceKind::QueryRelated => EvidenceConfidence::Weak,
        DiscoveryEvidenceKind::TransactionCorrelated => EvidenceConfidence::TransactionCorrelated,
    }
}

const fn evidence_confidence(strength: EvidenceStrength) -> EvidenceConfidence {
    match strength {
        EvidenceStrength::TupleCorrelatedUnauthenticated | EvidenceStrength::TruncatedQuote => {
            EvidenceConfidence::Weak
        }
        EvidenceStrength::ProtocolTransaction16
        | EvidenceStrength::ProtocolTransaction32
        | EvidenceStrength::ProtocolTransaction64
        | EvidenceStrength::AlternateEndpointHandshake => EvidenceConfidence::TransactionCorrelated,
        EvidenceStrength::StrongTcpSequence32 | EvidenceStrength::StrongPayload128 => {
            EvidenceConfidence::StrongCorrelated
        }
    }
}

const fn probe_family_code(value: ProbeFamily) -> u64 {
    match value {
        ProbeFamily::Arp => 1,
        ProbeFamily::Ndp => 2,
        ProbeFamily::Icmpv4Echo => 3,
        ProbeFamily::Icmpv6Echo => 4,
        ProbeFamily::TcpSyn => 5,
        ProbeFamily::Udp => 6,
    }
}

const fn network_state_code(value: NetworkState) -> u64 {
    match value {
        NetworkState::Open => 1,
        NetworkState::Closed => 2,
        NetworkState::Filtered => 3,
        NetworkState::OpenOrFiltered => 4,
        NetworkState::Up => 5,
        NetworkState::Unreachable => 6,
        NetworkState::Unknown => 7,
        NetworkState::DownByPolicy => 8,
    }
}

const fn probe_outcome_code(value: ProbeOutcome) -> u64 {
    match value {
        ProbeOutcome::Network(_) => 1,
        ProbeOutcome::Cancelled => 2,
        ProbeOutcome::SessionDeadline => 3,
        ProbeOutcome::TransportFailed => 4,
        ProbeOutcome::ContextInvalidated => 5,
    }
}

const fn terminal_reason_code(value: TerminalReason) -> u64 {
    match value {
        TerminalReason::Evidence(kind) => 100 + evidence_kind_code(kind),
        TerminalReason::Timeout => 1,
        TerminalReason::Cancelled => 2,
        TerminalReason::SessionDeadline => 3,
        TerminalReason::TransportFailure(_) => 4,
        TerminalReason::ContextInvalidated => 5,
    }
}

const fn evidence_kind_code(value: EvidenceKind) -> u64 {
    match value {
        EvidenceKind::TcpSynAcknowledgment => 1,
        EvidenceKind::TcpReset => 2,
        EvidenceKind::EchoReply => 3,
        EvidenceKind::UdpReply => 4,
        EvidenceKind::UdpServiceHint => 5,
        EvidenceKind::IcmpPortUnreachable => 6,
        EvidenceKind::IcmpOtherError => 7,
        EvidenceKind::ExplicitUnreachable => 8,
        EvidenceKind::ArpReply => 9,
        EvidenceKind::NeighborAdvertisement => 10,
        EvidenceKind::NeighborResolved => 11,
    }
}

trait ProbeOutcomeExt {
    fn network_state(self) -> Option<NetworkState>;
}

impl ProbeOutcomeExt for ProbeOutcome {
    fn network_state(self) -> Option<NetworkState> {
        match self {
            Self::Network(state) => Some(state),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LogicalProbe, LogicalProbeId, MonotonicTime, ScanTarget, TargetScope};
    use nodenet_protocols::{Ipv4Address, ProbePort};

    fn record(key: &[u8], value: &[u8], record_id: u64) -> EvidenceRecord {
        EvidenceRecord::new(EvidenceRecordInput {
            origin: EvidenceOrigin {
                source: EvidenceSourceKind::PassiveObservation,
                source_schema: 1,
                run_id: b"run-a".to_vec(),
                record_id,
            },
            entity: EvidenceEntityKey {
                kind: EvidenceEntityKind::DeviceCandidate,
                canonical: key.to_vec(),
            },
            confidence: EvidenceConfidence::Structural,
            disposition: EvidenceDisposition::Observed,
            observed_at_nanos: 10,
            expires_at_nanos: Some(20),
            wall_time_millis: None,
            fields: vec![EvidenceField {
                key: b"name".to_vec(),
                value: value.to_vec(),
            }],
            relations: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn ledger_is_deterministic_and_retains_conflicts() {
        let first = record(b"device", b"alpha", 1);
        let second = record(b"device", b"beta", 2);
        let mut left = EvidenceLedger::new(8, 4_096).unwrap();
        let mut right = EvidenceLedger::new(8, 4_096).unwrap();
        assert_eq!(
            left.retain(first.clone()).unwrap(),
            EvidenceRetainOutcome::Accepted
        );
        assert_eq!(
            left.retain(second.clone()).unwrap(),
            EvidenceRetainOutcome::Conflict
        );
        assert_eq!(
            left.retain(first.clone()).unwrap(),
            EvidenceRetainOutcome::Duplicate
        );
        right.retain(second).unwrap();
        right.retain(first).unwrap();
        assert_eq!(left.finish(), right.finish());
    }

    #[test]
    fn validation_rejects_time_and_byte_boundaries() {
        let mut invalid = record(b"device", b"alpha", 1);
        invalid.expires_at_nanos = Some(9);
        assert_eq!(
            EvidenceRecord::new(EvidenceRecordInput {
                origin: invalid.origin,
                entity: invalid.entity,
                confidence: invalid.confidence,
                disposition: invalid.disposition,
                observed_at_nanos: invalid.observed_at_nanos,
                expires_at_nanos: invalid.expires_at_nanos,
                wall_time_millis: invalid.wall_time_millis,
                fields: invalid.fields,
                relations: invalid.relations,
            }),
            Err(EvidenceValidationError::InvalidExpiry)
        );
        let oversized = vec![0; MAX_EVIDENCE_ITEM_BYTES + 1];
        assert_eq!(
            EvidenceRecord::new(EvidenceRecordInput {
                origin: EvidenceOrigin {
                    source: EvidenceSourceKind::ScanResult,
                    source_schema: 1,
                    run_id: oversized,
                    record_id: 1,
                },
                entity: EvidenceEntityKey {
                    kind: EvidenceEntityKind::Address,
                    canonical: vec![1],
                },
                confidence: EvidenceConfidence::Weak,
                disposition: EvidenceDisposition::Observed,
                observed_at_nanos: 0,
                expires_at_nanos: None,
                wall_time_millis: None,
                fields: Vec::new(),
                relations: Vec::new(),
            }),
            Err(EvidenceValidationError::ItemTooLarge)
        );
    }

    #[test]
    fn scan_adapter_preserves_source_schema_and_strength() {
        let scan = ScanResult {
            probe: LogicalProbe {
                logical_id: LogicalProbeId::new(7).get(),
                attempt: 0,
                target: ScanTarget {
                    address: IpAddress::V4(Ipv4Address::new([192, 0, 2, 1])),
                    scope: TargetScope::new(2).ok(),
                },
                family: ProbeFamily::TcpSyn,
                port: ProbePort::new(443).ok(),
            },
            outcome: ProbeOutcome::Network(NetworkState::Open),
            evidence_strength: Some(EvidenceStrength::StrongTcpSequence32),
            attempt: 0,
            transmissions: 1,
            rtt: None,
            terminal_at: MonotonicTime::from_micros(12),
            route_generation: 1,
            terminal_reason: TerminalReason::Evidence(EvidenceKind::TcpSynAcknowledgment),
            udp: None,
        };
        let evidence = adapt_scan_result(b"scan-1", 7, &scan).unwrap();
        assert_eq!(evidence.origin().source_schema, 1);
        assert_eq!(evidence.confidence(), EvidenceConfidence::StrongCorrelated);
        assert_eq!(evidence.observed_at_nanos(), 12_000);
    }
}
