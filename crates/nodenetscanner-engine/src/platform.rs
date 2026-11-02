//! Deterministic discovery-platform primitives shared by active and passive sessions.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::{
    AuthorityRiskSet, EvidenceEntityKey, EvidenceEntityKind, EvidenceRecord,
    MAX_EVIDENCE_BATCH_BYTES, MAX_EVIDENCE_RECORDS,
};

pub const PATH_SCHEMA_VERSION: u16 = 1;
pub const SERVICE_CONVERSATION_SCHEMA_VERSION: u16 = 1;
pub const ASSET_SCHEMA_VERSION: u16 = 1;
pub const INVENTORY_SCHEMA_VERSION: u16 = 1;
pub const SENSOR_ENVELOPE_VERSION: u16 = 1;
pub const MAX_PATH_HOPS: u8 = 64;
pub const MAX_PATH_ATTEMPTS_PER_HOP: u8 = 8;
pub const MAX_CONVERSATION_STEPS: usize = 32;
pub const MAX_CONVERSATION_BYTES: usize = 64 * 1024;
pub const MAX_ASSETS: usize = 8_192;
pub const MAX_SENSOR_ENVELOPE_RECORDS: usize = 8_192;
pub const MAX_SENSOR_STREAMS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PathMode {
    IcmpEcho,
    Udp,
    TcpSyn,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathPlan {
    pub target: IpAddr,
    pub mode: PathMode,
    pub port: Option<u16>,
    pub first_hop: u8,
    pub maximum_hop: u8,
    pub attempts_per_hop: u8,
    pub deadline_millis: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformValidationError {
    InvalidHopRange,
    InvalidAttempts,
    InvalidDeadline,
    MissingPort,
    UnexpectedPort,
    InvalidConversation,
    ConversationLimit,
    RiskConsent,
    InvalidUrl,
    AddressEscape,
    RedirectForbidden,
    Capacity,
    InvalidEnvelope,
    DuplicateEnvelope,
    SequenceGap,
}

impl std::fmt::Display for PlatformValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "discovery platform validation failed: {self:?}")
    }
}

impl std::error::Error for PlatformValidationError {}

impl PathPlan {
    /// Validates finite path work before any packet is emitted.
    ///
    /// # Errors
    ///
    /// Rejects invalid hop, attempt, deadline, and transport-port combinations.
    pub const fn validate(&self) -> Result<(), PlatformValidationError> {
        if self.first_hop == 0
            || self.maximum_hop < self.first_hop
            || self.maximum_hop > MAX_PATH_HOPS
        {
            return Err(PlatformValidationError::InvalidHopRange);
        }
        if self.attempts_per_hop == 0 || self.attempts_per_hop > MAX_PATH_ATTEMPTS_PER_HOP {
            return Err(PlatformValidationError::InvalidAttempts);
        }
        if self.deadline_millis == 0 || self.deadline_millis > 300_000 {
            return Err(PlatformValidationError::InvalidDeadline);
        }
        match (self.mode, self.port) {
            (PathMode::IcmpEcho, None) | (PathMode::Udp | PathMode::TcpSyn, Some(1..=u16::MAX)) => {
                Ok(())
            }
            (PathMode::IcmpEcho, Some(_)) => Err(PlatformValidationError::UnexpectedPort),
            (PathMode::Udp | PathMode::TcpSyn, _) => Err(PlatformValidationError::MissingPort),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PathAttemptOutcome {
    Timeout,
    HopResponse,
    DestinationReached,
    Unreachable,
    AdministrativelyFiltered,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PathAttempt {
    pub hop: u8,
    pub attempt: u8,
    pub responder: Option<IpAddr>,
    pub round_trip_micros: Option<u64>,
    pub outcome: PathAttemptOutcome,
    pub strong_correlation: bool,
}

#[derive(Clone, Debug)]
pub struct PathRun {
    plan: PathPlan,
    attempts: BTreeSet<PathAttempt>,
    stopped: bool,
}

impl PathRun {
    /// Creates a validated deterministic path run.
    ///
    /// # Errors
    ///
    /// Returns the underlying plan validation error.
    pub fn new(plan: PathPlan) -> Result<Self, PlatformValidationError> {
        plan.validate()?;
        Ok(Self {
            plan,
            attempts: BTreeSet::new(),
            stopped: false,
        })
    }

    /// Records one bounded attempt; destination outcomes atomically stop later work.
    ///
    /// # Errors
    ///
    /// Rejects work outside the declared plan or after its stop condition.
    pub fn record(&mut self, attempt: PathAttempt) -> Result<(), PlatformValidationError> {
        if self.stopped
            || attempt.hop < self.plan.first_hop
            || attempt.hop > self.plan.maximum_hop
            || attempt.attempt == 0
            || attempt.attempt > self.plan.attempts_per_hop
        {
            return Err(PlatformValidationError::InvalidHopRange);
        }
        if matches!(
            attempt.outcome,
            PathAttemptOutcome::DestinationReached | PathAttemptOutcome::Unreachable
        ) {
            self.stopped = true;
        }
        self.attempts.replace(attempt);
        Ok(())
    }

    pub fn attempts(&self) -> impl Iterator<Item = &PathAttempt> {
        self.attempts.iter()
    }

    #[must_use]
    pub const fn stopped(&self) -> bool {
        self.stopped
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationStepKind {
    Connect,
    Write,
    Read,
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationStep {
    pub kind: ConversationStepKind,
    pub bytes: Vec<u8>,
    pub maximum_read_bytes: usize,
    pub deadline_millis: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationPlan {
    pub registry_id: String,
    pub target: IpAddr,
    pub port: u16,
    pub required_risks: AuthorityRiskSet,
    pub steps: Vec<ConversationStep>,
}

impl ConversationPlan {
    /// Validates a declarative finite TCP state machine.
    ///
    /// # Errors
    ///
    /// Rejects arbitrary/unregistered shape, missing risk consent, and byte/time limits.
    pub fn validate(&self, allowed: AuthorityRiskSet) -> Result<(), PlatformValidationError> {
        if self.registry_id.is_empty()
            || self.registry_id.len() > 128
            || self.port == 0
            || self.steps.is_empty()
            || self.steps.len() > MAX_CONVERSATION_STEPS
            || self
                .steps
                .first()
                .is_none_or(|step| step.kind != ConversationStepKind::Connect)
            || self
                .steps
                .last()
                .is_none_or(|step| step.kind != ConversationStepKind::Shutdown)
        {
            return Err(PlatformValidationError::InvalidConversation);
        }
        if !allowed.contains(self.required_risks) {
            return Err(PlatformValidationError::RiskConsent);
        }
        let mut bytes = 0_usize;
        for step in &self.steps {
            if step.deadline_millis == 0 || step.deadline_millis > 30_000 {
                return Err(PlatformValidationError::InvalidDeadline);
            }
            bytes = bytes
                .checked_add(step.bytes.len())
                .and_then(|value| value.checked_add(step.maximum_read_bytes))
                .ok_or(PlatformValidationError::ConversationLimit)?;
            match step.kind {
                ConversationStepKind::Write if step.bytes.is_empty() => {
                    return Err(PlatformValidationError::InvalidConversation);
                }
                ConversationStepKind::Read if step.maximum_read_bytes == 0 => {
                    return Err(PlatformValidationError::InvalidConversation);
                }
                ConversationStepKind::Connect | ConversationStepKind::Shutdown
                    if !step.bytes.is_empty() || step.maximum_read_bytes != 0 =>
                {
                    return Err(PlatformValidationError::InvalidConversation);
                }
                _ => {}
            }
        }
        if bytes > MAX_CONVERSATION_BYTES {
            return Err(PlatformValidationError::ConversationLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedUrl {
    pub scheme: String,
    pub host: IpAddr,
    pub port: u16,
    pub path: String,
}

/// Parses an advertised URL using same-address, no-userinfo, no-fragment policy.
/// DNS resolution and redirects are intentionally not performed here.
///
/// # Errors
///
/// Rejects unsupported schemes, DNS names, userinfo, fragments, ambiguous literals,
/// cross-address targets, and unbounded paths.
pub fn authorize_advertised_url(
    value: &str,
    responder: IpAddr,
) -> Result<GovernedUrl, PlatformValidationError> {
    if value.len() > 2_048 || value.contains('@') || value.contains('#') {
        return Err(PlatformValidationError::InvalidUrl);
    }
    let (scheme, remainder, default_port) = if let Some(rest) = value.strip_prefix("http://") {
        ("http", rest, 80)
    } else if let Some(rest) = value.strip_prefix("https://") {
        ("https", rest, 443)
    } else {
        return Err(PlatformValidationError::InvalidUrl);
    };
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, "/"), |(host, _tail)| {
            (host, &remainder[host.len()..])
        });
    let (host_text, port) = split_ip_authority(authority, default_port)?;
    if port == 0 {
        return Err(PlatformValidationError::InvalidUrl);
    }
    let host = host_text
        .parse::<IpAddr>()
        .map_err(|_| PlatformValidationError::InvalidUrl)?;
    if host != responder {
        return Err(PlatformValidationError::AddressEscape);
    }
    Ok(GovernedUrl {
        scheme: scheme.into(),
        host,
        port,
        path: path.into(),
    })
}

fn split_ip_authority(
    authority: &str,
    default_port: u16,
) -> Result<(&str, u16), PlatformValidationError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or(PlatformValidationError::InvalidUrl)?;
        let host = &bracketed[..end];
        if host.contains('%') {
            return Err(PlatformValidationError::InvalidUrl);
        }
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix
                .strip_prefix(':')
                .ok_or(PlatformValidationError::InvalidUrl)?
                .parse::<u16>()
                .map_err(|_| PlatformValidationError::InvalidUrl)?
        };
        return Ok((host, port));
    }
    if authority.matches(':').count() > 1 {
        return Err(PlatformValidationError::InvalidUrl);
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        Ok((
            host,
            port.parse::<u16>()
                .map_err(|_| PlatformValidationError::InvalidUrl)?,
        ))
    } else {
        Ok((authority, default_port))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AssetCandidate {
    pub id: Vec<u8>,
    pub strong_identifiers: BTreeSet<Vec<u8>>,
    pub addresses: BTreeSet<IpAddr>,
    pub names: BTreeSet<String>,
    pub services: BTreeSet<String>,
    pub conflicts: BTreeSet<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AssetClassification {
    Router,
    Switch,
    Printer,
    Camera,
    WindowsHost,
    DnsInfrastructure,
    SmartHome,
    IndustrialController,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationEvidence {
    pub classification: AssetClassification,
    pub positive: Vec<String>,
    pub conflicting: Vec<String>,
}

/// Reconciles evidence only when a scoped strong identifier overlaps.
/// Names, addresses, certificates, and vendor labels alone never merge assets.
#[must_use]
pub fn reconcile_assets(records: &[EvidenceRecord]) -> Vec<AssetCandidate> {
    let active = records
        .iter()
        .take(MAX_EVIDENCE_RECORDS)
        .filter(|record| {
            !matches!(
                record.disposition(),
                crate::EvidenceDisposition::Expired | crate::EvidenceDisposition::Withdrawn
            )
        })
        .collect::<Vec<_>>();
    let mut parents = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for record in &active {
        let strong = strong_identifiers(record);
        if let Some(first) = strong.first() {
            for other in &strong[1..] {
                union_identifier(&mut parents, first, other);
            }
        }
    }
    let mut assets: BTreeMap<Vec<u8>, AssetCandidate> = BTreeMap::new();
    for record in active {
        let strong = strong_identifiers(record);
        let scope = evidence_scope(record);
        let id = strong.first().map_or_else(
            || {
                scoped_identifier(
                    &scope,
                    &[record.entity().kind as u8],
                    &record.entity().canonical,
                )
            },
            |first| find_identifier(&mut parents, first),
        );
        let asset = assets.entry(id.clone()).or_insert_with(|| AssetCandidate {
            id,
            strong_identifiers: BTreeSet::new(),
            addresses: BTreeSet::new(),
            names: BTreeSet::new(),
            services: BTreeSet::new(),
            conflicts: BTreeSet::new(),
        });
        for identifier in strong {
            asset.strong_identifiers.insert(identifier);
        }
        for field in record.fields() {
            match field.key.as_slice() {
                b"address" | b"responder" => {
                    if let Ok(text) = std::str::from_utf8(&field.value)
                        && let Ok(address) = text.parse()
                    {
                        asset.addresses.insert(address);
                    }
                }
                b"name" | b"hostname" => {
                    if let Ok(text) = std::str::from_utf8(&field.value) {
                        asset.names.insert(text.into());
                    }
                }
                b"protocol" | b"service" => {
                    if let Ok(text) = std::str::from_utf8(&field.value) {
                        asset.services.insert(text.into());
                    }
                }
                _ => {}
            }
        }
    }
    assets.into_values().take(MAX_ASSETS).collect()
}

fn strong_identifiers(record: &EvidenceRecord) -> Vec<Vec<u8>> {
    let scope = evidence_scope(record);
    record
        .fields()
        .iter()
        .filter(|field| {
            matches!(
                field.key.as_slice(),
                b"mac" | b"lldpChassisId" | b"smbServerGuid" | b"snmpEngineId" | b"upnpUdn"
            ) && !field.value.is_empty()
        })
        .map(|field| scoped_identifier(&scope, &field.key, &field.value))
        .collect()
}

fn evidence_scope(record: &EvidenceRecord) -> Vec<u8> {
    let mut scopes = record
        .fields()
        .iter()
        .filter(|field| field.key == b"networkScopeId")
        .map(|field| field.value.clone());
    let first = scopes.next();
    if first.is_some() && scopes.next().is_none() {
        return first.unwrap_or_default();
    }
    if first.is_none() {
        return b"local".to_vec();
    }
    let mut ambiguous = b"ambiguous:".to_vec();
    ambiguous.extend_from_slice(&record.origin().run_id);
    ambiguous.extend_from_slice(&record.origin().record_id.to_be_bytes());
    ambiguous
}

fn scoped_identifier(scope: &[u8], kind: &[u8], value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    for component in [scope, kind, value] {
        output.extend_from_slice(
            &u32::try_from(component.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        output.extend_from_slice(component);
    }
    output
}

fn find_identifier(parents: &mut BTreeMap<Vec<u8>, Vec<u8>>, value: &[u8]) -> Vec<u8> {
    let parent = parents.get(value).cloned();
    let Some(parent) = parent else {
        parents.insert(value.to_vec(), value.to_vec());
        return value.to_vec();
    };
    if parent == value {
        return parent;
    }
    let root = find_identifier(parents, &parent);
    parents.insert(value.to_vec(), root.clone());
    root
}

fn union_identifier(parents: &mut BTreeMap<Vec<u8>, Vec<u8>>, left: &[u8], right: &[u8]) {
    let left_root = find_identifier(parents, left);
    let right_root = find_identifier(parents, right);
    if left_root == right_root {
        return;
    }
    let (root, child) = if left_root < right_root {
        (left_root, right_root)
    } else {
        (right_root, left_root)
    };
    parents.insert(child, root);
}

#[must_use]
pub fn classify_asset(asset: &AssetCandidate) -> Vec<ClassificationEvidence> {
    let mut output = Vec::new();
    let has = |needle: &str| {
        asset
            .services
            .iter()
            .any(|service| service.eq_ignore_ascii_case(needle))
    };
    if has("routerAdvertisement") || has("nat-pmp") || has("pcp") {
        output.push(classification(
            AssetClassification::Router,
            "router control-plane evidence",
        ));
    }
    if has("lldp") && !has("routerAdvertisement") {
        output.push(classification(
            AssetClassification::Switch,
            "LLDP infrastructure evidence",
        ));
    }
    if has("ipp") || has("printer") {
        output.push(classification(
            AssetClassification::Printer,
            "printing service evidence",
        ));
    }
    if has("rtsp") || has("onvif") {
        output.push(classification(
            AssetClassification::Camera,
            "camera/media service evidence",
        ));
    }
    if has("smb") || has("ws-discovery") {
        output.push(classification(
            AssetClassification::WindowsHost,
            "Windows service evidence",
        ));
    }
    if has("dns") {
        output.push(classification(
            AssetClassification::DnsInfrastructure,
            "DNS service evidence",
        ));
    }
    if has("matter") || has("homekit") || has("cast") {
        output.push(classification(
            AssetClassification::SmartHome,
            "smart-home service evidence",
        ));
    }
    if has("modbus") || has("bacnet") || has("ethernet-ip") || has("s7") {
        output.push(classification(
            AssetClassification::IndustrialController,
            "industrial protocol evidence",
        ));
    }
    output
}

fn classification(classification: AssetClassification, reason: &str) -> ClassificationEvidence {
    ClassificationEvidence {
        classification,
        positive: vec![reason.into()],
        conflicting: Vec::new(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventorySnapshot {
    pub schema_version: u16,
    pub sequence: u64,
    pub assets: Vec<AssetCandidate>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InventoryChangeKind {
    New,
    Changed,
    Expired,
    Withdrawn,
    Reappeared,
    Conflicted,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InventoryChange {
    pub kind: InventoryChangeKind,
    pub asset_id: Vec<u8>,
}

/// Computes a stable storage-neutral asset delta.
#[must_use]
pub fn inventory_delta(
    before: &InventorySnapshot,
    after: &InventorySnapshot,
) -> Vec<InventoryChange> {
    let left: BTreeMap<_, _> = before
        .assets
        .iter()
        .map(|asset| (&asset.id, asset))
        .collect();
    let right: BTreeMap<_, _> = after
        .assets
        .iter()
        .map(|asset| (&asset.id, asset))
        .collect();
    let mut changes = Vec::new();
    for (id, asset) in &right {
        match left.get(id) {
            None => changes.push(InventoryChange {
                kind: InventoryChangeKind::New,
                asset_id: (*id).clone(),
            }),
            Some(previous) if *previous != *asset => changes.push(InventoryChange {
                kind: InventoryChangeKind::Changed,
                asset_id: (*id).clone(),
            }),
            _ => {}
        }
    }
    for id in left.keys() {
        if !right.contains_key(id) {
            changes.push(InventoryChange {
                kind: InventoryChangeKind::Expired,
                asset_id: (*id).clone(),
            });
        }
    }
    changes.sort_unstable();
    changes
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorEnvelope {
    pub version: u16,
    pub sensor_id: Vec<u8>,
    pub network_scope_id: Vec<u8>,
    pub sequence: u64,
    pub monotonic_start_nanos: u64,
    pub monotonic_end_nanos: u64,
    pub wall_time_millis: Option<i64>,
    pub clock_uncertainty_millis: u32,
    pub truncated: bool,
    pub records: Vec<EvidenceRecord>,
}

impl SensorEnvelope {
    /// Validates imported sensor input before reconciliation.
    ///
    /// # Errors
    ///
    /// Rejects identity, ordering, count, and byte ceilings.
    pub fn validate(&self) -> Result<(), PlatformValidationError> {
        if self.version != SENSOR_ENVELOPE_VERSION
            || self.sensor_id.is_empty()
            || self.sensor_id.len() > 256
            || self.sensor_id.contains(&0)
            || self.network_scope_id.is_empty()
            || self.network_scope_id.len() > 256
            || self.network_scope_id.contains(&0)
            || self.sequence == 0
            || self.monotonic_end_nanos < self.monotonic_start_nanos
            || self.records.len() > MAX_SENSOR_ENVELOPE_RECORDS
        {
            return Err(PlatformValidationError::InvalidEnvelope);
        }
        let bytes = self
            .records
            .iter()
            .try_fold(0_usize, |total, record| {
                total.checked_add(record.variable_bytes())
            })
            .ok_or(PlatformValidationError::Capacity)?;
        if bytes > MAX_EVIDENCE_BATCH_BYTES {
            return Err(PlatformValidationError::Capacity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct SensorFusion {
    last_sequences: BTreeMap<(Vec<u8>, Vec<u8>), u64>,
}

impl SensorFusion {
    /// Admits an untrusted envelope while preserving sensor and network scope.
    ///
    /// # Errors
    ///
    /// Rejects duplicate/replayed or sequence-gapped delivery.
    pub fn admit(&mut self, envelope: &SensorEnvelope) -> Result<(), PlatformValidationError> {
        envelope.validate()?;
        let key = (
            envelope.sensor_id.clone(),
            envelope.network_scope_id.clone(),
        );
        if !self.last_sequences.contains_key(&key)
            && self.last_sequences.len() >= MAX_SENSOR_STREAMS
        {
            return Err(PlatformValidationError::Capacity);
        }
        if let Some(previous) = self.last_sequences.get(&key) {
            if envelope.sequence <= *previous {
                return Err(PlatformValidationError::DuplicateEnvelope);
            }
            if envelope.sequence != previous.saturating_add(1) {
                return Err(PlatformValidationError::SequenceGap);
            }
        }
        self.last_sequences.insert(key, envelope.sequence);
        Ok(())
    }
}

#[must_use]
pub fn canonical_address_entity(address: IpAddr) -> EvidenceEntityKey {
    EvidenceEntityKey {
        kind: EvidenceEntityKind::Address,
        canonical: address.to_string().into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_stops_at_destination() {
        let mut run = PathRun::new(PathPlan {
            target: "192.0.2.1".parse().expect("IP"),
            mode: PathMode::Udp,
            port: Some(33434),
            first_hop: 1,
            maximum_hop: 30,
            attempts_per_hop: 3,
            deadline_millis: 1000,
        })
        .expect("plan");
        run.record(PathAttempt {
            hop: 1,
            attempt: 1,
            responder: Some("192.0.2.254".parse().expect("IP")),
            round_trip_micros: Some(100),
            outcome: PathAttemptOutcome::HopResponse,
            strong_correlation: true,
        })
        .expect("hop");
        run.record(PathAttempt {
            hop: 2,
            attempt: 1,
            responder: Some("192.0.2.1".parse().expect("IP")),
            round_trip_micros: Some(200),
            outcome: PathAttemptOutcome::DestinationReached,
            strong_correlation: true,
        })
        .expect("destination");
        assert!(run.stopped());
    }

    #[test]
    fn advertised_urls_cannot_escape_responder() {
        let responder = "192.0.2.1".parse().expect("IP");
        assert!(authorize_advertised_url("http://192.0.2.1/device.xml", responder).is_ok());
        assert_eq!(
            authorize_advertised_url("http://192.0.2.2/device.xml", responder),
            Err(PlatformValidationError::AddressEscape)
        );
        assert_eq!(
            authorize_advertised_url("http://name.example/device.xml", responder),
            Err(PlatformValidationError::InvalidUrl)
        );
    }

    #[test]
    fn inventory_delta_is_stable() {
        let asset = AssetCandidate {
            id: b"mac\0one".to_vec(),
            strong_identifiers: BTreeSet::new(),
            addresses: BTreeSet::new(),
            names: BTreeSet::new(),
            services: BTreeSet::new(),
            conflicts: BTreeSet::new(),
        };
        let before = InventorySnapshot {
            schema_version: 1,
            sequence: 1,
            assets: Vec::new(),
        };
        let after = InventorySnapshot {
            schema_version: 1,
            sequence: 2,
            assets: vec![asset.clone()],
        };
        assert_eq!(
            inventory_delta(&before, &after),
            vec![InventoryChange {
                kind: InventoryChangeKind::New,
                asset_id: asset.id
            }]
        );
    }
}
