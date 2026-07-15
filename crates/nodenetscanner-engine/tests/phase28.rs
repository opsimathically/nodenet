use std::cell::Cell;

use nodenet_protocols::{EvidenceStrength, IpAddress, Ipv4Address, ProbePort};
use nodenetscanner_engine::{
    Clock, ContextFailure, ContextResolution, ContextResolver, DiscoverySilencePolicy,
    EvidenceEvent, EvidenceKind, IcmpEvidence, LogicalProbe, MonotonicTime, NetworkState,
    PrefixKey, ProbeDefinition, ProbeEmission, ProbeOutcome, ProbeTransport, ProbeVariantId,
    ResolvedContext, ResultSink, ScanDuration, ScanPlan, ScanResult, ScanScheduler,
    SchedulerConfig, SchedulingSeed, SeededPermutation, SessionLifecycle, SinkFailure,
    SinkReservation, TargetEndpoint, TargetInput, TargetSet, TimingMode, TransportFailure,
    UdpProbeProgramme, UdpProbeStrategy, UdpProbeVariant, UdpResponseKind, UdpServiceConfidence,
    UdpServiceEvidence,
};

#[derive(Default)]
struct VirtualClock(Cell<u64>);

impl VirtualClock {
    fn set(&self, value: u64) {
        self.0.set(value);
    }
}

impl Clock for VirtualClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::from_micros(self.0.get())
    }
}

#[derive(Default)]
struct Transport(Vec<ProbeEmission>, Vec<u64>);

impl ProbeTransport for Transport {
    fn emit(&mut self, emission: ProbeEmission) -> Result<(), TransportFailure> {
        self.0.push(emission);
        Ok(())
    }

    fn retire(&mut self, probe_id: u64) {
        self.1.push(probe_id);
    }
}

#[derive(Default)]
struct Resolver;

impl ContextResolver for Resolver {
    fn resolve(&mut self, probe: LogicalProbe) -> Result<ContextResolution, ContextFailure> {
        Ok(ContextResolution::Ready(ResolvedContext {
            generation: 9,
            prefix_key: PrefixKey::default_for(probe.target),
            neighbor_setup: None,
        }))
    }
}

#[derive(Default)]
struct Sink {
    reserved: usize,
    reserved_bytes: usize,
    requested_bytes: Vec<usize>,
    results: Vec<ScanResult>,
}

impl ResultSink for Sink {
    fn try_reserve(&mut self) -> Result<SinkReservation, SinkFailure> {
        self.reserved += 1;
        Ok(SinkReservation::Reserved)
    }

    fn try_reserve_with_bytes(
        &mut self,
        maximum_metadata_bytes: usize,
    ) -> Result<SinkReservation, SinkFailure> {
        self.reserved += 1;
        self.reserved_bytes += maximum_metadata_bytes;
        self.requested_bytes.push(maximum_metadata_bytes);
        Ok(SinkReservation::Reserved)
    }

    fn commit_reserved(&mut self, result: ScanResult) -> Result<(), SinkFailure> {
        self.reserved = self
            .reserved
            .checked_sub(1)
            .ok_or(SinkFailure { code: 1 })?;
        self.results.push(result);
        Ok(())
    }

    fn commit_reserved_with_bytes(
        &mut self,
        result: ScanResult,
        actual_metadata_bytes: usize,
        reserved_metadata_bytes: usize,
    ) -> Result<(), SinkFailure> {
        assert_eq!(actual_metadata_bytes, 0);
        self.reserved_bytes = self
            .reserved_bytes
            .checked_sub(reserved_metadata_bytes)
            .ok_or(SinkFailure { code: 2 })?;
        self.commit_reserved(result)
    }

    fn release_reserved(&mut self, count: usize) -> Result<(), SinkFailure> {
        self.reserved = self
            .reserved
            .checked_sub(count)
            .ok_or(SinkFailure { code: 3 })?;
        Ok(())
    }

    fn release_reserved_with_bytes(
        &mut self,
        count: usize,
        maximum_metadata_bytes: usize,
    ) -> Result<(), SinkFailure> {
        self.reserved_bytes = self
            .reserved_bytes
            .checked_sub(maximum_metadata_bytes)
            .ok_or(SinkFailure { code: 4 })?;
        self.release_reserved(count)
    }
}

fn variant(index: u16, metadata: u16) -> UdpProbeVariant {
    UdpProbeVariant::new(ProbeVariantId::new(index + 1), index, metadata).unwrap()
}

fn plan(variant_count: u16, metadata: u16) -> ScanPlan {
    plan_with_strategy(variant_count, metadata, UdpProbeStrategy::Exhaustive)
}

fn plan_with_strategy(variant_count: u16, metadata: u16, strategy: UdpProbeStrategy) -> ScanPlan {
    let address = IpAddress::V4(Ipv4Address::new([192, 0, 2, 10]));
    let endpoint = TargetEndpoint::new(address, None).unwrap();
    let targets = TargetSet::normalize(&[TargetInput::Address(endpoint)], &[]).unwrap();
    let variants: Vec<_> = (0..variant_count)
        .map(|index| variant(index, metadata))
        .collect();
    let programme = UdpProbeProgramme::new(variants.clone(), variants)
        .unwrap()
        .with_strategy(strategy);
    ScanPlan::new(
        targets,
        vec![ProbeDefinition::udp(vec![ProbePort::new(53).unwrap()], programme).unwrap()],
        1,
    )
    .unwrap()
}

#[test]
fn adaptive_preserves_recall_and_reduces_requests_in_ten_deterministic_repetitions() {
    let mut exhaustive_counts = Vec::new();
    let mut adaptive_counts = Vec::new();
    for _ in 0..10 {
        for (strategy, counts) in [
            (UdpProbeStrategy::Exhaustive, &mut exhaustive_counts),
            (UdpProbeStrategy::Adaptive, &mut adaptive_counts),
        ] {
            let clock = VirtualClock::default();
            let mut transport = Transport::default();
            let mut sink = Sink::default();
            let mut scheduler = scheduler(plan_with_strategy(4, 0, strategy), config());
            scheduler.start(&clock).unwrap();
            drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
            let emitted = transport.0.len();
            clock.set(10);
            scheduler
                .handle_evidence(
                    &clock,
                    evidence(transport.0[0].probe_id, EvidenceKind::UdpReply, None),
                    &mut transport,
                    &mut sink,
                )
                .unwrap();
            drive_at(&mut scheduler, &clock, 600, &mut transport, &mut sink);
            assert_eq!(
                sink.results[0].outcome,
                ProbeOutcome::Network(NetworkState::Open)
            );
            counts.push(emitted);
        }
    }
    exhaustive_counts.sort_unstable();
    adaptive_counts.sort_unstable();
    assert_eq!(exhaustive_counts[5], 4);
    assert_eq!(adaptive_counts[5], 1);
}

#[test]
fn adaptive_closed_evidence_stops_unsent_variants_but_keeps_grace() {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut scheduler = scheduler(
        plan_with_strategy(4, 0, UdpProbeStrategy::Adaptive),
        config(),
    );
    scheduler.start(&clock).unwrap();
    drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    let id = transport.0[0].probe_id;
    clock.set(10);
    scheduler
        .handle_evidence(
            &clock,
            evidence(id, EvidenceKind::IcmpPortUnreachable, None),
            &mut transport,
            &mut sink,
        )
        .unwrap();
    assert!(sink.results.is_empty());
    drive_at(&mut scheduler, &clock, 600, &mut transport, &mut sink);
    assert_eq!(transport.0.len(), 1);
    assert_eq!(
        sink.results[0].outcome,
        ProbeOutcome::Network(NetworkState::Closed)
    );
}

#[test]
fn terminal_deadline_preserves_adaptive_evidence_observed_during_grace() {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut value = config();
    value.session_deadline = ScanDuration::from_micros(50);
    value.late_grace = ScanDuration::from_micros(500);
    let mut scheduler = scheduler(plan_with_strategy(4, 0, UdpProbeStrategy::Adaptive), value);
    scheduler.start(&clock).unwrap();
    drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    clock.set(10);
    scheduler
        .handle_evidence(
            &clock,
            evidence(transport.0[0].probe_id, EvidenceKind::UdpReply, None),
            &mut transport,
            &mut sink,
        )
        .unwrap();
    drive_at(&mut scheduler, &clock, 50, &mut transport, &mut sink);
    assert_eq!(sink.results.len(), 1);
    assert_eq!(
        sink.results[0].outcome,
        ProbeOutcome::Network(NetworkState::Open)
    );
}

#[test]
fn soft_service_hint_only_narrows_adaptive_followups() {
    let address = IpAddress::V4(Ipv4Address::new([192, 0, 2, 10]));
    let endpoint = TargetEndpoint::new(address, None).unwrap();
    let targets = TargetSet::normalize(&[TargetInput::Address(endpoint)], &[]).unwrap();
    let variants = vec![
        variant(0, 0).with_service_family(1),
        variant(1, 0).with_service_family(2),
        variant(2, 0).with_service_family(1),
    ];
    let programme = UdpProbeProgramme::new(variants.clone(), variants)
        .unwrap()
        .with_strategy(UdpProbeStrategy::Adaptive);
    let plan = ScanPlan::new(
        targets,
        vec![ProbeDefinition::udp(vec![ProbePort::new(53).unwrap()], programme).unwrap()],
        1,
    )
    .unwrap();
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut scheduler = scheduler(plan, config());
    scheduler.start(&clock).unwrap();
    drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    clock.set(10);
    scheduler
        .handle_evidence(
            &clock,
            EvidenceEvent {
                probe_id: transport.0[0].probe_id,
                kind: EvidenceKind::UdpServiceHint,
                strength: EvidenceStrength::TruncatedQuote,
                icmp: None,
                udp_service: Some(UdpServiceEvidence {
                    family: 2,
                    confidence: UdpServiceConfidence::Signature,
                    metadata: Box::new([]),
                }),
            },
            &mut transport,
            &mut sink,
        )
        .unwrap();
    drive_at(&mut scheduler, &clock, 10, &mut transport, &mut sink);
    assert_eq!(transport.0.len(), 2);
    assert_eq!(transport.0[1].udp_variant.unwrap().request_index, 1);
    assert!(
        sink.results.is_empty(),
        "a soft hint must never classify a port"
    );
}

#[test]
fn adaptive_icmp_then_silence_paces_without_inventing_open_evidence() {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut scheduler = scheduler(
        plan_with_strategy(4, 0, UdpProbeStrategy::Adaptive),
        config(),
    );
    scheduler.start(&clock).unwrap();
    drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    clock.set(10);
    scheduler
        .handle_evidence(
            &clock,
            evidence(
                transport.0[0].probe_id,
                EvidenceKind::IcmpOtherError,
                Some(IcmpEvidence {
                    family: 4,
                    message_type: 3,
                    code: 13,
                    emitter_is_target: false,
                    quote_strength: EvidenceStrength::TruncatedQuote,
                }),
            ),
            &mut transport,
            &mut sink,
        )
        .unwrap();
    drive_at(&mut scheduler, &clock, 10, &mut transport, &mut sink);
    assert_eq!(transport.0.len(), 2);
    drive_at(&mut scheduler, &clock, 110, &mut transport, &mut sink);
    assert_eq!(scheduler.diagnostics().udp_icmp_pacing, 1);
    assert!(
        sink.results.is_empty(),
        "silence must not create an open result"
    );
}

fn two_port_plan() -> ScanPlan {
    let endpoint =
        TargetEndpoint::new(IpAddress::V4(Ipv4Address::new([192, 0, 2, 10])), None).unwrap();
    let targets = TargetSet::normalize(&[TargetInput::Address(endpoint)], &[]).unwrap();
    let variants: Vec<_> = (0..4).map(|index| variant(index, 0)).collect();
    let programme = UdpProbeProgramme::new(variants.clone(), variants).unwrap();
    ScanPlan::new(
        targets,
        vec![
            ProbeDefinition::udp(
                vec![ProbePort::new(53).unwrap(), ProbePort::new(123).unwrap()],
                programme,
            )
            .unwrap(),
        ],
        1,
    )
    .unwrap()
}

fn config() -> SchedulerConfig {
    SchedulerConfig {
        rate_per_second: 1_000_000,
        burst: 8,
        max_outstanding: 8,
        max_retransmissions: 0,
        initial_timeout: ScanDuration::from_micros(100),
        minimum_timeout: ScanDuration::from_micros(100),
        maximum_timeout: ScanDuration::from_micros(100),
        session_deadline: ScanDuration::from_micros(100_000),
        late_grace: ScanDuration::from_micros(500),
        max_grace_entries: 64,
        max_per_target: 8,
        max_per_prefix: 8,
        timing_mode: TimingMode::FixedRate,
        discovery_silence: DiscoverySilencePolicy::Unknown,
        tcp_reset_cleanup: false,
    }
}

fn scheduler(plan: ScanPlan, config: SchedulerConfig) -> ScanScheduler {
    let permutation =
        SeededPermutation::new(plan.logical_probe_count(), SchedulingSeed::Explicit(1)).unwrap();
    ScanScheduler::new(plan, config, permutation).unwrap()
}

fn drive_at(
    scheduler: &mut ScanScheduler,
    clock: &VirtualClock,
    micros: u64,
    transport: &mut Transport,
    sink: &mut Sink,
) -> nodenetscanner_engine::DriveReport {
    clock.set(micros);
    scheduler
        .drive(clock, transport, &mut Resolver, sink)
        .unwrap()
}

#[test]
fn zero_and_one_variant_preserve_exactly_one_logical_result() {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut zero = scheduler(plan(0, 0), config());
    zero.start(&clock).unwrap();
    let report = drive_at(&mut zero, &clock, 0, &mut transport, &mut sink);
    assert_eq!(report.lifecycle, SessionLifecycle::Completed);
    assert!(transport.0.is_empty());
    assert_eq!(sink.results.len(), 1);
    assert_eq!(sink.results[0].transmissions, 0);
    assert_eq!(sink.results[0].udp.as_ref().unwrap().variants_attempted, 0);

    let mut one_sink = Sink::default();
    let mut one_transport = Transport::default();
    let mut one = scheduler(plan(1, 0), config());
    one.start(&clock).unwrap();
    drive_at(&mut one, &clock, 0, &mut one_transport, &mut one_sink);
    drive_at(&mut one, &clock, 100, &mut one_transport, &mut one_sink);
    assert_eq!(one_sink.results.len(), 1);
    assert_eq!(one_sink.results[0].transmissions, 1);
    assert!(one_sink.results[0].udp.is_none());
}

#[test]
fn four_sixteen_and_sixty_four_variants_use_bounded_fair_waves() {
    for count in [4_u16, 16, 64] {
        let clock = VirtualClock::default();
        let mut transport = Transport::default();
        let mut sink = Sink::default();
        let mut scheduler = scheduler(plan(count, 0), config());
        scheduler.start(&clock).unwrap();
        let mut maximum_outstanding = 0;
        for wave in 0..=count / 4 {
            let report = drive_at(
                &mut scheduler,
                &clock,
                u64::from(wave) * 100,
                &mut transport,
                &mut sink,
            );
            maximum_outstanding = maximum_outstanding.max(report.outstanding);
        }
        drive_at(
            &mut scheduler,
            &clock,
            u64::from(count / 4) * 100 + 600,
            &mut transport,
            &mut sink,
        );
        assert!(maximum_outstanding <= 4);
        assert_eq!(transport.0.len(), usize::from(count));
        assert_eq!(transport.1.len(), usize::from(count));
        assert_eq!(sink.results.len(), 1);
        assert_eq!(sink.results[0].transmissions, u32::from(count));
        let udp = sink.results[0].udp.as_ref().unwrap();
        assert_eq!(udp.variants_attempted, count);
        assert_eq!(udp.response_kind, UdpResponseKind::Silence);
        assert_eq!(sink.reserved, 0);
    }
}

#[test]
fn variant_waves_are_fair_across_ports_on_one_quiet_target() {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut value = config();
    value.max_outstanding = 4;
    value.burst = 4;
    value.max_per_target = 2;
    value.max_per_prefix = 4;
    let mut scheduler = scheduler(two_port_plan(), value);
    scheduler.start(&clock).unwrap();
    let report = drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    assert_eq!(report.outstanding, 2);
    assert_eq!(transport.0.len(), 2);
    assert_ne!(transport.0[0].probe.port, transport.0[1].probe.port);
}

fn evidence(probe_id: u64, kind: EvidenceKind, icmp: Option<IcmpEvidence>) -> EvidenceEvent {
    EvidenceEvent {
        probe_id,
        kind,
        strength: EvidenceStrength::StrongPayload128,
        icmp,
        udp_service: None,
    }
}

fn contradictory(order: [usize; 2]) -> ScanResult {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut scheduler = scheduler(plan(4, 0), config());
    scheduler.start(&clock).unwrap();
    drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    let events = [
        evidence(
            transport.0[0].probe_id,
            EvidenceKind::IcmpPortUnreachable,
            Some(IcmpEvidence {
                family: 4,
                message_type: 3,
                code: 3,
                emitter_is_target: true,
                quote_strength: EvidenceStrength::TruncatedQuote,
            }),
        ),
        evidence(transport.0[1].probe_id, EvidenceKind::UdpReply, None),
    ];
    clock.set(10);
    for index in order {
        scheduler
            .handle_evidence(&clock, events[index].clone(), &mut transport, &mut sink)
            .unwrap();
    }
    drive_at(&mut scheduler, &clock, 100, &mut transport, &mut sink);
    drive_at(&mut scheduler, &clock, 600, &mut transport, &mut sink);
    sink.results.remove(0)
}

#[test]
fn evidence_lattice_is_order_independent_at_the_decisive_rank() {
    let forward = contradictory([0, 1]);
    let reverse = contradictory([1, 0]);
    assert_eq!(forward.outcome, ProbeOutcome::Network(NetworkState::Open));
    assert_eq!(forward, reverse);
    let udp = forward.udp.unwrap();
    assert_eq!(udp.response_kind, UdpResponseKind::DirectUdp);
    assert_eq!(udp.contradictions, 0);
    assert_eq!(udp.terminal_probe_id.unwrap().get(), 2);
}

#[test]
fn metadata_is_reserved_once_per_logical_and_released_on_settlement_or_close() {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut scheduler = scheduler(plan(4, 512), config());
    scheduler.start(&clock).unwrap();
    drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    assert_eq!(sink.requested_bytes, [512]);
    assert_eq!(sink.reserved_bytes, 512);
    scheduler.close(&mut sink).unwrap();
    assert_eq!(sink.reserved, 0);
    assert_eq!(sink.reserved_bytes, 0);
}

#[test]
fn cancellation_settles_one_reserved_logical_result_from_any_programme_stage() {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut scheduler = scheduler(plan(16, 128), config());
    scheduler.start(&clock).unwrap();
    drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    clock.set(10);
    scheduler.cancel(&clock, &mut sink).unwrap();
    assert_eq!(scheduler.lifecycle(), SessionLifecycle::Completed);
    assert_eq!(sink.results.len(), 1);
    assert_eq!(sink.results[0].outcome, ProbeOutcome::Cancelled);
    assert_eq!(sink.results[0].transmissions, 4);
    assert_eq!(sink.reserved, 0);
    assert_eq!(sink.reserved_bytes, 0);
}

#[test]
fn duplicate_programme_identities_are_rejected() {
    let duplicate = vec![variant(0, 0), variant(0, 0)];
    assert!(UdpProbeProgramme::new(duplicate.clone(), duplicate).is_err());
}

fn classify_icmp(detail: IcmpEvidence) -> ProbeOutcome {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut scheduler = scheduler(plan(2, 0), config());
    scheduler.start(&clock).unwrap();
    drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    clock.set(10);
    scheduler
        .handle_evidence(
            &clock,
            evidence(
                transport.0[0].probe_id,
                EvidenceKind::IcmpOtherError,
                Some(detail),
            ),
            &mut transport,
            &mut sink,
        )
        .unwrap();
    drive_at(&mut scheduler, &clock, 100, &mut transport, &mut sink);
    drive_at(&mut scheduler, &clock, 600, &mut transport, &mut sink);
    sink.results[0].outcome
}

#[test]
fn frozen_ipv4_and_ipv6_icmp_matrix_is_conservative() {
    let detail = |family, message_type, code, emitter_is_target| IcmpEvidence {
        family,
        message_type,
        code,
        emitter_is_target,
        quote_strength: EvidenceStrength::TruncatedQuote,
    };
    assert_eq!(
        classify_icmp(detail(4, 3, 3, true)),
        ProbeOutcome::Network(NetworkState::Closed)
    );
    assert_eq!(
        classify_icmp(detail(4, 3, 3, false)),
        ProbeOutcome::Network(NetworkState::Filtered)
    );
    assert_eq!(
        classify_icmp(detail(4, 11, 1, false)),
        ProbeOutcome::Network(NetworkState::Filtered)
    );
    assert_eq!(
        classify_icmp(detail(6, 1, 4, true)),
        ProbeOutcome::Network(NetworkState::Closed)
    );
    assert_eq!(
        classify_icmp(detail(6, 1, 4, false)),
        ProbeOutcome::Network(NetworkState::Filtered)
    );
    assert_eq!(
        classify_icmp(detail(6, 4, 0, true)),
        ProbeOutcome::Network(NetworkState::Open)
    );
    assert_eq!(
        classify_icmp(detail(6, 4, 1, true)),
        ProbeOutcome::Network(NetworkState::Filtered)
    );
    assert_eq!(
        classify_icmp(detail(6, 4, 99, true)),
        ProbeOutcome::Network(NetworkState::OpenOrFiltered)
    );
}

#[test]
fn decisive_evidence_at_timeout_wins_without_waiting_for_logical_grace() {
    let clock = VirtualClock::default();
    let mut transport = Transport::default();
    let mut sink = Sink::default();
    let mut scheduler = scheduler(plan(2, 0), config());
    scheduler.start(&clock).unwrap();
    drive_at(&mut scheduler, &clock, 0, &mut transport, &mut sink);
    clock.set(100);
    scheduler
        .handle_evidence(
            &clock,
            evidence(transport.0[0].probe_id, EvidenceKind::UdpReply, None),
            &mut transport,
            &mut sink,
        )
        .unwrap();
    drive_at(&mut scheduler, &clock, 100, &mut transport, &mut sink);
    assert_eq!(
        sink.results[0].outcome,
        ProbeOutcome::Network(NetworkState::Open)
    );
    assert_eq!(scheduler.diagnostics().late_responses, 1);
}
