use std::collections::{BTreeMap, VecDeque};

use nodenet_protocols::EvidenceStrength;

use crate::{
    Clock, ContextResolution, ContextResolver, DiagnosticCounters, DiagnosticKind,
    DiscoverySilencePolicy, DriveReport, EmissionPurpose, EngineError, EvidenceEvent, EvidenceKind,
    IcmpEvidence, LogicalProbe, MAX_CONCURRENT_UDP_VARIANTS, MAX_DEFERRED_CANDIDATES,
    MAX_TRANSITIONS_PER_DRIVE, MonotonicTime, NetworkState, PrefixKey, ProbeEmission, ProbeFamily,
    ProbeOutcome, ProbeTransport, ResolvedContext, ResultSink, RttEstimator, ScanDuration,
    ScanPlan, ScanResult, SchedulerConfig, SeededPermutation, SessionLifecycle, SinkReservation,
    TerminalReason, TokenBucket, UdpProbeStrategy, UdpProbeVariant, UdpResponseKind,
    UdpResultEvidence,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveStage {
    Pending(EmissionPurpose),
    Waiting {
        purpose: EmissionPurpose,
        deadline: MonotonicTime,
    },
    PendingCleanup(PendingTerminal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingTerminal {
    outcome: ProbeOutcome,
    strength: Option<EvidenceStrength>,
    rtt: Option<ScanDuration>,
    reason: TerminalReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveProbe {
    probe: LogicalProbe,
    context: ResolvedContext,
    stage: ActiveStage,
    stage_transmissions: u8,
    total_transmissions: u32,
    last_probe_sent_at: Option<MonotonicTime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProgrammePhysical {
    logical_id: u64,
    variant: UdpProbeVariant,
    stage: ActiveStage,
    transmissions: u8,
    last_sent_at: Option<MonotonicTime>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProgrammeBest {
    rank: u8,
    state: NetworkState,
    strength: Option<EvidenceStrength>,
    reason: TerminalReason,
    response_kind: UdpResponseKind,
    variant: UdpProbeVariant,
    rtt: Option<ScanDuration>,
    service: Option<crate::UdpServiceEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProgrammeLogical {
    probe: LogicalProbe,
    context: ResolvedContext,
    variant_count: usize,
    next_variant: usize,
    active: usize,
    grace: usize,
    attempted: u16,
    transmissions: u32,
    contradictions: u16,
    best: Option<ProgrammeBest>,
    reservation_bytes: usize,
    neighbor_ready: bool,
    stop_unsent: bool,
    soft_service_family: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProgrammeGrace {
    logical_id: u64,
    expires: MonotonicTime,
    variant: UdpProbeVariant,
    last_sent_at: Option<MonotonicTime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StopState {
    outcome: ProbeOutcome,
    reason: TerminalReason,
    final_lifecycle: SessionLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationFilter {
    All,
    Exact(u64),
}

impl GenerationFilter {
    const fn matches(self, generation: u64) -> bool {
        match self {
            Self::All => true,
            Self::Exact(expected) => generation == expected,
        }
    }
}

/// Bounded deterministic scan state machine.
pub struct ScanScheduler {
    plan: ScanPlan,
    config: SchedulerConfig,
    permutation: SeededPermutation,
    lifecycle: SessionLifecycle,
    session_deadline: Option<MonotonicTime>,
    last_now: Option<MonotonicTime>,
    cursor: u64,
    active: BTreeMap<u64, ActiveProbe>,
    grace: BTreeMap<u64, MonotonicTime>,
    programmes: BTreeMap<u64, ProgrammeLogical>,
    programme_ready: VecDeque<u64>,
    physical: BTreeMap<u64, ProgrammePhysical>,
    programme_grace: BTreeMap<u64, ProgrammeGrace>,
    next_wire_id: u64,
    deferred: VecDeque<LogicalProbe>,
    per_target: BTreeMap<crate::ScanTarget, usize>,
    per_prefix: BTreeMap<PrefixKey, usize>,
    adaptive_icmp_seen: BTreeMap<crate::ScanTarget, u16>,
    adaptive_not_before: BTreeMap<crate::ScanTarget, MonotonicTime>,
    bucket: Option<TokenBucket>,
    rtt: RttEstimator,
    diagnostics: DiagnosticCounters,
    context_waiting: bool,
    sink_backpressured: bool,
    stop: Option<StopState>,
    invalidating_generation: Option<GenerationFilter>,
}

impl ScanScheduler {
    /// Creates an allocation-bounded session in `Created` state.
    ///
    /// # Errors
    ///
    /// Rejects invalid configuration or an empty permutation domain before
    /// active/result state is allocated.
    pub fn new(
        plan: ScanPlan,
        config: SchedulerConfig,
        permutation: SeededPermutation,
    ) -> Result<Self, EngineError> {
        let config = config.validate()?;
        if permutation.length() != plan.logical_probe_count() {
            return Err(EngineError::Plan(
                crate::PlanError::LogicalProbeIndexOutOfRange,
            ));
        }
        let next_wire_id = plan.logical_probe_count();
        Ok(Self {
            plan,
            config,
            permutation,
            lifecycle: SessionLifecycle::Created,
            session_deadline: None,
            last_now: None,
            cursor: 0,
            active: BTreeMap::new(),
            grace: BTreeMap::new(),
            programmes: BTreeMap::new(),
            programme_ready: VecDeque::new(),
            physical: BTreeMap::new(),
            programme_grace: BTreeMap::new(),
            next_wire_id,
            deferred: VecDeque::new(),
            per_target: BTreeMap::new(),
            per_prefix: BTreeMap::new(),
            adaptive_icmp_seen: BTreeMap::new(),
            adaptive_not_before: BTreeMap::new(),
            bucket: None,
            rtt: RttEstimator::default(),
            diagnostics: DiagnosticCounters::default(),
            context_waiting: false,
            sink_backpressured: false,
            stop: None,
            invalidating_generation: None,
        })
    }

    /// Starts the session at one injected monotonic instant.
    ///
    /// # Errors
    ///
    /// Rejects repeated start and deadline overflow.
    pub fn start(&mut self, clock: &impl Clock) -> Result<(), EngineError> {
        if self.lifecycle != SessionLifecycle::Created {
            return Err(EngineError::InvalidLifecycle);
        }
        let now = self.observe_now(clock)?;
        let deadline = now
            .checked_add(self.config.session_deadline)
            .ok_or(EngineError::DeadlineOverflow)?;
        self.session_deadline = Some(deadline);
        self.bucket = Some(TokenBucket::new(
            self.config.rate_per_second,
            self.config.burst,
            now,
        )?);
        self.lifecycle = SessionLifecycle::Running;
        Ok(())
    }

    #[must_use]
    pub const fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub const fn diagnostics(&self) -> DiagnosticCounters {
        self.diagnostics
    }

    #[must_use]
    pub const fn reported_seed(&self) -> Option<u64> {
        self.permutation.reported_seed()
    }

    #[must_use]
    pub const fn accuracy_tradeoff_reported(&self) -> bool {
        self.config.accuracy_tradeoff_reported()
    }

    /// Requests a deterministic no-new-transmission boundary.
    ///
    /// # Errors
    ///
    /// Only a running session can pause.
    pub fn request_pause(&mut self) -> Result<(), EngineError> {
        if self.lifecycle != SessionLifecycle::Running {
            return Err(EngineError::InvalidLifecycle);
        }
        self.lifecycle = SessionLifecycle::Pausing;
        Ok(())
    }

    /// Resumes admission and retransmission.
    ///
    /// # Errors
    ///
    /// Only a paused session can resume.
    pub fn resume(&mut self) -> Result<(), EngineError> {
        if self.lifecycle != SessionLifecycle::Paused {
            return Err(EngineError::InvalidLifecycle);
        }
        self.lifecycle = SessionLifecycle::Running;
        Ok(())
    }

    /// Clears a context-invalidated admission boundary.
    pub fn context_restored(&mut self) {
        if self.invalidating_generation.is_none() {
            self.context_waiting = false;
        }
    }

    /// Runs at most [`MAX_TRANSITIONS_PER_DRIVE`] state transitions.
    ///
    /// # Errors
    ///
    /// Propagates clock, context, or sink contract failures.
    pub fn drive<C, T, R, S>(
        &mut self,
        clock: &C,
        transport: &mut T,
        resolver: &mut R,
        sink: &mut S,
    ) -> Result<DriveReport, EngineError>
    where
        C: Clock,
        T: ProbeTransport,
        R: ContextResolver,
        S: ResultSink,
    {
        if self.lifecycle == SessionLifecycle::Created || self.lifecycle == SessionLifecycle::Closed
        {
            return Err(EngineError::InvalidLifecycle);
        }
        let now = self.observe_now(clock)?;
        self.prune_grace(now);
        let mut report = MutableReport::default();
        self.prune_programme_grace(now, transport, sink, &mut report)?;
        self.sink_backpressured = false;
        if self.lifecycle == SessionLifecycle::Pausing {
            self.lifecycle = SessionLifecycle::Paused;
            report.transitions += 1;
        }
        if self.deadline_reached(now) && !self.is_terminal() && self.stop.is_none() {
            self.initiate_stop(
                ProbeOutcome::SessionDeadline,
                TerminalReason::SessionDeadline,
                SessionLifecycle::Completed,
            );
        }
        if self.stop.is_some() {
            self.settle_stop(now, sink, &mut report)?;
        }
        if self.stop.is_none() && self.invalidating_generation.is_some() {
            self.settle_context_invalidation(now, sink, &mut report)?;
        }
        if !self.is_terminal() && self.stop.is_none() && self.invalidating_generation.is_none() {
            self.process_timeouts(now, sink, &mut report)?;
        }
        if self.lifecycle == SessionLifecycle::Running {
            self.emit_pending(now, transport, sink, &mut report)?;
            if !self.context_waiting {
                self.admit(now, resolver, sink, &mut report)?;
            }
            self.emit_pending(now, transport, sink, &mut report)?;
        }
        self.complete_if_finished();
        self.make_report(now, report)
    }

    /// Applies one correlated evidence event at its exact clock boundary.
    ///
    /// # Errors
    ///
    /// Propagates clock, transport, or sink failures.
    #[allow(
        clippy::too_many_lines,
        clippy::needless_pass_by_value,
        reason = "legacy and programme evidence share one exactly-once lifecycle boundary"
    )]
    pub fn handle_evidence<C, T, S>(
        &mut self,
        clock: &C,
        event: EvidenceEvent,
        transport: &mut T,
        sink: &mut S,
    ) -> Result<(), EngineError>
    where
        C: Clock,
        T: ProbeTransport,
        S: ResultSink,
    {
        let now = self.observe_now(clock)?;
        self.prune_grace(now);
        let mut grace_report = MutableReport::default();
        self.prune_programme_grace(now, transport, sink, &mut grace_report)?;
        if self.deadline_reached(now) && !self.is_terminal() && self.stop.is_none() {
            self.initiate_stop(
                ProbeOutcome::SessionDeadline,
                TerminalReason::SessionDeadline,
                SessionLifecycle::Completed,
            );
            let mut report = MutableReport::default();
            self.settle_stop(now, sink, &mut report)?;
        }
        if self.stop.is_some() {
            self.diagnostics.late_responses = self.diagnostics.late_responses.saturating_add(1);
            return Ok(());
        }
        if self.invalidating_generation.is_some() {
            let event_is_invalidated = self.active.get(&event.probe_id).is_some_and(|active| {
                self.invalidating_generation
                    .is_some_and(|filter| filter.matches(active.context.generation))
            });
            let mut report = MutableReport::default();
            self.settle_context_invalidation(now, sink, &mut report)?;
            if event_is_invalidated && self.active.contains_key(&event.probe_id) {
                self.diagnostics.forged_or_unrelated =
                    self.diagnostics.forged_or_unrelated.saturating_add(1);
                return Ok(());
            }
        }
        if self.physical.contains_key(&event.probe_id)
            || self.programme_grace.contains_key(&event.probe_id)
        {
            self.handle_programme_evidence(now, &event, sink)?;
            self.complete_if_finished();
            return Ok(());
        }
        if self.grace.contains_key(&event.probe_id) {
            self.diagnostics.duplicates = self.diagnostics.duplicates.saturating_add(1);
            self.diagnostics.late_responses = self.diagnostics.late_responses.saturating_add(1);
            return Ok(());
        }
        let Some(active) = self.active.get(&event.probe_id).copied() else {
            self.diagnostics.forged_or_unrelated =
                self.diagnostics.forged_or_unrelated.saturating_add(1);
            return Ok(());
        };
        let ActiveStage::Waiting { purpose, deadline } = active.stage else {
            self.diagnostics.forged_or_unrelated =
                self.diagnostics.forged_or_unrelated.saturating_add(1);
            return Ok(());
        };
        if now >= deadline {
            let mut report = MutableReport::default();
            self.timeout_one(event.probe_id, now, sink, &mut report)?;
            self.diagnostics.late_responses = self.diagnostics.late_responses.saturating_add(1);
            return Ok(());
        }
        if let EmissionPurpose::NeighborSetup(setup) = purpose {
            if !valid_neighbor_evidence(setup, event.kind) {
                self.diagnostics.forged_or_unrelated =
                    self.diagnostics.forged_or_unrelated.saturating_add(1);
                return Ok(());
            }
            let active = self
                .active
                .get_mut(&event.probe_id)
                .ok_or(EngineError::ReservationInvariant)?;
            active.stage = ActiveStage::Pending(EmissionPurpose::Probe);
            active.stage_transmissions = 0;
            return Ok(());
        }

        let Ok(mut terminal) = classify_terminal(active.probe, &event) else {
            self.diagnostics.forged_or_unrelated =
                self.diagnostics.forged_or_unrelated.saturating_add(1);
            return Ok(());
        };
        terminal.rtt = active
            .last_probe_sent_at
            .and_then(|sent| now.elapsed_since(sent));
        if active.stage_transmissions == 1
            && let Some(sample) = terminal.rtt
        {
            self.rtt.observe(sample);
        }
        if self.config.tcp_reset_cleanup
            && active.probe.family == ProbeFamily::TcpSyn
            && event.kind == EvidenceKind::TcpSynAcknowledgment
        {
            let active = self
                .active
                .get_mut(&event.probe_id)
                .ok_or(EngineError::ReservationInvariant)?;
            active.stage = ActiveStage::PendingCleanup(terminal);
            active.stage_transmissions = 0;
            let mut report = MutableReport::default();
            self.emit_pending(now, transport, sink, &mut report)?;
        } else {
            self.terminalize(event.probe_id, now, terminal, sink, None)?;
        }
        self.complete_if_finished();
        Ok(())
    }

    /// Increments one bounded diagnostic without guessing a result.
    pub fn record_diagnostic(&mut self, kind: DiagnosticKind) {
        let counter = match kind {
            DiagnosticKind::ForgedOrUnrelated => &mut self.diagnostics.forged_or_unrelated,
            DiagnosticKind::NonFirstFragment => &mut self.diagnostics.non_first_fragment,
            DiagnosticKind::OpaqueProtocol => &mut self.diagnostics.opaque_protocol,
            DiagnosticKind::InsufficientQuote => &mut self.diagnostics.insufficient_quote,
        };
        *counter = counter.saturating_add(1);
    }

    /// Invalidates active results joined to one route generation.
    ///
    /// # Errors
    ///
    /// Propagates sink failures while settling already-reserved records.
    pub fn invalidate_context(
        &mut self,
        clock: &impl Clock,
        generation: Option<u64>,
        sink: &mut impl ResultSink,
    ) -> Result<(), EngineError> {
        let now = self.observe_now(clock)?;
        self.context_waiting = true;
        self.diagnostics.context_invalidations =
            self.diagnostics.context_invalidations.saturating_add(1);
        let filter = generation.map_or(GenerationFilter::All, GenerationFilter::Exact);
        if self
            .invalidating_generation
            .is_some_and(|active| active != filter)
        {
            return Err(EngineError::InvalidContext);
        }
        self.invalidating_generation = Some(filter);
        let mut report = MutableReport::default();
        self.settle_context_invalidation(now, sink, &mut report)
    }

    fn settle_context_invalidation<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let filter = self
            .invalidating_generation
            .ok_or(EngineError::ReservationInvariant)?;
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let ids: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(id, active)| filter.matches(active.context.generation).then_some(*id))
            .take(remaining)
            .collect();
        for id in ids {
            self.terminalize(
                id,
                now,
                PendingTerminal {
                    outcome: ProbeOutcome::ContextInvalidated,
                    strength: None,
                    rtt: None,
                    reason: TerminalReason::ContextInvalidated,
                },
                sink,
                Some(report),
            )?;
        }
        let programme_ids: Vec<u64> = self
            .programmes
            .iter()
            .filter_map(|(id, logical)| filter.matches(logical.context.generation).then_some(*id))
            .take(MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions))
            .collect();
        for id in programme_ids {
            if self
                .programmes
                .get(&id)
                .is_some_and(|logical| logical.best.as_ref().is_some())
            {
                self.finish_programme_correlations(id, false)?;
                self.settle_programme(id, now, sink, report)?;
            } else {
                self.abort_programme(
                    id,
                    now,
                    ProbeOutcome::ContextInvalidated,
                    TerminalReason::ContextInvalidated,
                    sink,
                    report,
                )?;
            }
        }
        if !self
            .active
            .values()
            .any(|active| filter.matches(active.context.generation))
            && !self
                .programmes
                .values()
                .any(|logical| filter.matches(logical.context.generation))
        {
            self.invalidating_generation = None;
        }
        Ok(())
    }

    /// Cancels admitted work losslessly and stops future admission.
    ///
    /// # Errors
    ///
    /// Propagates clock or sink failures.
    pub fn cancel(
        &mut self,
        clock: &impl Clock,
        sink: &mut impl ResultSink,
    ) -> Result<(), EngineError> {
        if !matches!(
            self.lifecycle,
            SessionLifecycle::Running | SessionLifecycle::Pausing | SessionLifecycle::Paused
        ) {
            return Err(EngineError::InvalidLifecycle);
        }
        let now = self.observe_now(clock)?;
        self.initiate_stop(
            ProbeOutcome::Cancelled,
            TerminalReason::Cancelled,
            SessionLifecycle::Completed,
        );
        let mut report = MutableReport::default();
        self.settle_stop(now, sink, &mut report)?;
        Ok(())
    }

    /// Fails every admitted probe after an unrecoverable transport boundary.
    ///
    /// # Errors
    ///
    /// Propagates clock or sink failures while draining reserved results.
    pub fn transport_failed(
        &mut self,
        clock: &impl Clock,
        code: u32,
        sink: &mut impl ResultSink,
    ) -> Result<(), EngineError> {
        if self.is_terminal() || self.stop.is_some() {
            return Ok(());
        }
        let now = self.observe_now(clock)?;
        let mut report = MutableReport::default();
        self.fail_transport(now, code, sink, &mut report)
    }

    /// Fails every admitted probe after an unrecoverable context boundary.
    ///
    /// # Errors
    ///
    /// Propagates clock or sink failures while draining reserved results.
    pub fn context_failed(
        &mut self,
        clock: &impl Clock,
        sink: &mut impl ResultSink,
    ) -> Result<(), EngineError> {
        if self.is_terminal() || self.stop.is_some() {
            return Ok(());
        }
        let now = self.observe_now(clock)?;
        self.initiate_stop(
            ProbeOutcome::ContextInvalidated,
            TerminalReason::ContextInvalidated,
            SessionLifecycle::Failed,
        );
        let mut report = MutableReport::default();
        self.settle_stop(now, sink, &mut report)
    }

    /// Explicitly disposes admitted results and all correlation state.
    ///
    /// # Errors
    ///
    /// Propagates sink reservation-release failure.
    pub fn close(&mut self, sink: &mut impl ResultSink) -> Result<(), EngineError> {
        if self.lifecycle == SessionLifecycle::Closed {
            return Ok(());
        }
        sink.release_reserved(self.active.len())
            .map_err(EngineError::Sink)?;
        let programme_bytes = self
            .programmes
            .values()
            .try_fold(0_usize, |total, logical| {
                total.checked_add(logical.reservation_bytes)
            })
            .ok_or(EngineError::StateCapacityExceeded)?;
        sink.release_reserved_with_bytes(self.programmes.len(), programme_bytes)
            .map_err(EngineError::Sink)?;
        self.active.clear();
        self.grace.clear();
        self.programmes.clear();
        self.programme_ready.clear();
        self.physical.clear();
        self.programme_grace.clear();
        self.deferred.clear();
        self.per_target.clear();
        self.per_prefix.clear();
        self.stop = None;
        self.invalidating_generation = None;
        self.lifecycle = SessionLifecycle::Closed;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "logical reservation and route admission remain one transactional boundary"
    )]
    fn admit<R: ContextResolver, S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        resolver: &mut R,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let mut examined = 0_usize;
        let mut deferred_remaining = self.deferred.len();
        while self.outstanding_physical() < self.config.max_outstanding
            && self.active.len() + self.programmes.len() < self.config.max_outstanding
            && report.transitions < MAX_TRANSITIONS_PER_DRIVE
            && self.total_correlation_entries() < self.config.max_grace_entries
            && examined < MAX_TRANSITIONS_PER_DRIVE
        {
            let Some(probe) = self.next_candidate(&mut deferred_remaining)? else {
                break;
            };
            examined += 1;
            if self.per_target.get(&probe.target).copied().unwrap_or(0)
                >= self.config.max_per_target
            {
                self.defer(probe)?;
                report.transitions += 1;
                continue;
            }
            let resolution = match resolver.resolve(probe) {
                Ok(value) => value,
                Err(error) => {
                    self.requeue_front(probe)?;
                    return Err(EngineError::Context(error));
                }
            };
            let context = match resolution {
                ContextResolution::Ready(value) => value,
                ContextResolution::Pending => {
                    self.deferred.push_front(probe);
                    self.context_waiting = true;
                    report.transitions += 1;
                    break;
                }
                ContextResolution::Invalidated { .. } => {
                    self.deferred.push_front(probe);
                    self.context_waiting = true;
                    self.diagnostics.context_invalidations =
                        self.diagnostics.context_invalidations.saturating_add(1);
                    report.transitions += 1;
                    break;
                }
            };
            if !valid_neighbor_setup(probe, context.neighbor_setup) {
                self.requeue_front(probe)?;
                return Err(EngineError::InvalidContext);
            }
            if self
                .per_prefix
                .get(&context.prefix_key)
                .copied()
                .unwrap_or(0)
                >= self.config.max_per_prefix
            {
                self.defer(probe)?;
                report.transitions += 1;
                continue;
            }
            let udp_programme = self.plan.udp_programme_for(probe).map(|programme| {
                let port = probe.port.expect("UDP probes always have ports");
                (
                    programme.variant_count_for(probe.target.address, port),
                    programme.maximum_metadata_bytes_for_port(probe.target.address, port),
                    programme.requires_logical_programme(probe.target.address, port),
                )
            });
            if let Some((variant_count, reservation_bytes, requires_programme)) = udp_programme
                && requires_programme
            {
                let reservation = sink
                    .try_reserve_with_bytes(reservation_bytes)
                    .map_err(EngineError::Sink)?;
                if reservation == SinkReservation::Saturated {
                    self.deferred.push_front(probe);
                    self.sink_backpressured = true;
                    report.transitions += 1;
                    break;
                }
                let logical = ProgrammeLogical {
                    probe,
                    context,
                    variant_count,
                    next_variant: 0,
                    active: 0,
                    grace: 0,
                    attempted: 0,
                    transmissions: 0,
                    contradictions: 0,
                    best: None,
                    reservation_bytes,
                    neighbor_ready: context.neighbor_setup.is_none(),
                    stop_unsent: false,
                    soft_service_family: None,
                };
                if self.programmes.insert(probe.logical_id, logical).is_some() {
                    return Err(EngineError::ReservationInvariant);
                }
                if variant_count == 0 {
                    self.settle_programme(probe.logical_id, now, sink, report)?;
                } else {
                    self.programme_ready.push_back(probe.logical_id);
                }
                self.context_waiting = false;
                report.transitions += 1;
                continue;
            }
            let reservation = match sink.try_reserve() {
                Ok(value) => value,
                Err(error) => {
                    self.requeue_front(probe)?;
                    return Err(EngineError::Sink(error));
                }
            };
            match reservation {
                SinkReservation::Saturated => {
                    self.deferred.push_front(probe);
                    self.sink_backpressured = true;
                    report.transitions += 1;
                    break;
                }
                SinkReservation::Reserved => {}
            }
            let purpose = context
                .neighbor_setup
                .map_or(EmissionPurpose::Probe, EmissionPurpose::NeighborSetup);
            if self
                .active
                .insert(
                    probe.logical_id,
                    ActiveProbe {
                        probe,
                        context,
                        stage: ActiveStage::Pending(purpose),
                        stage_transmissions: 0,
                        total_transmissions: 0,
                        last_probe_sent_at: None,
                    },
                )
                .is_some()
            {
                return Err(EngineError::ReservationInvariant);
            }
            increment(&mut self.per_target, probe.target);
            increment(&mut self.per_prefix, context.prefix_key);
            self.context_waiting = false;
            report.transitions += 1;
        }
        Ok(())
    }

    fn emit_pending<T: ProbeTransport, S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        transport: &mut T,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        self.schedule_programme_variants(now, report)?;
        self.emit_programme_pending(now, transport, sink, report)?;
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let ids: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(id, active)| {
                matches!(
                    active.stage,
                    ActiveStage::Pending(_) | ActiveStage::PendingCleanup(_)
                )
                .then_some(*id)
            })
            .take(remaining)
            .collect();
        for id in ids {
            if report.transitions >= MAX_TRANSITIONS_PER_DRIVE {
                break;
            }
            let Some(active) = self.active.get(&id).copied() else {
                continue;
            };
            let (purpose, terminal) = match active.stage {
                ActiveStage::Pending(purpose) => (purpose, None),
                ActiveStage::PendingCleanup(terminal) => {
                    (EmissionPurpose::TcpResetCleanup, Some(terminal))
                }
                ActiveStage::Waiting { .. } => continue,
            };
            if !self
                .bucket
                .as_mut()
                .ok_or(EngineError::InvalidLifecycle)?
                .try_take(now)?
            {
                break;
            }
            let emission = ProbeEmission {
                probe_id: id,
                probe: active.probe,
                route_generation: active.context.generation,
                purpose,
                transmission: active.stage_transmissions.saturating_add(1),
                udp_variant: self
                    .plan
                    .udp_programme_for(active.probe)
                    .and_then(|programme| {
                        programme.variant_at_for(
                            active.probe.target.address,
                            active.probe.port.expect("UDP probes have ports"),
                            0,
                        )
                    }),
            };
            let tracked = self
                .active
                .get_mut(&id)
                .ok_or(EngineError::ReservationInvariant)?;
            if active.probe.family != ProbeFamily::Udp || purpose == EmissionPurpose::Probe {
                tracked.total_transmissions = tracked.total_transmissions.saturating_add(1);
            }
            if let Err(error) = transport.emit(emission) {
                if let Some(terminal) = terminal {
                    self.terminalize(id, now, terminal, sink, Some(report))?;
                }
                self.fail_transport(now, error.code, sink, report)?;
                break;
            }
            report.emissions += 1;
            report.transitions += 1;
            if let Some(terminal) = terminal {
                self.terminalize(id, now, terminal, sink, Some(report))?;
                continue;
            }
            let timeout = self.timeout_for(active.stage_transmissions)?;
            let deadline = now
                .checked_add(timeout)
                .ok_or(EngineError::DeadlineOverflow)?;
            let active = self
                .active
                .get_mut(&id)
                .ok_or(EngineError::ReservationInvariant)?;
            active.stage_transmissions = active.stage_transmissions.saturating_add(1);
            if purpose == EmissionPurpose::Probe {
                active.last_probe_sent_at = Some(now);
            }
            active.stage = ActiveStage::Waiting { purpose, deadline };
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one bounded scheduling transaction applies fairness, adaptive policy, and identity allocation"
    )]
    fn schedule_programme_variants(
        &mut self,
        now: MonotonicTime,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let mut turns = self.programme_ready.len();
        while turns > 0
            && self.outstanding_physical() < self.config.max_outstanding
            && self.total_correlation_entries() < self.config.max_grace_entries
            && report.transitions < MAX_TRANSITIONS_PER_DRIVE
        {
            turns -= 1;
            let Some(logical_id) = self.programme_ready.pop_front() else {
                break;
            };
            let Some(logical) = self.programmes.get(&logical_id) else {
                continue;
            };
            if logical.stop_unsent || logical.next_variant >= logical.variant_count {
                continue;
            }
            let programme = self
                .plan
                .udp_programme_for(logical.probe)
                .ok_or(EngineError::ReservationInvariant)?;
            let maximum_concurrent = if programme.strategy() == UdpProbeStrategy::Adaptive {
                1
            } else {
                MAX_CONCURRENT_UDP_VARIANTS
            };
            if programme.strategy() == UdpProbeStrategy::Adaptive
                && self
                    .adaptive_not_before
                    .get(&logical.probe.target)
                    .is_some_and(|deadline| now < *deadline)
            {
                self.programme_ready.push_back(logical_id);
                continue;
            }
            if logical.active >= maximum_concurrent
                || (!logical.neighbor_ready && logical.active > 0)
                || self
                    .per_target
                    .get(&logical.probe.target)
                    .copied()
                    .unwrap_or(0)
                    >= self.config.max_per_target
                || self
                    .per_prefix
                    .get(&logical.context.prefix_key)
                    .copied()
                    .unwrap_or(0)
                    >= self.config.max_per_prefix
            {
                self.programme_ready.push_back(logical_id);
                continue;
            }
            let mut selected_index = logical.next_variant;
            let variant = loop {
                let Some(candidate) = programme.variant_at_for(
                    logical.probe.target.address,
                    logical.probe.port.expect("UDP probes have ports"),
                    selected_index,
                ) else {
                    break None;
                };
                if logical
                    .soft_service_family
                    .is_none_or(|family| candidate.service_family == Some(family))
                {
                    break Some(candidate);
                }
                selected_index += 1;
            };
            if variant.is_none() {
                self.programmes
                    .get_mut(&logical_id)
                    .ok_or(EngineError::ReservationInvariant)?
                    .next_variant = logical.variant_count;
                continue;
            }
            let variant = variant.expect("checked above");
            let purpose = if logical.neighbor_ready {
                EmissionPurpose::Probe
            } else {
                EmissionPurpose::NeighborSetup(
                    logical
                        .context
                        .neighbor_setup
                        .ok_or(EngineError::InvalidContext)?,
                )
            };
            let wire_id = self.next_wire_id;
            self.next_wire_id = self
                .next_wire_id
                .checked_add(1)
                .ok_or(EngineError::StateCapacityExceeded)?;
            if self
                .physical
                .insert(
                    wire_id,
                    ProgrammePhysical {
                        logical_id,
                        variant,
                        stage: ActiveStage::Pending(purpose),
                        transmissions: 0,
                        last_sent_at: None,
                    },
                )
                .is_some()
            {
                return Err(EngineError::ReservationInvariant);
            }
            let logical = self
                .programmes
                .get_mut(&logical_id)
                .ok_or(EngineError::ReservationInvariant)?;
            logical.next_variant = selected_index + 1;
            logical.active += 1;
            increment(&mut self.per_target, logical.probe.target);
            increment(&mut self.per_prefix, logical.context.prefix_key);
            if logical.neighbor_ready
                && logical.next_variant < logical.variant_count
                && logical.active < maximum_concurrent
            {
                self.programme_ready.push_back(logical_id);
                turns += 1;
            }
            report.transitions += 1;
        }
        Ok(())
    }

    fn emit_programme_pending<T: ProbeTransport, S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        transport: &mut T,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let ids: Vec<u64> = self
            .physical
            .iter()
            .filter_map(|(id, physical)| {
                matches!(physical.stage, ActiveStage::Pending(_)).then_some(*id)
            })
            .take(remaining)
            .collect();
        for wire_id in ids {
            if !self
                .bucket
                .as_mut()
                .ok_or(EngineError::InvalidLifecycle)?
                .try_take(now)?
            {
                break;
            }
            let physical = self
                .physical
                .get(&wire_id)
                .copied()
                .ok_or(EngineError::ReservationInvariant)?;
            let ActiveStage::Pending(purpose) = physical.stage else {
                continue;
            };
            let logical = self
                .programmes
                .get(&physical.logical_id)
                .ok_or(EngineError::ReservationInvariant)?;
            let emission = ProbeEmission {
                probe_id: wire_id,
                probe: logical.probe,
                route_generation: logical.context.generation,
                purpose,
                transmission: physical.transmissions.saturating_add(1),
                udp_variant: Some(physical.variant),
            };
            if let Err(error) = transport.emit(emission) {
                self.fail_transport(now, error.code, sink, report)?;
                break;
            }
            let timeout = self.timeout_for(physical.transmissions)?;
            let deadline = now
                .checked_add(timeout)
                .ok_or(EngineError::DeadlineOverflow)?;
            let tracked = self
                .physical
                .get_mut(&wire_id)
                .ok_or(EngineError::ReservationInvariant)?;
            tracked.transmissions = tracked.transmissions.saturating_add(1);
            tracked.stage = ActiveStage::Waiting { purpose, deadline };
            if purpose == EmissionPurpose::Probe {
                tracked.last_sent_at = Some(now);
                let logical = self
                    .programmes
                    .get_mut(&physical.logical_id)
                    .ok_or(EngineError::ReservationInvariant)?;
                logical.transmissions = logical
                    .transmissions
                    .checked_add(1)
                    .ok_or(EngineError::StateCapacityExceeded)?;
                if physical.transmissions == 0 {
                    logical.attempted = logical.attempted.saturating_add(1);
                }
            }
            report.emissions += 1;
            report.transitions += 1;
        }
        Ok(())
    }

    fn process_timeouts<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let physical_ids: Vec<u64> = self
            .physical
            .iter()
            .filter_map(|(id, physical)| match physical.stage {
                ActiveStage::Waiting { deadline, .. } if now >= deadline => Some(*id),
                _ => None,
            })
            .take(remaining)
            .collect();
        for id in physical_ids {
            self.timeout_programme_one(id, now, report)?;
        }
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let ids: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(id, active)| match active.stage {
                ActiveStage::Waiting { deadline, .. } if now >= deadline => Some(*id),
                _ => None,
            })
            .take(remaining)
            .collect();
        for id in ids {
            if report.transitions >= MAX_TRANSITIONS_PER_DRIVE {
                break;
            }
            self.timeout_one(id, now, sink, report)?;
        }
        Ok(())
    }

    fn timeout_programme_one(
        &mut self,
        wire_id: u64,
        now: MonotonicTime,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let physical = self
            .physical
            .get(&wire_id)
            .copied()
            .ok_or(EngineError::ReservationInvariant)?;
        let ActiveStage::Waiting { purpose, .. } = physical.stage else {
            return Ok(());
        };
        if physical.transmissions.saturating_sub(1) < self.config.max_retransmissions {
            self.physical
                .get_mut(&wire_id)
                .ok_or(EngineError::ReservationInvariant)?
                .stage = ActiveStage::Pending(purpose);
            report.transitions += 1;
            return Ok(());
        }
        if matches!(purpose, EmissionPurpose::NeighborSetup(_)) {
            self.programmes
                .get_mut(&physical.logical_id)
                .ok_or(EngineError::ReservationInvariant)?
                .stop_unsent = true;
        } else if self.programme_strategy(physical.logical_id)? == UdpProbeStrategy::Adaptive {
            let target = self
                .programmes
                .get(&physical.logical_id)
                .ok_or(EngineError::ReservationInvariant)?
                .probe
                .target;
            if self.adaptive_icmp_seen.contains_key(&target) {
                let deadline = now
                    .checked_add(self.config.initial_timeout)
                    .ok_or(EngineError::DeadlineOverflow)?;
                self.adaptive_not_before.insert(target, deadline);
                self.diagnostics.udp_icmp_pacing =
                    self.diagnostics.udp_icmp_pacing.saturating_add(1);
            }
        }
        self.retire_physical(wire_id, now, report)
    }

    fn retire_physical(
        &mut self,
        wire_id: u64,
        now: MonotonicTime,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let physical = self
            .physical
            .remove(&wire_id)
            .ok_or(EngineError::ReservationInvariant)?;
        let expires = now
            .checked_add(self.config.late_grace)
            .ok_or(EngineError::DeadlineOverflow)?;
        let logical = self
            .programmes
            .get_mut(&physical.logical_id)
            .ok_or(EngineError::ReservationInvariant)?;
        logical.active = logical
            .active
            .checked_sub(1)
            .ok_or(EngineError::ReservationInvariant)?;
        logical.grace += 1;
        decrement(&mut self.per_target, logical.probe.target)?;
        decrement(&mut self.per_prefix, logical.context.prefix_key)?;
        self.programme_grace.insert(
            wire_id,
            ProgrammeGrace {
                logical_id: physical.logical_id,
                expires,
                variant: physical.variant,
                last_sent_at: physical.last_sent_at,
            },
        );
        if !logical.stop_unsent
            && logical.next_variant < logical.variant_count
            && !self.programme_ready.contains(&physical.logical_id)
        {
            self.programme_ready.push_back(physical.logical_id);
        }
        report.transitions += 1;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "active, grace, neighbor, hint, and terminal evidence share one exactly-once boundary"
    )]
    fn handle_programme_evidence<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        event: &EvidenceEvent,
        sink: &mut S,
    ) -> Result<(), EngineError> {
        if let Some(grace) = self.programme_grace.get(&event.probe_id).copied() {
            self.diagnostics.late_responses = self.diagnostics.late_responses.saturating_add(1);
            if event.kind == EvidenceKind::UdpServiceHint {
                if let Some(service) = event.udp_service.as_ref() {
                    if self.programme_strategy(grace.logical_id)? == UdpProbeStrategy::Adaptive {
                        self.programmes
                            .get_mut(&grace.logical_id)
                            .ok_or(EngineError::ReservationInvariant)?
                            .soft_service_family = Some(service.family);
                    }
                } else {
                    self.diagnostics.forged_or_unrelated =
                        self.diagnostics.forged_or_unrelated.saturating_add(1);
                }
                return Ok(());
            }
            if let Some(best) = classify_udp_evidence(grace.variant, event, grace.last_sent_at, now)
            {
                let decisive = best.rank == 4;
                let adaptive_stop = self.programme_strategy(grace.logical_id)?
                    == UdpProbeStrategy::Adaptive
                    && best.rank >= 3;
                self.update_programme_best(grace.logical_id, best)?;
                if adaptive_stop {
                    self.programmes
                        .get_mut(&grace.logical_id)
                        .ok_or(EngineError::ReservationInvariant)?
                        .stop_unsent = true;
                } else if decisive {
                    self.finish_programme_correlations(grace.logical_id, true)?;
                }
                if adaptive_stop || decisive {
                    let mut report = MutableReport::default();
                    self.settle_ready_programmes(now, sink, &mut report)?;
                }
            } else if !is_udp_observation(event.kind) {
                self.diagnostics.forged_or_unrelated =
                    self.diagnostics.forged_or_unrelated.saturating_add(1);
            }
            return Ok(());
        }
        let physical = self
            .physical
            .get(&event.probe_id)
            .copied()
            .ok_or(EngineError::ReservationInvariant)?;
        let ActiveStage::Waiting { purpose, deadline } = physical.stage else {
            self.diagnostics.forged_or_unrelated =
                self.diagnostics.forged_or_unrelated.saturating_add(1);
            return Ok(());
        };
        if now >= deadline {
            let mut report = MutableReport::default();
            self.timeout_programme_one(event.probe_id, now, &mut report)?;
            self.diagnostics.late_responses = self.diagnostics.late_responses.saturating_add(1);
            if let Some(grace) = self.programme_grace.get(&event.probe_id).copied()
                && let Some(best) =
                    classify_udp_evidence(grace.variant, event, grace.last_sent_at, now)
            {
                let decisive = best.rank == 4;
                let adaptive_stop = self.programme_strategy(grace.logical_id)?
                    == UdpProbeStrategy::Adaptive
                    && best.rank >= 3;
                self.update_programme_best(grace.logical_id, best)?;
                if adaptive_stop {
                    self.programmes
                        .get_mut(&grace.logical_id)
                        .ok_or(EngineError::ReservationInvariant)?
                        .stop_unsent = true;
                    self.settle_ready_programmes(now, sink, &mut report)?;
                } else if decisive {
                    self.finish_programme_correlations(grace.logical_id, true)?;
                    self.settle_ready_programmes(now, sink, &mut report)?;
                }
            }
            return Ok(());
        }
        if let EmissionPurpose::NeighborSetup(setup) = purpose {
            if !valid_neighbor_evidence(setup, event.kind) {
                self.diagnostics.forged_or_unrelated =
                    self.diagnostics.forged_or_unrelated.saturating_add(1);
                return Ok(());
            }
            self.physical
                .get_mut(&event.probe_id)
                .ok_or(EngineError::ReservationInvariant)?
                .stage = ActiveStage::Pending(EmissionPurpose::Probe);
            self.physical
                .get_mut(&event.probe_id)
                .ok_or(EngineError::ReservationInvariant)?
                .transmissions = 0;
            let logical = self
                .programmes
                .get_mut(&physical.logical_id)
                .ok_or(EngineError::ReservationInvariant)?;
            logical.neighbor_ready = true;
            if !self.programme_ready.contains(&physical.logical_id) {
                self.programme_ready.push_back(physical.logical_id);
            }
            return Ok(());
        }
        if event.kind == EvidenceKind::UdpServiceHint {
            let Some(service) = event.udp_service.as_ref() else {
                self.diagnostics.forged_or_unrelated =
                    self.diagnostics.forged_or_unrelated.saturating_add(1);
                return Ok(());
            };
            if self.programme_strategy(physical.logical_id)? == UdpProbeStrategy::Adaptive {
                self.programmes
                    .get_mut(&physical.logical_id)
                    .ok_or(EngineError::ReservationInvariant)?
                    .soft_service_family = Some(service.family);
            }
            let mut report = MutableReport::default();
            self.retire_physical(event.probe_id, now, &mut report)?;
            self.settle_ready_programmes(now, sink, &mut report)?;
            return Ok(());
        }
        let Some(best) = classify_udp_evidence(physical.variant, event, physical.last_sent_at, now)
        else {
            if !is_udp_observation(event.kind) {
                self.diagnostics.forged_or_unrelated =
                    self.diagnostics.forged_or_unrelated.saturating_add(1);
            }
            return Ok(());
        };
        let decisive = best.rank == 4;
        let adaptive_stop = self.programme_strategy(physical.logical_id)?
            == UdpProbeStrategy::Adaptive
            && best.rank >= 3;
        if self.programme_strategy(physical.logical_id)? == UdpProbeStrategy::Adaptive
            && event.icmp.is_some()
        {
            let target = self
                .programmes
                .get(&physical.logical_id)
                .ok_or(EngineError::ReservationInvariant)?
                .probe
                .target;
            let value = self.adaptive_icmp_seen.entry(target).or_default();
            *value = value.saturating_add(1);
        }
        self.update_programme_best(physical.logical_id, best)?;
        let mut report = MutableReport::default();
        self.retire_physical(event.probe_id, now, &mut report)?;
        if adaptive_stop {
            self.programmes
                .get_mut(&physical.logical_id)
                .ok_or(EngineError::ReservationInvariant)?
                .stop_unsent = true;
        } else if decisive {
            self.finish_programme_correlations(physical.logical_id, true)?;
        }
        self.settle_ready_programmes(now, sink, &mut report)
    }

    fn programme_strategy(&self, logical_id: u64) -> Result<UdpProbeStrategy, EngineError> {
        let logical = self
            .programmes
            .get(&logical_id)
            .ok_or(EngineError::ReservationInvariant)?;
        self.plan
            .udp_programme_for(logical.probe)
            .map(crate::UdpProbeProgramme::strategy)
            .ok_or(EngineError::ReservationInvariant)
    }

    fn update_programme_best(
        &mut self,
        logical_id: u64,
        candidate: ProgrammeBest,
    ) -> Result<(), EngineError> {
        let logical = self
            .programmes
            .get_mut(&logical_id)
            .ok_or(EngineError::ReservationInvariant)?;
        if logical
            .best
            .as_ref()
            .is_some_and(|prior| prior.state != candidate.state)
        {
            logical.contradictions = logical.contradictions.saturating_add(1);
        }
        let replace = logical.best.as_ref().is_none_or(|prior| {
            candidate.rank > prior.rank
                || (candidate.rank == prior.rank
                    && (service_rank(candidate.service.as_ref())
                        > service_rank(prior.service.as_ref())
                        || (service_rank(candidate.service.as_ref())
                            == service_rank(prior.service.as_ref())
                            && variant_order(candidate.variant) < variant_order(prior.variant))))
        });
        if replace {
            logical.best = Some(candidate);
        }
        Ok(())
    }

    fn finish_programme_correlations(
        &mut self,
        logical_id: u64,
        normalize_decisive: bool,
    ) -> Result<(), EngineError> {
        let (target, prefix) = self
            .programmes
            .get(&logical_id)
            .map(|logical| (logical.probe.target, logical.context.prefix_key))
            .ok_or(EngineError::ReservationInvariant)?;
        let active_ids: Vec<u64> = self
            .physical
            .iter()
            .filter_map(|(id, physical)| (physical.logical_id == logical_id).then_some(*id))
            .collect();
        for id in active_ids {
            self.physical.remove(&id);
            decrement(&mut self.per_target, target)?;
            decrement(&mut self.per_prefix, prefix)?;
        }
        self.programme_grace
            .retain(|_, grace| grace.logical_id != logical_id);
        self.programme_ready.retain(|id| *id != logical_id);
        let logical = self
            .programmes
            .get_mut(&logical_id)
            .ok_or(EngineError::ReservationInvariant)?;
        logical.active = 0;
        logical.grace = 0;
        logical.stop_unsent = true;
        // A direct UDP response is the maximum lattice rank. Earlier/later
        // lower-rank observations cannot change the serialized winner, and
        // normalizing this non-wire diagnostic keeps arrival order irrelevant.
        if normalize_decisive {
            logical.contradictions = 0;
        }
        Ok(())
    }

    fn prune_programme_grace<T: ProbeTransport, S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        transport: &mut T,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let expired: Vec<u64> = self
            .programme_grace
            .iter()
            .filter_map(|(id, grace)| (now >= grace.expires).then_some(*id))
            .take(MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions))
            .collect();
        for id in expired {
            let grace = self
                .programme_grace
                .remove(&id)
                .ok_or(EngineError::ReservationInvariant)?;
            transport.retire(id);
            let logical = self
                .programmes
                .get_mut(&grace.logical_id)
                .ok_or(EngineError::ReservationInvariant)?;
            logical.grace = logical
                .grace
                .checked_sub(1)
                .ok_or(EngineError::ReservationInvariant)?;
            report.transitions += 1;
        }
        self.settle_ready_programmes(now, sink, report)
    }

    fn settle_ready_programmes<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let ready: Vec<u64> = self
            .programmes
            .iter()
            .filter_map(|(id, logical)| {
                let no_more = logical.stop_unsent || logical.next_variant == logical.variant_count;
                (no_more && logical.active == 0 && logical.grace == 0).then_some(*id)
            })
            .take(MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions))
            .collect();
        for logical_id in ready {
            self.settle_programme(logical_id, now, sink, report)?;
        }
        Ok(())
    }

    fn settle_programme<S: ResultSink>(
        &mut self,
        logical_id: u64,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let logical = self
            .programmes
            .remove(&logical_id)
            .ok_or(EngineError::ReservationInvariant)?;
        let (outcome, strength, rtt, reason, response_kind, terminal_probe_id, service) =
            logical.best.map_or(
                (
                    ProbeOutcome::Network(NetworkState::OpenOrFiltered),
                    None,
                    None,
                    TerminalReason::Timeout,
                    UdpResponseKind::Silence,
                    None,
                    None,
                ),
                |best| {
                    (
                        ProbeOutcome::Network(best.state),
                        best.strength,
                        best.rtt,
                        best.reason,
                        best.response_kind,
                        best.variant.catalogue_probe_id,
                        best.service,
                    )
                },
            );
        let result = ScanResult {
            probe: logical.probe,
            outcome,
            evidence_strength: strength,
            attempt: logical.probe.attempt,
            transmissions: logical.transmissions,
            rtt,
            terminal_at: now,
            route_generation: logical.context.generation,
            terminal_reason: reason,
            udp: Some(UdpResultEvidence {
                terminal_probe_id,
                variants_attempted: logical.attempted,
                response_kind,
                contradictions: logical.contradictions,
                service,
            }),
        };
        let actual_metadata_bytes = result
            .udp
            .as_ref()
            .and_then(|udp| udp.service.as_ref())
            .map_or(0, |service| service.metadata.len());
        sink.commit_reserved_with_bytes(result, actual_metadata_bytes, logical.reservation_bytes)
            .map_err(EngineError::Sink)?;
        self.prune_adaptive_target_state(logical.probe.target);
        report.results += 1;
        report.transitions += 1;
        Ok(())
    }

    fn prune_adaptive_target_state(&mut self, target: crate::ScanTarget) {
        if !self
            .programmes
            .values()
            .any(|logical| logical.probe.target == target)
        {
            self.adaptive_icmp_seen.remove(&target);
            self.adaptive_not_before.remove(&target);
        }
    }

    fn abort_programme<S: ResultSink>(
        &mut self,
        logical_id: u64,
        now: MonotonicTime,
        outcome: ProbeOutcome,
        reason: TerminalReason,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let logical = self
            .programmes
            .remove(&logical_id)
            .ok_or(EngineError::ReservationInvariant)?;
        let active_ids: Vec<u64> = self
            .physical
            .iter()
            .filter_map(|(id, physical)| (physical.logical_id == logical_id).then_some(*id))
            .collect();
        for id in active_ids {
            let physical = self
                .physical
                .remove(&id)
                .ok_or(EngineError::ReservationInvariant)?;
            decrement(&mut self.per_target, logical.probe.target)?;
            decrement(&mut self.per_prefix, logical.context.prefix_key)?;
            debug_assert_eq!(physical.logical_id, logical_id);
        }
        self.programme_grace
            .retain(|_, grace| grace.logical_id != logical_id);
        self.programme_ready.retain(|id| *id != logical_id);
        let result = ScanResult {
            probe: logical.probe,
            outcome,
            evidence_strength: None,
            attempt: logical.probe.attempt,
            transmissions: logical.transmissions,
            rtt: None,
            terminal_at: now,
            route_generation: logical.context.generation,
            terminal_reason: reason,
            udp: Some(UdpResultEvidence {
                terminal_probe_id: None,
                variants_attempted: logical.attempted,
                response_kind: UdpResponseKind::Silence,
                contradictions: logical.contradictions,
                service: None,
            }),
        };
        sink.commit_reserved_with_bytes(result, 0, logical.reservation_bytes)
            .map_err(EngineError::Sink)?;
        report.results += 1;
        report.transitions += 1;
        Ok(())
    }

    fn timeout_one<S: ResultSink>(
        &mut self,
        id: u64,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let active = self
            .active
            .get(&id)
            .copied()
            .ok_or(EngineError::ReservationInvariant)?;
        let ActiveStage::Waiting { purpose, .. } = active.stage else {
            return Ok(());
        };
        let retries_used = active.stage_transmissions.saturating_sub(1);
        if retries_used < self.config.max_retransmissions {
            let active = self
                .active
                .get_mut(&id)
                .ok_or(EngineError::ReservationInvariant)?;
            active.stage = ActiveStage::Pending(purpose);
            report.transitions += 1;
            return Ok(());
        }
        let terminal = timeout_terminal(active.probe, self.config.discovery_silence);
        self.terminalize(id, now, terminal, sink, Some(report))
    }

    fn terminalize<S: ResultSink>(
        &mut self,
        id: u64,
        now: MonotonicTime,
        terminal: PendingTerminal,
        sink: &mut S,
        report: Option<&mut MutableReport>,
    ) -> Result<(), EngineError> {
        let active = self
            .active
            .get(&id)
            .copied()
            .ok_or(EngineError::ReservationInvariant)?;
        if self.grace.contains_key(&id)
            || self
                .per_target
                .get(&active.probe.target)
                .copied()
                .unwrap_or(0)
                == 0
            || self
                .per_prefix
                .get(&active.context.prefix_key)
                .copied()
                .unwrap_or(0)
                == 0
        {
            return Err(EngineError::ReservationInvariant);
        }
        let expires = now
            .checked_add(self.config.late_grace)
            .ok_or(EngineError::DeadlineOverflow)?;
        let result = ScanResult {
            probe: active.probe,
            outcome: terminal.outcome,
            evidence_strength: terminal.strength,
            attempt: active.probe.attempt,
            transmissions: active.total_transmissions,
            rtt: terminal.rtt,
            terminal_at: now,
            route_generation: active.context.generation,
            terminal_reason: terminal.reason,
            udp: None,
        };
        sink.commit_reserved(result).map_err(EngineError::Sink)?;
        if self.active.remove(&id).is_none() {
            return Err(EngineError::ReservationInvariant);
        }
        decrement(&mut self.per_target, active.probe.target)?;
        decrement(&mut self.per_prefix, active.context.prefix_key)?;
        self.grace.insert(id, expires);
        if let Some(report) = report {
            report.results += 1;
            report.transitions += 1;
        }
        Ok(())
    }

    fn initiate_stop(
        &mut self,
        outcome: ProbeOutcome,
        reason: TerminalReason,
        final_lifecycle: SessionLifecycle,
    ) {
        self.cursor = self.plan.logical_probe_count();
        self.deferred.clear();
        self.invalidating_generation = None;
        self.lifecycle = SessionLifecycle::Cancelling;
        self.stop = Some(StopState {
            outcome,
            reason,
            final_lifecycle,
        });
    }

    fn settle_stop<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let stop = self.stop.ok_or(EngineError::ReservationInvariant)?;
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let ids: Vec<u64> = self.active.keys().copied().take(remaining).collect();
        for id in ids {
            self.terminalize(
                id,
                now,
                PendingTerminal {
                    outcome: stop.outcome,
                    strength: None,
                    rtt: None,
                    reason: stop.reason,
                },
                sink,
                Some(report),
            )?;
        }
        let programme_ids: Vec<u64> = self
            .programmes
            .keys()
            .copied()
            .take(MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions))
            .collect();
        for id in programme_ids {
            if self
                .programmes
                .get(&id)
                .is_some_and(|logical| logical.best.is_some())
            {
                self.finish_programme_correlations(id, false)?;
                self.settle_programme(id, now, sink, report)?;
            } else {
                self.abort_programme(id, now, stop.outcome, stop.reason, sink, report)?;
            }
        }
        if self.active.is_empty() && self.programmes.is_empty() {
            self.lifecycle = stop.final_lifecycle;
            self.stop = None;
        }
        Ok(())
    }

    fn fail_transport<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        code: u32,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        self.initiate_stop(
            ProbeOutcome::TransportFailed,
            TerminalReason::TransportFailure(code),
            SessionLifecycle::Failed,
        );
        self.settle_stop(now, sink, report)
    }

    fn next_candidate(
        &mut self,
        deferred_remaining: &mut usize,
    ) -> Result<Option<LogicalProbe>, EngineError> {
        if *deferred_remaining > 0 {
            *deferred_remaining -= 1;
            return Ok(self.deferred.pop_front());
        }
        if self.cursor >= self.plan.logical_probe_count() {
            return Ok(None);
        }
        let logical_id = self
            .permutation
            .permute(self.cursor)
            .ok_or(EngineError::ReservationInvariant)?;
        self.cursor += 1;
        self.plan
            .logical_probe_at(logical_id)
            .map(Some)
            .map_err(EngineError::Plan)
    }

    fn defer(&mut self, probe: LogicalProbe) -> Result<(), EngineError> {
        if self.deferred.len() == MAX_DEFERRED_CANDIDATES {
            return Err(EngineError::StateCapacityExceeded);
        }
        self.deferred.push_back(probe);
        Ok(())
    }

    fn requeue_front(&mut self, probe: LogicalProbe) -> Result<(), EngineError> {
        if self.deferred.len() == MAX_DEFERRED_CANDIDATES {
            return Err(EngineError::StateCapacityExceeded);
        }
        self.deferred.push_front(probe);
        Ok(())
    }

    fn timeout_for(&self, prior_transmissions: u8) -> Result<ScanDuration, EngineError> {
        let base = self.rtt.timeout(
            self.config.timing_mode,
            self.config.initial_timeout,
            self.config.minimum_timeout,
            self.config.maximum_timeout,
        )?;
        let shift = u32::from(prior_transmissions.min(31));
        Ok(base
            .saturating_mul(1_u32 << shift)
            .min(self.config.maximum_timeout))
    }

    fn observe_now(&mut self, clock: &impl Clock) -> Result<MonotonicTime, EngineError> {
        let now = clock.now();
        if self.last_now.is_some_and(|last| now < last) {
            return Err(EngineError::ClockRegressed);
        }
        self.last_now = Some(now);
        Ok(now)
    }

    fn outstanding_physical(&self) -> usize {
        self.active.len().saturating_add(self.physical.len())
    }

    fn total_correlation_entries(&self) -> usize {
        self.active
            .len()
            .saturating_add(self.physical.len())
            .saturating_add(self.grace.len())
            .saturating_add(self.programme_grace.len())
    }

    fn can_schedule_programme_variant(&self, now: MonotonicTime) -> bool {
        if self.outstanding_physical() >= self.config.max_outstanding
            || self.total_correlation_entries() >= self.config.max_grace_entries
        {
            return false;
        }
        self.programme_ready.iter().any(|logical_id| {
            self.programmes.get(logical_id).is_some_and(|logical| {
                let programme = self.plan.udp_programme_for(logical.probe);
                let maximum_concurrent = if programme
                    .is_some_and(|value| value.strategy() == UdpProbeStrategy::Adaptive)
                {
                    1
                } else {
                    MAX_CONCURRENT_UDP_VARIANTS
                };
                !logical.stop_unsent
                    && logical.next_variant < logical.variant_count
                    && logical.active < maximum_concurrent
                    && self
                        .adaptive_not_before
                        .get(&logical.probe.target)
                        .is_none_or(|deadline| now >= *deadline)
                    && (logical.neighbor_ready || logical.active == 0)
                    && self
                        .per_target
                        .get(&logical.probe.target)
                        .copied()
                        .unwrap_or(0)
                        < self.config.max_per_target
                    && self
                        .per_prefix
                        .get(&logical.context.prefix_key)
                        .copied()
                        .unwrap_or(0)
                        < self.config.max_per_prefix
            })
        })
    }

    fn deadline_reached(&self, now: MonotonicTime) -> bool {
        self.session_deadline
            .is_some_and(|deadline| now >= deadline)
    }

    fn prune_grace(&mut self, now: MonotonicTime) {
        self.grace.retain(|_, expires| now < *expires);
    }

    fn complete_if_finished(&mut self) {
        if self.lifecycle == SessionLifecycle::Running
            && self.cursor == self.plan.logical_probe_count()
            && self.deferred.is_empty()
            && self.active.is_empty()
            && self.programmes.is_empty()
            && self.physical.is_empty()
        {
            self.lifecycle = SessionLifecycle::Completed;
        }
    }

    const fn is_terminal(&self) -> bool {
        matches!(
            self.lifecycle,
            SessionLifecycle::Completed | SessionLifecycle::Failed | SessionLifecycle::Closed
        )
    }

    fn make_report(
        &mut self,
        now: MonotonicTime,
        report: MutableReport,
    ) -> Result<DriveReport, EngineError> {
        if self.is_terminal() {
            return Ok(DriveReport {
                lifecycle: self.lifecycle,
                transitions: report.transitions,
                emissions: report.emissions,
                results: report.results,
                outstanding: self.outstanding_physical(),
                deferred: self.deferred.len(),
                grace: self.grace.len().saturating_add(self.programme_grace.len()),
                sink_backpressured: self.sink_backpressured,
                context_waiting: self.context_waiting,
                next_wakeup: None,
            });
        }
        let mut next_wakeup = self.session_deadline;
        if self.stop.is_some() || self.invalidating_generation.is_some() {
            next_wakeup = Some(now);
        }
        for active in self.active.values() {
            if let ActiveStage::Waiting { deadline, .. } = active.stage {
                next_wakeup = earlier(next_wakeup, Some(deadline));
            }
        }
        for physical in self.physical.values() {
            if let ActiveStage::Waiting { deadline, .. } = physical.stage {
                next_wakeup = earlier(next_wakeup, Some(deadline));
            }
        }
        if self.lifecycle == SessionLifecycle::Running {
            next_wakeup = earlier(next_wakeup, self.grace.values().copied().min());
            next_wakeup = earlier(
                next_wakeup,
                self.programme_grace
                    .values()
                    .map(|grace| grace.expires)
                    .min(),
            );
            next_wakeup = earlier(
                next_wakeup,
                self.adaptive_not_before
                    .values()
                    .copied()
                    .filter(|value| now < *value)
                    .min(),
            );
        }
        let has_pending_frame = self.active.values().any(|active| {
            matches!(
                active.stage,
                ActiveStage::Pending(_) | ActiveStage::PendingCleanup(_)
            )
        }) || self
            .physical
            .values()
            .any(|physical| matches!(physical.stage, ActiveStage::Pending(_)))
            || self.can_schedule_programme_variant(now);
        let can_admit = !self.context_waiting
            && !self.sink_backpressured
            && (self.cursor < self.plan.logical_probe_count() || !self.deferred.is_empty());
        if self.lifecycle == SessionLifecycle::Running && (has_pending_frame || can_admit) {
            let token_ready = self
                .bucket
                .as_mut()
                .ok_or(EngineError::InvalidLifecycle)?
                .next_ready(now)?;
            next_wakeup = earlier(next_wakeup, Some(token_ready));
        }
        Ok(DriveReport {
            lifecycle: self.lifecycle,
            transitions: report.transitions,
            emissions: report.emissions,
            results: report.results,
            outstanding: self.outstanding_physical(),
            deferred: self.deferred.len(),
            grace: self.grace.len().saturating_add(self.programme_grace.len()),
            sink_backpressured: self.sink_backpressured,
            context_waiting: self.context_waiting,
            next_wakeup,
        })
    }
}

fn service_rank(service: Option<&crate::UdpServiceEvidence>) -> u8 {
    service.map_or(0, |value| value.confidence as u8)
}

#[derive(Clone, Copy, Default)]
struct MutableReport {
    transitions: usize,
    emissions: usize,
    results: usize,
}

fn classify_terminal(
    probe: LogicalProbe,
    event: &EvidenceEvent,
) -> Result<PendingTerminal, EngineError> {
    let state = match probe.family {
        ProbeFamily::TcpSyn => match event.kind {
            EvidenceKind::TcpSynAcknowledgment => NetworkState::Open,
            EvidenceKind::TcpReset => NetworkState::Closed,
            EvidenceKind::IcmpPortUnreachable
            | EvidenceKind::IcmpOtherError
            | EvidenceKind::ExplicitUnreachable => NetworkState::Filtered,
            _ => return Err(EngineError::InvalidEvidence),
        },
        ProbeFamily::Udp => match event.kind {
            EvidenceKind::UdpReply => NetworkState::Open,
            EvidenceKind::IcmpPortUnreachable => NetworkState::Closed,
            EvidenceKind::IcmpOtherError | EvidenceKind::ExplicitUnreachable => {
                NetworkState::Filtered
            }
            _ => return Err(EngineError::InvalidEvidence),
        },
        ProbeFamily::Arp => match event.kind {
            EvidenceKind::ArpReply => NetworkState::Up,
            EvidenceKind::IcmpOtherError | EvidenceKind::ExplicitUnreachable => {
                NetworkState::Unreachable
            }
            _ => return Err(EngineError::InvalidEvidence),
        },
        ProbeFamily::Ndp => match event.kind {
            EvidenceKind::NeighborAdvertisement => NetworkState::Up,
            EvidenceKind::IcmpOtherError | EvidenceKind::ExplicitUnreachable => {
                NetworkState::Unreachable
            }
            _ => return Err(EngineError::InvalidEvidence),
        },
        ProbeFamily::Icmpv4Echo | ProbeFamily::Icmpv6Echo => match event.kind {
            EvidenceKind::EchoReply => NetworkState::Up,
            EvidenceKind::IcmpPortUnreachable
            | EvidenceKind::IcmpOtherError
            | EvidenceKind::ExplicitUnreachable => NetworkState::Unreachable,
            _ => return Err(EngineError::InvalidEvidence),
        },
    };
    Ok(PendingTerminal {
        outcome: ProbeOutcome::Network(state),
        strength: Some(event.strength),
        rtt: None,
        reason: TerminalReason::Evidence(event.kind),
    })
}

fn classify_udp_evidence(
    variant: UdpProbeVariant,
    event: &EvidenceEvent,
    sent_at: Option<MonotonicTime>,
    now: MonotonicTime,
) -> Option<ProgrammeBest> {
    let (rank, state, response_kind) = match event.kind {
        EvidenceKind::UdpReply => (4, NetworkState::Open, UdpResponseKind::DirectUdp),
        EvidenceKind::IcmpPortUnreachable
        | EvidenceKind::IcmpOtherError
        | EvidenceKind::ExplicitUnreachable => classify_udp_icmp(event.icmp, event.kind)?,
        _ => return None,
    };
    Some(ProgrammeBest {
        rank,
        state,
        strength: Some(event.strength),
        reason: TerminalReason::Evidence(event.kind),
        response_kind,
        variant,
        rtt: sent_at.and_then(|sent| now.elapsed_since(sent)),
        service: event.udp_service.clone(),
    })
}

const fn is_udp_observation(kind: EvidenceKind) -> bool {
    matches!(
        kind,
        EvidenceKind::UdpReply
            | EvidenceKind::IcmpPortUnreachable
            | EvidenceKind::IcmpOtherError
            | EvidenceKind::ExplicitUnreachable
    )
}

fn classify_udp_icmp(
    detail: Option<IcmpEvidence>,
    legacy_kind: EvidenceKind,
) -> Option<(u8, NetworkState, UdpResponseKind)> {
    let Some(detail) = detail else {
        return match legacy_kind {
            EvidenceKind::IcmpPortUnreachable => Some((
                3,
                NetworkState::Closed,
                UdpResponseKind::Icmpv4TargetPortUnreachable,
            )),
            EvidenceKind::IcmpOtherError | EvidenceKind::ExplicitUnreachable => {
                Some((2, NetworkState::Filtered, UdpResponseKind::OtherIcmpv4))
            }
            _ => None,
        };
    };
    match (detail.family, detail.message_type, detail.code) {
        (4, 3, 3) | (6, 1, 4) if detail.emitter_is_target => Some((
            3,
            NetworkState::Closed,
            if detail.family == 4 {
                UdpResponseKind::Icmpv4TargetPortUnreachable
            } else {
                UdpResponseKind::Icmpv6TargetPortUnreachable
            },
        )),
        (4, 3, 3) => Some((2, NetworkState::Filtered, UdpResponseKind::OtherIcmpv4)),
        (4, 3, 0 | 1 | 2 | 9 | 10 | 13) | (4, 11, 0 | 1) | (6, 1, 0..=6) | (6, 4, 1) => Some((
            2,
            NetworkState::Filtered,
            if detail.family == 4 {
                UdpResponseKind::OtherIcmpv4
            } else if detail.message_type == 4 {
                UdpResponseKind::Icmpv6ParameterProblem
            } else {
                UdpResponseKind::OtherIcmpv6
            },
        )),
        (6, 4, 0) => Some((
            4,
            NetworkState::Open,
            UdpResponseKind::Icmpv6ParameterProblem,
        )),
        _ => None,
    }
}

const fn variant_order(variant: UdpProbeVariant) -> (u16, u16) {
    (
        match variant.catalogue_probe_id {
            Some(value) => value.get(),
            None => u16::MAX,
        },
        variant.request_index,
    )
}

const fn valid_neighbor_setup(probe: LogicalProbe, setup: Option<ProbeFamily>) -> bool {
    match (probe.target.address, setup) {
        (_, None)
        | (nodenet_protocols::IpAddress::V4(_), Some(ProbeFamily::Arp))
        | (nodenet_protocols::IpAddress::V6(_), Some(ProbeFamily::Ndp)) => true,
        (nodenet_protocols::IpAddress::V4(_) | nodenet_protocols::IpAddress::V6(_), Some(_)) => {
            false
        }
    }
}

const fn valid_neighbor_evidence(setup: ProbeFamily, kind: EvidenceKind) -> bool {
    matches!(kind, EvidenceKind::NeighborResolved)
        || matches!(
            (setup, kind),
            (ProbeFamily::Arp, EvidenceKind::ArpReply)
                | (ProbeFamily::Ndp, EvidenceKind::NeighborAdvertisement)
        )
}

const fn timeout_terminal(
    probe: LogicalProbe,
    discovery_policy: DiscoverySilencePolicy,
) -> PendingTerminal {
    let state = match probe.family {
        ProbeFamily::TcpSyn => NetworkState::Filtered,
        ProbeFamily::Udp => NetworkState::OpenOrFiltered,
        ProbeFamily::Arp | ProbeFamily::Ndp | ProbeFamily::Icmpv4Echo | ProbeFamily::Icmpv6Echo => {
            match discovery_policy {
                DiscoverySilencePolicy::Unknown => NetworkState::Unknown,
                DiscoverySilencePolicy::DownByPolicy => NetworkState::DownByPolicy,
            }
        }
    };
    PendingTerminal {
        outcome: ProbeOutcome::Network(state),
        strength: None,
        rtt: None,
        reason: TerminalReason::Timeout,
    }
}

fn increment<K: Ord>(counts: &mut BTreeMap<K, usize>, key: K) {
    *counts.entry(key).or_insert(0) += 1;
}

fn decrement<K: Ord + Copy>(counts: &mut BTreeMap<K, usize>, key: K) -> Result<(), EngineError> {
    let value = counts
        .get_mut(&key)
        .ok_or(EngineError::ReservationInvariant)?;
    *value = value
        .checked_sub(1)
        .ok_or(EngineError::ReservationInvariant)?;
    if *value == 0 {
        counts.remove(&key);
    }
    Ok(())
}

const fn earlier(
    left: Option<MonotonicTime>,
    right: Option<MonotonicTime>,
) -> Option<MonotonicTime> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left.as_micros() <= right.as_micros() {
            left
        } else {
            right
        }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}
