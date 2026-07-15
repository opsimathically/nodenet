use crate::{
    ContextFailure, ContextResolution, EngineError, LogicalProbe, MonotonicTime, ProbeEmission,
    ScanResult, SinkFailure, SinkReservation, TransportFailure,
};

/// Injected monotonic time source; implementations must never move backwards.
pub trait Clock {
    fn now(&self) -> MonotonicTime;
}

/// Injected public scheduling entropy, independent from correlation secrets.
pub trait EntropySource {
    /// # Errors
    ///
    /// Reports caller-specific entropy acquisition failure.
    fn scheduling_seed(&mut self) -> Result<u64, EngineError>;
}

/// Generic frame-emission boundary implemented by the Phase 22 data plane.
pub trait ProbeTransport {
    /// # Errors
    ///
    /// Returns a compact fatal transport error; the scheduler never retries an
    /// unknown partial send.
    fn emit(&mut self, emission: ProbeEmission) -> Result<(), TransportFailure>;

    /// Releases one physical correlation lane after its finite engine grace.
    /// Syscall-free test transports do not need to retain external state.
    fn retire(&mut self, _probe_id: u64) {}
}

/// Policy-aware route context boundary implemented by Phase 20 integration.
pub trait ContextResolver {
    /// # Errors
    ///
    /// Returns a compact context-driver failure.
    fn resolve(&mut self, probe: LogicalProbe) -> Result<ContextResolution, ContextFailure>;
}

/// Lossless result capacity boundary. Reservations precede every first emission.
pub trait ResultSink {
    /// Reserves one terminal result slot without blocking the scheduler.
    ///
    /// # Errors
    ///
    /// Reports sink failure independently from ordinary saturation.
    fn try_reserve(&mut self) -> Result<SinkReservation, SinkFailure>;

    /// Reserves one row and its maximum possible winning metadata. Existing
    /// schema-1 sinks remain valid because they have no metadata sidecar.
    ///
    /// # Errors
    ///
    /// Reports sink failure independently from ordinary saturation.
    fn try_reserve_with_bytes(
        &mut self,
        _maximum_metadata_bytes: usize,
    ) -> Result<SinkReservation, SinkFailure> {
        self.try_reserve()
    }

    /// Consumes exactly one prior reservation.
    ///
    /// # Errors
    ///
    /// Reports a violated or failed sink contract.
    fn commit_reserved(&mut self, result: ScanResult) -> Result<(), SinkFailure>;

    /// Consumes a row reservation and releases unused metadata capacity.
    ///
    /// # Errors
    ///
    /// Reports a violated or failed sink contract.
    fn commit_reserved_with_bytes(
        &mut self,
        result: ScanResult,
        _actual_metadata_bytes: usize,
        _reserved_metadata_bytes: usize,
    ) -> Result<(), SinkFailure> {
        self.commit_reserved(result)
    }

    /// Releases reservations when explicit close requests result disposal.
    ///
    /// # Errors
    ///
    /// Reports a violated or failed sink contract.
    fn release_reserved(&mut self, count: usize) -> Result<(), SinkFailure>;

    /// Releases byte reservations alongside rows on explicit disposal.
    ///
    /// # Errors
    ///
    /// Reports a violated or failed sink contract.
    fn release_reserved_with_bytes(
        &mut self,
        count: usize,
        _maximum_metadata_bytes: usize,
    ) -> Result<(), SinkFailure> {
        self.release_reserved(count)
    }
}
