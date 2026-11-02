//! Backend-neutral scanner I/O ownership contract.
//!
//! Phase 25 freezes this internal boundary before any optional data plane is
//! selected. It intentionally is not exposed through Node-API. Implementations
//! retain every packet buffer and return owned, validated observations only.

#![allow(
    dead_code,
    reason = "Phase 25 contract is frozen for a conditional Phase 26 backend"
)]

use std::net::IpAddr;
use std::time::Duration;

/// Monotonic time relative to one backend instance's creation epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct BackendTime(Duration);

impl BackendTime {
    pub(crate) const fn from_duration(value: Duration) -> Self {
        Self(value)
    }

    pub(crate) const fn duration(self) -> Duration {
        self.0
    }
}

/// Stable input identity. Queue identity is absent when Linux does not report it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InputIdentity {
    pub interface_index: u32,
    pub queue_id: Option<u32>,
}

/// Destination metadata for one immutable packet template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FrameDestination {
    Link {
        interface_index: u32,
        queue_id: Option<u32>,
        hardware_address: [u8; 6],
    },
    RawIp(IpAddr),
}

/// One fully initialized frame submitted by the scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FrameTemplate {
    pub submission_id: u64,
    pub destination: FrameDestination,
    pub bytes: Vec<u8>,
}

/// Owned receive evidence. No view into a socket ring or UMEM may appear here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceivedFrame {
    pub bytes: Vec<u8>,
    pub input: InputIdentity,
    pub received_at: BackendTime,
    pub original_length: usize,
    pub checksum_not_ready: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BackendCounters {
    pub submitted: u64,
    pub received: u64,
    pub kernel_dropped: u64,
    pub backpressured: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SubmissionStatus {
    Complete,
    Backpressured,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SubmissionOutcome {
    pub accepted: usize,
    pub status: SubmissionStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendLifecycle {
    Running,
    Cancelling,
    Closed,
}

/// Internal data-plane contract shared by the portable and any selected backend.
///
/// Implementations must bound every call, preserve frame order within one
/// submission, keep writable storage native-owned, and make cancellation and
/// shutdown idempotent. `shutdown` may return only after kernel ownership and
/// mappings have been relinquished.
pub(crate) trait ScannerIoBackend {
    type Error;

    fn submit(&mut self, frames: &[FrameTemplate]) -> Result<SubmissionOutcome, Self::Error>;

    fn receive(&mut self, maximum: usize) -> Result<Vec<ReceivedFrame>, Self::Error>;

    fn counters(&mut self) -> Result<BackendCounters, Self::Error>;

    fn lifecycle(&self) -> BackendLifecycle;

    fn cancel(&mut self);

    fn shutdown(&mut self) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct ModelBackend {
        cancelled: bool,
        closed: bool,
        counters: BackendCounters,
    }

    impl ScannerIoBackend for ModelBackend {
        type Error = &'static str;

        fn submit(&mut self, frames: &[FrameTemplate]) -> Result<SubmissionOutcome, Self::Error> {
            if self.closed {
                return Err("closed");
            }
            if self.cancelled {
                return Ok(SubmissionOutcome {
                    accepted: 0,
                    status: SubmissionStatus::Cancelled,
                });
            }
            self.counters.submitted = self
                .counters
                .submitted
                .saturating_add(u64::try_from(frames.len()).unwrap_or(u64::MAX));
            Ok(SubmissionOutcome {
                accepted: frames.len(),
                status: SubmissionStatus::Complete,
            })
        }

        fn receive(&mut self, _maximum: usize) -> Result<Vec<ReceivedFrame>, Self::Error> {
            Ok(Vec::new())
        }

        fn counters(&mut self) -> Result<BackendCounters, Self::Error> {
            Ok(self.counters)
        }

        fn lifecycle(&self) -> BackendLifecycle {
            if self.closed {
                BackendLifecycle::Closed
            } else if self.cancelled {
                BackendLifecycle::Cancelling
            } else {
                BackendLifecycle::Running
            }
        }

        fn cancel(&mut self) {
            if !self.closed {
                self.cancelled = true;
            }
        }

        fn shutdown(&mut self) -> Result<(), Self::Error> {
            self.cancelled = true;
            self.closed = true;
            Ok(())
        }
    }

    #[test]
    fn contract_models_bounded_submission_and_idempotent_shutdown() {
        let frame = FrameTemplate {
            submission_id: 7,
            destination: FrameDestination::RawIp(IpAddr::from([127, 0, 0, 1])),
            bytes: vec![1, 2, 3],
        };
        let mut backend = ModelBackend::default();
        assert_eq!(
            backend.submit(&[frame]).unwrap(),
            SubmissionOutcome {
                accepted: 1,
                status: SubmissionStatus::Complete,
            }
        );
        backend.cancel();
        assert_eq!(backend.lifecycle(), BackendLifecycle::Cancelling);
        assert_eq!(
            backend.submit(&[]).unwrap().status,
            SubmissionStatus::Cancelled
        );
        backend.shutdown().unwrap();
        backend.shutdown().unwrap();
        assert_eq!(backend.lifecycle(), BackendLifecycle::Closed);
        assert_eq!(backend.counters().unwrap().submitted, 1);
    }

    #[test]
    fn receive_value_owns_bytes_and_records_monotonic_identity() {
        let received = ReceivedFrame {
            bytes: vec![4, 5, 6],
            input: InputIdentity {
                interface_index: 2,
                queue_id: Some(0),
            },
            received_at: BackendTime::from_duration(Duration::from_nanos(9)),
            original_length: 3,
            checksum_not_ready: false,
        };
        let mut moved = received.bytes;
        moved[0] = 9;
        assert_eq!(moved, [9, 5, 6]);
        assert_eq!(received.received_at.duration(), Duration::from_nanos(9));
    }
}
