use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use crate::error::NativeError;

/// The externally observable descriptor lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketStatus {
    Open,
    Closing,
    Closed,
}

/// The result of an explicit, idempotent close request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseOutcome {
    initiated: bool,
    status: SocketStatus,
}

impl CloseOutcome {
    #[must_use]
    pub const fn initiated(self) -> bool {
        self.initiated
    }

    #[must_use]
    pub const fn status(self) -> SocketStatus {
        self.status
    }
}

/// Shared ownership state for one native socket descriptor.
#[derive(Clone, Debug)]
pub struct SocketCore {
    inner: Arc<SocketInner>,
}

#[derive(Debug)]
struct SocketInner {
    lifecycle: Mutex<Lifecycle>,
}

#[derive(Debug)]
enum Lifecycle {
    Open(Arc<OwnedFd>),
    Closing(Weak<OwnedFd>),
    Closed,
}

/// Pins the owned descriptor for one operation.
///
/// A lease acquired before close may finish. Holding the `Arc<OwnedFd>` keeps
/// the same descriptor open, so a reused numeric descriptor cannot be targeted.
#[derive(Debug)]
pub struct OperationLease {
    descriptor: Arc<OwnedFd>,
}

impl OperationLease {
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl SocketCore {
    /// Takes sole ownership of a newly created descriptor.
    #[must_use]
    pub fn from_owned_fd(descriptor: OwnedFd) -> Self {
        Self {
            inner: Arc::new(SocketInner {
                lifecycle: Mutex::new(Lifecycle::Open(Arc::new(descriptor))),
            }),
        }
    }

    /// Acquires an operation lease only while the socket is open.
    ///
    /// # Errors
    ///
    /// Returns `ERR_SOCKET_CLOSED` after close has started.
    pub fn acquire_operation(&self) -> Result<OperationLease, NativeError> {
        let mut lifecycle = self.lock_lifecycle();
        normalize(&mut lifecycle);

        match &*lifecycle {
            Lifecycle::Open(descriptor) => Ok(OperationLease {
                descriptor: Arc::clone(descriptor),
            }),
            Lifecycle::Closing(_) | Lifecycle::Closed => Err(NativeError::socket_closed()),
        }
    }

    /// Starts close once and prevents all new operation leases.
    ///
    /// The descriptor closes immediately when no operation is active. Existing
    /// leases otherwise keep it alive until the last such operation releases it.
    #[must_use]
    pub fn close(&self) -> CloseOutcome {
        let mut lifecycle = self.lock_lifecycle();
        normalize(&mut lifecycle);

        let previous = std::mem::replace(&mut *lifecycle, Lifecycle::Closed);
        match previous {
            Lifecycle::Open(descriptor) => {
                if Arc::strong_count(&descriptor) == 1 {
                    drop(descriptor);
                    CloseOutcome {
                        initiated: true,
                        status: SocketStatus::Closed,
                    }
                } else {
                    let weak_descriptor = Arc::downgrade(&descriptor);
                    drop(descriptor);
                    *lifecycle = Lifecycle::Closing(weak_descriptor);
                    CloseOutcome {
                        initiated: true,
                        status: SocketStatus::Closing,
                    }
                }
            }
            Lifecycle::Closing(descriptor) => {
                *lifecycle = Lifecycle::Closing(descriptor);
                CloseOutcome {
                    initiated: false,
                    status: SocketStatus::Closing,
                }
            }
            Lifecycle::Closed => CloseOutcome {
                initiated: false,
                status: SocketStatus::Closed,
            },
        }
    }

    /// Returns a lifecycle snapshot, normalizing completed close operations.
    #[must_use]
    pub fn status(&self) -> SocketStatus {
        let mut lifecycle = self.lock_lifecycle();
        normalize(&mut lifecycle)
    }

    fn lock_lifecycle(&self) -> MutexGuard<'_, Lifecycle> {
        self.inner
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn normalize(lifecycle: &mut Lifecycle) -> SocketStatus {
    match lifecycle {
        Lifecycle::Open(_) => SocketStatus::Open,
        Lifecycle::Closing(descriptor) if descriptor.strong_count() == 0 => {
            *lifecycle = Lifecycle::Closed;
            SocketStatus::Closed
        }
        Lifecycle::Closing(_) => SocketStatus::Closing,
        Lifecycle::Closed => SocketStatus::Closed,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::error::ErrorKind as NativeErrorKind;

    use super::{SocketCore, SocketStatus};

    fn test_socket() -> (SocketCore, UnixStream) {
        let (owned, peer) = UnixStream::pair().unwrap();
        (SocketCore::from_owned_fd(OwnedFd::from(owned)), peer)
    }

    #[test]
    fn close_without_operations_releases_descriptor_immediately() {
        let (socket, mut peer) = test_socket();
        peer.set_nonblocking(true).unwrap();

        let outcome = socket.close();

        assert!(outcome.initiated());
        assert_eq!(outcome.status(), SocketStatus::Closed);
        assert_eq!(socket.status(), SocketStatus::Closed);
        assert_eq!(peer.read(&mut [0_u8; 1]).unwrap(), 0);
    }

    #[test]
    fn operation_lease_delays_descriptor_close() {
        let (socket, mut peer) = test_socket();
        let lease = socket.acquire_operation().unwrap();
        peer.set_nonblocking(true).unwrap();

        let outcome = socket.close();

        assert!(outcome.initiated());
        assert_eq!(outcome.status(), SocketStatus::Closing);
        assert_eq!(socket.status(), SocketStatus::Closing);
        let repeated = socket.close();
        assert!(!repeated.initiated());
        assert_eq!(repeated.status(), SocketStatus::Closing);
        assert_eq!(
            peer.read(&mut [0_u8; 1]).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );

        let error = socket.acquire_operation().unwrap_err();
        assert_eq!(error.kind(), NativeErrorKind::SocketClosed);

        drop(lease);
        assert_eq!(socket.status(), SocketStatus::Closed);
        assert_eq!(peer.read(&mut [0_u8; 1]).unwrap(), 0);
    }

    #[test]
    fn descriptor_closes_only_after_last_operation_lease() {
        let (socket, mut peer) = test_socket();
        let first_lease = socket.acquire_operation().unwrap();
        let second_lease = socket.acquire_operation().unwrap();
        peer.set_nonblocking(true).unwrap();

        assert_eq!(socket.close().status(), SocketStatus::Closing);
        drop(first_lease);
        assert_eq!(socket.status(), SocketStatus::Closing);
        assert_eq!(
            peer.read(&mut [0_u8; 1]).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );

        drop(second_lease);
        assert_eq!(socket.status(), SocketStatus::Closed);
        assert_eq!(peer.read(&mut [0_u8; 1]).unwrap(), 0);
    }

    #[test]
    fn repeated_close_is_idempotent() {
        let (socket, _peer) = test_socket();

        assert!(socket.close().initiated());
        let repeated = socket.close();

        assert!(!repeated.initiated());
        assert_eq!(repeated.status(), SocketStatus::Closed);
    }

    #[test]
    fn dropping_core_releases_descriptor() {
        let (socket, mut peer) = test_socket();
        peer.set_nonblocking(true).unwrap();

        drop(socket);

        assert_eq!(peer.read(&mut [0_u8; 1]).unwrap(), 0);
    }

    #[test]
    fn close_and_acquire_are_serialized_without_stale_ownership() {
        for _ in 0..256 {
            let (socket, _peer) = test_socket();
            let barrier = Arc::new(Barrier::new(2));
            let worker_socket = socket.clone();
            let worker_barrier = Arc::clone(&barrier);
            let worker = thread::spawn(move || {
                worker_barrier.wait();
                worker_socket.acquire_operation()
            });

            barrier.wait();
            let close_outcome = socket.close();
            assert!(close_outcome.initiated());

            match worker.join().unwrap() {
                Ok(lease) => {
                    assert_eq!(socket.status(), SocketStatus::Closing);
                    drop(lease);
                    assert_eq!(socket.status(), SocketStatus::Closed);
                }
                Err(error) => {
                    assert_eq!(error.kind(), NativeErrorKind::SocketClosed);
                    assert_eq!(socket.status(), SocketStatus::Closed);
                }
            }
        }
    }
}
