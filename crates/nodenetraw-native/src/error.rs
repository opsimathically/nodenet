use std::fmt;

use rustix::io::Errno;

/// Stable categories for errors produced by the native socket core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Aborted,
    Internal,
    InvalidArgument,
    MalformedControl,
    QueueFull,
    ReactorClosed,
    SocketClosed,
    System,
    Unsupported,
}

impl ErrorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aborted => "aborted",
            Self::Internal => "internal",
            Self::InvalidArgument => "invalidArgument",
            Self::MalformedControl => "malformedControl",
            Self::QueueFull => "queueFull",
            Self::ReactorClosed => "reactorClosed",
            Self::SocketClosed => "socketClosed",
            Self::System => "system",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Identifies the native operation that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    AcquireOperation,
    AttachFilter,
    Bind,
    Cancel,
    CloseSocket,
    CreateRawIpv4Socket,
    CreateRawIpv6Socket,
    CreatePacketSocket,
    Connect,
    ConfigurePacketRing,
    Disconnect,
    GetLocalAddress,
    GetStatistics,
    LookupInterface,
    PacketMembership,
    GetSocketOption,
    Receive,
    ReceiveBatch,
    ReceiveRingFrame,
    ReceiveMessage,
    RegisterSocket,
    Send,
    SendBatch,
    SendMessage,
    SetSocketOption,
    StartReactor,
    ValidateBufferRange,
    ValidatePacketBufferLength,
    ValidateRawIpv4Protocol,
    ValidateRawIpv6Protocol,
}

impl Operation {
    /// Returns the stable Node-facing operation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AcquireOperation => "acquireOperation",
            Self::AttachFilter => "attachFilter",
            Self::Bind => "bind",
            Self::Cancel => "cancel",
            Self::CloseSocket => "close",
            Self::CreateRawIpv4Socket => "createRawIpv4Socket",
            Self::CreateRawIpv6Socket => "createRawIpv6Socket",
            Self::CreatePacketSocket => "createPacketSocket",
            Self::Connect => "connect",
            Self::ConfigurePacketRing => "configurePacketRing",
            Self::Disconnect => "disconnect",
            Self::GetLocalAddress => "localAddress",
            Self::GetStatistics => "packetStatistics",
            Self::LookupInterface => "lookupInterface",
            Self::PacketMembership => "packetMembership",
            Self::GetSocketOption => "getOption",
            Self::Receive => "receive",
            Self::ReceiveBatch => "receiveBatch",
            Self::ReceiveRingFrame => "receiveRingFrame",
            Self::ReceiveMessage => "receiveMessage",
            Self::RegisterSocket => "registerSocket",
            Self::Send => "send",
            Self::SendBatch => "sendBatch",
            Self::SendMessage => "sendMessage",
            Self::SetSocketOption => "setOption",
            Self::StartReactor => "startReactor",
            Self::ValidateBufferRange => "validateBufferRange",
            Self::ValidatePacketBufferLength => "validatePacketBufferLength",
            Self::ValidateRawIpv4Protocol => "validateRawIpv4Protocol",
            Self::ValidateRawIpv6Protocol => "validateRawIpv6Protocol",
        }
    }
}

/// A structured error that preserves category, operation, and Linux errno.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeError {
    kind: ErrorKind,
    code: &'static str,
    operation: Operation,
    errno: Option<i32>,
    errno_name: Option<&'static str>,
    message: String,
}

impl NativeError {
    /// Creates an operation cancellation failure.
    #[must_use]
    pub fn aborted(operation: Operation) -> Self {
        Self {
            kind: ErrorKind::Aborted,
            code: "ERR_ABORTED",
            operation,
            errno: None,
            errno_name: None,
            message: String::from("the operation was aborted"),
        }
    }

    /// Creates a checked-argument failure.
    #[must_use]
    pub fn invalid_argument(operation: Operation, message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::InvalidArgument,
            code: "ERR_INVALID_ARGUMENT",
            operation,
            errno: None,
            errno_name: None,
            message: message.into(),
        }
    }

    /// Creates an operation-on-closed-socket failure.
    #[must_use]
    pub fn socket_closed() -> Self {
        Self {
            kind: ErrorKind::SocketClosed,
            code: "ERR_SOCKET_CLOSED",
            operation: Operation::AcquireOperation,
            errno: None,
            errno_name: None,
            message: String::from("the socket is closing or closed"),
        }
    }

    /// Creates a bounded-queue or resource-limit failure.
    #[must_use]
    pub fn queue_full(operation: Operation, message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::QueueFull,
            code: "ERR_QUEUE_FULL",
            operation,
            errno: None,
            errno_name: None,
            message: message.into(),
        }
    }

    /// Creates a reactor-shutdown failure.
    #[must_use]
    pub fn reactor_closed(operation: Operation) -> Self {
        Self {
            kind: ErrorKind::ReactorClosed,
            code: "ERR_REACTOR_CLOSED",
            operation,
            errno: None,
            errno_name: None,
            message: String::from("the native I/O reactor is shutting down"),
        }
    }

    /// Creates an internal resource or invariant failure without an errno.
    #[must_use]
    pub fn internal(operation: Operation, message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Internal,
            code: "ERR_INTERNAL",
            operation,
            errno: None,
            errno_name: None,
            message: message.into(),
        }
    }

    /// Creates a malformed ancillary-data failure.
    #[must_use]
    pub fn malformed_control(operation: Operation, message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::MalformedControl,
            code: "ERR_MALFORMED_CONTROL",
            operation,
            errno: None,
            errno_name: None,
            message: message.into(),
        }
    }

    /// Creates a known unsupported feature or combination failure.
    #[must_use]
    pub fn unsupported(operation: Operation, message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Unsupported,
            code: "ERR_UNSUPPORTED",
            operation,
            errno: None,
            errno_name: None,
            message: message.into(),
        }
    }

    /// Creates a Linux syscall failure without discarding errno.
    #[must_use]
    pub fn system(operation: Operation, errno: Errno) -> Self {
        Self {
            kind: ErrorKind::System,
            code: "ERR_SYSTEM",
            operation,
            errno: Some(errno.raw_os_error()),
            errno_name: linux_errno_name(errno),
            message: errno.to_string(),
        }
    }

    /// Converts a nix errno without losing its Linux numeric value.
    #[must_use]
    pub fn system_nix(operation: Operation, errno: nix::errno::Errno) -> Self {
        Self::system(operation, Errno::from_raw_os_error(errno as i32))
    }

    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    #[must_use]
    pub const fn errno(&self) -> Option<i32> {
        self.errno
    }

    #[must_use]
    pub const fn errno_name(&self) -> Option<&'static str> {
        self.errno_name
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn with_operation(&self, operation: Operation) -> Self {
        let mut error = self.clone();
        error.operation = operation;
        error
    }
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} failed: {}",
            self.operation.as_str(),
            self.message
        )
    }
}

impl std::error::Error for NativeError {}

fn linux_errno_name(errno: Errno) -> Option<&'static str> {
    match errno {
        Errno::ACCESS => Some("EACCES"),
        Errno::AFNOSUPPORT => Some("EAFNOSUPPORT"),
        Errno::INVAL => Some("EINVAL"),
        Errno::IO => Some("EIO"),
        Errno::MFILE => Some("EMFILE"),
        Errno::NFILE => Some("ENFILE"),
        Errno::NOBUFS => Some("ENOBUFS"),
        Errno::PERM => Some("EPERM"),
        Errno::PROTONOSUPPORT => Some("EPROTONOSUPPORT"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use rustix::io::Errno;

    use super::{ErrorKind, NativeError, Operation};

    #[test]
    fn system_error_preserves_linux_context() {
        let error = NativeError::system(Operation::CreateRawIpv4Socket, Errno::PERM);

        assert_eq!(error.kind(), ErrorKind::System);
        assert_eq!(error.code(), "ERR_SYSTEM");
        assert_eq!(error.operation(), Operation::CreateRawIpv4Socket);
        assert_eq!(error.errno(), Some(Errno::PERM.raw_os_error()));
        assert_eq!(error.errno_name(), Some("EPERM"));
        assert!(!error.message().is_empty());
        assert!(error.to_string().starts_with("createRawIpv4Socket failed:"));
    }

    #[test]
    fn argument_error_has_no_errno() {
        let error = NativeError::invalid_argument(
            Operation::ValidateRawIpv4Protocol,
            "protocol is invalid",
        );

        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
        assert_eq!(error.code(), "ERR_INVALID_ARGUMENT");
        assert_eq!(error.errno(), None);
        assert_eq!(error.errno_name(), None);
    }
}
