use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};

use rustix::buffer::spare_capacity;
use rustix::event::{EventfdFlags, epoll, eventfd};
use rustix::io::{Errno, read, write};

use crate::advanced::{
    ClassicBpfInstruction, PacketMembership, PacketStatistics, attach_classic_bpf, attach_ebpf,
    detach_filter, get_raw_option, lock_filter, packet_statistics, set_packet_auxdata,
    set_packet_fanout, set_packet_membership, set_raw_option,
};
use crate::batch::{
    BatchReceivedMessage, BatchSendMessage, BatchSendResult, receive_batch, send_batch,
};
use crate::conversion::PacketBufferLength;
use crate::error::{NativeError, Operation};
use crate::lifecycle::{OperationLease, SocketCore, SocketStatus};
use crate::linux::{
    Ipv4SocketOption, Ipv6SocketOption, bind_ipv4, bind_ipv6, connect_ipv4, connect_ipv6,
    disconnect_socket, get_bind_to_device, get_ipv4_socket_option, get_ipv6_socket_option,
    local_ipv4_address, local_ipv6_address, set_bind_to_device, set_ipv4_socket_option,
    set_ipv6_socket_option,
};
use crate::message::{
    ReceiveMessageFlags, ReceivedIpv4Message, ReceivedIpv6Message, SendControlMessage,
    SendMessageFlags, receive_ipv4_message, receive_ipv6_message, send_ipv4_message,
    send_ipv6_message,
};
use crate::packet::{
    PacketAddress, PacketMode, ReceivedPacketMessage, bind_packet, receive_packet_message,
    send_packet_message,
};
use crate::ring::{PacketRing, PacketRingConfig, RingFrame};

pub const MAX_SOCKETS_PER_ENVIRONMENT: usize = 64;
pub const MAX_PENDING_OPERATIONS: usize = 128;
pub const MAX_PENDING_SENDS_PER_SOCKET: usize = 16;
pub const MAX_PENDING_RECEIVES_PER_SOCKET: usize = 16;
pub const MAX_PENDING_OPERATIONS_PER_SOCKET: usize = 32;
pub const COMMAND_QUEUE_CAPACITY: usize = 256;
pub const MAX_PENDING_BYTES_PER_SOCKET: usize = 4 * 1024 * 1024;
pub const MAX_PENDING_BYTES_PER_ENVIRONMENT: usize = 16 * 1024 * 1024;
pub const MAX_PACKET_RING_BYTES_PER_ENVIRONMENT: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketFamily {
    Ipv4,
    Ipv6,
    Packet(PacketMode),
}

#[derive(Clone, Debug)]
enum MessageDestination {
    Ipv4(SocketAddrV4),
    Ipv6(SocketAddrV6),
    Packet(PacketAddress),
}

const WAKE_TOKEN: u64 = 0;
const EVENT_BATCH_SIZE: usize = 64;
const COMMAND_BATCH_SIZE: usize = 64;
const READY_OPERATION_BUDGET: usize = 16;
const READY_BYTE_BUDGET: usize = 1024 * 1024;

/// Successful values produced by the reactor.
#[derive(Debug)]
pub enum CompletionValue {
    Opened,
    Bound,
    LocalAddress(Ipv4Addr),
    LocalIpv6Address(SocketAddrV6),
    Connected,
    Disconnected,
    OptionValue(u32),
    OptionSet,
    DeviceValue(Option<String>),
    RawOption(Vec<u8>),
    PacketStatistics(PacketStatistics),
    Sent(usize),
    MessageSent(usize),
    BatchSent(BatchSendResult),
    BatchReceived(Vec<BatchReceivedMessage>),
    PacketRingConfigured,
    RingFrame(RingFrame),
    Received {
        data: Vec<u8>,
        source_address: Ipv4Addr,
        packet_length: usize,
        truncated: bool,
        ipv4: Option<Ipv4PacketMetadata>,
    },
    MessageReceived {
        message: ReceivedIpv4Message,
        ipv4: Option<Ipv4PacketMetadata>,
    },
    Ipv6MessageReceived {
        message: ReceivedIpv6Message,
    },
    PacketMessageReceived {
        message: ReceivedPacketMessage,
    },
    Closed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Ipv4PacketMetadata {
    pub destination_address: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub type_of_service: u8,
    pub header_length: u8,
    pub total_length: u16,
    pub identification: u16,
    pub fragment_offset: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
}

/// One operation result routed to the owning Node environment.
#[derive(Debug)]
pub struct Completion {
    pub operation_id: u32,
    pub result: Result<CompletionValue, NativeError>,
}

/// Environment-specific completion delivery implemented by the N-API adapter.
pub trait CompletionSink: Send + Sync + 'static {
    fn complete(&self, completion: Completion);
}

type SharedCompletionSink = Arc<Mutex<Option<Arc<dyn CompletionSink>>>>;

#[derive(Debug)]
struct OperationControl {
    cancelled: AtomicBool,
}

impl OperationControl {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }
}

#[derive(Debug)]
struct OperationAdmission {
    operation_id: u32,
    operation: Operation,
    control: Arc<OperationControl>,
    registry: Arc<Mutex<HashMap<u32, Weak<OperationControl>>>>,
    environment_count: Arc<AtomicUsize>,
    socket_count: Arc<AtomicUsize>,
    environment_bytes: Arc<AtomicUsize>,
    socket_bytes: Arc<AtomicUsize>,
    byte_charge: usize,
}

struct RingReservation {
    counter: Arc<AtomicUsize>,
    bytes: usize,
}

impl Drop for RingReservation {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

struct ConfiguredPacketRing {
    ring: PacketRing,
    _reservation: RingReservation,
}

impl OperationAdmission {
    fn cancelled(&self) -> bool {
        self.control.cancelled.load(Ordering::Acquire)
    }
}

impl Drop for OperationAdmission {
    fn drop(&mut self) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if registry
            .get(&self.operation_id)
            .and_then(Weak::upgrade)
            .is_some_and(|control| Arc::ptr_eq(&control, &self.control))
        {
            registry.remove(&self.operation_id);
        }
        drop(registry);
        self.environment_count.fetch_sub(1, Ordering::AcqRel);
        self.socket_count.fetch_sub(1, Ordering::AcqRel);
        self.environment_bytes
            .fetch_sub(self.byte_charge, Ordering::AcqRel);
        self.socket_bytes
            .fetch_sub(self.byte_charge, Ordering::AcqRel);
    }
}

/// A socket registered with one environment reactor.
pub struct ReactorSocket {
    id: u64,
    core: SocketCore,
    close_operation: Arc<Mutex<Option<u32>>>,
    sink: SharedCompletionSink,
    reactor: Arc<ReactorHandle>,
    operation_registry: Arc<Mutex<HashMap<u32, Weak<OperationControl>>>>,
    pending_operations: Arc<AtomicUsize>,
    pending_bytes: Arc<AtomicUsize>,
    family: SocketFamily,
}

#[allow(
    clippy::missing_errors_doc,
    reason = "submission methods share the documented admission error contract"
)]
impl ReactorSocket {
    /// Submits a serialized local IPv4 bind operation.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, queue-limit, or reactor-shutdown error.
    pub fn bind(&self, operation_id: u32, address: Ipv4Addr) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::Bind, 0)?;
        self.reactor.submit_operation(
            Command::Bind {
                socket_id: self.id,
                operation_id,
                lease,
                address,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::Bind,
        )
    }

    pub fn bind_ipv6(&self, operation_id: u32, address: SocketAddrV6) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::Bind, 0)?;
        self.reactor.submit_operation(
            Command::BindIpv6 {
                socket_id: self.id,
                operation_id,
                lease,
                address,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::Bind,
        )
    }

    pub fn bind_packet(
        &self,
        operation_id: u32,
        address: PacketAddress,
    ) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::Bind, 0)?;
        self.reactor.submit_operation(
            Command::BindPacket {
                socket_id: self.id,
                operation_id,
                lease,
                address,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::Bind,
        )
    }

    pub fn connect_ipv6(
        &self,
        operation_id: u32,
        address: SocketAddrV6,
    ) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::Connect, 0)?;
        self.reactor.submit_operation(
            Command::ConnectIpv6 {
                socket_id: self.id,
                operation_id,
                lease,
                address,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::Connect,
        )
    }

    pub fn connect_ipv4(&self, operation_id: u32, address: Ipv4Addr) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::Connect, 0)?;
        self.reactor.submit_operation(
            Command::ConnectIpv4 {
                socket_id: self.id,
                operation_id,
                lease,
                address,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::Connect,
        )
    }

    pub fn disconnect(&self, operation_id: u32) -> Result<(), NativeError> {
        if matches!(self.family, SocketFamily::Packet(_)) {
            return Err(NativeError::unsupported(
                Operation::Disconnect,
                "packet sockets use per-message link destinations",
            ));
        }
        let (lease, admission) = self.admit(operation_id, Operation::Disconnect, 0)?;
        self.reactor.submit_operation(
            Command::Disconnect {
                socket_id: self.id,
                operation_id,
                lease,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::Disconnect,
        )
    }

    /// Submits a serialized local-address query.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, queue-limit, or reactor-shutdown error.
    pub fn local_address(&self, operation_id: u32) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::GetLocalAddress, 0)?;
        self.reactor.submit_operation(
            Command::GetLocalAddress {
                socket_id: self.id,
                operation_id,
                lease,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::GetLocalAddress,
        )
    }

    /// Submits a serialized typed socket-option query.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, queue-limit, or reactor-shutdown error.
    pub fn get_option(
        &self,
        operation_id: u32,
        option: Ipv4SocketOption,
    ) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::GetSocketOption, 0)?;
        self.reactor.submit_operation(
            Command::GetOption {
                socket_id: self.id,
                operation_id,
                lease,
                option,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::GetSocketOption,
        )
    }

    /// Submits a serialized typed socket-option update.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, queue-limit, or reactor-shutdown error.
    pub fn set_option(
        &self,
        operation_id: u32,
        option: Ipv4SocketOption,
        value: u32,
    ) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::SetSocketOption, 0)?;
        self.reactor.submit_operation(
            Command::SetOption {
                socket_id: self.id,
                operation_id,
                lease,
                option,
                value,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::SetSocketOption,
        )
    }

    pub fn get_ipv6_option(
        &self,
        operation_id: u32,
        option: Ipv6SocketOption,
    ) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::GetSocketOption, 0)?;
        self.reactor.submit_operation(
            Command::GetIpv6Option {
                socket_id: self.id,
                operation_id,
                lease,
                option,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::GetSocketOption,
        )
    }

    pub fn set_ipv6_option(
        &self,
        operation_id: u32,
        option: Ipv6SocketOption,
        value: u32,
    ) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::SetSocketOption, 0)?;
        self.reactor.submit_operation(
            Command::SetIpv6Option {
                socket_id: self.id,
                operation_id,
                lease,
                option,
                value,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::SetSocketOption,
        )
    }

    /// Submits a serialized device-binding query.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, admission, queue, or shutdown error.
    pub fn get_device(&self, operation_id: u32) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::GetSocketOption, 0)?;
        self.reactor.submit_operation(
            Command::GetDevice {
                socket_id: self.id,
                operation_id,
                lease,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::GetSocketOption,
        )
    }

    /// Submits a serialized device-binding update.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, admission, queue, or shutdown error.
    pub fn set_device(&self, operation_id: u32, device: Option<String>) -> Result<(), NativeError> {
        let charge = device.as_ref().map_or(0, String::len);
        let (lease, admission) = self.admit(operation_id, Operation::SetSocketOption, charge)?;
        self.reactor.submit_operation(
            Command::SetDevice {
                socket_id: self.id,
                operation_id,
                lease,
                device,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::SetSocketOption,
        )
    }

    pub fn get_raw_option(
        &self,
        operation_id: u32,
        level: i32,
        name: i32,
        maximum: usize,
    ) -> Result<(), NativeError> {
        self.submit_advanced(
            operation_id,
            Operation::GetSocketOption,
            maximum,
            AdvancedAction::GetRawOption {
                level,
                name,
                maximum,
            },
        )
    }
    pub fn set_raw_option(
        &self,
        operation_id: u32,
        level: i32,
        name: i32,
        value: Vec<u8>,
    ) -> Result<(), NativeError> {
        let charge = value.len();
        self.submit_advanced(
            operation_id,
            Operation::SetSocketOption,
            charge,
            AdvancedAction::SetRawOption { level, name, value },
        )
    }
    pub fn attach_classic_filter(
        &self,
        operation_id: u32,
        program: Vec<ClassicBpfInstruction>,
    ) -> Result<(), NativeError> {
        let charge = program
            .len()
            .checked_mul(std::mem::size_of::<ClassicBpfInstruction>())
            .ok_or_else(|| {
                NativeError::invalid_argument(
                    Operation::AttachFilter,
                    "filter byte charge overflowed",
                )
            })?;
        self.submit_advanced(
            operation_id,
            Operation::AttachFilter,
            charge,
            AdvancedAction::AttachClassic(program),
        )
    }
    pub fn detach_filter(&self, operation_id: u32) -> Result<(), NativeError> {
        self.submit_advanced(
            operation_id,
            Operation::AttachFilter,
            0,
            AdvancedAction::DetachFilter,
        )
    }
    pub fn lock_filter(&self, operation_id: u32) -> Result<(), NativeError> {
        self.submit_advanced(
            operation_id,
            Operation::AttachFilter,
            0,
            AdvancedAction::LockFilter,
        )
    }
    pub fn attach_ebpf_filter(&self, operation_id: u32, fd: i32) -> Result<(), NativeError> {
        self.submit_advanced(
            operation_id,
            Operation::AttachFilter,
            0,
            AdvancedAction::AttachEbpf(fd),
        )
    }
    pub fn packet_membership(
        &self,
        operation_id: u32,
        membership: PacketMembership,
        add: bool,
    ) -> Result<(), NativeError> {
        self.submit_advanced(
            operation_id,
            Operation::PacketMembership,
            membership.address.len(),
            AdvancedAction::PacketMembership { membership, add },
        )
    }
    pub fn packet_auxdata(&self, operation_id: u32, enabled: bool) -> Result<(), NativeError> {
        self.submit_advanced(
            operation_id,
            Operation::SetSocketOption,
            0,
            AdvancedAction::PacketAuxdata(enabled),
        )
    }
    pub fn packet_fanout(
        &self,
        operation_id: u32,
        group: u16,
        mode: u16,
    ) -> Result<(), NativeError> {
        self.submit_advanced(
            operation_id,
            Operation::SetSocketOption,
            0,
            AdvancedAction::PacketFanout { group, mode },
        )
    }
    pub fn packet_statistics(&self, operation_id: u32) -> Result<(), NativeError> {
        self.submit_advanced(
            operation_id,
            Operation::GetStatistics,
            0,
            AdvancedAction::PacketStatistics,
        )
    }
    fn submit_advanced(
        &self,
        operation_id: u32,
        operation: Operation,
        charge: usize,
        action: AdvancedAction,
    ) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, operation, charge)?;
        self.reactor.submit_operation(
            Command::Advanced {
                socket_id: self.id,
                operation_id,
                lease,
                action,
                sink: Arc::clone(&self.sink),
                admission,
            },
            operation,
        )
    }

    /// Submits one owned packet for asynchronous delivery.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, queue-limit, or reactor-shutdown error before the
    /// operation is admitted.
    pub fn send(
        &self,
        operation_id: u32,
        data: Vec<u8>,
        destination: Ipv4Addr,
    ) -> Result<(), NativeError> {
        let byte_charge = data.len();
        let (lease, admission) = self.admit(operation_id, Operation::Send, byte_charge)?;
        let command = Command::Send {
            socket_id: self.id,
            operation_id,
            lease,
            data,
            destination: MessageDestination::Ipv4(SocketAddrV4::new(destination, 0)),
            flags: SendMessageFlags::default(),
            control: Vec::new(),
            message_api: false,
            sink: Arc::clone(&self.sink),
            admission,
        };
        self.reactor.submit_operation(command, Operation::Send)
    }

    /// Submits one bounded asynchronous packet receive.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, queue-limit, or reactor-shutdown error before the
    /// operation is admitted.
    pub fn receive(
        &self,
        operation_id: u32,
        buffer_length: PacketBufferLength,
    ) -> Result<(), NativeError> {
        let (lease, admission) =
            self.admit(operation_id, Operation::Receive, buffer_length.get())?;
        let command = Command::Receive {
            socket_id: self.id,
            operation_id,
            lease,
            buffer_length,
            control_capacity: 0,
            flags: ReceiveMessageFlags::default(),
            message_api: false,
            sink: Arc::clone(&self.sink),
            admission,
        };
        self.reactor.submit_operation(command, Operation::Receive)
    }

    /// Submits one typed IPv4 message for asynchronous delivery.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, validation, queue-limit, or shutdown error.
    pub fn send_message(
        &self,
        operation_id: u32,
        data: Vec<u8>,
        destination: Ipv4Addr,
        flags: SendMessageFlags,
        control: Vec<SendControlMessage>,
    ) -> Result<(), NativeError> {
        let control_charge = control.len().checked_mul(64).ok_or_else(|| {
            NativeError::invalid_argument(Operation::SendMessage, "control byte charge overflowed")
        })?;
        let byte_charge = data.len().checked_add(control_charge).ok_or_else(|| {
            NativeError::invalid_argument(Operation::SendMessage, "message byte charge overflowed")
        })?;
        let (lease, admission) = self.admit(operation_id, Operation::SendMessage, byte_charge)?;
        self.reactor.submit_operation(
            Command::Send {
                socket_id: self.id,
                operation_id,
                lease,
                data,
                destination: MessageDestination::Ipv4(SocketAddrV4::new(destination, 0)),
                flags,
                control,
                message_api: true,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::SendMessage,
        )
    }

    pub fn send_message_ipv6(
        &self,
        operation_id: u32,
        data: Vec<u8>,
        destination: SocketAddrV6,
        flags: SendMessageFlags,
        control: Vec<SendControlMessage>,
    ) -> Result<(), NativeError> {
        let control_charge = control.len().checked_mul(64).ok_or_else(|| {
            NativeError::invalid_argument(Operation::SendMessage, "control byte charge overflowed")
        })?;
        let byte_charge = data.len().checked_add(control_charge).ok_or_else(|| {
            NativeError::invalid_argument(Operation::SendMessage, "message byte charge overflowed")
        })?;
        let (lease, admission) = self.admit(operation_id, Operation::SendMessage, byte_charge)?;
        self.reactor.submit_operation(
            Command::Send {
                socket_id: self.id,
                operation_id,
                lease,
                data,
                destination: MessageDestination::Ipv6(destination),
                flags,
                control,
                message_api: true,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::SendMessage,
        )
    }

    pub fn send_message_packet(
        &self,
        operation_id: u32,
        data: Vec<u8>,
        destination: PacketAddress,
        flags: SendMessageFlags,
    ) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::SendMessage, data.len())?;
        self.reactor.submit_operation(
            Command::Send {
                socket_id: self.id,
                operation_id,
                lease,
                data,
                destination: MessageDestination::Packet(destination),
                flags,
                control: Vec::new(),
                message_api: true,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::SendMessage,
        )
    }

    /// Submits one bounded same-family `sendmmsg(2)` operation.
    ///
    /// # Errors
    /// Returns validation, lifecycle, admission, or reactor errors.
    pub fn send_batch(
        &self,
        operation_id: u32,
        messages: Vec<BatchSendMessage>,
    ) -> Result<(), NativeError> {
        let byte_charge = messages.iter().try_fold(0_usize, |total, message| {
            total.checked_add(message.data.len()).ok_or_else(|| {
                NativeError::invalid_argument(Operation::SendBatch, "batch byte charge overflowed")
            })
        })?;
        let (lease, admission) = self.admit(operation_id, Operation::SendBatch, byte_charge)?;
        self.reactor.submit_operation(
            Command::SendBatch {
                socket_id: self.id,
                operation_id,
                lease,
                messages,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::SendBatch,
        )
    }

    /// Submits one bounded typed IPv4 message receive.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, validation, queue-limit, or shutdown error.
    pub fn receive_message(
        &self,
        operation_id: u32,
        buffer_length: PacketBufferLength,
        control_capacity: usize,
        flags: ReceiveMessageFlags,
    ) -> Result<(), NativeError> {
        let byte_charge = buffer_length
            .get()
            .checked_add(control_capacity)
            .ok_or_else(|| {
                NativeError::invalid_argument(
                    Operation::ReceiveMessage,
                    "message byte charge overflowed",
                )
            })?;
        let (lease, admission) =
            self.admit(operation_id, Operation::ReceiveMessage, byte_charge)?;
        self.reactor.submit_operation(
            Command::Receive {
                socket_id: self.id,
                operation_id,
                lease,
                buffer_length,
                control_capacity,
                flags,
                message_api: true,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::ReceiveMessage,
        )
    }

    /// Submits one bounded nonblocking `recvmmsg(2)` operation.
    ///
    /// # Errors
    /// Returns validation, lifecycle, admission, or reactor errors.
    pub fn receive_batch(
        &self,
        operation_id: u32,
        count: usize,
        buffer_length: PacketBufferLength,
    ) -> Result<(), NativeError> {
        let byte_charge = count.checked_mul(buffer_length.get()).ok_or_else(|| {
            NativeError::invalid_argument(Operation::ReceiveBatch, "batch byte charge overflowed")
        })?;
        let (lease, admission) = self.admit(operation_id, Operation::ReceiveBatch, byte_charge)?;
        self.reactor.submit_operation(
            Command::ReceiveBatch {
                socket_id: self.id,
                operation_id,
                lease,
                count,
                buffer_length,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::ReceiveBatch,
        )
    }

    pub fn configure_packet_ring(
        &self,
        operation_id: u32,
        config: PacketRingConfig,
    ) -> Result<(), NativeError> {
        let mapping_length = config.validate()?;
        reserve_bounded_amount(
            &self.reactor.mapped_ring_bytes,
            mapping_length,
            MAX_PACKET_RING_BYTES_PER_ENVIRONMENT,
            Operation::ConfigurePacketRing,
            "maximum mapped packet-ring bytes per Node environment reached",
        )?;
        let reservation = RingReservation {
            counter: Arc::clone(&self.reactor.mapped_ring_bytes),
            bytes: mapping_length,
        };
        let (lease, admission) = self.admit(operation_id, Operation::ConfigurePacketRing, 0)?;
        self.reactor.submit_operation(
            Command::ConfigurePacketRing {
                socket_id: self.id,
                operation_id,
                lease,
                config,
                reservation,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::ConfigurePacketRing,
        )
    }

    pub fn receive_ring_frame(&self, operation_id: u32) -> Result<(), NativeError> {
        let (lease, admission) = self.admit(operation_id, Operation::ReceiveRingFrame, 0)?;
        self.reactor.submit_operation(
            Command::ReceiveRingFrame {
                socket_id: self.id,
                operation_id,
                lease,
                sink: Arc::clone(&self.sink),
                admission,
            },
            Operation::ReceiveRingFrame,
        )
    }

    /// Marks one admitted operation cancelled and wakes the reactor.
    #[must_use]
    pub fn cancel(&self, operation_id: u32) -> bool {
        let control = self
            .operation_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&operation_id)
            .and_then(Weak::upgrade);
        if let Some(control) = control {
            let newly_cancelled = !control.cancelled.swap(true, Ordering::AcqRel);
            if newly_cancelled {
                self.reactor.wake_ignoring_shutdown();
            }
            newly_cancelled
        } else {
            false
        }
    }

    fn admit(
        &self,
        operation_id: u32,
        operation: Operation,
        byte_charge: usize,
    ) -> Result<(OperationLease, OperationAdmission), NativeError> {
        let lease = self.core.acquire_operation()?;
        if !self.reactor.accepting.load(Ordering::Acquire) {
            return Err(NativeError::reactor_closed(operation));
        }
        reserve_bounded(
            &self.reactor.pending_operations,
            MAX_PENDING_OPERATIONS,
            operation,
            "maximum pending operations per Node environment reached",
        )?;
        if let Err(error) = reserve_bounded(
            &self.pending_operations,
            MAX_PENDING_OPERATIONS_PER_SOCKET,
            operation,
            "maximum total pending operations per socket reached",
        ) {
            self.reactor
                .pending_operations
                .fetch_sub(1, Ordering::AcqRel);
            return Err(error);
        }
        if let Err(error) = reserve_bounded_amount(
            &self.reactor.pending_bytes,
            byte_charge,
            MAX_PENDING_BYTES_PER_ENVIRONMENT,
            operation,
            "maximum pending operation bytes per Node environment reached",
        ) {
            self.pending_operations.fetch_sub(1, Ordering::AcqRel);
            self.reactor
                .pending_operations
                .fetch_sub(1, Ordering::AcqRel);
            return Err(error);
        }
        if let Err(error) = reserve_bounded_amount(
            &self.pending_bytes,
            byte_charge,
            MAX_PENDING_BYTES_PER_SOCKET,
            operation,
            "maximum pending operation bytes per socket reached",
        ) {
            self.reactor
                .pending_bytes
                .fetch_sub(byte_charge, Ordering::AcqRel);
            self.pending_operations.fetch_sub(1, Ordering::AcqRel);
            self.reactor
                .pending_operations
                .fetch_sub(1, Ordering::AcqRel);
            return Err(error);
        }

        let control = Arc::new(OperationControl::new());
        let mut registry = self
            .operation_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if registry
            .get(&operation_id)
            .and_then(Weak::upgrade)
            .is_some()
        {
            drop(registry);
            self.pending_bytes.fetch_sub(byte_charge, Ordering::AcqRel);
            self.reactor
                .pending_bytes
                .fetch_sub(byte_charge, Ordering::AcqRel);
            self.pending_operations.fetch_sub(1, Ordering::AcqRel);
            self.reactor
                .pending_operations
                .fetch_sub(1, Ordering::AcqRel);
            return Err(NativeError::internal(
                operation,
                "duplicate native operation identifier",
            ));
        }
        registry.insert(operation_id, Arc::downgrade(&control));
        drop(registry);
        let admission = OperationAdmission {
            operation_id,
            operation,
            control,
            registry: Arc::clone(&self.operation_registry),
            environment_count: Arc::clone(&self.reactor.pending_operations),
            socket_count: Arc::clone(&self.pending_operations),
            environment_bytes: Arc::clone(&self.reactor.pending_bytes),
            socket_bytes: Arc::clone(&self.pending_bytes),
            byte_charge,
        };
        Ok((lease, admission))
    }

    /// Starts idempotent close and wakes the reactor to cancel pending work.
    #[must_use]
    pub fn close(&self, operation_id: Option<u32>) -> bool {
        let outcome = self.core.close();
        if outcome.initiated() {
            if let Some(operation_id) = operation_id {
                *self
                    .close_operation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(operation_id);
            }
            self.reactor.wake_ignoring_shutdown();
        }
        outcome.initiated()
    }

    #[must_use]
    pub fn status(&self) -> SocketStatus {
        self.core.status()
    }

    #[must_use]
    pub const fn family(&self) -> SocketFamily {
        self.family
    }
}

impl Drop for ReactorSocket {
    fn drop(&mut self) {
        let _ = self.close(None);
    }
}

/// One bounded epoll reactor for a Node environment.
#[derive(Debug)]
pub struct ReactorHandle {
    command_sender: SyncSender<Command>,
    wake_descriptor: Arc<OwnedFd>,
    accepting: Arc<AtomicBool>,
    pending_operations: Arc<AtomicUsize>,
    pending_bytes: Arc<AtomicUsize>,
    mapped_ring_bytes: Arc<AtomicUsize>,
    socket_count: Arc<AtomicUsize>,
    next_socket_id: AtomicU64,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ReactorHandle {
    /// Starts the reactor thread and its close-on-exec epoll/eventfd resources.
    ///
    /// # Errors
    ///
    /// Returns a structured system/internal error if resource or thread
    /// creation fails.
    pub fn start() -> Result<Arc<Self>, NativeError> {
        let epoll_descriptor = epoll::create(epoll::CreateFlags::CLOEXEC)
            .map_err(|error| NativeError::system(Operation::StartReactor, error))?;
        let wake_descriptor = Arc::new(
            eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
                .map_err(|error| NativeError::system(Operation::StartReactor, error))?,
        );
        epoll::add(
            &epoll_descriptor,
            &*wake_descriptor,
            epoll::EventData::new_u64(WAKE_TOKEN),
            epoll::EventFlags::IN,
        )
        .map_err(|error| NativeError::system(Operation::StartReactor, error))?;

        let (command_sender, command_receiver) = sync_channel(COMMAND_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let pending_operations = Arc::new(AtomicUsize::new(0));
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        let mapped_ring_bytes = Arc::new(AtomicUsize::new(0));
        let socket_count = Arc::new(AtomicUsize::new(0));

        let thread_accepting = Arc::clone(&accepting);
        let thread_socket_count = Arc::clone(&socket_count);
        let thread_wake = Arc::clone(&wake_descriptor);
        let reactor_thread = thread::Builder::new()
            .name(String::from("nodenetraw-epoll"))
            .spawn(move || {
                run_reactor(
                    epoll_descriptor,
                    thread_wake,
                    command_receiver,
                    thread_accepting,
                    thread_socket_count,
                );
            })
            .map_err(|error| {
                NativeError::internal(
                    Operation::StartReactor,
                    format!("failed to spawn reactor thread: {error}"),
                )
            })?;

        Ok(Arc::new(Self {
            command_sender,
            wake_descriptor,
            accepting,
            pending_operations,
            pending_bytes,
            mapped_ring_bytes,
            socket_count,
            next_socket_id: AtomicU64::new(1),
            thread: Mutex::new(Some(reactor_thread)),
        }))
    }

    /// Registers a socket and schedules the open completion.
    ///
    /// # Errors
    ///
    /// Returns a socket-limit, command-queue, or shutdown error.
    pub fn register(
        self: &Arc<Self>,
        core: SocketCore,
        family: SocketFamily,
        sink: Arc<dyn CompletionSink>,
    ) -> Result<ReactorSocket, NativeError> {
        self.reserve_socket()?;
        let id = self.next_socket_id.fetch_add(1, Ordering::Relaxed);
        if id == WAKE_TOKEN {
            self.release_socket();
            self.accepting.store(false, Ordering::Release);
            self.wake_ignoring_shutdown();
            return Err(NativeError::internal(
                Operation::RegisterSocket,
                "reactor socket identifier space was exhausted",
            ));
        }

        let close_operation = Arc::new(Mutex::new(None));
        let sink = Arc::new(Mutex::new(Some(sink)));
        let operation_registry = Arc::new(Mutex::new(HashMap::new()));
        let pending_operations = Arc::new(AtomicUsize::new(0));
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        let command = Command::Register {
            socket_id: id,
            core: core.clone(),
            sink: Arc::clone(&sink),
            close_operation: Arc::clone(&close_operation),
            pending_operations: Arc::clone(&pending_operations),
            family,
        };

        if let Err(error) = self.submit_control(command, Operation::RegisterSocket) {
            self.release_socket();
            let _ = core.close();
            return Err(error);
        }

        Ok(ReactorSocket {
            id,
            core,
            close_operation,
            sink,
            reactor: Arc::clone(self),
            operation_registry,
            pending_operations,
            pending_bytes,
            family,
        })
    }

    /// Signals teardown and joins on a detached reaper thread.
    pub fn shutdown_in_background(&self) {
        self.accepting.store(false, Ordering::Release);
        self.wake_ignoring_shutdown();
        let thread = self
            .thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(thread) = thread {
            let _ = thread::Builder::new()
                .name(String::from("nodenetraw-reaper"))
                .spawn(move || {
                    let _ = thread.join();
                });
        }
    }

    #[cfg(test)]
    fn shutdown_and_join(&self) {
        self.accepting.store(false, Ordering::Release);
        self.wake_ignoring_shutdown();
        if let Some(thread) = self
            .thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            thread.join().unwrap();
        }
    }

    #[cfg(test)]
    fn inject_fatal_failure(&self) {
        self.submit_control(Command::InjectFatalFailure, Operation::StartReactor)
            .unwrap();
    }

    fn reserve_socket(&self) -> Result<(), NativeError> {
        reserve_bounded(
            &self.socket_count,
            MAX_SOCKETS_PER_ENVIRONMENT,
            Operation::RegisterSocket,
            "maximum sockets per Node environment reached",
        )
    }

    fn release_socket(&self) {
        self.socket_count.fetch_sub(1, Ordering::AcqRel);
    }

    fn submit_operation(&self, command: Command, operation: Operation) -> Result<(), NativeError> {
        self.try_send(command, operation)
    }

    fn submit_control(&self, command: Command, operation: Operation) -> Result<(), NativeError> {
        self.try_send(command, operation)
    }

    fn try_send(&self, command: Command, operation: Operation) -> Result<(), NativeError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(NativeError::reactor_closed(operation));
        }
        self.command_sender
            .try_send(command)
            .map_err(|error| match error {
                TrySendError::Full(_) => {
                    NativeError::queue_full(operation, "native reactor command queue is full")
                }
                TrySendError::Disconnected(_) => NativeError::reactor_closed(operation),
            })?;
        self.wake_ignoring_shutdown();
        Ok(())
    }

    fn wake_ignoring_shutdown(&self) {
        loop {
            match write(&*self.wake_descriptor, &1_u64.to_ne_bytes()) {
                Ok(_) | Err(Errno::AGAIN) => break,
                Err(Errno::INTR) => {}
                Err(_) => {
                    self.accepting.store(false, Ordering::Release);
                    break;
                }
            }
        }
    }
}

impl Drop for ReactorHandle {
    fn drop(&mut self) {
        self.accepting.store(false, Ordering::Release);
        self.wake_ignoring_shutdown();
    }
}

enum AdvancedAction {
    GetRawOption {
        level: i32,
        name: i32,
        maximum: usize,
    },
    SetRawOption {
        level: i32,
        name: i32,
        value: Vec<u8>,
    },
    AttachClassic(Vec<ClassicBpfInstruction>),
    AttachEbpf(i32),
    DetachFilter,
    LockFilter,
    PacketMembership {
        membership: PacketMembership,
        add: bool,
    },
    PacketAuxdata(bool),
    PacketFanout {
        group: u16,
        mode: u16,
    },
    PacketStatistics,
}

enum Command {
    #[cfg(test)]
    InjectFatalFailure,
    Register {
        socket_id: u64,
        core: SocketCore,
        sink: SharedCompletionSink,
        close_operation: Arc<Mutex<Option<u32>>>,
        pending_operations: Arc<AtomicUsize>,
        family: SocketFamily,
    },
    Bind {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        address: Ipv4Addr,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    BindIpv6 {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        address: SocketAddrV6,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    BindPacket {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        address: PacketAddress,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    ConnectIpv6 {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        address: SocketAddrV6,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    ConnectIpv4 {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        address: Ipv4Addr,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    Disconnect {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    GetLocalAddress {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    GetOption {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        option: Ipv4SocketOption,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    SetOption {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        option: Ipv4SocketOption,
        value: u32,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    GetIpv6Option {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        option: Ipv6SocketOption,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    SetIpv6Option {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        option: Ipv6SocketOption,
        value: u32,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    GetDevice {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    SetDevice {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        device: Option<String>,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    Advanced {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        action: AdvancedAction,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    Send {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        data: Vec<u8>,
        destination: MessageDestination,
        flags: SendMessageFlags,
        control: Vec<SendControlMessage>,
        message_api: bool,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    SendBatch {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        messages: Vec<BatchSendMessage>,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    Receive {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        buffer_length: PacketBufferLength,
        control_capacity: usize,
        flags: ReceiveMessageFlags,
        message_api: bool,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    ReceiveBatch {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        count: usize,
        buffer_length: PacketBufferLength,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    ConfigurePacketRing {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        config: PacketRingConfig,
        reservation: RingReservation,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
    ReceiveRingFrame {
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        sink: SharedCompletionSink,
        admission: OperationAdmission,
    },
}

struct PendingSend {
    operation_id: u32,
    lease: OperationLease,
    data: Vec<u8>,
    destination: MessageDestination,
    flags: SendMessageFlags,
    control: Vec<SendControlMessage>,
    message_api: bool,
    batch: Option<Vec<BatchSendMessage>>,
    admission: OperationAdmission,
}

struct PendingReceive {
    operation_id: u32,
    lease: OperationLease,
    buffer_length: PacketBufferLength,
    control_capacity: usize,
    flags: ReceiveMessageFlags,
    message_api: bool,
    batch_count: Option<usize>,
    ring_frame: bool,
    admission: OperationAdmission,
}

struct SocketEntry {
    core: SocketCore,
    sink: SharedCompletionSink,
    close_operation: Arc<Mutex<Option<u32>>>,
    pending_operations: Arc<AtomicUsize>,
    sends: VecDeque<PendingSend>,
    receives: VecDeque<PendingReceive>,
    error_receives: VecDeque<PendingReceive>,
    family: SocketFamily,
    epoll_registered: bool,
    epoll_lease: Option<OperationLease>,
    ring: Option<ConfiguredPacketRing>,
}

struct ReactorState {
    epoll_descriptor: OwnedFd,
    socket_count: Arc<AtomicUsize>,
    sockets: HashMap<u64, SocketEntry>,
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the reactor thread owns these resources until shutdown"
)]
fn run_reactor(
    epoll_descriptor: OwnedFd,
    wake_descriptor: Arc<OwnedFd>,
    command_receiver: Receiver<Command>,
    accepting: Arc<AtomicBool>,
    socket_count: Arc<AtomicUsize>,
) {
    let mut state = ReactorState {
        epoll_descriptor,
        socket_count,
        sockets: HashMap::new(),
    };
    let mut events = Vec::with_capacity(EVENT_BATCH_SIZE);

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reactor_loop(
            &mut state,
            &mut events,
            &wake_descriptor,
            &command_receiver,
            &accepting,
        )
    }));
    let terminal_error = match outcome {
        Ok(error) => error,
        Err(_) => Some(NativeError::internal(
            Operation::StartReactor,
            "native I/O reactor panicked",
        )),
    };
    accepting.store(false, Ordering::Release);

    if let Some(error) = terminal_error {
        ReactorState::fail_queued_commands(&command_receiver, &error);
        state.fail_all_operations(&error);
    }
    for entry in state.sockets.values() {
        clear_completion_sink(&entry.sink);
    }
    state.sockets.clear();
    state.socket_count.store(0, Ordering::Release);
}

fn reactor_loop(
    state: &mut ReactorState,
    events: &mut Vec<epoll::Event>,
    wake_descriptor: &OwnedFd,
    command_receiver: &Receiver<Command>,
    accepting: &AtomicBool,
) -> Option<NativeError> {
    while accepting.load(Ordering::Acquire) {
        events.clear();
        match epoll::wait(&state.epoll_descriptor, spare_capacity(events), None) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(error) => {
                return Some(NativeError::system(Operation::StartReactor, error));
            }
        }

        if !accepting.load(Ordering::Acquire) {
            return None;
        }

        for event in events.drain(..) {
            let token = event.data.u64();
            if token == WAKE_TOKEN {
                drain_eventfd(wake_descriptor);
                if state.drain_commands(command_receiver) {
                    wake_eventfd(wake_descriptor);
                }
                state.cancel_requested_operations();
                state.close_requested_sockets();
            } else {
                state.process_ready(token, event.flags);
            }
        }
        state.close_requested_sockets();
    }
    None
}

impl ReactorState {
    fn drain_commands(&mut self, receiver: &Receiver<Command>) -> bool {
        for _ in 0..COMMAND_BATCH_SIZE {
            let Ok(command) = receiver.try_recv() else {
                return false;
            };
            #[cfg(test)]
            if matches!(command, Command::InjectFatalFailure) {
                panic!("injected reactor failure");
            }
            self.process_command(command);
        }
        true
    }

    #[allow(
        clippy::too_many_lines,
        reason = "each bounded command variant is handled in one exhaustive dispatch"
    )]
    fn process_command(&mut self, command: Command) {
        match command {
            #[cfg(test)]
            Command::InjectFatalFailure => {
                unreachable!("injected failure is consumed by drain_commands")
            }
            Command::Register {
                socket_id,
                core,
                sink,
                close_operation,
                pending_operations,
                family,
            } => {
                if core.status() != SocketStatus::Open {
                    deliver_completion(
                        &sink,
                        Completion {
                            operation_id: 0,
                            result: Err(NativeError::socket_closed()),
                        },
                    );
                    clear_completion_sink(&sink);
                    self.socket_count.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                let entry = SocketEntry {
                    core,
                    sink: Arc::clone(&sink),
                    close_operation,
                    pending_operations,
                    sends: VecDeque::new(),
                    receives: VecDeque::new(),
                    error_receives: VecDeque::new(),
                    family,
                    epoll_registered: false,
                    epoll_lease: None,
                    ring: None,
                };
                if self.sockets.insert(socket_id, entry).is_some() {
                    deliver_completion(
                        &sink,
                        Completion {
                            operation_id: 0,
                            result: Err(NativeError::internal(
                                Operation::RegisterSocket,
                                "duplicate reactor socket identifier",
                            )),
                        },
                    );
                    clear_completion_sink(&sink);
                    self.socket_count.fetch_sub(1, Ordering::AcqRel);
                } else {
                    deliver_completion(
                        &sink,
                        Completion {
                            operation_id: 0,
                            result: Ok(CompletionValue::Opened),
                        },
                    );
                }
            }
            Command::Bind {
                socket_id,
                operation_id,
                lease,
                address,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    bind_ipv4(descriptor, address)?;
                    Ok(CompletionValue::Bound)
                },
            ),
            Command::BindIpv6 {
                socket_id,
                operation_id,
                lease,
                address,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    bind_ipv6(descriptor, address)?;
                    Ok(CompletionValue::Bound)
                },
            ),
            Command::BindPacket {
                socket_id,
                operation_id,
                lease,
                address,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    bind_packet(descriptor, &address)?;
                    Ok(CompletionValue::Bound)
                },
            ),
            Command::ConnectIpv6 {
                socket_id,
                operation_id,
                lease,
                address,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    connect_ipv6(descriptor, address)?;
                    Ok(CompletionValue::Connected)
                },
            ),
            Command::ConnectIpv4 {
                socket_id,
                operation_id,
                lease,
                address,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    connect_ipv4(descriptor, address)?;
                    Ok(CompletionValue::Connected)
                },
            ),
            Command::Disconnect {
                socket_id,
                operation_id,
                lease,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    disconnect_socket(descriptor)?;
                    Ok(CompletionValue::Disconnected)
                },
            ),
            Command::GetLocalAddress {
                socket_id,
                operation_id,
                lease,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| match self.sockets.get(&socket_id).map(|entry| entry.family) {
                    Some(SocketFamily::Ipv4) => {
                        local_ipv4_address(descriptor).map(CompletionValue::LocalAddress)
                    }
                    Some(SocketFamily::Ipv6) => {
                        local_ipv6_address(descriptor).map(CompletionValue::LocalIpv6Address)
                    }
                    Some(SocketFamily::Packet(_)) => Err(NativeError::unsupported(
                        Operation::GetLocalAddress,
                        "packet sockets use their bound link address",
                    )),
                    None => Err(NativeError::socket_closed()),
                },
            ),
            Command::GetOption {
                socket_id,
                operation_id,
                lease,
                option,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    get_ipv4_socket_option(descriptor, option).map(CompletionValue::OptionValue)
                },
            ),
            Command::SetOption {
                socket_id,
                operation_id,
                lease,
                option,
                value,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    set_ipv4_socket_option(descriptor, option, value)?;
                    Ok(CompletionValue::OptionSet)
                },
            ),
            Command::GetIpv6Option {
                socket_id,
                operation_id,
                lease,
                option,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    get_ipv6_socket_option(descriptor, option).map(CompletionValue::OptionValue)
                },
            ),
            Command::SetIpv6Option {
                socket_id,
                operation_id,
                lease,
                option,
                value,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    set_ipv6_socket_option(descriptor, option, value)?;
                    Ok(CompletionValue::OptionSet)
                },
            ),
            Command::GetDevice {
                socket_id,
                operation_id,
                lease,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| get_bind_to_device(descriptor).map(CompletionValue::DeviceValue),
            ),
            Command::SetDevice {
                socket_id,
                operation_id,
                lease,
                device,
                sink,
                admission,
            } => self.process_control(
                socket_id,
                operation_id,
                lease,
                admission,
                &sink,
                |descriptor| {
                    set_bind_to_device(descriptor, device.as_deref())?;
                    Ok(CompletionValue::OptionSet)
                },
            ),
            Command::Advanced {
                socket_id,
                operation_id,
                lease,
                action,
                sink,
                admission,
            } => {
                let packet_family = matches!(
                    self.sockets.get(&socket_id).map(|entry| entry.family),
                    Some(SocketFamily::Packet(_))
                );
                self.process_control(
                    socket_id,
                    operation_id,
                    lease,
                    admission,
                    &sink,
                    |descriptor| {
                        let packet_required = matches!(
                            &action,
                            AdvancedAction::PacketMembership { .. }
                                | AdvancedAction::PacketAuxdata(_)
                                | AdvancedAction::PacketFanout { .. }
                                | AdvancedAction::PacketStatistics
                        );
                        if packet_required && !packet_family {
                            return Err(NativeError::invalid_argument(
                                Operation::SetSocketOption,
                                "operation requires a packet socket",
                            ));
                        }
                        match action {
                            AdvancedAction::GetRawOption {
                                level,
                                name,
                                maximum,
                            } => get_raw_option(descriptor, level, name, maximum)
                                .map(CompletionValue::RawOption),
                            AdvancedAction::SetRawOption { level, name, value } => {
                                set_raw_option(descriptor, level, name, &value)?;
                                Ok(CompletionValue::OptionSet)
                            }
                            AdvancedAction::AttachClassic(program) => {
                                attach_classic_bpf(descriptor, &program)?;
                                Ok(CompletionValue::OptionSet)
                            }
                            AdvancedAction::AttachEbpf(fd) => {
                                attach_ebpf(descriptor, fd)?;
                                Ok(CompletionValue::OptionSet)
                            }
                            AdvancedAction::DetachFilter => {
                                detach_filter(descriptor)?;
                                Ok(CompletionValue::OptionSet)
                            }
                            AdvancedAction::LockFilter => {
                                lock_filter(descriptor)?;
                                Ok(CompletionValue::OptionSet)
                            }
                            AdvancedAction::PacketMembership { membership, add } => {
                                set_packet_membership(descriptor, &membership, add)?;
                                Ok(CompletionValue::OptionSet)
                            }
                            AdvancedAction::PacketAuxdata(enabled) => {
                                set_packet_auxdata(descriptor, enabled)?;
                                Ok(CompletionValue::OptionSet)
                            }
                            AdvancedAction::PacketFanout { group, mode } => {
                                set_packet_fanout(descriptor, group, mode)?;
                                Ok(CompletionValue::OptionSet)
                            }
                            AdvancedAction::PacketStatistics => {
                                packet_statistics(descriptor).map(CompletionValue::PacketStatistics)
                            }
                        }
                    },
                );
            }
            Command::Send {
                socket_id,
                operation_id,
                lease,
                data,
                destination,
                flags,
                control,
                message_api,
                sink,
                admission,
            } => {
                if let Some(mut entry) = self.sockets.remove(&socket_id) {
                    if admission.cancelled() || entry.core.status() != SocketStatus::Open {
                        drop(lease);
                        let error = if admission.cancelled() {
                            NativeError::aborted(admission.operation)
                        } else {
                            NativeError::socket_closed()
                        };
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(error),
                            },
                        );
                        self.sockets.insert(socket_id, entry);
                        return;
                    }
                    if entry.sends.len() >= MAX_PENDING_SENDS_PER_SOCKET {
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(NativeError::queue_full(
                                    admission.operation,
                                    "maximum pending sends per socket reached",
                                )),
                            },
                        );
                    } else {
                        entry.sends.push_back(PendingSend {
                            operation_id,
                            lease,
                            data,
                            destination,
                            flags,
                            control,
                            message_api,
                            batch: None,
                            admission,
                        });
                        self.drive_sends(&mut entry, READY_OPERATION_BUDGET, READY_BYTE_BUDGET);
                    }
                    self.refresh_interest(socket_id, &mut entry);
                    self.sockets.insert(socket_id, entry);
                } else {
                    drop(lease);
                    deliver_completion(
                        &sink,
                        Completion {
                            operation_id,
                            result: Err(NativeError::socket_closed()),
                        },
                    );
                }
            }
            Command::SendBatch {
                socket_id,
                operation_id,
                lease,
                messages,
                sink,
                admission,
            } => {
                if let Some(mut entry) = self.sockets.remove(&socket_id) {
                    if admission.cancelled() || entry.core.status() != SocketStatus::Open {
                        let error = if admission.cancelled() {
                            NativeError::aborted(admission.operation)
                        } else {
                            NativeError::socket_closed()
                        };
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(error),
                            },
                        );
                    } else if entry.sends.len() >= MAX_PENDING_SENDS_PER_SOCKET {
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(NativeError::queue_full(
                                    admission.operation,
                                    "maximum pending sends per socket reached",
                                )),
                            },
                        );
                    } else {
                        entry.sends.push_back(PendingSend {
                            operation_id,
                            lease,
                            data: Vec::new(),
                            destination: MessageDestination::Ipv4(SocketAddrV4::new(
                                Ipv4Addr::UNSPECIFIED,
                                0,
                            )),
                            flags: SendMessageFlags::default(),
                            control: Vec::new(),
                            message_api: true,
                            batch: Some(messages),
                            admission,
                        });
                        self.drive_sends(&mut entry, READY_OPERATION_BUDGET, READY_BYTE_BUDGET);
                    }
                    self.refresh_interest(socket_id, &mut entry);
                    self.sockets.insert(socket_id, entry);
                } else {
                    drop(lease);
                    deliver_completion(
                        &sink,
                        Completion {
                            operation_id,
                            result: Err(NativeError::socket_closed()),
                        },
                    );
                }
            }
            Command::Receive {
                socket_id,
                operation_id,
                lease,
                buffer_length,
                control_capacity,
                flags,
                message_api,
                sink,
                admission,
            } => {
                if let Some(mut entry) = self.sockets.remove(&socket_id) {
                    if admission.cancelled() || entry.core.status() != SocketStatus::Open {
                        drop(lease);
                        let error = if admission.cancelled() {
                            NativeError::aborted(admission.operation)
                        } else {
                            NativeError::socket_closed()
                        };
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(error),
                            },
                        );
                        self.sockets.insert(socket_id, entry);
                        return;
                    }
                    if entry.ring.is_some() {
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(NativeError::unsupported(
                                    admission.operation,
                                    "message receive is unavailable after packet-ring configuration",
                                )),
                            },
                        );
                    } else if entry.receives.len() + entry.error_receives.len()
                        >= MAX_PENDING_RECEIVES_PER_SOCKET
                    {
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(NativeError::queue_full(
                                    admission.operation,
                                    "maximum pending receives per socket reached",
                                )),
                            },
                        );
                    } else {
                        let error_queue = flags.error_queue;
                        let pending = PendingReceive {
                            operation_id,
                            lease,
                            buffer_length,
                            control_capacity,
                            flags,
                            message_api,
                            batch_count: None,
                            ring_frame: false,
                            admission,
                        };
                        if error_queue {
                            entry.error_receives.push_back(pending);
                        } else {
                            entry.receives.push_back(pending);
                        }
                        self.drive_receives(
                            &mut entry,
                            error_queue,
                            READY_OPERATION_BUDGET,
                            READY_BYTE_BUDGET,
                        );
                    }
                    self.refresh_interest(socket_id, &mut entry);
                    self.sockets.insert(socket_id, entry);
                } else {
                    drop(lease);
                    deliver_completion(
                        &sink,
                        Completion {
                            operation_id,
                            result: Err(NativeError::socket_closed()),
                        },
                    );
                }
            }
            Command::ReceiveBatch {
                socket_id,
                operation_id,
                lease,
                count,
                buffer_length,
                sink,
                admission,
            } => {
                if let Some(mut entry) = self.sockets.remove(&socket_id) {
                    if admission.cancelled() || entry.core.status() != SocketStatus::Open {
                        let error = if admission.cancelled() {
                            NativeError::aborted(admission.operation)
                        } else {
                            NativeError::socket_closed()
                        };
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(error),
                            },
                        );
                    } else if entry.ring.is_some() {
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(NativeError::unsupported(
                                    admission.operation,
                                    "batch receive is unavailable after packet-ring configuration",
                                )),
                            },
                        );
                    } else if entry.receives.len() + entry.error_receives.len()
                        >= MAX_PENDING_RECEIVES_PER_SOCKET
                    {
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(NativeError::queue_full(
                                    admission.operation,
                                    "maximum pending receives per socket reached",
                                )),
                            },
                        );
                    } else {
                        entry.receives.push_back(PendingReceive {
                            operation_id,
                            lease,
                            buffer_length,
                            control_capacity: 0,
                            flags: ReceiveMessageFlags::default(),
                            message_api: true,
                            batch_count: Some(count),
                            ring_frame: false,
                            admission,
                        });
                        self.drive_receives(
                            &mut entry,
                            false,
                            READY_OPERATION_BUDGET,
                            READY_BYTE_BUDGET,
                        );
                    }
                    self.refresh_interest(socket_id, &mut entry);
                    self.sockets.insert(socket_id, entry);
                } else {
                    drop(lease);
                    deliver_completion(
                        &sink,
                        Completion {
                            operation_id,
                            result: Err(NativeError::socket_closed()),
                        },
                    );
                }
            }
            Command::ConfigurePacketRing {
                socket_id,
                operation_id,
                lease,
                config,
                reservation,
                sink,
                admission,
            } => {
                let result = if admission.cancelled() {
                    Err(NativeError::aborted(admission.operation))
                } else if let Some(entry) = self.sockets.get_mut(&socket_id) {
                    if !matches!(entry.family, SocketFamily::Packet(_)) {
                        Err(NativeError::invalid_argument(
                            Operation::ConfigurePacketRing,
                            "packet rings require an AF_PACKET socket",
                        ))
                    } else if entry.ring.is_some() {
                        Err(NativeError::unsupported(
                            Operation::ConfigurePacketRing,
                            "the socket already owns a packet ring",
                        ))
                    } else if !entry.receives.is_empty() || !entry.error_receives.is_empty() {
                        Err(NativeError::unsupported(
                            Operation::ConfigurePacketRing,
                            "configure the packet ring before submitting receives",
                        ))
                    } else {
                        PacketRing::configure(lease.as_fd(), config).map(|ring| {
                            entry.ring = Some(ConfiguredPacketRing {
                                ring,
                                _reservation: reservation,
                            });
                            CompletionValue::PacketRingConfigured
                        })
                    }
                } else {
                    Err(NativeError::socket_closed())
                };
                drop(lease);
                drop(admission);
                deliver_completion(
                    &sink,
                    Completion {
                        operation_id,
                        result,
                    },
                );
            }
            Command::ReceiveRingFrame {
                socket_id,
                operation_id,
                lease,
                sink,
                admission,
            } => {
                if let Some(mut entry) = self.sockets.remove(&socket_id) {
                    if admission.cancelled() || entry.core.status() != SocketStatus::Open {
                        let error = if admission.cancelled() {
                            NativeError::aborted(admission.operation)
                        } else {
                            NativeError::socket_closed()
                        };
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(error),
                            },
                        );
                    } else if entry.ring.is_none() {
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(NativeError::unsupported(
                                    Operation::ReceiveRingFrame,
                                    "configure a packet ring before receiving frames",
                                )),
                            },
                        );
                    } else if entry.receives.len() >= MAX_PENDING_RECEIVES_PER_SOCKET {
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id,
                                result: Err(NativeError::queue_full(
                                    admission.operation,
                                    "maximum pending receives per socket reached",
                                )),
                            },
                        );
                    } else {
                        entry.receives.push_back(PendingReceive {
                            operation_id,
                            lease,
                            buffer_length: PacketBufferLength::try_from(1_u64)
                                .expect("one is a valid packet length"),
                            control_capacity: 0,
                            flags: ReceiveMessageFlags::default(),
                            message_api: false,
                            batch_count: None,
                            ring_frame: true,
                            admission,
                        });
                        self.drive_receives(
                            &mut entry,
                            false,
                            READY_OPERATION_BUDGET,
                            READY_BYTE_BUDGET,
                        );
                    }
                    self.refresh_interest(socket_id, &mut entry);
                    self.sockets.insert(socket_id, entry);
                } else {
                    drop(lease);
                    deliver_completion(
                        &sink,
                        Completion {
                            operation_id,
                            result: Err(NativeError::socket_closed()),
                        },
                    );
                }
            }
        }
    }

    fn process_control(
        &self,
        socket_id: u64,
        operation_id: u32,
        lease: OperationLease,
        admission: OperationAdmission,
        sink: &SharedCompletionSink,
        operation: impl FnOnce(std::os::fd::BorrowedFd<'_>) -> Result<CompletionValue, NativeError>,
    ) {
        let result = if admission.cancelled() {
            Err(NativeError::aborted(admission.operation))
        } else {
            match self.sockets.get(&socket_id) {
                Some(entry) if entry.core.status() == SocketStatus::Open => {
                    operation(lease.as_fd())
                }
                Some(_) | None => Err(NativeError::socket_closed()),
            }
        };
        drop(lease);
        drop(admission);
        deliver_completion(
            sink,
            Completion {
                operation_id,
                result,
            },
        );
    }

    fn process_ready(&mut self, socket_id: u64, flags: epoll::EventFlags) {
        let Some(mut entry) = self.sockets.remove(&socket_id) else {
            return;
        };

        if flags.contains(epoll::EventFlags::OUT) {
            self.drive_sends(&mut entry, READY_OPERATION_BUDGET, READY_BYTE_BUDGET);
        }
        if flags.contains(epoll::EventFlags::IN) {
            self.drive_receives(&mut entry, false, READY_OPERATION_BUDGET, READY_BYTE_BUDGET);
        }
        if flags.intersects(epoll::EventFlags::ERR | epoll::EventFlags::HUP) {
            self.drive_sends(&mut entry, READY_OPERATION_BUDGET, READY_BYTE_BUDGET);
            self.drive_receives(&mut entry, true, READY_OPERATION_BUDGET, READY_BYTE_BUDGET);
            self.drive_receives(&mut entry, false, READY_OPERATION_BUDGET, READY_BYTE_BUDGET);
            if !entry.sends.is_empty()
                || !entry.receives.is_empty()
                || !entry.error_receives.is_empty()
            {
                self.fail_entry_operations(
                    &mut entry,
                    &NativeError::system(Operation::Receive, Errno::IO),
                );
            }
        }

        self.refresh_interest(socket_id, &mut entry);
        self.sockets.insert(socket_id, entry);
    }

    #[allow(
        clippy::unused_self,
        clippy::too_many_lines,
        reason = "single and batch send fairness share one queue and budget"
    )]
    fn drive_sends(&self, entry: &mut SocketEntry, operation_budget: usize, byte_budget: usize) {
        let mut completed = 0;
        let mut bytes = 0;
        while completed < operation_budget && bytes < byte_budget {
            let Some(operation) = entry.sends.front() else {
                break;
            };
            if operation.admission.cancelled() {
                let operation = entry.sends.pop_front().expect("front operation exists");
                deliver_completion(
                    &entry.sink,
                    Completion {
                        operation_id: operation.operation_id,
                        result: Err(NativeError::aborted(operation.admission.operation)),
                    },
                );
                completed += 1;
                continue;
            }
            let operation_kind = operation.admission.operation;
            if let Some(batch) = &operation.batch {
                match send_batch(operation.lease.as_fd(), batch) {
                    Ok(result) => {
                        let operation = entry.sends.pop_front().expect("front operation exists");
                        let sent_bytes = result.lengths.iter().copied().sum::<usize>();
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result: Ok(CompletionValue::BatchSent(result)),
                            },
                        );
                        completed += 1;
                        bytes = bytes.saturating_add(sent_bytes);
                    }
                    Err(error) if error_is_again(&error) => break,
                    Err(error) => {
                        let operation = entry.sends.pop_front().expect("front operation exists");
                        deliver_completion(
                            &entry.sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result: Err(error),
                            },
                        );
                        completed += 1;
                    }
                }
                continue;
            }
            let result = match &operation.destination {
                MessageDestination::Ipv4(destination) => send_ipv4_message(
                    operation.lease.as_fd(),
                    operation_kind,
                    &operation.data,
                    *destination,
                    operation.flags,
                    &operation.control,
                ),
                MessageDestination::Ipv6(destination) => send_ipv6_message(
                    operation.lease.as_fd(),
                    operation_kind,
                    &operation.data,
                    *destination,
                    operation.flags,
                    &operation.control,
                ),
                MessageDestination::Packet(destination) => send_packet_message(
                    operation.lease.as_fd(),
                    operation_kind,
                    &operation.data,
                    destination,
                    operation.flags,
                ),
            };

            match result {
                Ok(bytes_sent) => {
                    let operation = entry.sends.pop_front().expect("front operation exists");
                    let completion = if bytes_sent == operation.data.len() {
                        if operation.message_api {
                            Ok(CompletionValue::MessageSent(bytes_sent))
                        } else {
                            Ok(CompletionValue::Sent(bytes_sent))
                        }
                    } else {
                        Err(NativeError::internal(
                            operation_kind,
                            format!(
                                "raw datagram send was partial: {bytes_sent} of {} bytes",
                                operation.data.len()
                            ),
                        ))
                    };
                    deliver_completion(
                        &entry.sink,
                        Completion {
                            operation_id: operation.operation_id,
                            result: completion,
                        },
                    );
                    completed += 1;
                    bytes = bytes.saturating_add(bytes_sent);
                }
                Err(error) if error_is_again(&error) => break,
                Err(error) => {
                    let operation = entry.sends.pop_front().expect("front operation exists");
                    deliver_completion(
                        &entry.sink,
                        Completion {
                            operation_id: operation.operation_id,
                            result: Err(error),
                        },
                    );
                    completed += 1;
                }
            }
        }
    }

    #[allow(clippy::unused_self, reason = "keeps reactor state operations grouped")]
    #[allow(
        clippy::too_many_lines,
        reason = "IPv4 and IPv6 completion paths remain exhaustive"
    )]
    fn drive_receives(
        &self,
        entry: &mut SocketEntry,
        error_queue: bool,
        operation_budget: usize,
        byte_budget: usize,
    ) {
        let sink = Arc::clone(&entry.sink);
        let family = entry.family;
        let ring = &mut entry.ring;
        let receives = if error_queue {
            &mut entry.error_receives
        } else {
            &mut entry.receives
        };
        let mut completed = 0;
        let mut bytes = 0;
        while completed < operation_budget && bytes < byte_budget {
            let Some(operation) = receives.front() else {
                break;
            };
            if operation.admission.cancelled() {
                let operation = receives.pop_front().expect("front operation exists");
                deliver_completion(
                    &sink,
                    Completion {
                        operation_id: operation.operation_id,
                        result: Err(NativeError::aborted(operation.admission.operation)),
                    },
                );
                completed += 1;
                continue;
            }
            let operation_kind = operation.admission.operation;
            if operation.ring_frame {
                let Some(packet_ring) = ring.as_mut() else {
                    let operation = receives.pop_front().expect("front operation exists");
                    deliver_completion(
                        &sink,
                        Completion {
                            operation_id: operation.operation_id,
                            result: Err(NativeError::internal(
                                Operation::ReceiveRingFrame,
                                "configured packet ring disappeared",
                            )),
                        },
                    );
                    completed += 1;
                    continue;
                };
                match packet_ring.ring.next_frame() {
                    Ok(Some(frame)) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        let received_bytes = frame.data.len();
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result: Ok(CompletionValue::RingFrame(frame)),
                            },
                        );
                        completed += 1;
                        bytes = bytes.saturating_add(received_bytes);
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result: Err(error),
                            },
                        );
                        completed += 1;
                    }
                }
                continue;
            }
            if let Some(count) = operation.batch_count {
                let family_code = match family {
                    SocketFamily::Ipv4 => 4,
                    SocketFamily::Ipv6 => 6,
                    SocketFamily::Packet(_) => 17,
                };
                match receive_batch(
                    operation.lease.as_fd(),
                    family_code,
                    count,
                    operation.buffer_length.get(),
                ) {
                    Ok(messages) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        let received_bytes = messages
                            .iter()
                            .map(|message| match message {
                                BatchReceivedMessage::Ipv4(value) => value.data.len(),
                                BatchReceivedMessage::Ipv6(value) => value.data.len(),
                                BatchReceivedMessage::Packet(value) => value.data.len(),
                            })
                            .sum::<usize>();
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result: Ok(CompletionValue::BatchReceived(messages)),
                            },
                        );
                        completed += 1;
                        bytes = bytes.saturating_add(received_bytes);
                    }
                    Err(error) if error_is_again(&error) => break,
                    Err(error) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result: Err(error),
                            },
                        );
                        completed += 1;
                    }
                }
                continue;
            }
            match family {
                SocketFamily::Ipv4 => match receive_ipv4_message(
                    operation.lease.as_fd(),
                    operation_kind,
                    operation.buffer_length.get(),
                    operation.control_capacity,
                    operation.flags,
                ) {
                    Ok(message) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        let received_bytes = message.data.len();
                        let ipv4 = parse_ipv4_packet_metadata(&message.data);
                        let result = if operation.message_api {
                            Ok(CompletionValue::MessageReceived { message, ipv4 })
                        } else if let Some(source_address) = message.source_address {
                            Ok(CompletionValue::Received {
                                data: message.data,
                                source_address,
                                packet_length: message.data_length,
                                truncated: message.data_truncated,
                                ipv4,
                            })
                        } else {
                            Err(NativeError::internal(
                                operation_kind,
                                "kernel returned a packet without a source address",
                            ))
                        };
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result,
                            },
                        );
                        completed += 1;
                        bytes = bytes.saturating_add(received_bytes);
                    }
                    Err(error) if error_is_again(&error) => break,
                    Err(error) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result: Err(error),
                            },
                        );
                        completed += 1;
                    }
                },
                SocketFamily::Ipv6 => match receive_ipv6_message(
                    operation.lease.as_fd(),
                    operation_kind,
                    operation.buffer_length.get(),
                    operation.control_capacity,
                    operation.flags,
                ) {
                    Ok(message) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        let received_bytes = message.data.len();
                        let result = if operation.message_api {
                            Ok(CompletionValue::Ipv6MessageReceived { message })
                        } else {
                            Err(NativeError::unsupported(
                                operation_kind,
                                "legacy receive is IPv4-only",
                            ))
                        };
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result,
                            },
                        );
                        completed += 1;
                        bytes = bytes.saturating_add(received_bytes);
                    }
                    Err(error) if error_is_again(&error) => break,
                    Err(error) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result: Err(error),
                            },
                        );
                        completed += 1;
                    }
                },
                SocketFamily::Packet(_) => match receive_packet_message(
                    operation.lease.as_fd(),
                    operation_kind,
                    operation.buffer_length.get(),
                    operation.flags,
                ) {
                    Ok(message) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        let received_bytes = message.data.len();
                        let result = if operation.message_api {
                            Ok(CompletionValue::PacketMessageReceived { message })
                        } else {
                            Err(NativeError::unsupported(
                                operation_kind,
                                "legacy receive is IPv4-only",
                            ))
                        };
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result,
                            },
                        );
                        completed += 1;
                        bytes = bytes.saturating_add(received_bytes);
                    }
                    Err(error) if error_is_again(&error) => break,
                    Err(error) => {
                        let operation = receives.pop_front().expect("front operation exists");
                        deliver_completion(
                            &sink,
                            Completion {
                                operation_id: operation.operation_id,
                                result: Err(error),
                            },
                        );
                        completed += 1;
                    }
                },
            }
        }
    }

    fn refresh_interest(&self, socket_id: u64, entry: &mut SocketEntry) {
        let mut flags = epoll::EventFlags::empty();
        if !entry.receives.is_empty() || !entry.error_receives.is_empty() {
            flags |= epoll::EventFlags::IN;
        }
        if !entry.sends.is_empty() {
            flags |= epoll::EventFlags::OUT;
        }

        if flags.is_empty() {
            if entry.epoll_registered {
                if let Some(lease) = entry.epoll_lease.take() {
                    let _ = epoll::delete(&self.epoll_descriptor, lease.as_fd());
                }
                entry.epoll_registered = false;
            }
            return;
        }

        if !entry.epoll_registered {
            match entry.core.acquire_operation() {
                Ok(lease) => entry.epoll_lease = Some(lease),
                Err(error) => {
                    self.fail_entry_operations(entry, &error);
                    return;
                }
            }
        }
        let descriptor = entry
            .epoll_lease
            .as_ref()
            .expect("registered interest owns a lease")
            .as_fd();

        let result = if entry.epoll_registered {
            epoll::modify(
                &self.epoll_descriptor,
                descriptor,
                epoll::EventData::new_u64(socket_id),
                flags,
            )
        } else {
            epoll::add(
                &self.epoll_descriptor,
                descriptor,
                epoll::EventData::new_u64(socket_id),
                flags,
            )
        };

        if result.is_ok() {
            entry.epoll_registered = true;
        } else if let Err(error) = result {
            self.fail_entry_operations(
                entry,
                &NativeError::system(Operation::RegisterSocket, error),
            );
            entry.epoll_lease = None;
            entry.epoll_registered = false;
        }
    }

    fn fail_queued_commands(receiver: &Receiver<Command>, error: &NativeError) {
        while let Ok(command) = receiver.try_recv() {
            fail_queued_command(command, error);
        }
    }

    fn fail_all_operations(&mut self, error: &NativeError) {
        let socket_ids: Vec<u64> = self.sockets.keys().copied().collect();
        for socket_id in socket_ids {
            let Some(mut entry) = self.sockets.remove(&socket_id) else {
                continue;
            };
            self.fail_entry_operations(&mut entry, error);
            let close_operation = entry
                .close_operation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(operation_id) = close_operation {
                deliver_completion(
                    &entry.sink,
                    Completion {
                        operation_id,
                        result: Err(error_for_operation(error, Operation::CloseSocket)),
                    },
                );
            }
            clear_completion_sink(&entry.sink);
        }
    }

    #[allow(clippy::unused_self, reason = "keeps reactor state operations grouped")]
    fn fail_entry_operations(&self, entry: &mut SocketEntry, error: &NativeError) {
        while let Some(operation) = entry.sends.pop_front() {
            deliver_completion(
                &entry.sink,
                Completion {
                    operation_id: operation.operation_id,
                    result: Err(error_for_operation(error, operation.admission.operation)),
                },
            );
        }
        while let Some(operation) = entry.receives.pop_front() {
            deliver_completion(
                &entry.sink,
                Completion {
                    operation_id: operation.operation_id,
                    result: Err(error_for_operation(error, operation.admission.operation)),
                },
            );
        }
        while let Some(operation) = entry.error_receives.pop_front() {
            deliver_completion(
                &entry.sink,
                Completion {
                    operation_id: operation.operation_id,
                    result: Err(error_for_operation(error, operation.admission.operation)),
                },
            );
        }
    }

    fn cancel_requested_operations(&mut self) {
        let socket_ids: Vec<u64> = self.sockets.keys().copied().collect();
        for socket_id in socket_ids {
            let Some(mut entry) = self.sockets.remove(&socket_id) else {
                continue;
            };

            let mut remaining_sends = VecDeque::with_capacity(entry.sends.len());
            while let Some(operation) = entry.sends.pop_front() {
                if operation.admission.cancelled() {
                    deliver_completion(
                        &entry.sink,
                        Completion {
                            operation_id: operation.operation_id,
                            result: Err(NativeError::aborted(operation.admission.operation)),
                        },
                    );
                } else {
                    remaining_sends.push_back(operation);
                }
            }
            entry.sends = remaining_sends;

            let mut remaining_receives = VecDeque::with_capacity(entry.receives.len());
            while let Some(operation) = entry.receives.pop_front() {
                if operation.admission.cancelled() {
                    deliver_completion(
                        &entry.sink,
                        Completion {
                            operation_id: operation.operation_id,
                            result: Err(NativeError::aborted(operation.admission.operation)),
                        },
                    );
                } else {
                    remaining_receives.push_back(operation);
                }
            }
            entry.receives = remaining_receives;

            let mut remaining_error_receives = VecDeque::with_capacity(entry.error_receives.len());
            while let Some(operation) = entry.error_receives.pop_front() {
                if operation.admission.cancelled() {
                    deliver_completion(
                        &entry.sink,
                        Completion {
                            operation_id: operation.operation_id,
                            result: Err(NativeError::aborted(operation.admission.operation)),
                        },
                    );
                } else {
                    remaining_error_receives.push_back(operation);
                }
            }
            entry.error_receives = remaining_error_receives;

            self.refresh_interest(socket_id, &mut entry);
            self.sockets.insert(socket_id, entry);
        }
    }

    fn close_requested_sockets(&mut self) {
        let closing: Vec<u64> = self
            .sockets
            .iter()
            .filter_map(|(id, entry)| (entry.core.status() != SocketStatus::Open).then_some(*id))
            .collect();

        for socket_id in closing {
            if let Some(mut entry) = self.sockets.remove(&socket_id) {
                if entry.epoll_registered
                    && let Some(lease) = entry.epoll_lease.take()
                {
                    let _ = epoll::delete(&self.epoll_descriptor, lease.as_fd());
                }
                entry.epoll_registered = false;
                self.fail_entry_operations(&mut entry, &NativeError::socket_closed());
                if entry.pending_operations.load(Ordering::Acquire) != 0 {
                    self.sockets.insert(socket_id, entry);
                    continue;
                }
                let close_operation = entry
                    .close_operation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(operation_id) = close_operation {
                    deliver_completion(
                        &entry.sink,
                        Completion {
                            operation_id,
                            result: Ok(CompletionValue::Closed),
                        },
                    );
                }
                clear_completion_sink(&entry.sink);
                self.socket_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "every command owns one completion path"
)]
fn fail_queued_command(command: Command, error: &NativeError) {
    match command {
        #[cfg(test)]
        Command::InjectFatalFailure => {}
        Command::Register { sink, .. } => {
            deliver_completion(
                &sink,
                Completion {
                    operation_id: 0,
                    result: Err(error_for_operation(error, Operation::RegisterSocket)),
                },
            );
            clear_completion_sink(&sink);
        }
        Command::Bind {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::BindIpv6 {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::BindPacket {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::ConnectIpv6 {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::ConnectIpv4 {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::Disconnect {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::GetLocalAddress {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::GetOption {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::SetOption {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::GetIpv6Option {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::SetIpv6Option {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::GetDevice {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::SetDevice {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::Advanced {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::Send {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::SendBatch {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::Receive {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::ReceiveBatch {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::ConfigurePacketRing {
            operation_id,
            sink,
            admission,
            ..
        }
        | Command::ReceiveRingFrame {
            operation_id,
            sink,
            admission,
            ..
        } => {
            deliver_completion(
                &sink,
                Completion {
                    operation_id,
                    result: Err(error_for_operation(error, admission.operation)),
                },
            );
        }
    }
}

fn deliver_completion(sink: &SharedCompletionSink, completion: Completion) {
    let owned_sink = sink
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(owned_sink) = owned_sink {
        owned_sink.complete(completion);
    }
}

fn error_for_operation(error: &NativeError, operation: Operation) -> NativeError {
    error.with_operation(operation)
}

fn clear_completion_sink(sink: &SharedCompletionSink) {
    *sink
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

fn reserve_bounded(
    counter: &AtomicUsize,
    maximum: usize,
    operation: Operation,
    message: &'static str,
) -> Result<(), NativeError> {
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < maximum).then_some(current + 1)
        })
        .map(|_| ())
        .map_err(|_| NativeError::queue_full(operation, message))
}

fn reserve_bounded_amount(
    counter: &AtomicUsize,
    amount: usize,
    maximum: usize,
    operation: Operation,
    message: &'static str,
) -> Result<(), NativeError> {
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(amount).filter(|next| *next <= maximum)
        })
        .map(|_| ())
        .map_err(|_| NativeError::queue_full(operation, message))
}

fn drain_eventfd(descriptor: &OwnedFd) {
    let mut bytes = [0_u8; 8];
    while matches!(read(descriptor, &mut bytes), Ok(_) | Err(Errno::INTR)) {}
}

fn wake_eventfd(descriptor: &OwnedFd) {
    #[allow(
        clippy::match_same_arms,
        reason = "EINTR retries while all other results terminate the best-effort wake"
    )]
    loop {
        match write(descriptor, &1_u64.to_ne_bytes()) {
            Ok(_) | Err(Errno::AGAIN) => break,
            Err(Errno::INTR) => {}
            Err(_) => break,
        }
    }
}

fn error_is_again(error: &NativeError) -> bool {
    error.errno() == Some(Errno::AGAIN.raw_os_error())
}

pub(crate) fn parse_ipv4_packet_metadata(bytes: &[u8]) -> Option<Ipv4PacketMetadata> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let header_length = (bytes[0] & 0x0f).checked_mul(4)?;
    if header_length < 20 || usize::from(header_length) > bytes.len() {
        return None;
    }
    let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
    if total_length < u16::from(header_length) {
        return None;
    }
    let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    Some(Ipv4PacketMetadata {
        destination_address: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        protocol: bytes[9],
        ttl: bytes[8],
        type_of_service: bytes[1],
        header_length,
        total_length,
        identification: u16::from_be_bytes([bytes[4], bytes[5]]),
        fragment_offset: fragment & 0x1fff,
        dont_fragment: fragment & 0x4000 != 0,
        more_fragments: fragment & 0x2000 != 0,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::os::fd::OwnedFd;
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::time::Duration;

    use super::{
        Completion, CompletionSink, CompletionValue, MAX_PENDING_RECEIVES_PER_SOCKET, ReactorHandle,
    };
    use crate::conversion::PacketBufferLength;
    use crate::error::{ErrorKind, Operation};
    use crate::lifecycle::SocketCore;

    struct ChannelSink(Sender<Completion>);

    impl CompletionSink for ChannelSink {
        fn complete(&self, completion: Completion) {
            self.0.send(completion).unwrap();
        }
    }

    fn registered_udp_socket() -> (
        Arc<ReactorHandle>,
        super::ReactorSocket,
        Receiver<Completion>,
        UdpSocket,
        SocketAddr,
    ) {
        let reactor = ReactorHandle::start().unwrap();
        let (socket, peer) = udp_pair();
        let socket_address = socket.local_addr().unwrap();
        let core = SocketCore::from_owned_fd(OwnedFd::from(socket));
        let (sender, receiver) = channel();
        let registered = reactor
            .register(
                core,
                super::SocketFamily::Ipv4,
                Arc::new(ChannelSink(sender)),
            )
            .unwrap();
        assert!(matches!(
            receive_completion(&receiver, 0).result,
            Ok(CompletionValue::Opened)
        ));
        (reactor, registered, receiver, peer, socket_address)
    }

    fn udp_pair() -> (UdpSocket, UdpSocket) {
        let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let second = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        first.set_nonblocking(true).unwrap();
        second.set_nonblocking(true).unwrap();
        (first, second)
    }

    fn receive_completion(receiver: &Receiver<Completion>, operation_id: u32) -> Completion {
        let completion = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(completion.operation_id, operation_id);
        completion
    }

    #[test]
    fn reactor_receives_one_datagram_without_blocking_caller() {
        let (reactor, socket, receiver, peer, socket_address) = registered_udp_socket();
        socket
            .receive(1, PacketBufferLength::try_from(64).unwrap())
            .unwrap();

        peer.send_to(b"hello", socket_address).unwrap();
        let completion = receive_completion(&receiver, 1);
        match completion.result.unwrap() {
            CompletionValue::Received {
                data,
                source_address,
                truncated,
                ..
            } => {
                assert_eq!(data, b"hello");
                assert_eq!(source_address, Ipv4Addr::LOCALHOST);
                assert!(!truncated);
            }
            other => panic!("unexpected completion: {other:?}"),
        }

        assert!(socket.close(Some(2)));
        assert!(matches!(
            receive_completion(&receiver, 2).result,
            Ok(CompletionValue::Closed)
        ));
        reactor.shutdown_and_join();
    }

    #[test]
    fn fatal_reactor_failure_settles_admitted_operations() {
        let (reactor, socket, receiver, _peer, _socket_address) = registered_udp_socket();
        socket
            .receive(41, PacketBufferLength::try_from(64).unwrap())
            .unwrap();

        reactor.inject_fatal_failure();
        let completion = receive_completion(&receiver, 41);
        let error = completion.result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Internal);
        assert_eq!(error.operation(), Operation::Receive);
        reactor.shutdown_and_join();
    }

    #[test]
    fn close_cancels_pending_receive() {
        let (reactor, socket, receiver, _peer, _address) = registered_udp_socket();
        for operation_id in 3..19 {
            socket
                .receive(operation_id, PacketBufferLength::try_from(64).unwrap())
                .unwrap();
        }

        assert!(socket.close(Some(19)));
        let mut cancelled_ids = Vec::with_capacity(16);
        for _ in 3..19 {
            let cancelled = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
            cancelled_ids.push(cancelled.operation_id);
            assert_eq!(
                cancelled.result.unwrap_err().kind(),
                ErrorKind::SocketClosed
            );
        }
        cancelled_ids.sort_unstable();
        assert_eq!(cancelled_ids, (3..19).collect::<Vec<_>>());
        assert!(matches!(
            receive_completion(&receiver, 19).result,
            Ok(CompletionValue::Closed)
        ));
        reactor.shutdown_and_join();
    }

    #[test]
    fn cancellation_wakes_reactor_without_closing_socket() {
        let (reactor, socket, receiver, peer, socket_address) = registered_udp_socket();
        socket
            .receive(30, PacketBufferLength::try_from(64).unwrap())
            .unwrap();
        assert!(socket.cancel(30));
        let cancelled = receive_completion(&receiver, 30);
        assert_eq!(cancelled.result.unwrap_err().kind(), ErrorKind::Aborted);
        assert_eq!(socket.status(), crate::lifecycle::SocketStatus::Open);

        socket
            .receive(31, PacketBufferLength::try_from(64).unwrap())
            .unwrap();
        peer.send_to(b"still-open", socket_address).unwrap();
        assert!(matches!(
            receive_completion(&receiver, 31).result,
            Ok(CompletionValue::Received { .. })
        ));
        assert!(socket.close(Some(32)));
        assert!(matches!(
            receive_completion(&receiver, 32).result,
            Ok(CompletionValue::Closed)
        ));
        reactor.shutdown_and_join();
    }

    #[test]
    fn per_socket_receive_limit_is_enforced() {
        let (reactor, socket, receiver, _peer, _address) = registered_udp_socket();
        let receive_limit = u32::try_from(MAX_PENDING_RECEIVES_PER_SOCKET).unwrap();
        for operation_id in 1..=(receive_limit + 1) {
            socket
                .receive(operation_id, PacketBufferLength::try_from(64).unwrap())
                .unwrap();
        }

        let completion = receive_completion(&receiver, receive_limit + 1);
        assert_eq!(completion.result.unwrap_err().kind(), ErrorKind::QueueFull);

        assert!(socket.close(Some(100)));
        for operation_id in 1..=receive_limit {
            let completion = receive_completion(&receiver, operation_id);
            assert_eq!(
                completion.result.unwrap_err().kind(),
                ErrorKind::SocketClosed
            );
        }
        assert!(matches!(
            receive_completion(&receiver, 100).result,
            Ok(CompletionValue::Closed)
        ));
        reactor.shutdown_and_join();
    }

    #[test]
    fn reactor_sends_datagram() {
        let (reactor, socket, receiver, peer, _address) = registered_udp_socket();
        let peer_address = match peer.local_addr().unwrap() {
            SocketAddr::V4(address) => *address.ip(),
            SocketAddr::V6(_) => unreachable!(),
        };

        // The production raw-socket path always uses port zero. This test uses
        // the internal queue directly with a UDP destination port below.
        let (lease, admission) = socket
            .admit(7, crate::error::Operation::Send, b"outbound".len())
            .unwrap();
        reactor
            .submit_operation(
                super::Command::Send {
                    socket_id: socket.id,
                    operation_id: 7,
                    lease,
                    data: b"outbound".to_vec(),
                    destination: super::MessageDestination::Ipv4(SocketAddrV4::new(
                        peer_address,
                        peer.local_addr().unwrap().port(),
                    )),
                    flags: crate::message::SendMessageFlags::default(),
                    control: Vec::new(),
                    message_api: false,
                    sink: Arc::clone(&socket.sink),
                    admission,
                },
                crate::error::Operation::Send,
            )
            .unwrap();

        assert!(matches!(
            receive_completion(&receiver, 7).result,
            Ok(CompletionValue::Sent(8))
        ));
        let mut bytes = [0_u8; 16];
        let received_length = loop {
            match peer.recv(&mut bytes) {
                Ok(length) => break length,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                }
                Err(error) => panic!("UDP receive failed: {error}"),
            }
        };
        assert_eq!(&bytes[..received_length], b"outbound");

        assert!(socket.close(Some(8)));
        let _ = receive_completion(&receiver, 8);
        reactor.shutdown_and_join();
    }

    #[test]
    fn reactor_serializes_typed_socket_options() {
        let (reactor, socket, receiver, _peer, _address) = registered_udp_socket();
        socket
            .set_option(20, crate::linux::Ipv4SocketOption::IpTtl, 42)
            .unwrap();
        assert!(matches!(
            receive_completion(&receiver, 20).result,
            Ok(CompletionValue::OptionSet)
        ));

        socket
            .get_option(21, crate::linux::Ipv4SocketOption::IpTtl)
            .unwrap();
        assert!(matches!(
            receive_completion(&receiver, 21).result,
            Ok(CompletionValue::OptionValue(42))
        ));

        socket.local_address(22).unwrap();
        assert!(matches!(
            receive_completion(&receiver, 22).result,
            Ok(CompletionValue::LocalAddress(Ipv4Addr::LOCALHOST))
        ));

        assert!(socket.close(Some(23)));
        let _ = receive_completion(&receiver, 23);
        reactor.shutdown_and_join();
    }

    #[test]
    fn parses_valid_ipv4_metadata_and_rejects_short_headers() {
        let mut packet = [0_u8; 24];
        packet[0] = 0x45;
        packet[1] = 0xb8;
        packet[2..4].copy_from_slice(&24_u16.to_be_bytes());
        packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x6007_u16.to_be_bytes());
        packet[8] = 37;
        packet[9] = 1;
        packet[16..20].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 9).octets());

        let metadata = super::parse_ipv4_packet_metadata(&packet).unwrap();
        assert_eq!(metadata.destination_address, Ipv4Addr::new(192, 0, 2, 9));
        assert_eq!(metadata.protocol, 1);
        assert_eq!(metadata.ttl, 37);
        assert_eq!(metadata.type_of_service, 0xb8);
        assert_eq!(metadata.header_length, 20);
        assert_eq!(metadata.total_length, 24);
        assert_eq!(metadata.identification, 0x1234);
        assert_eq!(metadata.fragment_offset, 7);
        assert!(metadata.dont_fragment);
        assert!(metadata.more_fragments);
        assert!(super::parse_ipv4_packet_metadata(&packet[..19]).is_none());
    }
}
