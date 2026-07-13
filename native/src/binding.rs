use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};
use std::sync::Arc;

use napi::bindgen_prelude::{Buffer, Either, Env, External, Function};
use napi::threadsafe_function::{
    ThreadsafeCallContext, ThreadsafeFunction, ThreadsafeFunctionCallMode,
};
use napi::{Status, bindgen_prelude};
use napi_derive::napi;

use crate::advanced::{
    ClassicBpfInstruction, MAX_RAW_OPTION_LENGTH, PacketMembership, PacketMembershipKind,
};
use crate::batch::{BatchDestination, BatchReceivedMessage, BatchSendMessage};
use crate::conversion::{PacketBufferLength, RawIpv4Protocol, RawIpv6Protocol};
use crate::error::NativeError;
use crate::linux::{
    Ipv4SocketOption, Ipv6SocketOption, create_ipv4_raw_socket, create_ipv6_raw_socket,
    create_packet_socket, interface_index, interface_name,
};
use crate::message::{
    MAX_CONTROL_CAPACITY, MAX_CONTROL_MESSAGES, ReceiveMessageFlags, ReceivedControlMessage,
    ReceivedIpv4Message, ReceivedIpv6Message, SendControlMessage, SendMessageFlags,
};
use crate::packet::{PacketAddress, PacketMode, ReceivedPacketMessage};
use crate::reactor::{
    Completion, CompletionSink, CompletionValue, Ipv4PacketMetadata, ReactorHandle, ReactorSocket,
    SocketFamily,
};
use crate::ring::PacketRingConfig;

const COMPLETION_QUEUE_CAPACITY: usize = 64;

type CompletionFunction = ThreadsafeFunction<
    Completion,
    (),
    NativeCompletion,
    Status,
    false,
    false,
    COMPLETION_QUEUE_CAPACITY,
>;

struct EnvironmentReactor {
    reactor: Arc<ReactorHandle>,
}

struct NapiCompletionSink(CompletionFunction);

impl CompletionSink for NapiCompletionSink {
    fn complete(&self, completion: Completion) {
        let status = self
            .0
            .call(completion, ThreadsafeFunctionCallMode::Blocking);
        debug_assert!(matches!(status, Status::Ok | Status::Closing));
    }
}

#[napi(object)]
pub struct NativeErrorData {
    pub kind: String,
    pub code: String,
    pub operation: String,
    pub errno: Option<i32>,
    pub errno_name: Option<String>,
    pub message: String,
}

impl From<NativeError> for NativeErrorData {
    fn from(error: NativeError) -> Self {
        Self {
            kind: String::from(error.kind().as_str()),
            code: String::from(error.code()),
            operation: String::from(error.operation().as_str()),
            errno: error.errno(),
            errno_name: error.errno_name().map(String::from),
            message: error.message().to_owned(),
        }
    }
}

#[napi(object)]
pub struct NativeIpv4PacketMetadata {
    pub destination_address: String,
    pub protocol: u32,
    pub ttl: u32,
    pub type_of_service: u32,
    pub header_length: u32,
    pub total_length: u32,
    pub identification: u32,
    pub fragment_offset: u32,
    pub dont_fragment: bool,
    pub more_fragments: bool,
}

#[napi(object)]
pub struct NativeSendControlMessage {
    pub kind: String,
    pub interface_index: Option<u32>,
    pub source_address: Option<String>,
    pub value: Option<u32>,
}

#[napi(object)]
pub struct NativeReceivedControlMessage {
    pub kind: String,
    pub interface_index: Option<u32>,
    pub selected_address: Option<String>,
    pub destination_address: Option<String>,
    pub value: Option<u32>,
    pub seconds: Option<String>,
    pub nanoseconds: Option<u32>,
    pub errno: Option<u32>,
    pub origin: Option<u32>,
    pub error_type: Option<u32>,
    pub error_code: Option<u32>,
    pub info: Option<u32>,
    pub extended_data: Option<u32>,
    pub offender: Option<String>,
    pub level: Option<i32>,
    pub message_type: Option<i32>,
    pub data: Option<Buffer>,
}

impl From<ReceivedControlMessage> for NativeReceivedControlMessage {
    #[allow(
        clippy::too_many_lines,
        reason = "exhaustive N-API control DTO conversion"
    )]
    fn from(message: ReceivedControlMessage) -> Self {
        let mut value = Self {
            kind: String::new(),
            interface_index: None,
            selected_address: None,
            destination_address: None,
            value: None,
            seconds: None,
            nanoseconds: None,
            errno: None,
            origin: None,
            error_type: None,
            error_code: None,
            info: None,
            extended_data: None,
            offender: None,
            level: None,
            message_type: None,
            data: None,
        };
        match message {
            ReceivedControlMessage::Ipv4PacketInfo {
                interface_index,
                selected_address,
                destination_address,
            } => {
                value.kind = "ipv4PacketInfo".into();
                value.interface_index = Some(interface_index);
                value.selected_address = Some(selected_address.to_string());
                value.destination_address = Some(destination_address.to_string());
            }
            ReceivedControlMessage::Ipv4Ttl(ttl) => {
                value.kind = "ipv4Ttl".into();
                value.value = Some(u32::from(ttl));
            }
            ReceivedControlMessage::Ipv4TypeOfService(tos) => {
                value.kind = "ipv4TypeOfService".into();
                value.value = Some(u32::from(tos));
            }
            ReceivedControlMessage::TimestampNanoseconds {
                seconds,
                nanoseconds,
            } => {
                value.kind = "timestampNanoseconds".into();
                value.seconds = Some(seconds.to_string());
                value.nanoseconds = Some(nanoseconds);
            }
            ReceivedControlMessage::ReceiveQueueOverflow(count) => {
                value.kind = "receiveQueueOverflow".into();
                value.value = Some(count);
            }
            ReceivedControlMessage::Ipv4ExtendedError {
                errno,
                origin,
                error_type,
                error_code,
                info,
                data,
                offender,
            } => {
                value.kind = "ipv4ExtendedError".into();
                value.errno = Some(errno);
                value.origin = Some(u32::from(origin));
                value.error_type = Some(u32::from(error_type));
                value.error_code = Some(u32::from(error_code));
                value.info = Some(info);
                value.extended_data = Some(data);
                value.offender = offender.map(|address| address.to_string());
            }
            ReceivedControlMessage::Ipv6PacketInfo {
                interface_index,
                destination_address,
            } => {
                value.kind = "ipv6PacketInfo".into();
                value.interface_index = Some(interface_index);
                value.destination_address = Some(destination_address.to_string());
            }
            ReceivedControlMessage::Ipv6HopLimit(limit) => {
                value.kind = "ipv6HopLimit".into();
                value.value = Some(u32::from(limit));
            }
            ReceivedControlMessage::Ipv6TrafficClass(class) => {
                value.kind = "ipv6TrafficClass".into();
                value.value = Some(u32::from(class));
            }
            ReceivedControlMessage::Ipv6ExtendedError {
                errno,
                origin,
                error_type,
                error_code,
                info,
                data,
                offender,
            } => {
                value.kind = "ipv6ExtendedError".into();
                value.errno = Some(errno);
                value.origin = Some(u32::from(origin));
                value.error_type = Some(u32::from(error_type));
                value.error_code = Some(u32::from(error_code));
                value.info = Some(info);
                value.extended_data = Some(data);
                value.offender = offender.map(|address| address.ip().to_string());
            }
            ReceivedControlMessage::Unknown {
                level,
                message_type,
                data,
            } => {
                value.kind = "unknown".into();
                value.level = Some(level);
                value.message_type = Some(message_type);
                value.data = Some(data.into());
            }
        }
        value
    }
}

#[napi(object)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "these booleans preserve independent Linux recvmsg result flags"
)]
pub struct NativeReceivedMessage {
    pub data: Buffer,
    pub source_address: Option<String>,
    pub source_family: Option<String>,
    pub source_scope_id: Option<u32>,
    pub source_flow_info: Option<u32>,
    pub source_interface_index: Option<u32>,
    pub source_protocol: Option<u32>,
    pub source_hardware_address: Option<Buffer>,
    pub source_hardware_type: Option<u32>,
    pub source_packet_type: Option<u32>,
    pub packet_aux_status: Option<u32>,
    pub packet_aux_original_length: Option<u32>,
    pub packet_aux_snapshot_length: Option<u32>,
    pub packet_aux_mac_offset: Option<u32>,
    pub packet_aux_network_offset: Option<u32>,
    pub packet_aux_vlan_tci: Option<u32>,
    pub packet_aux_vlan_tpid: Option<u32>,
    pub data_length: u32,
    pub data_truncated: bool,
    pub control_truncated: bool,
    pub end_of_record: bool,
    pub out_of_band: bool,
    pub error_queue: bool,
    pub control: Vec<NativeReceivedControlMessage>,
    pub ipv4: Option<NativeIpv4PacketMetadata>,
}

impl NativeReceivedMessage {
    fn from_message(message: ReceivedIpv4Message, ipv4: Option<Ipv4PacketMetadata>) -> Self {
        Self {
            data: message.data.into(),
            source_address: message.source_address.map(|address| address.to_string()),
            source_family: Some(String::from("ipv4")),
            source_scope_id: None,
            source_flow_info: None,
            source_interface_index: None,
            source_protocol: None,
            source_hardware_address: None,
            source_hardware_type: None,
            source_packet_type: None,
            packet_aux_status: None,
            packet_aux_original_length: None,
            packet_aux_snapshot_length: None,
            packet_aux_mac_offset: None,
            packet_aux_network_offset: None,
            packet_aux_vlan_tci: None,
            packet_aux_vlan_tpid: None,
            data_length: u32::try_from(message.data_length).unwrap_or(u32::MAX),
            data_truncated: message.data_truncated,
            control_truncated: message.control_truncated,
            end_of_record: message.flags.end_of_record,
            out_of_band: message.flags.out_of_band,
            error_queue: message.flags.error_queue,
            control: message.control.into_iter().map(Into::into).collect(),
            ipv4: ipv4.map(Into::into),
        }
    }

    fn from_ipv6_message(message: ReceivedIpv6Message) -> Self {
        let source = message.source_address;
        Self {
            data: message.data.into(),
            source_address: source.map(|address| address.ip().to_string()),
            source_family: Some(String::from("ipv6")),
            source_scope_id: source.map(|address| address.scope_id()),
            source_flow_info: source.map(|address| address.flowinfo()),
            source_interface_index: None,
            source_protocol: None,
            source_hardware_address: None,
            source_hardware_type: None,
            source_packet_type: None,
            packet_aux_status: None,
            packet_aux_original_length: None,
            packet_aux_snapshot_length: None,
            packet_aux_mac_offset: None,
            packet_aux_network_offset: None,
            packet_aux_vlan_tci: None,
            packet_aux_vlan_tpid: None,
            data_length: u32::try_from(message.data_length).unwrap_or(u32::MAX),
            data_truncated: message.data_truncated,
            control_truncated: message.control_truncated,
            end_of_record: message.flags.end_of_record,
            out_of_band: message.flags.out_of_band,
            error_queue: message.flags.error_queue,
            control: message.control.into_iter().map(Into::into).collect(),
            ipv4: None,
        }
    }

    fn from_packet_message(message: ReceivedPacketMessage) -> Self {
        let aux = message.auxdata;
        Self {
            data: message.data.into(),
            source_address: None,
            source_family: Some(String::from("packet")),
            source_scope_id: None,
            source_flow_info: None,
            source_interface_index: Some(message.source.interface_index),
            source_protocol: Some(u32::from(message.source.protocol)),
            source_hardware_address: Some(message.source.hardware_address.into()),
            source_hardware_type: Some(u32::from(message.hardware_type)),
            source_packet_type: Some(u32::from(message.packet_type)),
            packet_aux_status: aux.map(|value| value.status),
            packet_aux_original_length: aux.map(|value| value.original_length),
            packet_aux_snapshot_length: aux.map(|value| value.snapshot_length),
            packet_aux_mac_offset: aux.map(|value| u32::from(value.mac_offset)),
            packet_aux_network_offset: aux.map(|value| u32::from(value.network_offset)),
            packet_aux_vlan_tci: aux.map(|value| u32::from(value.vlan_tci)),
            packet_aux_vlan_tpid: aux.map(|value| u32::from(value.vlan_tpid)),
            data_length: u32::try_from(message.data_length).unwrap_or(u32::MAX),
            data_truncated: message.data_truncated,
            control_truncated: message.control_truncated,
            end_of_record: message.flags.end_of_record,
            out_of_band: message.flags.out_of_band,
            error_queue: message.flags.error_queue,
            control: Vec::new(),
            ipv4: None,
        }
    }
}

impl From<Ipv4PacketMetadata> for NativeIpv4PacketMetadata {
    fn from(metadata: Ipv4PacketMetadata) -> Self {
        Self {
            destination_address: metadata.destination_address.to_string(),
            protocol: u32::from(metadata.protocol),
            ttl: u32::from(metadata.ttl),
            type_of_service: u32::from(metadata.type_of_service),
            header_length: u32::from(metadata.header_length),
            total_length: u32::from(metadata.total_length),
            identification: u32::from(metadata.identification),
            fragment_offset: u32::from(metadata.fragment_offset),
            dont_fragment: metadata.dont_fragment,
            more_fragments: metadata.more_fragments,
        }
    }
}

#[napi(object)]
pub struct NativeCompletion {
    pub operation_id: u32,
    pub kind: String,
    pub bytes_sent: Option<u32>,
    pub data: Option<Buffer>,
    pub source_address: Option<String>,
    pub packet_length: Option<u32>,
    pub truncated: Option<bool>,
    pub ipv4: Option<NativeIpv4PacketMetadata>,
    pub local_address: Option<String>,
    pub local_family: Option<String>,
    pub local_scope_id: Option<u32>,
    pub local_flow_info: Option<u32>,
    pub option_value: Option<u32>,
    pub device_value: Option<String>,
    pub message: Option<NativeReceivedMessage>,
    pub raw_option: Option<Buffer>,
    pub statistics_packets: Option<u32>,
    pub statistics_drops: Option<u32>,
    pub batch_messages: Option<Vec<NativeReceivedMessage>>,
    pub batch_lengths: Option<Vec<u32>>,
    pub batch_requested: Option<u32>,
    pub ring_data: Option<Buffer>,
    pub ring_original_length: Option<u32>,
    pub ring_snapshot_length: Option<u32>,
    pub ring_seconds: Option<u32>,
    pub ring_nanoseconds: Option<u32>,
    pub ring_status: Option<u32>,
    pub ring_vlan_tci: Option<u32>,
    pub ring_vlan_tpid: Option<u32>,
    pub error: Option<NativeErrorData>,
}

impl From<Completion> for NativeCompletion {
    #[allow(
        clippy::too_many_lines,
        reason = "completion conversion exhaustively maps every public result shape"
    )]
    fn from(completion: Completion) -> Self {
        let mut native = Self {
            operation_id: completion.operation_id,
            kind: String::from("error"),
            bytes_sent: None,
            data: None,
            source_address: None,
            packet_length: None,
            truncated: None,
            ipv4: None,
            local_address: None,
            local_family: None,
            local_scope_id: None,
            local_flow_info: None,
            option_value: None,
            device_value: None,
            message: None,
            raw_option: None,
            statistics_packets: None,
            statistics_drops: None,
            batch_messages: None,
            batch_lengths: None,
            batch_requested: None,
            ring_data: None,
            ring_original_length: None,
            ring_snapshot_length: None,
            ring_seconds: None,
            ring_nanoseconds: None,
            ring_status: None,
            ring_vlan_tci: None,
            ring_vlan_tpid: None,
            error: None,
        };

        match completion.result {
            Ok(CompletionValue::Opened) => native.kind = String::from("open"),
            Ok(CompletionValue::Bound) => native.kind = String::from("bind"),
            Ok(CompletionValue::LocalAddress(address)) => {
                native.kind = String::from("localAddress");
                native.local_address = Some(address.to_string());
                native.local_family = Some(String::from("ipv4"));
            }
            Ok(CompletionValue::LocalIpv6Address(address)) => {
                native.kind = String::from("localAddress");
                native.local_address = Some(address.ip().to_string());
                native.local_family = Some(String::from("ipv6"));
                native.local_scope_id = Some(address.scope_id());
                native.local_flow_info = Some(address.flowinfo());
            }
            Ok(CompletionValue::Connected) => native.kind = String::from("connect"),
            Ok(CompletionValue::Disconnected) => native.kind = String::from("disconnect"),
            Ok(CompletionValue::OptionValue(value)) => {
                native.kind = String::from("getOption");
                native.option_value = Some(value);
            }
            Ok(CompletionValue::OptionSet) => native.kind = String::from("setOption"),
            Ok(CompletionValue::RawOption(value)) => {
                native.kind = String::from("getRawOption");
                native.raw_option = Some(value.into());
            }
            Ok(CompletionValue::PacketStatistics(value)) => {
                native.kind = String::from("packetStatistics");
                native.statistics_packets = Some(value.packets);
                native.statistics_drops = Some(value.drops);
            }
            Ok(CompletionValue::DeviceValue(value)) => {
                native.kind = String::from("getOption");
                native.device_value = value;
            }
            Ok(CompletionValue::Sent(bytes_sent)) => {
                native.kind = String::from("send");
                native.bytes_sent = u32::try_from(bytes_sent).ok();
            }
            Ok(CompletionValue::MessageSent(bytes_sent)) => {
                native.kind = String::from("sendMessage");
                native.bytes_sent = u32::try_from(bytes_sent).ok();
            }
            Ok(CompletionValue::BatchSent(result)) => {
                native.kind = String::from("sendBatch");
                native.batch_lengths = Some(
                    result
                        .lengths
                        .into_iter()
                        .filter_map(|length| u32::try_from(length).ok())
                        .collect(),
                );
                native.batch_requested = u32::try_from(result.requested).ok();
            }
            Ok(CompletionValue::BatchReceived(messages)) => {
                native.kind = String::from("receiveBatch");
                native.batch_requested = u32::try_from(messages.len()).ok();
                native.batch_messages = Some(
                    messages
                        .into_iter()
                        .map(|message| match message {
                            BatchReceivedMessage::Ipv4(message) => {
                                let ipv4 =
                                    crate::reactor::parse_ipv4_packet_metadata(&message.data);
                                NativeReceivedMessage::from_message(message, ipv4)
                            }
                            BatchReceivedMessage::Ipv6(message) => {
                                NativeReceivedMessage::from_ipv6_message(message)
                            }
                            BatchReceivedMessage::Packet(message) => {
                                NativeReceivedMessage::from_packet_message(message)
                            }
                        })
                        .collect(),
                );
            }
            Ok(CompletionValue::PacketRingConfigured) => {
                native.kind = String::from("configurePacketRing");
            }
            Ok(CompletionValue::RingFrame(frame)) => {
                native.kind = String::from("receiveRingFrame");
                native.ring_data = Some(frame.data.into());
                native.ring_original_length = Some(frame.original_length);
                native.ring_snapshot_length = Some(frame.snapshot_length);
                native.ring_seconds = Some(frame.seconds);
                native.ring_nanoseconds = Some(frame.nanoseconds);
                native.ring_status = Some(frame.status);
                native.ring_vlan_tci = Some(frame.vlan_tci);
                native.ring_vlan_tpid = Some(u32::from(frame.vlan_tpid));
            }
            Ok(CompletionValue::Received {
                data,
                source_address,
                packet_length,
                truncated,
                ipv4,
            }) => {
                native.kind = String::from("receive");
                native.data = Some(data.into());
                native.source_address = Some(source_address.to_string());
                native.packet_length = u32::try_from(packet_length).ok();
                native.truncated = Some(truncated);
                native.ipv4 = ipv4.map(Into::into);
            }
            Ok(CompletionValue::MessageReceived { message, ipv4 }) => {
                native.kind = String::from("receiveMessage");
                native.message = Some(NativeReceivedMessage::from_message(message, ipv4));
            }
            Ok(CompletionValue::Ipv6MessageReceived { message }) => {
                native.kind = String::from("receiveMessage");
                native.message = Some(NativeReceivedMessage::from_ipv6_message(message));
            }
            Ok(CompletionValue::PacketMessageReceived { message }) => {
                native.kind = String::from("receiveMessage");
                native.message = Some(NativeReceivedMessage::from_packet_message(message));
            }
            Ok(CompletionValue::Closed) => native.kind = String::from("close"),
            Err(error) => native.error = Some(error.into()),
        }
        native
    }
}

#[napi(object)]
pub struct NativeSubmitResult {
    pub accepted: bool,
    pub error: Option<NativeErrorData>,
}

#[napi(object)]
pub struct NativeClassicBpfInstruction {
    pub code: u32,
    pub jump_true: u32,
    pub jump_false: u32,
    pub value: u32,
}

#[napi(object)]
pub struct NativeBatchSendMessage {
    pub data: Buffer,
    pub destination: String,
    pub destination_family: String,
    pub scope_id: u32,
    pub flow_info: u32,
    pub packet_protocol: u32,
    pub interface_index: u32,
    pub hardware_address: Buffer,
}

#[napi(object)]
pub struct NativePacketRingConfig {
    pub block_size: u32,
    pub block_count: u32,
    pub frame_size: u32,
    pub retire_timeout_ms: u32,
}

impl NativeSubmitResult {
    fn from_result(result: Result<(), NativeError>) -> Self {
        match result {
            Ok(()) => Self {
                accepted: true,
                error: None,
            },
            Err(error) => Self {
                accepted: false,
                error: Some(error.into()),
            },
        }
    }
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "the callback is an owned scoped value supplied by the N-API boundary"
)]
/// Creates and registers an IPv4 raw socket or returns structured error data.
///
/// # Errors
///
/// Returns a N-API error only if callback/environment value creation fails.
pub fn native_open_raw_socket(
    env: Env,
    family: String,
    mode: Option<String>,
    protocol: u32,
    callback: Function<'_, NativeCompletion, ()>,
) -> bindgen_prelude::Result<Either<External<ReactorSocket>, NativeErrorData>> {
    let family = match family.as_str() {
        "ipv4" => SocketFamily::Ipv4,
        "ipv6" => SocketFamily::Ipv6,
        "packet" => match mode.as_deref() {
            Some("raw") => SocketFamily::Packet(PacketMode::Raw),
            Some("cooked") => SocketFamily::Packet(PacketMode::Cooked),
            _ => {
                return Ok(Either::B(
                    NativeError::invalid_argument(
                        crate::error::Operation::CreatePacketSocket,
                        "packet mode must be raw or cooked",
                    )
                    .into(),
                ));
            }
        },
        _ => {
            return Ok(Either::B(
                NativeError::invalid_argument(
                    crate::error::Operation::RegisterSocket,
                    "family must be ipv4, ipv6, or packet",
                )
                .into(),
            ));
        }
    };
    let completion = callback
        .build_threadsafe_function::<Completion>()
        .callee_handled::<false>()
        .max_queue_size::<COMPLETION_QUEUE_CAPACITY>()
        .build_callback(|context: ThreadsafeCallContext<Completion>| {
            Ok(NativeCompletion::from(context.value))
        })?;
    let sink: Arc<dyn CompletionSink> = Arc::new(NapiCompletionSink(completion));
    let reactor = match environment_reactor(env)? {
        Ok(reactor) => reactor,
        Err(error) => return Ok(Either::B(error.into())),
    };
    let core = match family {
        SocketFamily::Ipv4 => RawIpv4Protocol::try_from(protocol).and_then(create_ipv4_raw_socket),
        SocketFamily::Ipv6 => RawIpv6Protocol::try_from(protocol).and_then(create_ipv6_raw_socket),
        SocketFamily::Packet(mode) => u16::try_from(protocol)
            .map_err(|_| {
                NativeError::invalid_argument(
                    crate::error::Operation::CreatePacketSocket,
                    "packet protocol must fit u16",
                )
            })
            .and_then(|protocol| create_packet_socket(mode, protocol)),
    };
    let core = match core {
        Ok(core) => core,
        Err(error) => return Ok(Either::B(error.into())),
    };
    let socket = match reactor.register(core, family, sink) {
        Ok(socket) => socket,
        Err(error) => return Ok(Either::B(error.into())),
    };

    Ok(Either::A(External::new(socket)))
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies owned Buffer and String values at this boundary"
)]
#[must_use]
pub fn native_submit_send(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    data: Buffer,
    destination: String,
) -> NativeSubmitResult {
    let result = validate_send(data.as_ref(), &destination).and_then(|destination| {
        let owned_data: Vec<u8> = data.into();
        handle.send(operation_id, owned_data, destination)
    });
    NativeSubmitResult::from_result(result)
}

#[napi]
#[must_use]
pub fn native_submit_receive(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    buffer_length: u32,
) -> NativeSubmitResult {
    let result = PacketBufferLength::try_from(u64::from(buffer_length))
        .and_then(|buffer_length| handle.receive(operation_id, buffer_length));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies owned message values"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "flat checked N-API message DTO fields"
)]
#[must_use]
pub fn native_submit_send_message(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    data: Buffer,
    destination: String,
    destination_family: String,
    scope_id: u32,
    flow_info: u32,
    packet_protocol: u32,
    interface_index: u32,
    hardware_address: Buffer,
    dont_route: bool,
    control: Vec<NativeSendControlMessage>,
) -> NativeSubmitResult {
    let result = PacketBufferLength::try_from(u64::try_from(data.len()).unwrap_or(u64::MAX))
        .and_then(|_| parse_send_control(control))
        .and_then(|control| match destination_family.as_str() {
            "ipv4" => validate_control_family(&control, SocketFamily::Ipv4).and_then(|()| {
                destination
                    .parse::<Ipv4Addr>()
                    .map_err(|_| {
                        NativeError::invalid_argument(
                            crate::error::Operation::SendMessage,
                            "destination must be IPv4",
                        )
                    })
                    .and_then(|destination| {
                        handle.send_message(
                            operation_id,
                            data.into(),
                            destination,
                            SendMessageFlags { dont_route },
                            control,
                        )
                    })
            }),
            "ipv6" => validate_control_family(&control, SocketFamily::Ipv6)
                .and_then(|()| {
                    parse_ipv6_address(
                        &destination,
                        scope_id,
                        flow_info,
                        crate::error::Operation::SendMessage,
                    )
                })
                .and_then(|destination| {
                    handle.send_message_ipv6(
                        operation_id,
                        data.into(),
                        destination,
                        SendMessageFlags { dont_route },
                        control,
                    )
                }),
            "packet" => validate_control_family(&control, SocketFamily::Packet(PacketMode::Raw))
                .and_then(|()| {
                    u16::try_from(packet_protocol).map_err(|_| {
                        NativeError::invalid_argument(
                            crate::error::Operation::SendMessage,
                            "packet protocol must fit u16",
                        )
                    })
                })
                .and_then(|protocol| {
                    PacketAddress::new(
                        interface_index,
                        protocol,
                        hardware_address.into(),
                        crate::error::Operation::SendMessage,
                    )
                })
                .and_then(|destination| {
                    handle.send_message_packet(
                        operation_id,
                        data.into(),
                        destination,
                        SendMessageFlags { dont_route },
                    )
                }),
            _ => Err(NativeError::invalid_argument(
                crate::error::Operation::SendMessage,
                "destination family must be ipv4, ipv6, or packet",
            )),
        });
    NativeSubmitResult::from_result(result)
}

fn parse_batch_message(
    message: NativeBatchSendMessage,
    family: SocketFamily,
) -> Result<BatchSendMessage, NativeError> {
    PacketBufferLength::try_from(u64::try_from(message.data.len()).unwrap_or(u64::MAX))?;
    let destination = match (message.destination_family.as_str(), family) {
        ("ipv4", SocketFamily::Ipv4) => message
            .destination
            .parse::<Ipv4Addr>()
            .map(|address| BatchDestination::Ipv4(std::net::SocketAddrV4::new(address, 0)))
            .map_err(|_| {
                NativeError::invalid_argument(
                    crate::error::Operation::SendBatch,
                    "batch destination must be IPv4",
                )
            })?,
        ("ipv6", SocketFamily::Ipv6) => BatchDestination::Ipv6(parse_ipv6_address(
            &message.destination,
            message.scope_id,
            message.flow_info,
            crate::error::Operation::SendBatch,
        )?),
        ("packet", SocketFamily::Packet(_)) => {
            let protocol = u16::try_from(message.packet_protocol).map_err(|_| {
                NativeError::invalid_argument(
                    crate::error::Operation::SendBatch,
                    "packet batch protocol must fit u16",
                )
            })?;
            BatchDestination::Packet(PacketAddress::new(
                message.interface_index,
                protocol,
                message.hardware_address.into(),
                crate::error::Operation::SendBatch,
            )?)
        }
        _ => {
            return Err(NativeError::invalid_argument(
                crate::error::Operation::SendBatch,
                "batch destination family must match the socket",
            ));
        }
    };
    Ok(BatchSendMessage {
        data: message.data.into(),
        destination,
    })
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned bounded message vector"
)]
#[must_use]
pub fn native_submit_send_batch(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    messages: Vec<NativeBatchSendMessage>,
) -> NativeSubmitResult {
    let result = messages
        .into_iter()
        .map(|message| parse_batch_message(message, handle.family()))
        .collect::<Result<Vec<_>, _>>()
        .and_then(|messages| handle.send_batch(operation_id, messages));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[must_use]
pub fn native_submit_receive_batch(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    count: u32,
    buffer_length: u32,
) -> NativeSubmitResult {
    let result = usize::try_from(count)
        .map_err(|_| {
            NativeError::invalid_argument(
                crate::error::Operation::ReceiveBatch,
                "batch count does not fit usize",
            )
        })
        .and_then(|count| {
            PacketBufferLength::try_from(u64::from(buffer_length))
                .and_then(|length| handle.receive_batch(operation_id, count, length))
        });
    NativeSubmitResult::from_result(result)
}

#[napi]
#[must_use]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned configuration object"
)]
pub fn native_configure_packet_ring(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    config: NativePacketRingConfig,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.configure_packet_ring(
        operation_id,
        PacketRingConfig {
            block_size: config.block_size,
            block_count: config.block_count,
            frame_size: config.frame_size,
            retire_timeout_ms: config.retire_timeout_ms,
        },
    ))
}

#[napi]
#[must_use]
pub fn native_receive_ring_frame(
    handle: &External<ReactorSocket>,
    operation_id: u32,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.receive_ring_frame(operation_id))
}

#[napi]
#[must_use]
pub fn native_submit_receive_message(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    buffer_length: u32,
    control_capacity: u32,
    peek: bool,
    error_queue: bool,
) -> NativeSubmitResult {
    let result = PacketBufferLength::try_from(u64::from(buffer_length)).and_then(|length| {
        let control_capacity = usize::try_from(control_capacity).map_err(|_| {
            NativeError::invalid_argument(
                crate::error::Operation::ReceiveMessage,
                "control capacity does not fit in usize",
            )
        })?;
        if control_capacity > MAX_CONTROL_CAPACITY {
            return Err(NativeError::invalid_argument(
                crate::error::Operation::ReceiveMessage,
                "control capacity exceeds 65536",
            ));
        }
        handle.receive_message(
            operation_id,
            length,
            control_capacity,
            ReceiveMessageFlags { peek, error_queue },
        )
    });
    NativeSubmitResult::from_result(result)
}

#[napi]
#[must_use]
pub fn native_cancel(handle: &External<ReactorSocket>, operation_id: u32) -> bool {
    handle.cancel(operation_id)
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned String at this boundary"
)]
#[must_use]
pub fn native_bind(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    address: String,
) -> NativeSubmitResult {
    let result = address
        .parse::<Ipv4Addr>()
        .map_err(|_| {
            NativeError::invalid_argument(
                crate::error::Operation::Bind,
                "address must be a dotted-decimal IPv4 address",
            )
        })
        .and_then(|address| handle.bind(operation_id, address));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned String"
)]
#[must_use]
pub fn native_bind_ipv6(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    address: String,
    scope_id: u32,
    flow_info: u32,
) -> NativeSubmitResult {
    let result = parse_ipv6_address(&address, scope_id, flow_info, crate::error::Operation::Bind)
        .and_then(|address| handle.bind_ipv6(operation_id, address));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies owned address bytes"
)]
#[must_use]
pub fn native_bind_packet(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    interface_index: u32,
    protocol: u32,
) -> NativeSubmitResult {
    let result = u16::try_from(protocol)
        .map_err(|_| {
            NativeError::invalid_argument(
                crate::error::Operation::Bind,
                "packet protocol must fit u16",
            )
        })
        .and_then(|protocol| {
            PacketAddress::new(
                interface_index,
                protocol,
                Vec::new(),
                crate::error::Operation::Bind,
            )
        })
        .and_then(|address| handle.bind_packet(operation_id, address));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[must_use]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned String"
)]
pub fn native_interface_index(name: String) -> Either<u32, NativeErrorData> {
    match interface_index(&name) {
        Ok(value) => Either::A(value),
        Err(error) => Either::B(error.into()),
    }
}

#[napi]
#[must_use]
pub fn native_interface_name(index: u32) -> Either<String, NativeErrorData> {
    match interface_name(index) {
        Ok(value) => Either::A(value),
        Err(error) => Either::B(error.into()),
    }
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned String"
)]
#[must_use]
pub fn native_connect_ipv6(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    address: String,
    scope_id: u32,
    flow_info: u32,
) -> NativeSubmitResult {
    let result = parse_ipv6_address(
        &address,
        scope_id,
        flow_info,
        crate::error::Operation::Connect,
    )
    .and_then(|address| handle.connect_ipv6(operation_id, address));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned String"
)]
#[must_use]
pub fn native_connect_ipv4(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    address: String,
) -> NativeSubmitResult {
    let result = address
        .parse::<Ipv4Addr>()
        .map_err(|_| {
            NativeError::invalid_argument(crate::error::Operation::Connect, "address must be IPv4")
        })
        .and_then(|address| handle.connect_ipv4(operation_id, address));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[must_use]
pub fn native_disconnect(
    handle: &External<ReactorSocket>,
    operation_id: u32,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.disconnect(operation_id))
}

#[napi]
#[must_use]
pub fn native_local_address(
    handle: &External<ReactorSocket>,
    operation_id: u32,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.local_address(operation_id))
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned String at this boundary"
)]
#[must_use]
pub fn native_get_option(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    option: String,
) -> NativeSubmitResult {
    let result = Ipv4SocketOption::parse(&option, crate::error::Operation::GetSocketOption)
        .and_then(|option| handle.get_option(operation_id, option));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned String at this boundary"
)]
#[must_use]
pub fn native_set_option(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    option: String,
    value: u32,
) -> NativeSubmitResult {
    let result = Ipv4SocketOption::parse(&option, crate::error::Operation::SetSocketOption)
        .and_then(|option| handle.set_option(operation_id, option, value));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned String"
)]
#[must_use]
pub fn native_get_ipv6_option(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    option: String,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(
        Ipv6SocketOption::parse(&option, crate::error::Operation::GetSocketOption)
            .and_then(|option| handle.get_ipv6_option(operation_id, option)),
    )
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned String"
)]
#[must_use]
pub fn native_set_ipv6_option(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    option: String,
    value: u32,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(
        Ipv6SocketOption::parse(&option, crate::error::Operation::SetSocketOption)
            .and_then(|option| handle.set_ipv6_option(operation_id, option, value)),
    )
}

#[napi]
#[must_use]
pub fn native_get_raw_option(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    level: i32,
    name: i32,
    maximum: u32,
) -> NativeSubmitResult {
    let result = usize::try_from(maximum)
        .map_err(|_| {
            NativeError::invalid_argument(
                crate::error::Operation::GetSocketOption,
                "maximum does not fit usize",
            )
        })
        .and_then(|maximum| {
            if maximum > MAX_RAW_OPTION_LENGTH {
                Err(NativeError::invalid_argument(
                    crate::error::Operation::GetSocketOption,
                    "maximum exceeds 4096",
                ))
            } else {
                handle.get_raw_option(operation_id, level, name, maximum)
            }
        });
    NativeSubmitResult::from_result(result)
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies owned option bytes"
)]
#[must_use]
pub fn native_set_raw_option(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    level: i32,
    name: i32,
    value: Buffer,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.set_raw_option(operation_id, level, name, value.into()))
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies owned instruction DTOs"
)]
#[must_use]
pub fn native_attach_classic_filter(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    program: Vec<NativeClassicBpfInstruction>,
) -> NativeSubmitResult {
    let result = program
        .into_iter()
        .map(|instruction| {
            Ok(ClassicBpfInstruction {
                code: u16::try_from(instruction.code).map_err(|_| {
                    NativeError::invalid_argument(
                        crate::error::Operation::AttachFilter,
                        "BPF code must fit u16",
                    )
                })?,
                jump_true: u8::try_from(instruction.jump_true).map_err(|_| {
                    NativeError::invalid_argument(
                        crate::error::Operation::AttachFilter,
                        "BPF jumpTrue must fit u8",
                    )
                })?,
                jump_false: u8::try_from(instruction.jump_false).map_err(|_| {
                    NativeError::invalid_argument(
                        crate::error::Operation::AttachFilter,
                        "BPF jumpFalse must fit u8",
                    )
                })?,
                value: instruction.value,
            })
        })
        .collect::<Result<Vec<_>, NativeError>>()
        .and_then(|program| handle.attach_classic_filter(operation_id, program));
    NativeSubmitResult::from_result(result)
}

#[napi]
#[must_use]
pub fn native_detach_filter(
    handle: &External<ReactorSocket>,
    operation_id: u32,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.detach_filter(operation_id))
}
#[napi]
#[must_use]
pub fn native_lock_filter(
    handle: &External<ReactorSocket>,
    operation_id: u32,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.lock_filter(operation_id))
}

#[napi]
#[must_use]
pub fn native_attach_ebpf_filter(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    fd: i32,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.attach_ebpf_filter(operation_id, fd))
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies owned membership bytes"
)]
#[must_use]
pub fn native_packet_membership(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    interface_index: u32,
    kind: String,
    address: Buffer,
    add: bool,
) -> NativeSubmitResult {
    let kind = match kind.as_str() {
        "promiscuous" => Ok(PacketMembershipKind::Promiscuous),
        "allMulticast" => Ok(PacketMembershipKind::AllMulticast),
        "multicast" => Ok(PacketMembershipKind::Multicast),
        _ => Err(NativeError::invalid_argument(
            crate::error::Operation::PacketMembership,
            "unsupported packet membership kind",
        )),
    };
    NativeSubmitResult::from_result(kind.and_then(|kind| {
        handle.packet_membership(
            operation_id,
            PacketMembership {
                interface_index,
                kind,
                address: address.into(),
            },
            add,
        )
    }))
}

#[napi]
#[must_use]
pub fn native_packet_auxdata(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    enabled: bool,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.packet_auxdata(operation_id, enabled))
}
#[napi]
#[must_use]
pub fn native_packet_fanout(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    group: u32,
    mode: u32,
) -> NativeSubmitResult {
    let result = u16::try_from(group)
        .map_err(|_| {
            NativeError::invalid_argument(
                crate::error::Operation::SetSocketOption,
                "fanout group must fit u16",
            )
        })
        .and_then(|group| {
            u16::try_from(mode)
                .map_err(|_| {
                    NativeError::invalid_argument(
                        crate::error::Operation::SetSocketOption,
                        "fanout mode must fit u16",
                    )
                })
                .and_then(|mode| handle.packet_fanout(operation_id, group, mode))
        });
    NativeSubmitResult::from_result(result)
}
#[napi]
#[must_use]
pub fn native_packet_statistics(
    handle: &External<ReactorSocket>,
    operation_id: u32,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.packet_statistics(operation_id))
}

#[napi]
#[must_use]
pub fn native_get_bind_to_device(
    handle: &External<ReactorSocket>,
    operation_id: u32,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.get_device(operation_id))
}

#[napi]
#[allow(
    clippy::needless_pass_by_value,
    reason = "N-API supplies an owned optional String"
)]
#[must_use]
pub fn native_set_bind_to_device(
    handle: &External<ReactorSocket>,
    operation_id: u32,
    device: Option<String>,
) -> NativeSubmitResult {
    NativeSubmitResult::from_result(handle.set_device(operation_id, device))
}

#[napi]
#[must_use]
pub fn native_close(handle: &External<ReactorSocket>, operation_id: u32) -> NativeSubmitResult {
    NativeSubmitResult {
        accepted: handle.close(Some(operation_id)),
        error: None,
    }
}

#[napi]
#[must_use]
pub fn native_socket_status(handle: &External<ReactorSocket>) -> String {
    format!("{:?}", handle.status()).to_ascii_lowercase()
}

fn validate_send(data: &[u8], destination: &str) -> Result<Ipv4Addr, NativeError> {
    PacketBufferLength::try_from(u64::try_from(data.len()).unwrap_or(u64::MAX))?;
    destination.parse::<Ipv4Addr>().map_err(|_| {
        NativeError::invalid_argument(
            crate::error::Operation::Send,
            "destination must be an IPv4 address",
        )
    })
}

fn parse_ipv6_address(
    address: &str,
    scope_id: u32,
    flow_info: u32,
    operation: crate::error::Operation,
) -> Result<SocketAddrV6, NativeError> {
    if flow_info > 0x000f_ffff {
        return Err(NativeError::invalid_argument(
            operation,
            "IPv6 flowInfo must be from 0 through 1048575",
        ));
    }
    let address = address.parse::<Ipv6Addr>().map_err(|_| {
        NativeError::invalid_argument(
            operation,
            "address must be an IPv6 address without a zone suffix",
        )
    })?;
    if address.is_unicast_link_local() && scope_id == 0 {
        return Err(NativeError::invalid_argument(
            operation,
            "link-local IPv6 addresses require a nonzero scopeId",
        ));
    }
    Ok(SocketAddrV6::new(address, 0, flow_info, scope_id))
}

fn parse_send_control(
    messages: Vec<NativeSendControlMessage>,
) -> Result<Vec<SendControlMessage>, NativeError> {
    use crate::error::Operation;

    if messages.len() > MAX_CONTROL_MESSAGES {
        return Err(NativeError::invalid_argument(
            Operation::SendMessage,
            "too many control messages",
        ));
    }
    messages
        .into_iter()
        .map(|message| match message.kind.as_str() {
            "ipv4PacketInfo" => {
                let source_address = message
                    .source_address
                    .map(|address| {
                        address.parse::<Ipv4Addr>().map_err(|_| {
                            NativeError::invalid_argument(
                                Operation::SendMessage,
                                "packet-info sourceAddress must be an IPv4 address",
                            )
                        })
                    })
                    .transpose()?;
                Ok(SendControlMessage::Ipv4PacketInfo {
                    interface_index: message.interface_index.unwrap_or(0),
                    source_address,
                })
            }
            "ipv4Ttl" => {
                let ttl = message.value.ok_or_else(|| {
                    NativeError::invalid_argument(
                        Operation::SendMessage,
                        "ipv4Ttl control requires value",
                    )
                })?;
                let ttl = u8::try_from(ttl).map_err(|_| {
                    NativeError::invalid_argument(
                        Operation::SendMessage,
                        "ipv4Ttl must be from 0 through 255",
                    )
                })?;
                Ok(SendControlMessage::Ipv4Ttl(ttl))
            }
            "ipv6PacketInfo" => {
                let source_address = message
                    .source_address
                    .map(|address| {
                        address.parse::<Ipv6Addr>().map_err(|_| {
                            NativeError::invalid_argument(
                                Operation::SendMessage,
                                "IPv6 packet-info sourceAddress must be IPv6",
                            )
                        })
                    })
                    .transpose()?;
                Ok(SendControlMessage::Ipv6PacketInfo {
                    interface_index: message.interface_index.unwrap_or(0),
                    source_address,
                })
            }
            "ipv6HopLimit" => {
                let value = u8::try_from(message.value.ok_or_else(|| {
                    NativeError::invalid_argument(
                        Operation::SendMessage,
                        "ipv6HopLimit requires value",
                    )
                })?)
                .map_err(|_| {
                    NativeError::invalid_argument(
                        Operation::SendMessage,
                        "IPv6 hop limit must fit u8",
                    )
                })?;
                Ok(SendControlMessage::Ipv6HopLimit(value))
            }
            "ipv6TrafficClass" => {
                let value = u8::try_from(message.value.ok_or_else(|| {
                    NativeError::invalid_argument(
                        Operation::SendMessage,
                        "ipv6TrafficClass requires value",
                    )
                })?)
                .map_err(|_| {
                    NativeError::invalid_argument(
                        Operation::SendMessage,
                        "IPv6 traffic class must fit u8",
                    )
                })?;
                Ok(SendControlMessage::Ipv6TrafficClass(value))
            }
            _ => Err(NativeError::invalid_argument(
                Operation::SendMessage,
                "unsupported send control message",
            )),
        })
        .collect()
}

fn validate_control_family(
    messages: &[SendControlMessage],
    family: SocketFamily,
) -> Result<(), NativeError> {
    let valid = messages.iter().all(|message| match family {
        SocketFamily::Ipv4 => matches!(
            message,
            SendControlMessage::Ipv4PacketInfo { .. } | SendControlMessage::Ipv4Ttl(_)
        ),
        SocketFamily::Ipv6 => matches!(
            message,
            SendControlMessage::Ipv6PacketInfo { .. }
                | SendControlMessage::Ipv6HopLimit(_)
                | SendControlMessage::Ipv6TrafficClass(_)
        ),
        SocketFamily::Packet(_) => false,
    });
    if valid {
        Ok(())
    } else {
        Err(NativeError::invalid_argument(
            crate::error::Operation::SendMessage,
            "control family must match destination family",
        ))
    }
}

fn environment_reactor(
    env: Env,
) -> bindgen_prelude::Result<Result<Arc<ReactorHandle>, NativeError>> {
    if let Some(instance) = env.get_instance_data::<EnvironmentReactor>()? {
        return Ok(Ok(Arc::clone(&instance.reactor)));
    }

    let reactor = match ReactorHandle::start() {
        Ok(reactor) => reactor,
        Err(error) => return Ok(Err(error)),
    };
    env.set_instance_data(
        EnvironmentReactor {
            reactor: Arc::clone(&reactor),
        },
        (),
        |context| context.value.reactor.shutdown_in_background(),
    )?;
    Ok(Ok(reactor))
}
