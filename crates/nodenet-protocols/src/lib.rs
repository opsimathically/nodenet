//! Bounded, syscall-free protocol foundations shared by the `nodenet` crates.
//!
//! This crate deliberately owns its public types and errors. Codec dependencies
//! are implementation details and may be replaced without changing consumers.

mod arp;
mod bounds;
mod checksum;
mod correlation;
mod discovery_dns;
mod discovery_registry;
mod discovery_targeted;
mod discovery_ws;
mod envelope;
mod error;
mod icmpv4;
mod icmpv6;
mod ipv4;
mod ipv6;
mod link;
mod ndp;
mod network;
mod parse;
mod passive;
mod quoted;
mod service;
mod tcp;
mod template;
mod types;
mod udp;
mod udp_capability;
mod udp_catalogue;
mod udp_coverage;
mod udp_extended;
mod udp_request;
mod udp_safe;
mod udp_signature;
mod writer;

pub use arp::{
    ArpEthernetIpv4Operation, ArpEthernetIpv4Packet, ParsedArpPacket, UnknownArpPacket,
    parse_arp_packet,
};
pub use bounds::{
    MAX_CORRELATION_LEASES, MAX_ETHERNET_FRAME_LENGTH, MAX_ICMPV4_MESSAGE_BYTES,
    MAX_ICMPV6_MESSAGE_BYTES, MAX_IP_PACKET_LENGTH, MAX_IPV6_EXTENSION_BYTES,
    MAX_IPV6_EXTENSION_HEADER_COUNT, MAX_NDP_OPTION_BYTES, MAX_NDP_OPTION_COUNT,
    MAX_OWNED_OPTION_BYTES, MAX_OWNED_PAYLOAD_BYTES, MAX_TCP_OPTION_BYTES, MAX_TCP_OPTION_COUNT,
    MAX_TEMPLATE_PATCH_DESCRIPTORS, MAX_VLAN_HEADER_COUNT, PacketKind, PacketLength,
};
pub use checksum::{
    TransportChecksumContext, compute_internet_checksum, compute_transport_checksum,
    validate_internet_checksum, validate_transport_checksum,
};
pub use correlation::{
    CorrelationEvidence, CorrelationEvidenceKind, CorrelationIdentityError, CorrelationLeaseKey,
    CorrelationRejection, CorrelationReuseGuard, CorrelationToken, EvidenceStrength, ProbeIdentity,
    ResponseTuple, ReuseGuardError, SessionSecret, classify_arp_reply, classify_echo_reply,
    classify_neighbor_advertisement, classify_quoted_response, classify_tcp_reply,
    classify_udp_reply,
};
pub use discovery_dns::{
    DiscoveryDnsError, DiscoveryDnsMessage, DiscoveryDnsName, DiscoveryDnsQuestion,
    DiscoveryDnsRecord, DiscoveryDnsRecordData, DiscoveryDnsTxtEntry,
    MAX_DISCOVERY_DNS_MESSAGE_BYTES, MAX_DISCOVERY_DNS_NAME_BYTES, MAX_DISCOVERY_DNS_POINTERS,
    MAX_DISCOVERY_DNS_RECORDS, MAX_DISCOVERY_DNS_TXT_BYTES, MAX_DISCOVERY_DNS_TXT_ENTRIES,
    build_discovery_dns_query, build_mdns_service_enumeration_query, parse_discovery_dns_message,
};
pub use discovery_registry::{
    DISCOVERY_OPERATION_REGISTRY, DISCOVERY_OPERATION_REGISTRY_VERSION, DiscoveryEntityKind,
    DiscoveryEvidenceKind, DiscoveryOperationDescriptor, DiscoveryOperationId,
    DiscoveryOperationProvenance, DiscoveryRegistryError, DiscoveryScopeKind,
    DiscoveryTransportKind, MAX_DISCOVERY_OPERATIONS, MAX_DISCOVERY_REQUEST_BYTES,
    MAX_DISCOVERY_RESPONSE_BYTES, discovery_operation_registry_sha256,
    discovery_operation_registry_sha256_hex, validate_discovery_operation_registry,
};
pub use discovery_targeted::{
    MAX_QUIC_ADVERTISED_VERSIONS, MAX_RIPV1_RESPONSE_BYTES, MAX_RIPV1_ROUTES_PER_DATAGRAM,
    MAX_SQL_BROWSER_FIELDS, MAX_SQL_BROWSER_INSTANCES, MAX_SQL_BROWSER_RESPONSE_BYTES,
    MAX_SQL_BROWSER_TEXT_BYTES, MAX_TFTP_DISCOVERY_RESPONSE_BYTES, NatPmpExternalAddressResponse,
    QUIC_VERSION_NEGOTIATION_REQUEST_BYTES, QuicVersionNegotiationRequest,
    QuicVersionNegotiationResponse, RIPV1_TABLE_REQUEST_BYTES, RipV1Route, SqlBrowserInstance,
    TargetedDiscoveryError, TftpDiscoveryResponse, build_nat_pmp_external_address_request,
    build_quic_version_negotiation_request, build_ripv1_table_request,
    build_rpcbind_getaddr_request, build_sql_browser_enumeration_request, build_tftp_discovery_rrq,
    build_tftp_termination_error, parse_nat_pmp_external_address_response,
    parse_quic_version_negotiation_response, parse_ripv1_table_response,
    parse_rpcbind_getaddr_response, parse_rpcbind_universal_address, parse_sql_browser_response,
    parse_tftp_discovery_response,
};
pub use discovery_ws::{
    LlmnrResponse, MAX_WS_DISCOVERY_ENVELOPE_BYTES, MAX_WS_DISCOVERY_MATCHES,
    MAX_WS_DISCOVERY_TEXT_BYTES, MAX_WS_DISCOVERY_VALUES, MAX_WS_DISCOVERY_XML_DEPTH,
    MAX_WS_DISCOVERY_XML_TOKENS, WsDiscoveryAppSequence, WsDiscoveryError, WsDiscoveryProbeMatch,
    WsDiscoveryProbeMatches, build_llmnr_query, build_ws_discovery_probe, parse_llmnr_response,
    parse_ws_discovery_probe_matches,
};
pub use envelope::{ParsedNetworkFrame, ParsedNetworkPayload, parse_network_frame};
pub use error::{BuildError, Field, Layer, ParseError, Resource};
pub use icmpv4::{
    Icmpv4Conformance, Icmpv4Message, ParsedIcmpv4Message, ParsedIcmpv4Packet, parse_icmpv4_message,
};
pub use icmpv6::{
    Icmpv6Conformance, Icmpv6Message, Icmpv6Packet, ParsedIcmpv6Message, ParsedIcmpv6Packet,
    parse_icmpv6_message,
};
pub use ipv4::{Ipv4Conformance, Ipv4Packet, ParsedIpv4Packet, parse_ipv4_packet};
pub use ipv6::{
    Ipv6Conformance, Ipv6Extension, Ipv6Packet, ParsedIpv6Extension, ParsedIpv6Extensions,
    ParsedIpv6Packet, parse_ipv6_packet,
};
pub use link::{
    ETHER_TYPE_ARP, ETHER_TYPE_IPV4, ETHER_TYPE_IPV6, ETHER_TYPE_PROVIDER_BRIDGING,
    ETHER_TYPE_VLAN, EthernetFrame, EthernetHeader, ParsedEthernetFrame, VlanStack, VlanTag,
    VlanTagProtocol, parse_ethernet_frame,
};
pub use ndp::{
    NdpConformance, NdpContext, NdpMessage, NdpOption, NdpPacket, ParsedNdpMessage,
    ParsedNdpOption, ParsedNdpOptions, ParsedNdpPacket, parse_ndp_message,
};
pub use network::{FragmentState, UpperLayerState};
pub use parse::{PacketStart, ParseStatus, inspect_packet};
pub use passive::{
    MAX_LLDP_TLVS, MAX_PASSIVE_FIELD_BYTES, MAX_PASSIVE_FIELDS, MAX_RA_OPTIONS, PassiveField,
    PassivePacketMetadata, PassiveProtocol, decode_passive_frame,
    decode_passive_frame_with_checksum_policy, parse_router_advertisement_metadata,
};
pub use quoted::{QuotedIpPacket, QuotedTransport, parse_quoted_ip_packet};
pub use service::{
    MAX_SERVICE_FIELDS, MAX_SERVICE_RESPONSE_BYTES, MAX_SERVICE_TEXT_BYTES, SERVICE_REGISTRY,
    SERVICE_REGISTRY_VERSION, ServiceCodecError, ServiceDescriptor, ServiceDisposition,
    ServiceIdentity, ServiceRisk, parse_service_response,
};
pub use tcp::{
    ParsedTcpOption, ParsedTcpOptions, ParsedTcpSackBlocks, ParsedTcpSegment, TcpConformance,
    TcpFlags, TcpOption, TcpSackBlock, TcpSegment, parse_tcp_segment,
};
pub use template::{FrameTemplate, PatchDescriptor, PatchKind, PatchValue, TemplatePatch};
pub use types::{
    EtherType, InternetChecksum, IpAddress, IpProtocol, Ipv4Address, Ipv6Address, MacAddress,
    OwnedOptions, OwnedPayload, PacketSpan, ParseMode, Port, ProbePort,
};
pub use udp::{
    OwnedUdpDatagram, ParsedUdpDatagram, UdpChecksumMode, UdpChecksumStatus, UdpDatagram,
    parse_udp_datagram,
};
pub use udp_capability::{
    CapabilityImplementation, UDP_CAPABILITY_LEDGER, UdpCapabilityDisposition, UdpCapabilityEntry,
    UdpCapabilityLedgerError, validate_udp_capability_ledger,
};
pub use udp_catalogue::{
    MAX_UDP_CATALOGUE_VARIANTS, MAX_UDP_CORRELATION_FIELDS, MAX_UDP_RESPONSE_BYTES,
    UDP_PROBE_CATALOGUE, UDP_PROBE_CATALOGUE_SHA256_HEX, UDP_PROBE_CATALOGUE_VERSION,
    UdpAddressFamilies, UdpCatalogueError, UdpCorrelationField, UdpCorrelationFieldKind,
    UdpPortRange, UdpProbeDescriptor, UdpProbeId, UdpProbeProfile, UdpProbeProvenance,
    UdpProbeRisk, UdpProbeRiskSet, UdpResponseEndpointPolicy, UdpServiceFamilyId,
    UdpSourcePortConstraint, udp_probe_catalogue_sha256, udp_probe_catalogue_sha256_hex,
    validate_udp_probe_catalogue,
};
pub use udp_coverage::{
    MAX_UDP_COVERAGE_CANDIDATES, UDP_COVERAGE_REGISTRY, UDP_COVERAGE_REGISTRY_VERSION,
    UDP_COVERAGE_RESOURCE_CONTRACT, UdpCoverageDimension, UdpCoverageDimensionSet,
    UdpCoverageDisposition, UdpCoverageEntry, UdpCoverageExecutionModel, UdpCoveragePolicy,
    UdpCoverageRegistryError, UdpCoverageResourceContract, UdpCoverageRisk, UdpCoverageRiskSet,
    validate_udp_coverage_registry,
};
pub use udp_extended::{
    UdpCatalogueProbe, UdpProbeBuildContext, build_udp_catalogue_request,
    parse_udp_catalogue_response,
};
pub use udp_request::{
    MAX_UDP_REQUEST_BYTES, MAX_UDP_REQUEST_PATCHES, UdpRequestPatch, UdpRequestPatchField,
    UdpRequestPatchKind, UdpRequestPatchValue, UdpRequestPlan, UdpRequestPlanError,
};
pub use udp_safe::{
    MAX_UDP_SERVICE_METADATA_BYTES, UdpSafeCodecError, UdpSafeMatch, UdpSafeProbe,
    build_udp_safe_request, parse_udp_safe_response,
};
pub use udp_signature::{
    MAX_UDP_SIGNATURE_CLAUSES, MAX_UDP_SIGNATURE_EXTRACT_BYTES, MAX_UDP_SIGNATURE_WORK,
    UdpByteSignature, UdpSignatureClause, UdpSignatureError, UdpSignatureMatch,
    match_udp_signature, validate_udp_signature,
};
pub use writer::{OwnedPacket, PacketPlan};

#[cfg(feature = "fuzzing")]
pub mod fuzzing;
