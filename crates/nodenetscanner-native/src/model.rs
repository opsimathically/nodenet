use std::net::IpAddr;
use std::time::Duration;

use napi_derive::napi;
use nodenet_protocols::{
    DISCOVERY_OPERATION_REGISTRY, DiscoveryOperationId, DiscoveryScopeKind, IpAddress, Ipv4Address,
    Ipv6Address, ProbePort, UDP_PROBE_CATALOGUE, UdpAddressFamilies, UdpCatalogueProbe,
    UdpProbeProfile, UdpProbeRisk, UdpProbeRiskSet, UdpResponseEndpointPolicy,
    UdpSourcePortConstraint,
};
use nodenetscanner_engine::{
    DiscoveryLimits, DiscoveryPlan, DiscoveryScopeMember, DiscoverySilencePolicy,
    MAX_DISCOVERY_INTERFACES, ProbeDefinition, ProbeFamily, ScanDuration, ScanPlan,
    SchedulerConfig, TargetCidr, TargetEndpoint, TargetInput, TargetIntervalInput, TargetScope,
    TargetSet, TimingMode, UdpProbeProgramme, UdpProbeStrategy, UdpProbeVariant,
    UdpVariantEligibility,
};

use crate::error::ScannerError;

pub(crate) const MAX_BATCH_RESULTS: u32 = 4_096;
pub(crate) const DEFAULT_BATCH_RESULTS: u32 = 512;
pub(crate) const DEFAULT_SOURCE_PORT_START: u16 = 49_152;
pub(crate) const DEFAULT_SOURCE_PORT_END: u16 = 65_535;
pub(crate) const MAX_UDP_USER_PAYLOAD_BYTES: usize = 65_491;
const MAX_TEMPLATE_PAYLOAD_BYTES: usize = 1_048_576;

#[napi(object)]
#[derive(Clone)]
pub struct NativeScanTarget {
    pub cidr: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativePortSelection {
    pub start: u32,
    pub end: u32,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeScanProbe {
    pub kind: String,
    pub family: Option<String>,
    pub ports: Option<Vec<NativePortSelection>>,
    pub payload: Option<Vec<u8>>,
    pub udp_mode: Option<String>,
    pub udp_profile: Option<String>,
    pub udp_intensity: Option<u32>,
    pub udp_strategy: Option<String>,
    pub udp_empty_fallback: Option<String>,
    pub udp_allow_risks: Option<Vec<String>>,
    pub udp_correlation: Option<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeRateOptions {
    pub packets_per_second: Option<u32>,
    pub burst: Option<u32>,
    pub max_outstanding: Option<u32>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeTimingOptions {
    pub timeout_ms: Option<u32>,
    pub minimum_timeout_ms: Option<u32>,
    pub maximum_timeout_ms: Option<u32>,
    pub retries: Option<u32>,
    pub fixed: Option<bool>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeVlanOptions {
    pub identifier: u32,
    pub priority: Option<u32>,
    pub drop_eligible: Option<bool>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeScanPlan {
    pub targets: Vec<NativeScanTarget>,
    pub exclude: Option<Vec<NativeScanTarget>>,
    pub probes: Vec<NativeScanProbe>,
    pub deadline_ms: u32,
    pub rate: Option<NativeRateOptions>,
    pub timing: Option<NativeTimingOptions>,
    pub seed: Option<String>,
    pub source_address: Option<String>,
    pub interface: Option<String>,
    pub vlan: Option<NativeVlanOptions>,
    pub source_port_start: Option<u32>,
    pub source_port_end: Option<u32>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeDiscoveryOperation {
    pub id: u32,
    pub query: Option<String>,
    pub follow_up: Option<bool>,
    pub receive_mode: Option<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeDiscoveryScope {
    pub kind: String,
    pub interfaces: Option<Vec<String>>,
    pub all_eligible: Option<bool>,
    pub families: Vec<String>,
    pub targets: Option<Vec<NativeScanTarget>>,
    pub exclude: Option<Vec<NativeScanTarget>>,
    pub kernel_default_ipv4_gateway: Option<bool>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeDiscoveryLimits {
    pub max_results: Option<u32>,
    pub max_metadata_bytes: Option<u32>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeDiscoveryRate {
    pub packets_per_second: Option<u32>,
    pub burst: Option<u32>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeDiscoveryPlan {
    pub scope: NativeDiscoveryScope,
    pub operations: Vec<NativeDiscoveryOperation>,
    pub deadline_ms: u32,
    pub limits: Option<NativeDiscoveryLimits>,
    pub rate: Option<NativeDiscoveryRate>,
    pub allow_risks: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatedDiscoveryOperation {
    pub id: DiscoveryOperationId,
    pub query: Option<String>,
    pub follow_up: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum ValidatedDiscoveryScope {
    Links {
        interfaces: Vec<String>,
        ipv4: bool,
        ipv6: bool,
    },
    Targets {
        targets: Vec<(IpAddr, Option<u32>)>,
        kernel_default_ipv4_gateway: bool,
        exclusions: Option<TargetSet>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatedDiscoveryPlan {
    pub scope: ValidatedDiscoveryScope,
    pub operations: Vec<ValidatedDiscoveryOperation>,
    pub deadline: Duration,
    pub limits: DiscoveryLimits,
    pub packets_per_second: u32,
    pub burst: u32,
    pub allow_risks: UdpProbeRiskSet,
}

#[derive(Clone, Debug)]
pub(crate) struct VlanOverride {
    pub identifier: u16,
    pub priority: u8,
    pub drop_eligible: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct SessionOptions {
    pub udp_program: UdpProbeProgram,
    pub source_address: Option<IpAddr>,
    pub interface: Option<String>,
    pub vlan: Option<VlanOverride>,
    pub source_port_start: u16,
    pub source_port_end: u16,
    pub seed: u64,
    pub late_grace: Duration,
    pub result_schema_version: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UdpRequestCorrelation {
    Tuple,
    PrefixToken,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpProgramRequest {
    pub catalogue_probe_id: Option<u16>,
    pub payload: Vec<u8>,
    pub correlation: UdpRequestCorrelation,
    pub catalogue_probe: Option<UdpCatalogueProbe>,
    pub maximum_response_bytes: usize,
    pub maximum_parser_bytes: usize,
    pub maximum_state_lifetime_ms: u32,
    pub service_family: Option<u16>,
    pub eligibility: UdpVariantEligibility,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UdpProbeProgram {
    pub ipv4: Vec<UdpProgramRequest>,
    pub ipv6: Vec<UdpProgramRequest>,
    pub allowed_risks: UdpProbeRiskSet,
    pub catalogue_mode: bool,
    pub strategy: UdpProbeStrategy,
    pub policy_mode: Option<String>,
    pub profile: Option<String>,
    pub intensity: Option<u8>,
    pub empty_fallback: Option<String>,
    pub custom_correlation: Option<String>,
}

impl UdpProbeProgram {
    pub(crate) fn request_at(
        &self,
        target: IpAddr,
        request_index: u16,
    ) -> Option<&UdpProgramRequest> {
        match target {
            IpAddr::V4(_) => self.ipv4.get(usize::from(request_index)),
            IpAddr::V6(_) => self.ipv6.get(usize::from(request_index)),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ValidatedPlan {
    pub plan: ScanPlan,
    pub scheduler: SchedulerConfig,
    pub options: SessionOptions,
}

impl NativeScanPlan {
    #[allow(
        clippy::too_many_lines,
        reason = "one pre-admission transaction enforces every independent public limit"
    )]
    pub(crate) fn validate(self) -> Result<ValidatedPlan, ScannerError> {
        if self.deadline_ms == 0 {
            return Err(ScannerError::invalid(
                "validate scan plan",
                "deadlineMs must be greater than zero",
            ));
        }
        let includes = parse_targets(&self.targets)?;
        let excludes = parse_targets(self.exclude.as_deref().unwrap_or_default())?;
        let targets = TargetSet::normalize(&includes, &excludes).map_err(|error| {
            ScannerError::invalid("validate scan targets", format!("{error:?}"))
        })?;

        let mut definitions = Vec::new();
        let mut udp_program = UdpProbeProgram::default();
        let mut saw_udp = false;
        for probe in self.probes {
            let (family, ports, udp_definition) = parse_probe(&probe)?;
            if family == ProbeFamily::Udp {
                if saw_udp {
                    return Err(ScannerError::invalid(
                        "validate scan probes",
                        "a scan plan may contain exactly one UDP probe definition",
                    ));
                }
                saw_udp = true;
                udp_program = udp_definition.unwrap_or_default();
            }
            let definition = if family == ProbeFamily::Udp {
                ProbeDefinition::udp(ports, engine_udp_programme(&udp_program)?)
            } else {
                ProbeDefinition::new(family, ports)
            };
            definitions.push(definition.map_err(|error| {
                ScannerError::invalid("validate scan probes", format!("{error:?}"))
            })?);
        }
        if saw_udp
            && udp_program.catalogue_mode
            && targets.contains_multicast_or_limited_broadcast()
        {
            if !udp_program
                .allowed_risks
                .contains(UdpProbeRisk::MulticastOrBroadcast)
            {
                return Err(ScannerError::invalid(
                    "validate UDP targets",
                    "multicast or limited-broadcast protocol targets require multicastOrBroadcast consent",
                ));
            }
            if self.interface.is_none() {
                return Err(ScannerError::invalid(
                    "validate UDP targets",
                    "multicast or limited-broadcast protocol targets require an explicit interface",
                ));
            }
        }

        let timing = self.timing.unwrap_or(NativeTimingOptions {
            timeout_ms: None,
            minimum_timeout_ms: None,
            maximum_timeout_ms: None,
            retries: None,
            fixed: None,
        });
        let retries = timing.retries.unwrap_or(1);
        let plan = ScanPlan::new(targets, definitions, 1)
            .map_err(|error| ScannerError::invalid("validate scan probes", format!("{error:?}")))?;

        let rate = self.rate.unwrap_or(NativeRateOptions {
            packets_per_second: None,
            burst: None,
            max_outstanding: None,
        });
        let max_outstanding = usize::try_from(rate.max_outstanding.unwrap_or(4_096))
            .map_err(|_| ScannerError::invalid("validate rate", "maxOutstanding is too large"))?;
        let initial_timeout = timing.timeout_ms.unwrap_or(1_000);
        let minimum_timeout = timing
            .minimum_timeout_ms
            .unwrap_or(initial_timeout.min(100));
        let maximum_timeout = timing
            .maximum_timeout_ms
            .unwrap_or(initial_timeout.max(10_000));
        if udp_program
            .ipv4
            .iter()
            .chain(&udp_program.ipv6)
            .any(|request| {
                request.maximum_state_lifetime_ms != 0
                    && maximum_timeout > request.maximum_state_lifetime_ms
            })
        {
            return Err(ScannerError::invalid(
                "validate UDP timing",
                "maximumTimeoutMs exceeds a selected stateful UDP probe lifetime",
            ));
        }
        let scheduler = SchedulerConfig {
            rate_per_second: rate.packets_per_second.unwrap_or(100),
            burst: rate
                .burst
                .unwrap_or_else(|| u32::try_from(max_outstanding.min(32)).unwrap_or(1)),
            max_outstanding,
            max_retransmissions: u8::try_from(retries).map_err(|_| {
                ScannerError::invalid("validate timing", "retries must not exceed 10")
            })?,
            initial_timeout: duration_ms(initial_timeout),
            minimum_timeout: duration_ms(minimum_timeout),
            maximum_timeout: duration_ms(maximum_timeout),
            session_deadline: duration_ms(self.deadline_ms),
            late_grace: duration_ms(maximum_timeout),
            max_grace_entries: max_outstanding,
            max_per_target: max_outstanding.clamp(1, 64),
            max_per_prefix: max_outstanding.clamp(1, 1_024),
            timing_mode: if timing.fixed.unwrap_or(false) {
                TimingMode::FixedRate
            } else {
                TimingMode::Adaptive
            },
            discovery_silence: DiscoverySilencePolicy::Unknown,
            tcp_reset_cleanup: false,
        }
        .validate()
        .map_err(|error| ScannerError::invalid("validate scheduler", format!("{error:?}")))?;

        let source_address = self
            .source_address
            .map(|value| parse_plain_address(&value, "sourceAddress"))
            .transpose()?;
        let source_port_start = checked_port(
            self.source_port_start
                .unwrap_or(u32::from(DEFAULT_SOURCE_PORT_START)),
            "sourcePortRange.start",
        )?;
        let source_port_end = checked_port(
            self.source_port_end
                .unwrap_or(u32::from(DEFAULT_SOURCE_PORT_END)),
            "sourcePortRange.end",
        )?;
        if source_port_start > source_port_end {
            return Err(ScannerError::invalid(
                "validate source port range",
                "source port range is reversed",
            ));
        }
        let source_port_span = usize::from(source_port_end - source_port_start) + 1;
        let ports_per_session = source_port_span / 4;
        if scheduler.max_outstanding > ports_per_session {
            return Err(ScannerError::invalid(
                "validate source port range",
                "source port range provides fewer collision-free ports than maxOutstanding across four sessions",
            ));
        }
        let template_payload_bytes = udp_program
            .ipv4
            .iter()
            .chain(&udp_program.ipv6)
            .try_fold(0_usize, |total, request| {
                total.checked_add(request.payload.len())
            })
            .ok_or_else(|| {
                ScannerError::resource(
                    "validate UDP payload",
                    "UDP payload accounting overflowed the session template budget",
                )
            })?;
        if template_payload_bytes > MAX_TEMPLATE_PAYLOAD_BYTES {
            return Err(ScannerError::resource(
                "validate UDP payload",
                "UDP payloads exceed the 1 MiB session template budget",
            ));
        }
        let vlan = self.vlan.as_ref().map(validate_vlan).transpose()?;
        let seed = self.seed.map_or(Ok(0), |value| {
            value.parse::<u64>().map_err(|_| {
                ScannerError::invalid("validate seed", "seed must fit an unsigned 64-bit integer")
            })
        })?;

        let result_schema_version = if udp_program
            .ipv4
            .iter()
            .chain(&udp_program.ipv6)
            .any(|request| request.catalogue_probe.is_some())
        {
            2
        } else {
            1
        };
        Ok(ValidatedPlan {
            plan,
            scheduler,
            options: SessionOptions {
                udp_program,
                source_address,
                interface: self.interface,
                vlan,
                source_port_start,
                source_port_end,
                seed,
                late_grace: Duration::from_millis(u64::from(maximum_timeout)),
                result_schema_version,
            },
        })
    }
}

impl NativeDiscoveryPlan {
    #[allow(
        clippy::too_many_lines,
        reason = "one pre-admission transaction validates every hostile discovery plan field"
    )]
    pub(crate) fn validate(self) -> Result<ValidatedDiscoveryPlan, ScannerError> {
        if self.deadline_ms == 0 || self.deadline_ms > 60_000 {
            return Err(ScannerError::invalid(
                "validate discovery plan",
                "deadlineMs must be from 1 through 60000",
            ));
        }
        if self.operations.is_empty() || self.operations.len() > 8 {
            return Err(ScannerError::invalid(
                "validate discovery plan",
                "operations must contain from 1 through 8 selections",
            ));
        }
        let allow_risks = parse_risk_set(self.allow_risks.as_deref().unwrap_or_default())?;
        let mut operations = Vec::with_capacity(self.operations.len());
        let mut prior_id = 0_u16;
        for selection in self.operations {
            let id = u16::try_from(selection.id).map_err(|_| {
                ScannerError::invalid(
                    "validate discovery operation",
                    "operation identifier is too large",
                )
            })?;
            let id = DiscoveryOperationId::new(id).ok_or_else(|| {
                ScannerError::invalid(
                    "validate discovery operation",
                    "operation identifier must be nonzero",
                )
            })?;
            if id.get() <= prior_id {
                return Err(ScannerError::invalid(
                    "validate discovery operation",
                    "operation identifiers must be unique and ascending",
                ));
            }
            prior_id = id.get();
            let descriptor = DISCOVERY_OPERATION_REGISTRY
                .iter()
                .find(|entry| entry.id == id)
                .ok_or_else(|| {
                    ScannerError::invalid(
                        "validate discovery operation",
                        "unknown discovery operation identifier",
                    )
                })?;
            if descriptor.required_risks.bits() & !allow_risks.bits() != 0 {
                return Err(ScannerError::invalid(
                    "validate discovery operation",
                    "required discovery risk consent is missing",
                ));
            }
            if selection.query.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 255 || value.as_bytes().contains(&0)
            }) {
                return Err(ScannerError::invalid(
                    "validate discovery operation",
                    "operation query must contain from 1 through 255 non-NUL bytes",
                ));
            }
            if id.get() == 4 && selection.query.is_none() {
                return Err(ScannerError::invalid(
                    "validate discovery operation",
                    "LLMNR requires an explicit query name",
                ));
            }
            if id.get() != 4 && selection.query.is_some() {
                return Err(ScannerError::invalid(
                    "validate discovery operation",
                    "this discovery operation does not accept a query parameter",
                ));
            }
            if id.get() != 7 && selection.follow_up.is_some() {
                return Err(ScannerError::invalid(
                    "validate discovery operation",
                    "only rpcbind accepts the follow-up parameter",
                ));
            }
            if id.get() == 1 && selection.receive_mode.as_deref() != Some("legacyUnicast") {
                return Err(ScannerError::invalid(
                    "validate discovery operation",
                    "mDNS requires the explicit legacyUnicast receive mode",
                ));
            }
            if id.get() != 1 && selection.receive_mode.is_some() {
                return Err(ScannerError::invalid(
                    "validate discovery operation",
                    "only mDNS accepts a receive mode",
                ));
            }
            operations.push(ValidatedDiscoveryOperation {
                id,
                query: selection.query,
                follow_up: selection.follow_up.unwrap_or(true),
            });
        }

        let limits_value = self.limits.unwrap_or(NativeDiscoveryLimits {
            max_results: None,
            max_metadata_bytes: None,
        });
        let limits = DiscoveryLimits {
            max_results: usize::try_from(limits_value.max_results.unwrap_or(8_192))
                .unwrap_or(usize::MAX),
            max_metadata_bytes: usize::try_from(
                limits_value
                    .max_metadata_bytes
                    .unwrap_or(16 * 1_024 * 1_024),
            )
            .unwrap_or(usize::MAX),
        };
        let rate = self.rate.unwrap_or(NativeDiscoveryRate {
            packets_per_second: None,
            burst: None,
        });
        let packets_per_second = rate.packets_per_second.unwrap_or(100);
        let burst = rate.burst.unwrap_or(16);
        if packets_per_second == 0 || packets_per_second > 1_000_000 {
            return Err(ScannerError::invalid(
                "validate discovery rate",
                "packetsPerSecond must be from 1 through 1000000",
            ));
        }
        if burst == 0 || burst > 65_536 {
            return Err(ScannerError::invalid(
                "validate discovery rate",
                "burst must be from 1 through 65536",
            ));
        }
        let deadline = Duration::from_millis(u64::from(self.deadline_ms));
        let scope = match self.scope.kind.as_str() {
            "links" => {
                if self.scope.targets.is_some()
                    || self.scope.exclude.is_some()
                    || self.scope.kernel_default_ipv4_gateway == Some(true)
                {
                    return Err(ScannerError::invalid(
                        "validate discovery scope",
                        "link scope cannot contain target fields",
                    ));
                }
                let all_eligible = self.scope.all_eligible.unwrap_or(false);
                if all_eligible == self.scope.interfaces.is_some() {
                    return Err(ScannerError::invalid(
                        "validate discovery scope",
                        "link scope requires exactly explicit interfaces or allEligible",
                    ));
                }
                let mut interfaces = self.scope.interfaces.unwrap_or_default();
                interfaces.sort();
                if (!all_eligible && interfaces.is_empty())
                    || interfaces.len() > MAX_DISCOVERY_INTERFACES
                    || interfaces.windows(2).any(|pair| pair[0] == pair[1])
                    || interfaces.iter().any(|name| {
                        name.is_empty() || name.len() > 64 || name.as_bytes().contains(&0)
                    })
                {
                    return Err(ScannerError::invalid(
                        "validate discovery scope",
                        "interfaces must be a unique bounded nonempty list",
                    ));
                }
                let (ipv4, ipv6) = parse_discovery_families(&self.scope.families)?;
                if operations.iter().any(|operation| {
                    DISCOVERY_OPERATION_REGISTRY
                        .iter()
                        .find(|entry| entry.id == operation.id)
                        .is_none_or(|entry| entry.scope != DiscoveryScopeKind::Links)
                }) {
                    return Err(ScannerError::invalid(
                        "validate discovery scope",
                        "link scope contains a target-only operation",
                    ));
                }
                ValidatedDiscoveryScope::Links {
                    interfaces,
                    ipv4,
                    ipv6,
                }
            }
            "targets" => {
                if self.scope.interfaces.is_some() || self.scope.all_eligible.is_some() {
                    return Err(ScannerError::invalid(
                        "validate discovery scope",
                        "target scope cannot contain link interface fields",
                    ));
                }
                if operations.iter().any(|operation| {
                    DISCOVERY_OPERATION_REGISTRY
                        .iter()
                        .find(|entry| entry.id == operation.id)
                        .is_none_or(|entry| entry.scope != DiscoveryScopeKind::Targets)
                }) {
                    return Err(ScannerError::invalid(
                        "validate discovery scope",
                        "target scope contains a link-only operation",
                    ));
                }
                let (ipv4, ipv6) = parse_discovery_families(&self.scope.families)?;
                let include = parse_targets(self.scope.targets.as_deref().unwrap_or_default())?;
                let exclude = parse_targets(self.scope.exclude.as_deref().unwrap_or_default())?;
                let use_gateway = self.scope.kernel_default_ipv4_gateway.unwrap_or(false);
                let exclusions = if exclude.is_empty() {
                    None
                } else {
                    Some(TargetSet::normalize(&exclude, &[]).map_err(|error| {
                        ScannerError::invalid("validate discovery exclusions", format!("{error:?}"))
                    })?)
                };
                let mut targets = Vec::new();
                if !include.is_empty() {
                    let normalized = TargetSet::normalize(&include, &exclude).map_err(|error| {
                        ScannerError::invalid("validate discovery targets", format!("{error:?}"))
                    })?;
                    if normalized.count() > 65_536 {
                        return Err(ScannerError::resource(
                            "validate discovery targets",
                            "target discovery expands to more than 65536 addresses",
                        ));
                    }
                    for family in [4_u8, 6] {
                        let count = if family == 4 {
                            normalized.ipv4_count()
                        } else {
                            normalized.ipv6_count()
                        };
                        if (family == 4 && !ipv4) || (family == 6 && !ipv6) {
                            continue;
                        }
                        for index in 0..count {
                            let target =
                                normalized.target_at_family(family, index).ok_or_else(|| {
                                    ScannerError::internal(
                                        "validate discovery targets",
                                        "normalized target expansion failed",
                                    )
                                })?;
                            targets.push((
                                to_std_address(target.address),
                                target.scope.map(TargetScope::get),
                            ));
                        }
                    }
                }
                if targets.is_empty() && !use_gateway {
                    return Err(ScannerError::invalid(
                        "validate discovery scope",
                        "target scope requires targets or kernelDefaultIpv4Gateway",
                    ));
                }
                if use_gateway && !ipv4 {
                    return Err(ScannerError::invalid(
                        "validate discovery scope",
                        "kernelDefaultIpv4Gateway requires the ipv4 family",
                    ));
                }
                if use_gateway
                    && operations.iter().any(|operation| {
                        DISCOVERY_OPERATION_REGISTRY
                            .iter()
                            .find(|entry| entry.id == operation.id)
                            .is_none_or(|entry| !entry.permits_kernel_default_ipv4_gateway)
                    })
                {
                    return Err(ScannerError::invalid(
                        "validate discovery scope",
                        "kernelDefaultIpv4Gateway is not compatible with every selected operation",
                    ));
                }
                ValidatedDiscoveryScope::Targets {
                    targets,
                    kernel_default_ipv4_gateway: use_gateway,
                    exclusions,
                }
            }
            _ => {
                return Err(ScannerError::invalid(
                    "validate discovery scope",
                    "scope kind must be links or targets",
                ));
            }
        };

        // Reuse the syscall-free plan validator with representative normalized
        // members so bounds and risk rules remain independently enforced.
        let members = match &scope {
            ValidatedDiscoveryScope::Links { ipv4, ipv6, .. } => {
                let mut members = Vec::new();
                if *ipv4 {
                    members.push(DiscoveryScopeMember::Link {
                        interface_index: 1,
                        family: nodenetscanner_engine::DiscoveryAddressFamily::Ipv4,
                    });
                }
                if *ipv6 {
                    members.push(DiscoveryScopeMember::Link {
                        interface_index: 1,
                        family: nodenetscanner_engine::DiscoveryAddressFamily::Ipv6,
                    });
                }
                members
            }
            ValidatedDiscoveryScope::Targets {
                targets,
                kernel_default_ipv4_gateway,
                ..
            } => {
                let mut members: Vec<_> = targets
                    .iter()
                    .map(|(address, interface_index)| DiscoveryScopeMember::Target {
                        address: *address,
                        interface_index: *interface_index,
                    })
                    .collect();
                if *kernel_default_ipv4_gateway {
                    members.push(DiscoveryScopeMember::KernelDefaultIpv4Gateway);
                }
                members
            }
        };
        DiscoveryPlan::new(
            operations.iter().map(|operation| operation.id).collect(),
            members,
            deadline,
            limits,
            allow_risks,
        )
        .map_err(|error| ScannerError::invalid("validate discovery plan", format!("{error:?}")))?;

        Ok(ValidatedDiscoveryPlan {
            scope,
            operations,
            deadline,
            limits,
            packets_per_second,
            burst,
            allow_risks,
        })
    }
}

fn parse_discovery_families(values: &[String]) -> Result<(bool, bool), ScannerError> {
    match values {
        [value] if value == "ipv4" => Ok((true, false)),
        [value] if value == "ipv6" => Ok((false, true)),
        [first, second] if first == "ipv4" && second == "ipv6" => Ok((true, true)),
        _ => Err(ScannerError::invalid(
            "validate discovery scope",
            "families must be canonical ipv4, ipv6, or ipv4 then ipv6",
        )),
    }
}

fn duration_ms(value: u32) -> ScanDuration {
    ScanDuration::from_micros(u64::from(value) * 1_000)
}

fn checked_port(value: u32, field: &str) -> Result<u16, ScannerError> {
    let value = u16::try_from(value).map_err(|_| {
        ScannerError::invalid(
            "validate port",
            format!("{field} must be from 1 through 65535"),
        )
    })?;
    if value == 0 {
        return Err(ScannerError::invalid(
            "validate port",
            format!("{field} must be from 1 through 65535"),
        ));
    }
    Ok(value)
}

fn validate_vlan(value: &NativeVlanOptions) -> Result<VlanOverride, ScannerError> {
    if value.identifier == 0 || value.identifier > 4_094 {
        return Err(ScannerError::invalid(
            "validate VLAN",
            "VLAN identifier must be from 1 through 4094",
        ));
    }
    let priority = value.priority.unwrap_or(0);
    if priority > 7 {
        return Err(ScannerError::invalid(
            "validate VLAN",
            "VLAN priority must be from 0 through 7",
        ));
    }
    Ok(VlanOverride {
        identifier: u16::try_from(value.identifier).unwrap_or_default(),
        priority: u8::try_from(priority).unwrap_or_default(),
        drop_eligible: value.drop_eligible.unwrap_or(false),
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum UdpPayloadFamily {
    Both,
    Ipv4,
    Ipv6,
}

type ParsedProbe = (ProbeFamily, Vec<ProbePort>, Option<UdpProbeProgram>);

const UDP_PROBE_RISKS: [&str; 6] = [
    "highAmplification",
    "statefulHandshake",
    "fixedSourcePort",
    "multicastOrBroadcast",
    "authenticationAttempt",
    "sensitiveRead",
];

fn parse_probe(probe: &NativeScanProbe) -> Result<ParsedProbe, ScannerError> {
    let payload = probe.payload.clone().unwrap_or_default();
    if payload.len() > MAX_UDP_USER_PAYLOAD_BYTES {
        return Err(ScannerError::invalid(
            "validate UDP payload",
            "UDP payload plus correlation, UDP, and IPv4 headers exceeds the maximum IP packet length",
        ));
    }
    let ports = expand_ports(probe.ports.as_deref().unwrap_or_default())?;
    let family = match (probe.kind.as_str(), probe.family.as_deref()) {
        ("arp", None) => ProbeFamily::Arp,
        ("ndp", None) => ProbeFamily::Ndp,
        ("icmpEcho", Some("ipv4")) => ProbeFamily::Icmpv4Echo,
        ("icmpEcho", Some("ipv6")) => ProbeFamily::Icmpv6Echo,
        ("tcpSyn", None) => ProbeFamily::TcpSyn,
        ("udp", None | Some("both" | "ipv4" | "ipv6")) => ProbeFamily::Udp,
        _ => {
            return Err(ScannerError::invalid(
                "validate scan probe",
                "unsupported probe kind/family combination",
            ));
        }
    };
    if family != ProbeFamily::Udp
        && (!payload.is_empty()
            || probe.udp_mode.is_some()
            || probe.udp_profile.is_some()
            || probe.udp_intensity.is_some()
            || probe.udp_strategy.is_some()
            || probe.udp_empty_fallback.is_some()
            || probe.udp_allow_risks.is_some()
            || probe.udp_correlation.is_some())
    {
        return Err(ScannerError::invalid(
            "validate scan probe",
            "payload is supported only for UDP probes",
        ));
    }
    if family != ProbeFamily::Udp {
        return Ok((family, ports, None));
    }
    Ok((
        ProbeFamily::Udp,
        ports,
        Some(parse_udp_program(probe, payload)?),
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "all UDP policy modes share one conflict-validation boundary"
)]
fn parse_udp_program(
    probe: &NativeScanProbe,
    payload: Vec<u8>,
) -> Result<UdpProbeProgram, ScannerError> {
    let mode = probe.udp_mode.as_deref().unwrap_or(if payload.is_empty() {
        "protocol"
    } else {
        "legacyPrefix"
    });
    let correlation = match mode {
        "legacyPrefix" => UdpRequestCorrelation::PrefixToken,
        "empty" => {
            if !payload.is_empty() {
                return Err(ScannerError::invalid(
                    "validate UDP policy",
                    "empty UDP policy cannot contain payload bytes",
                ));
            }
            UdpRequestCorrelation::Tuple
        }
        "custom" => match probe.udp_correlation.as_deref().unwrap_or("tuple") {
            "tuple" => UdpRequestCorrelation::Tuple,
            "prefixToken" => UdpRequestCorrelation::PrefixToken,
            _ => {
                return Err(ScannerError::invalid(
                    "validate UDP policy",
                    "UDP custom correlation is unsupported",
                ));
            }
        },
        "protocol" => {
            validate_protocol_policy(probe)?;
            let strategy = match probe.udp_strategy.as_deref().unwrap_or("exhaustive") {
                "adaptive" => UdpProbeStrategy::Adaptive,
                "exhaustive" => UdpProbeStrategy::Exhaustive,
                _ => unreachable!("validated strategy"),
            };
            let profile = match probe.udp_profile.as_deref().unwrap_or("safe") {
                "safe" => UdpProbeProfile::Safe,
                "comprehensive" => UdpProbeProfile::Comprehensive,
                "legacy" => UdpProbeProfile::Legacy,
                _ => unreachable!("validated profile"),
            };
            let intensity = u8::try_from(probe.udp_intensity.unwrap_or(7)).map_err(|_| {
                ScannerError::invalid(
                    "validate UDP policy",
                    "UDP intensity must be from 0 through 9",
                )
            })?;
            let allowed_risks = protocol_risk_set(probe)?;
            let mut program = UdpProbeProgram {
                allowed_risks,
                catalogue_mode: true,
                strategy,
                policy_mode: Some("protocol".into()),
                profile: Some(probe.udp_profile.as_deref().unwrap_or("safe").into()),
                intensity: Some(intensity),
                empty_fallback: Some(
                    probe
                        .udp_empty_fallback
                        .as_deref()
                        .unwrap_or("unmapped")
                        .into(),
                ),
                ..UdpProbeProgram::default()
            };
            for descriptor in UDP_PROBE_CATALOGUE {
                if !profile_includes(profile, descriptor.profile)
                    || descriptor.minimum_intensity > intensity
                    || !risks_are_allowed(descriptor.risks, allowed_risks)
                {
                    continue;
                }
                if !matches!(descriptor.source_port, UdpSourcePortConstraint::Ephemeral)
                    || descriptor.response_endpoint != UdpResponseEndpointPolicy::RequestTupleOnly
                {
                    return Err(ScannerError::unsupported(
                        "validate UDP catalogue",
                        "selected UDP probe requires an unsupported source or response endpoint policy",
                    ));
                }
                let Some(catalogue_probe) =
                    UdpCatalogueProbe::from_id(descriptor.request_builder_id)
                else {
                    continue;
                };
                for range in descriptor.ports {
                    let start = ProbePort::new(range.start)?;
                    let end = ProbePort::new(range.end)?;
                    let eligibility = if start == end {
                        UdpVariantEligibility::DestinationPort(start)
                    } else {
                        UdpVariantEligibility::DestinationPortRange { start, end }
                    };
                    let request = UdpProgramRequest {
                        catalogue_probe_id: Some(descriptor.id.get()),
                        payload: Vec::new(),
                        correlation: UdpRequestCorrelation::Tuple,
                        catalogue_probe: Some(catalogue_probe),
                        maximum_response_bytes: descriptor.maximum_response_bytes,
                        maximum_parser_bytes: descriptor.maximum_parser_bytes,
                        maximum_state_lifetime_ms: descriptor.maximum_state_lifetime_ms,
                        service_family: Some(descriptor.service_family.get()),
                        eligibility,
                    };
                    match descriptor.address_families {
                        UdpAddressFamilies::Ipv4 => program.ipv4.push(request),
                        UdpAddressFamilies::Ipv6 => program.ipv6.push(request),
                        UdpAddressFamilies::Both => {
                            program.ipv4.push(request.clone());
                            program.ipv6.push(request);
                        }
                    }
                }
            }
            let fallback = probe.udp_empty_fallback.as_deref().unwrap_or("unmapped");
            if fallback != "never" {
                let request = UdpProgramRequest {
                    catalogue_probe_id: None,
                    payload: Vec::new(),
                    correlation: UdpRequestCorrelation::Tuple,
                    catalogue_probe: None,
                    maximum_response_bytes: 0,
                    maximum_parser_bytes: 0,
                    maximum_state_lifetime_ms: 0,
                    service_family: None,
                    eligibility: if fallback == "afterProtocol" {
                        UdpVariantEligibility::AfterProgrammeFallback
                    } else {
                        UdpVariantEligibility::UnmappedFallback
                    },
                };
                program.ipv4.push(request.clone());
                program.ipv6.push(request);
            }
            return Ok(program);
        }
        _ => {
            return Err(ScannerError::invalid(
                "validate UDP policy",
                "UDP policy mode is unsupported",
            ));
        }
    };
    if mode != "protocol"
        && (probe.udp_profile.is_some()
            || probe.udp_intensity.is_some()
            || probe.udp_strategy.is_some()
            || probe.udp_empty_fallback.is_some()
            || probe.udp_allow_risks.is_some())
    {
        return Err(ScannerError::invalid(
            "validate UDP policy",
            "protocol-only UDP policy fields are not valid for empty or custom mode",
        ));
    }
    if mode != "custom" && probe.udp_correlation.is_some() {
        return Err(ScannerError::invalid(
            "validate UDP policy",
            "correlation is valid only for custom UDP policy",
        ));
    }
    let family = match probe.family.as_deref() {
        Some("ipv4") => UdpPayloadFamily::Ipv4,
        Some("ipv6") => UdpPayloadFamily::Ipv6,
        _ => UdpPayloadFamily::Both,
    };
    let request = UdpProgramRequest {
        catalogue_probe_id: None,
        payload,
        correlation,
        catalogue_probe: None,
        maximum_response_bytes: 0,
        maximum_parser_bytes: 0,
        maximum_state_lifetime_ms: 0,
        service_family: None,
        eligibility: UdpVariantEligibility::AnyPort,
    };
    let mut program = UdpProbeProgram {
        policy_mode: Some(
            if mode == "legacyPrefix" {
                "custom"
            } else {
                mode
            }
            .into(),
        ),
        custom_correlation: (mode == "custom" || mode == "legacyPrefix").then(|| {
            match correlation {
                UdpRequestCorrelation::Tuple => "tuple",
                UdpRequestCorrelation::PrefixToken => "prefixToken",
            }
            .into()
        }),
        ..UdpProbeProgram::default()
    };
    match family {
        UdpPayloadFamily::Both => {
            program.ipv4.push(request.clone());
            program.ipv6.push(request);
        }
        UdpPayloadFamily::Ipv4 => program.ipv4.push(request),
        UdpPayloadFamily::Ipv6 => program.ipv6.push(request),
    }
    Ok(program)
}

fn engine_udp_programme(program: &UdpProbeProgram) -> Result<UdpProbeProgramme, ScannerError> {
    fn variants(requests: &[UdpProgramRequest]) -> Result<Vec<UdpProbeVariant>, ScannerError> {
        requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let request_index = u16::try_from(index).map_err(|_| {
                    ScannerError::resource("validate UDP programme", "too many UDP variants")
                })?;
                let catalogue_probe_id = request
                    .catalogue_probe_id
                    .and_then(nodenetscanner_engine::ProbeVariantId::new);
                UdpProbeVariant::new(
                    catalogue_probe_id,
                    request_index,
                    if request.catalogue_probe.is_some() {
                        1_024
                    } else {
                        0
                    },
                )
                .map(|variant| {
                    let variant = variant.with_eligibility(request.eligibility);
                    request
                        .service_family
                        .map_or(variant, |family| variant.with_service_family(family))
                })
                .map_err(|error| {
                    ScannerError::invalid("validate UDP programme", format!("{error:?}"))
                })
            })
            .collect()
    }
    UdpProbeProgramme::new(variants(&program.ipv4)?, variants(&program.ipv6)?)
        .map(|programme| programme.with_strategy(program.strategy))
        .map_err(|error| ScannerError::invalid("validate UDP programme", format!("{error:?}")))
}

fn profile_includes(selected: UdpProbeProfile, candidate: UdpProbeProfile) -> bool {
    matches!(
        (selected, candidate),
        (UdpProbeProfile::Safe, UdpProbeProfile::Safe)
            | (
                UdpProbeProfile::Comprehensive,
                UdpProbeProfile::Safe | UdpProbeProfile::Comprehensive
            )
            | (UdpProbeProfile::Legacy, _)
    )
}

fn risks_are_allowed(required: UdpProbeRiskSet, allowed: UdpProbeRiskSet) -> bool {
    required.bits() & !allowed.bits() == 0
}

fn protocol_risk_set(probe: &NativeScanProbe) -> Result<UdpProbeRiskSet, ScannerError> {
    parse_risk_set(probe.udp_allow_risks.as_deref().unwrap_or_default())
}

fn parse_risk_set(risks: &[String]) -> Result<UdpProbeRiskSet, ScannerError> {
    let mut bits = 0_u8;
    let mut prior = None;
    for risk in risks {
        let value = match risk.as_str() {
            "highAmplification" => UdpProbeRisk::HighAmplification,
            "statefulHandshake" => UdpProbeRisk::StatefulHandshake,
            "fixedSourcePort" => UdpProbeRisk::FixedSourcePort,
            "multicastOrBroadcast" => UdpProbeRisk::MulticastOrBroadcast,
            "authenticationAttempt" => UdpProbeRisk::AuthenticationAttempt,
            "sensitiveRead" => UdpProbeRisk::SensitiveRead,
            _ => {
                return Err(ScannerError::invalid(
                    "validate UDP policy",
                    "UDP risk consent is unsupported",
                ));
            }
        };
        let index = value as u8;
        if prior.is_some_and(|prior| index <= prior) {
            return Err(ScannerError::invalid(
                "validate UDP policy",
                "UDP risk consent must be unique and canonical",
            ));
        }
        prior = Some(index);
        bits |= 1 << value as u8;
    }
    UdpProbeRiskSet::from_bits(bits).ok_or_else(|| {
        ScannerError::invalid("validate UDP policy", "UDP risk consent bits are invalid")
    })
}

fn validate_protocol_policy(probe: &NativeScanProbe) -> Result<(), ScannerError> {
    if !matches!(
        probe.udp_profile.as_deref(),
        None | Some("safe" | "comprehensive" | "legacy")
    ) {
        return Err(ScannerError::invalid(
            "validate UDP policy",
            "UDP profile is unsupported",
        ));
    }
    if probe.udp_intensity.is_some_and(|value| value > 9) {
        return Err(ScannerError::invalid(
            "validate UDP policy",
            "UDP intensity must be from 0 through 9",
        ));
    }
    if !matches!(
        probe.udp_strategy.as_deref(),
        None | Some("exhaustive" | "adaptive")
    ) {
        return Err(ScannerError::invalid(
            "validate UDP policy",
            "UDP strategy is unsupported",
        ));
    }
    if !matches!(
        probe.udp_empty_fallback.as_deref(),
        None | Some("unmapped" | "afterProtocol" | "never")
    ) {
        return Err(ScannerError::invalid(
            "validate UDP policy",
            "UDP empty fallback is unsupported",
        ));
    }
    if probe
        .payload
        .as_ref()
        .is_some_and(|value| !value.is_empty())
        || probe.udp_correlation.is_some()
    {
        return Err(ScannerError::invalid(
            "validate UDP policy",
            "protocol UDP policy cannot contain custom payload fields",
        ));
    }
    let risks = probe.udp_allow_risks.as_deref().unwrap_or_default();
    let mut prior = None;
    for risk in risks {
        let Some(index) = UDP_PROBE_RISKS.iter().position(|known| risk == known) else {
            return Err(ScannerError::invalid(
                "validate UDP policy",
                "UDP risk consent is unsupported",
            ));
        };
        if prior.is_some_and(|value| index <= value) {
            return Err(ScannerError::invalid(
                "validate UDP policy",
                "UDP risk consent must be unique and canonical",
            ));
        }
        prior = Some(index);
    }
    Ok(())
}

fn expand_ports(values: &[NativePortSelection]) -> Result<Vec<ProbePort>, ScannerError> {
    let mut ports = Vec::new();
    for value in values {
        let start = checked_port(value.start, "port.start")?;
        let end = checked_port(value.end, "port.end")?;
        if start > end {
            return Err(ScannerError::invalid(
                "validate ports",
                "port range is reversed",
            ));
        }
        let additional = usize::from(end - start) + 1;
        if ports.len().saturating_add(additional) > 65_536 {
            return Err(ScannerError::resource(
                "validate ports",
                "a probe family may contain at most 65536 ports",
            ));
        }
        for port in start..=end {
            ports.push(ProbePort::new(port)?);
        }
    }
    Ok(ports)
}

fn parse_targets(values: &[NativeScanTarget]) -> Result<Vec<TargetInput>, ScannerError> {
    values.iter().map(parse_target).collect()
}

fn parse_target(value: &NativeScanTarget) -> Result<TargetInput, ScannerError> {
    match (&value.cidr, &value.start, &value.end) {
        (Some(cidr), None, None) => {
            let (address, prefix) = cidr.rsplit_once('/').ok_or_else(|| {
                ScannerError::invalid("validate target", "CIDR target requires a prefix length")
            })?;
            let endpoint = parse_endpoint(address)?;
            let prefix_length = prefix.parse::<u8>().map_err(|_| {
                ScannerError::invalid("validate target", "invalid CIDR prefix length")
            })?;
            Ok(TargetInput::Cidr(TargetCidr {
                network: endpoint,
                prefix_length,
            }))
        }
        (None, Some(start), Some(end)) => Ok(TargetInput::Range(TargetIntervalInput {
            start: parse_endpoint(start)?,
            end: parse_endpoint(end)?,
        })),
        _ => Err(ScannerError::invalid(
            "validate target",
            "target must contain exactly cidr or start/end",
        )),
    }
}

fn parse_endpoint(value: &str) -> Result<TargetEndpoint, ScannerError> {
    let (address, scope) = match value.rsplit_once('%') {
        Some((address, scope)) => {
            let value = scope.parse::<u32>().map_err(|_| {
                ScannerError::invalid(
                    "validate target",
                    "IPv6 zones must be numeric interface indices",
                )
            })?;
            (
                address,
                Some(TargetScope::new(value).map_err(|error| {
                    ScannerError::invalid("validate target", format!("{error:?}"))
                })?),
            )
        }
        None => (value, None),
    };
    let address = parse_plain_address(address, "target")?;
    TargetEndpoint::new(to_protocol_address(address), scope)
        .map_err(|error| ScannerError::invalid("validate target", format!("{error:?}")))
}

fn parse_plain_address(value: &str, field: &str) -> Result<IpAddr, ScannerError> {
    value.parse::<IpAddr>().map_err(|_| {
        ScannerError::invalid(
            "validate address",
            format!("{field} is not an IPv4/IPv6 address"),
        )
    })
}

pub(crate) fn to_protocol_address(value: IpAddr) -> IpAddress {
    match value {
        IpAddr::V4(value) => IpAddress::V4(Ipv4Address::from(value)),
        IpAddr::V6(value) => IpAddress::V6(Ipv6Address::from(value)),
    }
}

pub(crate) fn to_std_address(value: IpAddress) -> IpAddr {
    match value {
        IpAddress::V4(value) => IpAddr::V4(value.into()),
        IpAddress::V6(value) => IpAddr::V6(value.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_plan(payload_bytes: usize) -> NativeScanPlan {
        NativeScanPlan {
            targets: vec![NativeScanTarget {
                cidr: Some("127.0.0.1/32".into()),
                start: None,
                end: None,
            }],
            exclude: None,
            probes: vec![NativeScanProbe {
                kind: "udp".into(),
                family: None,
                ports: Some(vec![NativePortSelection { start: 7, end: 7 }]),
                payload: Some(vec![0; payload_bytes]),
                udp_mode: None,
                udp_profile: None,
                udp_intensity: None,
                udp_strategy: None,
                udp_empty_fallback: None,
                udp_allow_risks: None,
                udp_correlation: None,
            }],
            deadline_ms: 1_000,
            rate: Some(NativeRateOptions {
                packets_per_second: Some(1),
                burst: Some(1),
                max_outstanding: Some(1),
            }),
            timing: None,
            seed: None,
            source_address: None,
            interface: None,
            vlan: None,
            source_port_start: None,
            source_port_end: None,
        }
    }

    fn validation_error(plan: NativeScanPlan) -> ScannerError {
        plan.validate().err().expect("plan must fail validation")
    }

    #[test]
    fn compact_plan_validation_rejects_implicit_or_reversed_inputs() {
        let empty = NativeScanPlan {
            targets: Vec::new(),
            exclude: None,
            probes: Vec::new(),
            deadline_ms: 1,
            rate: None,
            timing: None,
            seed: None,
            source_address: None,
            interface: None,
            vlan: None,
            source_port_start: None,
            source_port_end: None,
        };
        assert!(empty.validate().is_err());
        assert!(expand_ports(&[NativePortSelection { start: 2, end: 1 }]).is_err());
    }

    #[test]
    fn udp_payload_limit_accounts_for_every_ipv4_wire_header() {
        assert!(udp_plan(MAX_UDP_USER_PAYLOAD_BYTES).validate().is_ok());
        let error = udp_plan(MAX_UDP_USER_PAYLOAD_BYTES + 1)
            .validate()
            .err()
            .expect("oversized UDP payload must fail before session admission");
        assert_eq!(error.operation, "validate UDP payload");
    }

    #[test]
    fn udp_policy_normalizes_exact_and_legacy_programmes() {
        let legacy = udp_plan(3).validate().unwrap();
        assert_eq!(legacy.options.udp_program.ipv4.len(), 1);
        assert_eq!(
            legacy.options.udp_program.ipv4[0].correlation,
            UdpRequestCorrelation::PrefixToken
        );

        let mut exact = udp_plan(3);
        exact.probes[0].udp_mode = Some("custom".into());
        exact.probes[0].udp_correlation = Some("tuple".into());
        let exact = exact.validate().unwrap();
        assert_eq!(exact.options.udp_program.ipv4[0].payload, [0; 3]);
        assert_eq!(
            exact.options.udp_program.ipv4[0].correlation,
            UdpRequestCorrelation::Tuple
        );

        let mut empty = udp_plan(0);
        empty.probes[0].udp_mode = Some("empty".into());
        let empty = empty.validate().unwrap();
        assert!(empty.options.udp_program.ipv4[0].payload.is_empty());
        assert_eq!(
            empty.options.udp_program.ipv4[0].correlation,
            UdpRequestCorrelation::Tuple
        );
    }

    #[test]
    fn protocol_mode_is_normalized_and_duplicate_udp_definitions_fail_before_runtime() {
        let mut protocol = udp_plan(0);
        let probe = &mut protocol.probes[0];
        probe.udp_mode = Some("protocol".into());
        probe.udp_profile = Some("safe".into());
        probe.udp_intensity = Some(7);
        probe.udp_strategy = Some("exhaustive".into());
        probe.udp_empty_fallback = Some("unmapped".into());
        probe.udp_allow_risks = Some(Vec::new());
        let protocol = protocol.validate().expect("Phase 28 protocol scheduler");
        assert_eq!(protocol.options.udp_program.ipv4.len(), 10);
        assert_eq!(
            protocol.options.udp_program.ipv4[0].catalogue_probe_id,
            Some(1)
        );
        assert!(
            protocol.options.udp_program.ipv4[0]
                .catalogue_probe
                .is_some()
        );
        assert_eq!(protocol.options.result_schema_version, 2);

        let mut adaptive = udp_plan(0);
        adaptive.probes[0].udp_mode = Some("protocol".into());
        adaptive.probes[0].udp_strategy = Some("adaptive".into());
        let adaptive = adaptive.validate().expect("Phase 32 adaptive policy");
        assert_eq!(
            adaptive.options.udp_program.strategy,
            UdpProbeStrategy::Adaptive
        );
        assert_eq!(
            adaptive.options.udp_program.policy_mode.as_deref(),
            Some("protocol")
        );

        let mut duplicate = udp_plan(0);
        duplicate.probes.push(duplicate.probes[0].clone());
        let error = duplicate
            .validate()
            .err()
            .expect("duplicate UDP definitions must fail");
        assert_eq!(error.operation, "validate scan probes");
    }

    #[test]
    fn comprehensive_profile_and_each_risk_consent_are_independent() {
        let mut plan = udp_plan(0);
        let probe = &mut plan.probes[0];
        probe.udp_mode = Some("protocol".into());
        probe.udp_profile = Some("comprehensive".into());
        probe.udp_intensity = Some(7);
        probe.udp_empty_fallback = Some("unmapped".into());
        probe.udp_allow_risks = Some(Vec::new());
        let no_risks = plan.clone().validate().unwrap();
        let no_risk_ids: Vec<u16> = no_risks.options.udp_program.ipv4[..10]
            .iter()
            .filter_map(|request| request.catalogue_probe_id)
            .collect();
        assert_eq!(no_risk_ids, [1, 2, 3, 4, 5, 6, 7, 8, 9, 11]);

        plan.probes[0].udp_allow_risks = Some(vec!["sensitiveRead".into()]);
        let sensitive = plan.clone().validate().unwrap();
        let sensitive_ids: Vec<u16> = sensitive
            .options
            .udp_program
            .ipv4
            .iter()
            .filter_map(|request| request.catalogue_probe_id)
            .collect();
        assert!(sensitive_ids.contains(&10));
        assert!(sensitive_ids.contains(&12));
        assert!(!sensitive_ids.contains(&13));
        assert!(!sensitive_ids.contains(&14));
        assert!(!sensitive_ids.contains(&15));
        assert!(!sensitive_ids.contains(&16));

        plan.probes[0].udp_allow_risks = Some(vec![
            "highAmplification".into(),
            "statefulHandshake".into(),
            "fixedSourcePort".into(),
            "multicastOrBroadcast".into(),
            "authenticationAttempt".into(),
            "sensitiveRead".into(),
        ]);
        let all = plan.validate().unwrap();
        let all_ids: Vec<u16> = all
            .options
            .udp_program
            .ipv4
            .iter()
            .filter_map(|request| request.catalogue_probe_id)
            .collect();
        assert_eq!(
            all_ids,
            [
                (1_u16..=16).collect::<Vec<_>>(),
                (25_u16..=30).collect::<Vec<_>>(),
                vec![33, 36, 37],
            ]
            .concat()
        );

        let mut legacy = udp_plan(0);
        let probe = &mut legacy.probes[0];
        probe.udp_mode = Some("protocol".into());
        probe.udp_profile = Some("legacy".into());
        probe.udp_intensity = Some(9);
        probe.udp_empty_fallback = Some("never".into());
        probe.udp_allow_risks = Some(vec![
            "highAmplification".into(),
            "statefulHandshake".into(),
            "fixedSourcePort".into(),
            "multicastOrBroadcast".into(),
            "authenticationAttempt".into(),
            "sensitiveRead".into(),
        ]);
        let legacy = legacy.validate().unwrap();
        let legacy_ids: Vec<u16> = legacy
            .options
            .udp_program
            .ipv4
            .iter()
            .filter_map(|request| request.catalogue_probe_id)
            .collect();
        assert_eq!(legacy_ids, (1_u16..=37).collect::<Vec<_>>());
        assert!(matches!(
            legacy.options.udp_program.ipv4[25].eligibility,
            UdpVariantEligibility::DestinationPortRange { start, end }
                if start.get() == 19_132 && end.get() == 19_133
        ));
    }

    #[test]
    fn risky_profiles_cannot_weaken_safe_mode_or_bypass_target_prerequisites() {
        let mut safe_with_every_consent = udp_plan(0);
        let probe = &mut safe_with_every_consent.probes[0];
        probe.udp_mode = Some("protocol".into());
        probe.udp_profile = Some("safe".into());
        probe.udp_intensity = Some(9);
        probe.udp_allow_risks = Some(vec![
            "highAmplification".into(),
            "statefulHandshake".into(),
            "fixedSourcePort".into(),
            "multicastOrBroadcast".into(),
            "authenticationAttempt".into(),
            "sensitiveRead".into(),
        ]);
        let safe = safe_with_every_consent.validate().unwrap();
        assert_eq!(
            safe.options
                .udp_program
                .ipv4
                .iter()
                .filter(|request| request.catalogue_probe_id.is_some())
                .count(),
            9
        );

        let mut multicast = udp_plan(0);
        multicast.targets[0].cidr = Some("224.0.0.251/32".into());
        multicast.probes[0].udp_mode = Some("protocol".into());
        multicast.probes[0].udp_allow_risks = Some(Vec::new());
        assert_eq!(
            validation_error(multicast.clone()).operation,
            "validate UDP targets"
        );
        multicast.probes[0].udp_allow_risks = Some(vec!["multicastOrBroadcast".into()]);
        assert_eq!(
            validation_error(multicast.clone()).operation,
            "validate UDP targets"
        );
        multicast.interface = Some("fixture0".into());
        assert!(multicast.validate().is_ok());
    }

    #[test]
    fn stateful_probe_lifetime_and_canonical_risks_are_admission_gates() {
        let mut plan = udp_plan(0);
        let probe = &mut plan.probes[0];
        probe.udp_mode = Some("protocol".into());
        probe.udp_profile = Some("comprehensive".into());
        probe.udp_intensity = Some(7);
        probe.udp_allow_risks = Some(vec!["statefulHandshake".into()]);
        plan.timing = Some(NativeTimingOptions {
            timeout_ms: Some(1_000),
            minimum_timeout_ms: Some(100),
            maximum_timeout_ms: Some(10_001),
            retries: Some(0),
            fixed: Some(true),
        });
        assert_eq!(
            validation_error(plan.clone()).operation,
            "validate UDP timing"
        );
        plan.timing.as_mut().unwrap().maximum_timeout_ms = Some(10_000);
        assert!(plan.validate().is_ok());

        let mut duplicate = udp_plan(0);
        duplicate.probes[0].udp_mode = Some("protocol".into());
        duplicate.probes[0].udp_allow_risks =
            Some(vec!["sensitiveRead".into(), "sensitiveRead".into()]);
        assert_eq!(validation_error(duplicate).operation, "validate UDP policy");
    }

    #[test]
    fn source_port_capacity_is_validated_before_runtime_admission() {
        let mut plan = udp_plan(0);
        plan.source_port_start = Some(60_000);
        plan.source_port_end = Some(60_004);
        assert!(plan.clone().validate().is_ok());
        plan.rate.as_mut().unwrap().max_outstanding = Some(2);
        let error = plan
            .validate()
            .err()
            .expect("five ports cannot provide two ports to each of four sessions");
        assert_eq!(error.operation, "validate source port range");
    }

    #[test]
    fn discovery_scope_risks_and_operation_parameters_fail_before_transport() {
        let plan = NativeDiscoveryPlan {
            scope: NativeDiscoveryScope {
                kind: "targets".into(),
                interfaces: None,
                all_eligible: None,
                families: vec!["ipv4".into()],
                targets: Some(vec![NativeScanTarget {
                    cidr: Some("127.0.0.1/32".into()),
                    start: None,
                    end: None,
                }]),
                exclude: None,
                kernel_default_ipv4_gateway: None,
            },
            operations: vec![NativeDiscoveryOperation {
                id: 5,
                query: None,
                follow_up: None,
                receive_mode: None,
            }],
            deadline_ms: 100,
            limits: None,
            rate: None,
            allow_risks: Some(vec!["sensitiveRead".into()]),
        };
        assert!(plan.clone().validate().is_ok());

        let mut missing_risk = plan.clone();
        missing_risk.allow_risks = Some(Vec::new());
        assert_eq!(
            missing_risk.validate().unwrap_err().operation,
            "validate discovery operation"
        );

        let mut wrong_parameter = plan.clone();
        wrong_parameter.operations[0].query = Some("unexpected".into());
        assert_eq!(
            wrong_parameter.validate().unwrap_err().operation,
            "validate discovery operation"
        );

        let mut wrong_follow_up = plan.clone();
        wrong_follow_up.operations[0].follow_up = Some(false);
        assert_eq!(
            wrong_follow_up.validate().unwrap_err().operation,
            "validate discovery operation"
        );

        let mut wrong_scope = plan;
        wrong_scope.operations[0].id = 1;
        wrong_scope.operations[0].receive_mode = Some("legacyUnicast".into());
        wrong_scope.allow_risks = Some(vec!["multicastOrBroadcast".into(), "sensitiveRead".into()]);
        assert_eq!(
            wrong_scope.validate().unwrap_err().operation,
            "validate discovery scope"
        );
    }
}
