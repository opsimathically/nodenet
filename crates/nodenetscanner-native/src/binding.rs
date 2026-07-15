use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use napi::bindgen_prelude::{AsyncTask, Env, Function};
use napi::threadsafe_function::{
    ThreadsafeCallContext, ThreadsafeFunction, ThreadsafeFunctionCallMode,
};
use napi::{Result, Status, Task};
use napi_derive::napi;
use nodenet_linux_context::{NetworkSnapshot, RouteContext};
use nodenet_protocols::{
    DISCOVERY_OPERATION_REGISTRY, DISCOVERY_OPERATION_REGISTRY_VERSION, UDP_PROBE_CATALOGUE,
    UDP_PROBE_CATALOGUE_VERSION, discovery_operation_registry_sha256_hex,
    udp_probe_catalogue_sha256_hex,
};

use crate::discovery_session::{
    DiscoveryControl, NativeDiscoveryProgress, NativeDiscoveryRun, run_discovery,
};
use crate::error::ScannerError;
use crate::model::{DEFAULT_BATCH_RESULTS, MAX_BATCH_RESULTS, NativeDiscoveryPlan, NativeScanPlan};
use crate::runtime::{Command, RuntimeHandle};
use crate::session::{NativePullResult, NativeScanProgress, NativeScanSummary, PullResult};

struct EnvironmentRuntime {
    runtime: Arc<RuntimeHandle>,
}

#[napi(object)]
pub struct NativeNetworkInterface {
    pub index: u32,
    pub name: String,
    pub flags: u32,
    pub link_layer_type: u32,
    pub mtu: Option<u32>,
    pub hardware_address: Vec<u8>,
    pub link_kind: Option<String>,
}

#[napi(object)]
pub struct NativeNetworkAddress {
    pub interface_index: u32,
    pub family: u32,
    pub prefix_length: u32,
    pub address: Option<String>,
    pub local: Option<String>,
}

#[napi(object)]
pub struct NativeNetworkRoute {
    pub family: u32,
    pub destination: Option<String>,
    pub prefix_length: u32,
    pub gateway: Option<String>,
    pub preferred_source: Option<String>,
    pub interface_index: Option<u32>,
    pub table: u32,
    pub route_type: u32,
}

#[napi(object)]
pub struct NativeNetworkContextSnapshot {
    pub generation: String,
    pub netns_cookie: Option<String>,
    pub interfaces: Vec<NativeNetworkInterface>,
    pub addresses: Vec<NativeNetworkAddress>,
    pub routes: Vec<NativeNetworkRoute>,
    pub rule_count: u32,
    pub neighbor_count: u32,
}

#[napi(object)]
pub struct NativeUdpProbeCatalogueCapabilities {
    pub version: String,
    pub sha256: String,
    pub variants: u32,
}

#[napi(object)]
pub struct NativeDiscoveryOperationCapability {
    pub id: u32,
    pub name: String,
    pub scope: String,
    pub families: Vec<String>,
    pub destination_port: u32,
    pub required_risks: Vec<String>,
    pub maximum_request_bytes: u32,
    pub maximum_response_bytes: u32,
    pub maximum_entities_per_query: u32,
    pub maximum_metadata_bytes_per_query: u32,
    pub response_window_ms: u32,
    pub supports_follow_up: bool,
    pub receive_modes: Vec<String>,
}

#[napi(object)]
pub struct NativeDiscoveryCapabilities {
    pub registry_version: String,
    pub registry_sha256: String,
    pub schema_version: u32,
    pub max_sessions: u32,
    pub max_results: u32,
    pub max_metadata_bytes: u32,
    pub max_sockets: u32,
    pub max_physical_queries: u32,
    pub operations: Vec<NativeDiscoveryOperationCapability>,
    pub no_go: Vec<String>,
}

#[napi(object)]
pub struct NativeDiscoveryFailure {
    pub kind: String,
    pub code: String,
    pub operation: String,
    pub errno: Option<i32>,
    pub message: String,
}

impl From<ScannerError> for NativeDiscoveryFailure {
    fn from(error: ScannerError) -> Self {
        Self {
            kind: error.kind.into(),
            code: error.code.into(),
            operation: error.operation.into(),
            errno: error.errno,
            message: error.message,
        }
    }
}

struct DiscoveryCompletion(std::result::Result<NativeDiscoveryRun, ScannerError>);

#[napi(object)]
pub struct NativeDiscoveryCompletion {
    pub run: Option<NativeDiscoveryRun>,
    pub error: Option<NativeDiscoveryFailure>,
}

impl From<DiscoveryCompletion> for NativeDiscoveryCompletion {
    fn from(completion: DiscoveryCompletion) -> Self {
        match completion.0 {
            Ok(run) => Self {
                run: Some(run),
                error: None,
            },
            Err(error) => Self {
                run: None,
                error: Some(error.into()),
            },
        }
    }
}

const DISCOVERY_COMPLETION_QUEUE_CAPACITY: usize = 1;
type DiscoveryCompletionFunction = ThreadsafeFunction<
    DiscoveryCompletion,
    (),
    NativeDiscoveryCompletion,
    Status,
    false,
    false,
    DISCOVERY_COMPLETION_QUEUE_CAPACITY,
>;

#[napi]
pub struct NativeScanner {
    runtime: Arc<RuntimeHandle>,
    id: u32,
    next_discovery_id: AtomicU32,
    discoveries: Arc<Mutex<HashMap<u32, Arc<DiscoveryControl>>>>,
}

#[napi]
impl NativeScanner {
    #[napi]
    pub fn ready(&self) -> AsyncTask<ReadyTask> {
        AsyncTask::new(ReadyTask {
            runtime: Arc::clone(&self.runtime),
            scanner_id: self.id,
        })
    }

    #[napi]
    pub fn start(&self, plan: NativeScanPlan) -> AsyncTask<StartTask> {
        AsyncTask::new(StartTask {
            runtime: Arc::clone(&self.runtime),
            scanner_id: self.id,
            plan: Some(plan),
        })
    }

    #[napi]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "napi-rs owns the JavaScript callback while constructing its threadsafe function"
    )]
    pub fn discover(
        &self,
        plan: NativeDiscoveryPlan,
        discovery_id: u32,
        callback: Function<'_, NativeDiscoveryCompletion, ()>,
    ) -> Result<()> {
        let plan = plan.validate().map_err(ScannerError::into_napi)?;
        if discovery_id == 0 {
            return Err(ScannerError::invalid(
                "start discovery session",
                "discovery identifier must be nonzero",
            )
            .into_napi());
        }
        let expected = self.next_discovery_id.fetch_add(1, Ordering::AcqRel);
        if expected != discovery_id || expected == 0 {
            return Err(ScannerError::resource(
                "start discovery session",
                "discovery identifiers must increase and may not be reused",
            )
            .into_napi());
        }
        let completion: DiscoveryCompletionFunction = callback
            .build_threadsafe_function::<DiscoveryCompletion>()
            .callee_handled::<false>()
            .max_queue_size::<DISCOVERY_COMPLETION_QUEUE_CAPACITY>()
            .build_callback(|context: ThreadsafeCallContext<DiscoveryCompletion>| {
                Ok(NativeDiscoveryCompletion::from(context.value))
            })?;
        let permit = self
            .runtime
            .admit_external_discovery(plan.limits.max_metadata_bytes)
            .map_err(ScannerError::into_napi)?;
        let control = Arc::new(DiscoveryControl::new());
        lock(&self.discoveries).insert(discovery_id, Arc::clone(&control));
        let discoveries = Arc::clone(&self.discoveries);
        let thread_control = Arc::clone(&control);
        let spawn = thread::Builder::new()
            .name(format!("nodenetscanner-discovery-{discovery_id}"))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_discovery(plan, &thread_control)
                }))
                .unwrap_or_else(|_| {
                    Err(ScannerError::internal(
                        "run discovery session",
                        "native discovery worker panicked",
                    ))
                });
                lock(&discoveries).remove(&discovery_id);
                let status = completion.call(
                    DiscoveryCompletion(result),
                    ThreadsafeFunctionCallMode::Blocking,
                );
                debug_assert!(matches!(status, Status::Ok | Status::Closing));
                drop(permit);
            });
        if let Err(error) = spawn {
            lock(&self.discoveries).remove(&discovery_id);
            return Err(ScannerError::internal(
                "start discovery session",
                format!("failed to spawn discovery worker: {error}"),
            )
            .into_napi());
        }
        Ok(())
    }

    #[napi]
    pub fn pause_discovery(&self, discovery_id: u32) -> Result<()> {
        discovery_control(&self.discoveries, discovery_id)?
            .pause()
            .map_err(ScannerError::into_napi)
    }

    #[napi]
    pub fn resume_discovery(&self, discovery_id: u32) -> Result<()> {
        discovery_control(&self.discoveries, discovery_id)?
            .resume()
            .map_err(ScannerError::into_napi)
    }

    #[napi]
    pub fn cancel_discovery(&self, discovery_id: u32) -> Result<()> {
        discovery_control(&self.discoveries, discovery_id)?.cancel();
        Ok(())
    }

    #[napi]
    pub fn discovery_state(&self, discovery_id: u32) -> Result<String> {
        Ok(discovery_control(&self.discoveries, discovery_id)?
            .state_name()
            .into())
    }

    #[napi]
    pub fn discovery_progress(&self, discovery_id: u32) -> Result<NativeDiscoveryProgress> {
        Ok(discovery_control(&self.discoveries, discovery_id)?.progress())
    }

    #[napi]
    pub fn pause(&self, session_id: u32) -> AsyncTask<PauseTask> {
        AsyncTask::new(PauseTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn resume(&self, session_id: u32) -> AsyncTask<ResumeTask> {
        AsyncTask::new(ResumeTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn cancel(&self, session_id: u32) -> AsyncTask<CancelTask> {
        AsyncTask::new(CancelTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn next_batch(
        &self,
        session_id: u32,
        pull_id: u32,
        maximum: Option<u32>,
    ) -> Result<AsyncTask<PullTask>> {
        let maximum = maximum.unwrap_or(DEFAULT_BATCH_RESULTS);
        if maximum == 0 || maximum > MAX_BATCH_RESULTS {
            return Err(ScannerError::invalid(
                "pull result batch",
                "maxResults must be from 1 through 4096",
            )
            .into_napi());
        }
        Ok(AsyncTask::new(PullTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
            pull_id,
            maximum: usize::try_from(maximum).unwrap_or(usize::MAX),
        }))
    }

    #[napi]
    pub fn cancel_pull(&self, session_id: u32, pull_id: u32) -> AsyncTask<CancelPullTask> {
        AsyncTask::new(CancelPullTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
            pull_id,
        })
    }

    #[napi]
    pub fn progress(&self, session_id: u32) -> AsyncTask<ProgressTask> {
        AsyncTask::new(ProgressTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn summary(&self, session_id: u32) -> AsyncTask<SummaryTask> {
        AsyncTask::new(SummaryTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn close_session(&self, session_id: u32) -> AsyncTask<CloseSessionTask> {
        AsyncTask::new(CloseSessionTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn state(&self, session_id: u32) -> Result<String> {
        self.runtime
            .state(session_id)
            .map_err(ScannerError::into_napi)
    }

    #[napi]
    pub fn close(&self) -> AsyncTask<CloseScannerTask> {
        for control in lock(&self.discoveries).values() {
            control.cancel();
        }
        AsyncTask::new(CloseScannerTask {
            runtime: Arc::clone(&self.runtime),
            scanner_id: self.id,
        })
    }
}

impl Drop for NativeScanner {
    fn drop(&mut self) {
        for control in lock(&self.discoveries).values() {
            control.cancel();
        }
        self.runtime.close_scanner_background(self.id);
    }
}

#[napi]
pub fn create_native_scanner(env: Env) -> Result<NativeScanner> {
    let runtime = environment_runtime(env)?;
    let id = runtime
        .allocate_scanner_id()
        .map_err(ScannerError::into_napi)?;
    Ok(NativeScanner {
        runtime,
        id,
        next_discovery_id: AtomicU32::new(1),
        discoveries: Arc::new(Mutex::new(HashMap::new())),
    })
}

#[napi]
pub fn inspect_network_context() -> AsyncTask<InspectTask> {
    AsyncTask::new(InspectTask)
}

#[napi]
pub fn udp_probe_catalogue_capabilities() -> NativeUdpProbeCatalogueCapabilities {
    NativeUdpProbeCatalogueCapabilities {
        version: UDP_PROBE_CATALOGUE_VERSION.into(),
        sha256: udp_probe_catalogue_sha256_hex(UDP_PROBE_CATALOGUE),
        variants: u32::try_from(UDP_PROBE_CATALOGUE.len()).unwrap_or(u32::MAX),
    }
}

#[napi]
pub fn discovery_capabilities() -> NativeDiscoveryCapabilities {
    NativeDiscoveryCapabilities {
        registry_version: DISCOVERY_OPERATION_REGISTRY_VERSION.into(),
        registry_sha256: discovery_operation_registry_sha256_hex(DISCOVERY_OPERATION_REGISTRY),
        schema_version: 1,
        max_sessions: 4,
        max_results: 8_192,
        max_metadata_bytes: 16 * 1_024 * 1_024,
        max_sockets: 256,
        max_physical_queries: 1_024,
        operations: DISCOVERY_OPERATION_REGISTRY
            .iter()
            .map(|operation| NativeDiscoveryOperationCapability {
                id: u32::from(operation.id.get()),
                name: operation.name.into(),
                scope: format!("{:?}", operation.scope),
                families: match operation.families {
                    nodenet_protocols::UdpAddressFamilies::Ipv4 => vec!["ipv4".into()],
                    nodenet_protocols::UdpAddressFamilies::Ipv6 => vec!["ipv6".into()],
                    nodenet_protocols::UdpAddressFamilies::Both => {
                        vec!["ipv4".into(), "ipv6".into()]
                    }
                },
                destination_port: u32::from(operation.destination_port),
                required_risks: risk_names(operation.required_risks),
                maximum_request_bytes: u32::try_from(operation.maximum_request_bytes)
                    .unwrap_or(u32::MAX),
                maximum_response_bytes: u32::try_from(operation.maximum_response_bytes)
                    .unwrap_or(u32::MAX),
                maximum_entities_per_query: u32::from(operation.maximum_entities_per_query),
                maximum_metadata_bytes_per_query: operation.maximum_metadata_bytes_per_query,
                response_window_ms: operation.response_window_ms,
                supports_follow_up: operation.id.get() == 7,
                receive_modes: if operation.id.get() == 1 {
                    vec!["legacyUnicast".into()]
                } else {
                    Vec::new()
                },
            })
            .collect(),
        no_go: vec![
            "mdns-full-port-5353-browse".into(),
            "kerberos".into(),
            "ikev1".into(),
            "ikev2".into(),
            "dtls".into(),
            "dhcpv4-inform-host-namespace".into(),
            "dhcpv6-information-request-host-namespace".into(),
            "gtp".into(),
            "mqtt-sn".into(),
            "beckhoff-ads".into(),
            "omron-fins".into(),
            "teamspeak-discovery".into(),
            "mumble-discovery".into(),
            "quake-family-discovery".into(),
            "cldap".into(),
            "openvpn".into(),
            "radius".into(),
            "ubiquiti-discovery".into(),
            "pcanywhere".into(),
            "wireguard".into(),
        ],
    }
}

fn risk_names(risks: nodenet_protocols::UdpProbeRiskSet) -> Vec<String> {
    [
        (
            nodenet_protocols::UdpProbeRisk::HighAmplification,
            "highAmplification",
        ),
        (
            nodenet_protocols::UdpProbeRisk::StatefulHandshake,
            "statefulHandshake",
        ),
        (
            nodenet_protocols::UdpProbeRisk::FixedSourcePort,
            "fixedSourcePort",
        ),
        (
            nodenet_protocols::UdpProbeRisk::MulticastOrBroadcast,
            "multicastOrBroadcast",
        ),
        (
            nodenet_protocols::UdpProbeRisk::AuthenticationAttempt,
            "authenticationAttempt",
        ),
        (
            nodenet_protocols::UdpProbeRisk::SensitiveRead,
            "sensitiveRead",
        ),
    ]
    .into_iter()
    .filter(|(risk, _)| risks.contains(*risk))
    .map(|(_, name)| name.into())
    .collect()
}

fn discovery_control(
    discoveries: &Mutex<HashMap<u32, Arc<DiscoveryControl>>>,
    discovery_id: u32,
) -> Result<Arc<DiscoveryControl>> {
    lock(discoveries)
        .get(&discovery_id)
        .cloned()
        .ok_or_else(|| {
            ScannerError::lifecycle("control discovery", "unknown discovery session").into_napi()
        })
}

fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub struct InspectTask;

impl Task for InspectTask {
    type Output = NativeNetworkContextSnapshot;
    type JsValue = NativeNetworkContextSnapshot;

    fn compute(&mut self) -> Result<Self::Output> {
        let mut context = RouteContext::new().map_err(|error| {
            ScannerError::context("inspect network context", error.to_string()).into_napi()
        })?;
        let snapshot = context.snapshot().map_err(|error| {
            ScannerError::context("inspect network context", error.to_string()).into_napi()
        })?;
        Ok(native_snapshot(snapshot))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct ReadyTask {
    runtime: Arc<RuntimeHandle>,
    scanner_id: u32,
}

impl Task for ReadyTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::RegisterScanner {
                scanner_id: self.scanner_id,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct StartTask {
    runtime: Arc<RuntimeHandle>,
    scanner_id: u32,
    plan: Option<NativeScanPlan>,
}

impl Task for StartTask {
    type Output = u32;
    type JsValue = u32;

    fn compute(&mut self) -> Result<Self::Output> {
        let plan = self
            .plan
            .take()
            .ok_or_else(|| {
                ScannerError::internal("start session", "scan plan already consumed").into_napi()
            })?
            .validate()
            .map_err(ScannerError::into_napi)?;
        self.runtime
            .request(|reply| Command::Start {
                scanner_id: self.scanner_id,
                plan: Box::new(plan),
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

macro_rules! unit_task {
    ($name:ident, $variant:ident) => {
        pub struct $name {
            runtime: Arc<RuntimeHandle>,
            session_id: u32,
        }

        impl Task for $name {
            type Output = ();
            type JsValue = ();

            fn compute(&mut self) -> Result<Self::Output> {
                self.runtime
                    .request(|reply| Command::$variant {
                        session_id: self.session_id,
                        reply,
                    })
                    .map_err(ScannerError::into_napi)
            }

            fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
                Ok(output)
            }
        }
    };
}

unit_task!(PauseTask, Pause);
unit_task!(ResumeTask, Resume);
unit_task!(CloseSessionTask, CloseSession);

pub struct CancelTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
}

impl Task for CancelTask {
    type Output = NativeScanSummary;
    type JsValue = NativeScanSummary;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::Cancel {
                session_id: self.session_id,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct SummaryTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
}

impl Task for SummaryTask {
    type Output = NativeScanSummary;
    type JsValue = NativeScanSummary;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::Summary {
                session_id: self.session_id,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct PullTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
    pull_id: u32,
    maximum: usize,
}

impl Task for PullTask {
    type Output = PullResult;
    type JsValue = NativePullResult;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::Pull {
                session_id: self.session_id,
                pull_id: self.pull_id,
                maximum: self.maximum,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(NativePullResult::from_pull(output))
    }
}

pub struct CancelPullTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
    pull_id: u32,
}

impl Task for CancelPullTask {
    type Output = bool;
    type JsValue = bool;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request_pull_cancellation(self.session_id, self.pull_id)
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct ProgressTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
}

impl Task for ProgressTask {
    type Output = NativeScanProgress;
    type JsValue = NativeScanProgress;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::Progress {
                session_id: self.session_id,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct CloseScannerTask {
    runtime: Arc<RuntimeHandle>,
    scanner_id: u32,
}

impl Task for CloseScannerTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::CloseScanner {
                scanner_id: self.scanner_id,
                reply: Some(reply),
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

fn environment_runtime(env: Env) -> Result<Arc<RuntimeHandle>> {
    if let Some(instance) = env.get_instance_data::<EnvironmentRuntime>()? {
        return Ok(Arc::clone(&instance.runtime));
    }
    let runtime = RuntimeHandle::start().map_err(ScannerError::into_napi)?;
    env.add_async_cleanup_hook(Arc::clone(&runtime), |runtime| {
        runtime.shutdown_and_join();
    })?;
    env.set_instance_data(
        EnvironmentRuntime {
            runtime: Arc::clone(&runtime),
        },
        (),
        |context| context.value.runtime.shutdown_and_join(),
    )?;
    Ok(runtime)
}

fn native_snapshot(snapshot: NetworkSnapshot) -> NativeNetworkContextSnapshot {
    NativeNetworkContextSnapshot {
        generation: snapshot.generation.to_string(),
        netns_cookie: snapshot.netns_cookie.map(|value| value.to_string()),
        interfaces: snapshot
            .interfaces
            .into_iter()
            .map(|value| NativeNetworkInterface {
                index: value.index,
                name: value.name,
                flags: value.flags,
                link_layer_type: u32::from(value.link_layer_type),
                mtu: value.mtu,
                hardware_address: value.hardware_address,
                link_kind: value.link_kind,
            })
            .collect(),
        addresses: snapshot
            .addresses
            .into_iter()
            .map(|value| NativeNetworkAddress {
                interface_index: value.interface_index,
                family: u32::from(value.family),
                prefix_length: u32::from(value.prefix_length),
                address: value.address.map(|address| address.to_string()),
                local: value.local.map(|address| address.to_string()),
            })
            .collect(),
        routes: snapshot
            .routes
            .into_iter()
            .map(|value| NativeNetworkRoute {
                family: u32::from(value.family),
                destination: value.destination.map(|address| address.to_string()),
                prefix_length: u32::from(value.destination_prefix_length),
                gateway: value.gateway.map(|address| address.to_string()),
                preferred_source: value.preferred_source.map(|address| address.to_string()),
                interface_index: value.output_interface,
                table: value.table,
                route_type: u32::from(value.route_type),
            })
            .collect(),
        rule_count: u32::try_from(snapshot.rules.len()).unwrap_or(u32::MAX),
        neighbor_count: u32::try_from(snapshot.neighbors.len()).unwrap_or(u32::MAX),
    }
}
