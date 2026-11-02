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
    DISCOVERY_OPERATION_REGISTRY, DISCOVERY_OPERATION_REGISTRY_VERSION, SERVICE_REGISTRY,
    SERVICE_REGISTRY_VERSION, ServiceDisposition, ServiceRisk, UDP_COVERAGE_REGISTRY,
    UDP_COVERAGE_REGISTRY_VERSION, UDP_COVERAGE_RESOURCE_CONTRACT, UDP_PROBE_CATALOGUE,
    UDP_PROBE_CATALOGUE_VERSION, UdpCoverageDimension, UdpCoverageDisposition,
    UdpCoverageExecutionModel, UdpCoveragePolicy, UdpCoverageRisk,
    discovery_operation_registry_sha256_hex, udp_probe_catalogue_sha256_hex,
};

use crate::discovery_session::{
    DiscoveryControl, NativeDiscoveryProgress, NativeDiscoveryRun, run_discovery,
};
use crate::error::ScannerError;
use crate::model::{DEFAULT_BATCH_RESULTS, MAX_BATCH_RESULTS, NativeDiscoveryPlan, NativeScanPlan};
use crate::observation::{
    NativeObservationBatch, NativeObservationPlan, NativeObservationProgress, NativeObservationRun,
    ObservationControl, run_observation,
};
use crate::path_trace::{
    NativePathPlan, NativePathRun, PATH_RESERVATION_BYTES, PathControl, run as run_path,
};
use crate::router_solicitation::{
    NativeRouterSolicitationPlan, NativeRouterSolicitationRun,
    ROUTER_SOLICITATION_RESERVATION_BYTES, RouterSolicitationControl,
    run as run_router_solicitation,
};
use crate::runtime::{Command, RuntimeHandle};
use crate::service_conversation::{
    CONVERSATION_RESERVATION_BYTES, NativeServiceIdentificationPlan,
    NativeServiceIdentificationRun, ServiceControl, run as run_service_conversation,
};
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
pub struct NativeNetworkRule {
    pub family: u32,
    pub destination: Option<String>,
    pub destination_prefix_length: u32,
    pub source: Option<String>,
    pub source_prefix_length: u32,
    pub table: u32,
    pub action: u32,
    pub priority: Option<u32>,
    pub input_interface: Option<String>,
    pub output_interface: Option<String>,
    pub firewall_mark: Option<u32>,
    pub firewall_mask: Option<u32>,
    pub ip_protocol: Option<u32>,
}

#[napi(object)]
pub struct NativeNetworkNeighbor {
    pub family: u32,
    pub interface_index: u32,
    pub destination: Option<String>,
    pub state: u32,
    pub flags: u32,
    pub neighbor_type: u32,
    pub link_layer_address: Vec<u8>,
    pub probes: Option<u32>,
}

#[napi(object)]
pub struct NativeNetworkContextSnapshot {
    pub generation: String,
    pub netns_cookie: Option<String>,
    pub interfaces: Vec<NativeNetworkInterface>,
    pub addresses: Vec<NativeNetworkAddress>,
    pub routes: Vec<NativeNetworkRoute>,
    pub rules: Vec<NativeNetworkRule>,
    pub neighbors: Vec<NativeNetworkNeighbor>,
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
pub struct NativeUdpCoverageEntry {
    pub id: u32,
    pub project_id: String,
    pub phase: u32,
    pub family: String,
    pub disposition: String,
    pub execution_model: String,
    pub policy: String,
    pub risks: Vec<String>,
    pub required_consents: Vec<String>,
    pub dimensions: Vec<String>,
    pub implementation_kind: Option<String>,
    pub implementation_id: Option<u32>,
    pub primary_source_url: String,
    pub rationale: String,
}

#[napi(object)]
pub struct NativeUdpCoverageCapabilities {
    pub version: String,
    pub maximum_candidates: u32,
    pub maximum_compiled_variants: u32,
    pub maximum_physical_queries: u32,
    pub maximum_response_bytes: u32,
    pub maximum_metadata_bytes: u32,
    pub maximum_returned_endpoints: u32,
    pub maximum_state_lifetime_ms: u32,
    pub entries: Vec<NativeUdpCoverageEntry>,
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

struct ObservationCompletion(std::result::Result<NativeObservationRun, ScannerError>);

#[napi(object)]
pub struct NativeObservationCompletion {
    pub run: Option<NativeObservationRun>,
    pub error: Option<NativeDiscoveryFailure>,
}

impl From<ObservationCompletion> for NativeObservationCompletion {
    fn from(completion: ObservationCompletion) -> Self {
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

const OBSERVATION_COMPLETION_QUEUE_CAPACITY: usize = 1;
type ObservationCompletionFunction = ThreadsafeFunction<
    ObservationCompletion,
    (),
    NativeObservationCompletion,
    Status,
    false,
    false,
    OBSERVATION_COMPLETION_QUEUE_CAPACITY,
>;

struct RouterSolicitationCompletion(std::result::Result<NativeRouterSolicitationRun, ScannerError>);

#[napi(object)]
pub struct NativeRouterSolicitationCompletion {
    pub run: Option<NativeRouterSolicitationRun>,
    pub error: Option<NativeDiscoveryFailure>,
}

impl From<RouterSolicitationCompletion> for NativeRouterSolicitationCompletion {
    fn from(completion: RouterSolicitationCompletion) -> Self {
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

const ROUTER_SOLICITATION_COMPLETION_QUEUE_CAPACITY: usize = 1;
type RouterSolicitationCompletionFunction = ThreadsafeFunction<
    RouterSolicitationCompletion,
    (),
    NativeRouterSolicitationCompletion,
    Status,
    false,
    false,
    ROUTER_SOLICITATION_COMPLETION_QUEUE_CAPACITY,
>;

struct PathCompletion(std::result::Result<NativePathRun, ScannerError>);

#[napi(object)]
pub struct NativePathCompletion {
    pub run: Option<NativePathRun>,
    pub error: Option<NativeDiscoveryFailure>,
}

impl From<PathCompletion> for NativePathCompletion {
    fn from(completion: PathCompletion) -> Self {
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

const PATH_COMPLETION_QUEUE_CAPACITY: usize = 1;
type PathCompletionFunction = ThreadsafeFunction<
    PathCompletion,
    (),
    NativePathCompletion,
    Status,
    false,
    false,
    PATH_COMPLETION_QUEUE_CAPACITY,
>;

struct ServiceCompletion(std::result::Result<NativeServiceIdentificationRun, ScannerError>);

#[napi(object)]
pub struct NativeServiceCompletion {
    pub run: Option<NativeServiceIdentificationRun>,
    pub error: Option<NativeDiscoveryFailure>,
}

impl From<ServiceCompletion> for NativeServiceCompletion {
    fn from(completion: ServiceCompletion) -> Self {
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

const SERVICE_COMPLETION_QUEUE_CAPACITY: usize = 1;
type ServiceCompletionFunction = ThreadsafeFunction<
    ServiceCompletion,
    (),
    NativeServiceCompletion,
    Status,
    false,
    false,
    SERVICE_COMPLETION_QUEUE_CAPACITY,
>;

#[napi]
pub struct NativeScanner {
    runtime: Arc<RuntimeHandle>,
    id: u32,
    next_discovery_id: AtomicU32,
    discoveries: Arc<Mutex<HashMap<u32, Arc<DiscoveryControl>>>>,
    next_observation_id: AtomicU32,
    observations: Arc<Mutex<HashMap<u32, Arc<ObservationControl>>>>,
    next_router_solicitation_id: AtomicU32,
    router_solicitations: Arc<Mutex<HashMap<u32, Arc<RouterSolicitationControl>>>>,
    next_path_id: AtomicU32,
    paths: Arc<Mutex<HashMap<u32, Arc<PathControl>>>>,
    next_service_id: AtomicU32,
    services: Arc<Mutex<HashMap<u32, Arc<ServiceControl>>>>,
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
    #[allow(
        clippy::needless_pass_by_value,
        reason = "napi-rs owns the JavaScript callback while constructing its threadsafe function"
    )]
    pub fn solicit_routers(
        &self,
        plan: NativeRouterSolicitationPlan,
        solicitation_id: u32,
        callback: Function<'_, NativeRouterSolicitationCompletion, ()>,
    ) -> Result<()> {
        let plan = plan.validate().map_err(ScannerError::into_napi)?;
        if solicitation_id == 0 {
            return Err(ScannerError::invalid(
                "start router solicitation",
                "router solicitation identifier must be nonzero",
            )
            .into_napi());
        }
        let expected = self
            .next_router_solicitation_id
            .fetch_add(1, Ordering::AcqRel);
        if expected != solicitation_id || expected == 0 {
            return Err(ScannerError::resource(
                "start router solicitation",
                "router solicitation identifiers must increase and may not be reused",
            )
            .into_napi());
        }
        let completion: RouterSolicitationCompletionFunction = callback
            .build_threadsafe_function::<RouterSolicitationCompletion>()
            .callee_handled::<false>()
            .max_queue_size::<ROUTER_SOLICITATION_COMPLETION_QUEUE_CAPACITY>()
            .build_callback(
                |context: ThreadsafeCallContext<RouterSolicitationCompletion>| {
                    Ok(NativeRouterSolicitationCompletion::from(context.value))
                },
            )?;
        let permit = self
            .runtime
            .admit_external_session(
                ROUTER_SOLICITATION_RESERVATION_BYTES,
                "start router solicitation",
            )
            .map_err(ScannerError::into_napi)?;
        let control = Arc::new(RouterSolicitationControl::new());
        lock(&self.router_solicitations).insert(solicitation_id, Arc::clone(&control));
        let solicitations = Arc::clone(&self.router_solicitations);
        let thread_control = Arc::clone(&control);
        let spawn = thread::Builder::new()
            .name(format!(
                "nodenetscanner-router-solicitation-{solicitation_id}"
            ))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_router_solicitation(plan, &thread_control)
                }))
                .unwrap_or_else(|_| {
                    Err(ScannerError::internal(
                        "run router solicitation",
                        "native router solicitation worker panicked",
                    ))
                });
                lock(&solicitations).remove(&solicitation_id);
                let status = completion.call(
                    RouterSolicitationCompletion(result),
                    ThreadsafeFunctionCallMode::Blocking,
                );
                debug_assert!(matches!(status, Status::Ok | Status::Closing));
                drop(permit);
            });
        if let Err(error) = spawn {
            lock(&self.router_solicitations).remove(&solicitation_id);
            return Err(ScannerError::internal(
                "start router solicitation",
                format!("failed to spawn router solicitation worker: {error}"),
            )
            .into_napi());
        }
        Ok(())
    }

    #[napi]
    pub fn cancel_router_solicitation(&self, solicitation_id: u32) -> Result<()> {
        router_solicitation_control(&self.router_solicitations, solicitation_id)?.cancel();
        Ok(())
    }

    #[napi]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "napi-rs owns the JavaScript callback while constructing its threadsafe function"
    )]
    pub fn trace_path(
        &self,
        plan: NativePathPlan,
        path_id: u32,
        callback: Function<'_, NativePathCompletion, ()>,
    ) -> Result<()> {
        let plan = plan.validate().map_err(ScannerError::into_napi)?;
        if path_id == 0 {
            return Err(ScannerError::invalid(
                "start path trace",
                "path identifier must be nonzero",
            )
            .into_napi());
        }
        let expected = self.next_path_id.fetch_add(1, Ordering::AcqRel);
        if expected != path_id || expected == 0 {
            return Err(ScannerError::resource(
                "start path trace",
                "path identifiers must increase and may not be reused",
            )
            .into_napi());
        }
        let completion: PathCompletionFunction = callback
            .build_threadsafe_function::<PathCompletion>()
            .callee_handled::<false>()
            .max_queue_size::<PATH_COMPLETION_QUEUE_CAPACITY>()
            .build_callback(|context: ThreadsafeCallContext<PathCompletion>| {
                Ok(NativePathCompletion::from(context.value))
            })?;
        let permit = self
            .runtime
            .admit_external_session(PATH_RESERVATION_BYTES, "start path trace")
            .map_err(ScannerError::into_napi)?;
        let control = Arc::new(PathControl::new());
        lock(&self.paths).insert(path_id, Arc::clone(&control));
        let paths = Arc::clone(&self.paths);
        let thread_control = Arc::clone(&control);
        let spawn = thread::Builder::new()
            .name(format!("nodenetscanner-path-{path_id}"))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_path(plan, &thread_control)
                }))
                .unwrap_or_else(|_| {
                    Err(ScannerError::internal(
                        "run path trace",
                        "native path worker panicked",
                    ))
                });
                lock(&paths).remove(&path_id);
                let status =
                    completion.call(PathCompletion(result), ThreadsafeFunctionCallMode::Blocking);
                debug_assert!(matches!(status, Status::Ok | Status::Closing));
                drop(permit);
            });
        if let Err(error) = spawn {
            lock(&self.paths).remove(&path_id);
            return Err(ScannerError::internal(
                "start path trace",
                format!("failed to spawn path worker: {error}"),
            )
            .into_napi());
        }
        Ok(())
    }

    #[napi]
    pub fn cancel_path(&self, path_id: u32) -> Result<()> {
        path_control(&self.paths, path_id)?.cancel();
        Ok(())
    }

    #[napi]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "napi-rs owns the JavaScript callback while constructing its threadsafe function"
    )]
    pub fn identify_service(
        &self,
        plan: NativeServiceIdentificationPlan,
        service_id: u32,
        callback: Function<'_, NativeServiceCompletion, ()>,
    ) -> Result<()> {
        let plan = plan.validate().map_err(ScannerError::into_napi)?;
        if service_id == 0 {
            return Err(ScannerError::invalid(
                "start service identification",
                "service identifier must be nonzero",
            )
            .into_napi());
        }
        let expected = self.next_service_id.fetch_add(1, Ordering::AcqRel);
        if expected != service_id || expected == 0 {
            return Err(ScannerError::resource(
                "start service identification",
                "service identifiers must increase and may not be reused",
            )
            .into_napi());
        }
        let completion: ServiceCompletionFunction = callback
            .build_threadsafe_function::<ServiceCompletion>()
            .callee_handled::<false>()
            .max_queue_size::<SERVICE_COMPLETION_QUEUE_CAPACITY>()
            .build_callback(|context: ThreadsafeCallContext<ServiceCompletion>| {
                Ok(NativeServiceCompletion::from(context.value))
            })?;
        let permit = self
            .runtime
            .admit_external_session(
                CONVERSATION_RESERVATION_BYTES,
                "start service identification",
            )
            .map_err(ScannerError::into_napi)?;
        let control = Arc::new(ServiceControl::new());
        lock(&self.services).insert(service_id, Arc::clone(&control));
        let services = Arc::clone(&self.services);
        let thread_control = Arc::clone(&control);
        let spawn = thread::Builder::new()
            .name(format!("nodenetscanner-service-{service_id}"))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_service_conversation(&plan, &thread_control)
                }))
                .unwrap_or_else(|_| {
                    Err(ScannerError::internal(
                        "run service identification",
                        "native service worker panicked",
                    ))
                });
                lock(&services).remove(&service_id);
                let status = completion.call(
                    ServiceCompletion(result),
                    ThreadsafeFunctionCallMode::Blocking,
                );
                debug_assert!(matches!(status, Status::Ok | Status::Closing));
                drop(permit);
            });
        if let Err(error) = spawn {
            lock(&self.services).remove(&service_id);
            return Err(ScannerError::internal(
                "start service identification",
                format!("failed to spawn service worker: {error}"),
            )
            .into_napi());
        }
        Ok(())
    }

    #[napi]
    pub fn cancel_service(&self, service_id: u32) -> Result<()> {
        service_control(&self.services, service_id)?.cancel();
        Ok(())
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
            .admit_external_session(plan.limits.max_metadata_bytes, "start discovery session")
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
    #[allow(
        clippy::needless_pass_by_value,
        reason = "napi-rs owns the JavaScript callback while constructing its threadsafe function"
    )]
    pub fn observe(
        &self,
        plan: NativeObservationPlan,
        observation_id: u32,
        callback: Function<'_, NativeObservationCompletion, ()>,
    ) -> Result<()> {
        let plan = plan.validate().map_err(ScannerError::into_napi)?;
        if observation_id == 0 {
            return Err(ScannerError::invalid(
                "start observation session",
                "observation identifier must be nonzero",
            )
            .into_napi());
        }
        let expected = self.next_observation_id.fetch_add(1, Ordering::AcqRel);
        if expected != observation_id || expected == 0 {
            return Err(ScannerError::resource(
                "start observation session",
                "observation identifiers must increase and may not be reused",
            )
            .into_napi());
        }
        let completion: ObservationCompletionFunction = callback
            .build_threadsafe_function::<ObservationCompletion>()
            .callee_handled::<false>()
            .max_queue_size::<OBSERVATION_COMPLETION_QUEUE_CAPACITY>()
            .build_callback(|context: ThreadsafeCallContext<ObservationCompletion>| {
                Ok(NativeObservationCompletion::from(context.value))
            })?;
        let permit = self
            .runtime
            .admit_external_session(plan.max_metadata_bytes, "start observation session")
            .map_err(ScannerError::into_napi)?;
        let control = Arc::new(ObservationControl::new());
        lock(&self.observations).insert(observation_id, Arc::clone(&control));
        let observations = Arc::clone(&self.observations);
        let thread_control = Arc::clone(&control);
        let spawn = thread::Builder::new()
            .name(format!("nodenetscanner-observation-{observation_id}"))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_observation(plan, &thread_control)
                }))
                .unwrap_or_else(|_| {
                    Err(ScannerError::internal(
                        "run observation session",
                        "native observation worker panicked",
                    ))
                });
                if let Err(error) = &result {
                    thread_control.settle_ready(Err(error.clone()));
                    thread_control.fail();
                }
                let status = completion.call(
                    ObservationCompletion(result),
                    ThreadsafeFunctionCallMode::Blocking,
                );
                debug_assert!(matches!(status, Status::Ok | Status::Closing));
                drop(permit);
                // Retain the completed control until JavaScript drains its
                // immutable queue or closes the session.
                if status == Status::Closing {
                    lock(&observations).remove(&observation_id);
                }
            });
        if let Err(error) = spawn {
            lock(&self.observations).remove(&observation_id);
            return Err(ScannerError::internal(
                "start observation session",
                format!("failed to spawn observation worker: {error}"),
            )
            .into_napi());
        }
        Ok(())
    }

    #[napi]
    pub fn ready_observation(
        &self,
        observation_id: u32,
    ) -> Result<AsyncTask<ObservationReadyTask>> {
        Ok(AsyncTask::new(ObservationReadyTask {
            control: observation_control(&self.observations, observation_id)?,
        }))
    }

    #[napi]
    pub fn pause_observation(&self, observation_id: u32) -> Result<()> {
        observation_control(&self.observations, observation_id)?
            .pause()
            .map_err(ScannerError::into_napi)
    }

    #[napi]
    pub fn resume_observation(&self, observation_id: u32) -> Result<()> {
        observation_control(&self.observations, observation_id)?
            .resume()
            .map_err(ScannerError::into_napi)
    }

    #[napi]
    pub fn cancel_observation(&self, observation_id: u32) -> Result<()> {
        observation_control(&self.observations, observation_id)?.cancel();
        Ok(())
    }

    #[napi]
    pub fn observation_batch(
        &self,
        observation_id: u32,
        maximum: Option<u32>,
    ) -> Result<NativeObservationBatch> {
        let maximum = maximum.unwrap_or(DEFAULT_BATCH_RESULTS);
        if maximum == 0 || maximum > MAX_BATCH_RESULTS {
            return Err(ScannerError::invalid(
                "pull observation batch",
                "maxResults must be from 1 through 4096",
            )
            .into_napi());
        }
        Ok(observation_control(&self.observations, observation_id)?
            .batch(usize::try_from(maximum).unwrap_or(usize::MAX)))
    }

    #[napi]
    pub fn observation_progress(&self, observation_id: u32) -> Result<NativeObservationProgress> {
        Ok(observation_control(&self.observations, observation_id)?.progress())
    }

    #[napi]
    pub fn close_observation(&self, observation_id: u32) {
        if let Some(control) = lock(&self.observations).remove(&observation_id) {
            control.cancel();
        }
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
        for control in lock(&self.observations).values() {
            control.cancel();
        }
        for control in lock(&self.router_solicitations).values() {
            control.cancel();
        }
        for control in lock(&self.paths).values() {
            control.cancel();
        }
        for control in lock(&self.services).values() {
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
        for control in lock(&self.observations).values() {
            control.cancel();
        }
        for control in lock(&self.router_solicitations).values() {
            control.cancel();
        }
        for control in lock(&self.paths).values() {
            control.cancel();
        }
        for control in lock(&self.services).values() {
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
        next_observation_id: AtomicU32::new(1),
        observations: Arc::new(Mutex::new(HashMap::new())),
        next_router_solicitation_id: AtomicU32::new(1),
        router_solicitations: Arc::new(Mutex::new(HashMap::new())),
        next_path_id: AtomicU32::new(1),
        paths: Arc::new(Mutex::new(HashMap::new())),
        next_service_id: AtomicU32::new(1),
        services: Arc::new(Mutex::new(HashMap::new())),
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
pub fn udp_coverage_capabilities() -> NativeUdpCoverageCapabilities {
    NativeUdpCoverageCapabilities {
        version: UDP_COVERAGE_REGISTRY_VERSION.into(),
        maximum_candidates: u32::from(UDP_COVERAGE_RESOURCE_CONTRACT.maximum_candidates),
        maximum_compiled_variants: u32::from(
            UDP_COVERAGE_RESOURCE_CONTRACT.maximum_compiled_variants,
        ),
        maximum_physical_queries: u32::from(
            UDP_COVERAGE_RESOURCE_CONTRACT.maximum_physical_queries,
        ),
        maximum_response_bytes: UDP_COVERAGE_RESOURCE_CONTRACT.maximum_response_bytes,
        maximum_metadata_bytes: UDP_COVERAGE_RESOURCE_CONTRACT.maximum_metadata_bytes,
        maximum_returned_endpoints: u32::from(
            UDP_COVERAGE_RESOURCE_CONTRACT.maximum_returned_endpoints,
        ),
        maximum_state_lifetime_ms: UDP_COVERAGE_RESOURCE_CONTRACT.maximum_state_lifetime_ms,
        entries: UDP_COVERAGE_REGISTRY
            .iter()
            .map(|entry| {
                let (implementation_kind, implementation_id) = match entry.implementation {
                    Some(nodenet_protocols::CapabilityImplementation::UdpProbe(id)) => {
                        (Some("udpProbe".into()), Some(u32::from(id)))
                    }
                    Some(nodenet_protocols::CapabilityImplementation::DiscoveryOperation(id)) => {
                        (Some("discoveryOperation".into()), Some(u32::from(id)))
                    }
                    None => (None, None),
                };
                NativeUdpCoverageEntry {
                    id: u32::from(entry.id),
                    project_id: entry.project_id.into(),
                    phase: u32::from(entry.phase),
                    family: entry.family.into(),
                    disposition: match entry.disposition {
                        UdpCoverageDisposition::Research => "research",
                        UdpCoverageDisposition::Implemented => "implemented",
                        UdpCoverageDisposition::NoGo => "noGo",
                        UdpCoverageDisposition::Excluded => "excluded",
                    }
                    .into(),
                    execution_model: match entry.execution_model {
                        UdpCoverageExecutionModel::None => "none",
                        UdpCoverageExecutionModel::TargetPort => "targetPort",
                        UdpCoverageExecutionModel::Discovery => "discovery",
                        UdpCoverageExecutionModel::Conversation => "conversation",
                    }
                    .into(),
                    policy: match entry.policy {
                        UdpCoveragePolicy::Safe => "safe",
                        UdpCoveragePolicy::OptIn => "optIn",
                        UdpCoveragePolicy::Excluded => "excluded",
                    }
                    .into(),
                    risks: udp_coverage_risk_names(entry.risks),
                    required_consents: risk_names(entry.required_consents),
                    dimensions: udp_coverage_dimension_names(entry.dimensions),
                    implementation_kind,
                    implementation_id,
                    primary_source_url: entry.primary_source_url.into(),
                    rationale: entry.rationale.into(),
                }
            })
            .collect(),
    }
}

fn udp_coverage_risk_names(risks: nodenet_protocols::UdpCoverageRiskSet) -> Vec<String> {
    [
        (
            UdpCoverageRisk::ManagementDisclosure,
            "managementDisclosure",
        ),
        (UdpCoverageRisk::TopologyDisclosure, "topologyDisclosure"),
        (UdpCoverageRisk::Amplification, "amplification"),
        (
            UdpCoverageRisk::StatefulParticipation,
            "statefulParticipation",
        ),
        (UdpCoverageRisk::LegacyFragility, "legacyFragility"),
        (UdpCoverageRisk::ThreatSignature, "threatSignature"),
    ]
    .into_iter()
    .filter(|(risk, _)| risks.contains(*risk))
    .map(|(_, name)| name.into())
    .collect()
}

fn udp_coverage_dimension_names(
    dimensions: nodenet_protocols::UdpCoverageDimensionSet,
) -> Vec<String> {
    [
        (UdpCoverageDimension::Request, "request"),
        (UdpCoverageDimension::Correlation, "correlation"),
        (UdpCoverageDimension::TypedEvidence, "typedEvidence"),
        (UdpCoverageDimension::ProjectResponder, "projectResponder"),
        (
            UdpCoverageDimension::ProductFingerprint,
            "productFingerprint",
        ),
    ]
    .into_iter()
    .filter(|(dimension, _)| dimensions.contains(*dimension))
    .map(|(_, name)| name.into())
    .collect()
}

#[napi(object)]
pub struct NativeServiceRegistryCapability {
    pub id: String,
    pub ports: Vec<u32>,
    pub disposition: String,
    pub risk: String,
    pub maximum_request_bytes: u32,
    pub maximum_response_bytes: u32,
}

#[napi(object)]
pub struct NativeServiceRegistryCapabilities {
    pub version: String,
    pub entries: Vec<NativeServiceRegistryCapability>,
}

#[napi]
pub fn service_registry_capabilities() -> NativeServiceRegistryCapabilities {
    NativeServiceRegistryCapabilities {
        version: SERVICE_REGISTRY_VERSION.into(),
        entries: SERVICE_REGISTRY
            .iter()
            .map(|entry| NativeServiceRegistryCapability {
                id: entry.id.into(),
                ports: entry
                    .default_ports
                    .iter()
                    .map(|port| u32::from(*port))
                    .collect(),
                disposition: match entry.disposition {
                    ServiceDisposition::Implemented => "implemented",
                    ServiceDisposition::OptIn => "optIn",
                    ServiceDisposition::NoGo => "noGo",
                }
                .into(),
                risk: match entry.risk {
                    ServiceRisk::ServerFirst => "serverFirst",
                    ServiceRisk::ClientNegotiation => "clientNegotiation",
                    ServiceRisk::StatefulHandshake => "statefulHandshake",
                    ServiceRisk::SensitiveRead => "sensitiveRead",
                }
                .into(),
                maximum_request_bytes: u32::try_from(entry.maximum_request_bytes)
                    .unwrap_or(u32::MAX),
                maximum_response_bytes: u32::try_from(entry.maximum_response_bytes)
                    .unwrap_or(u32::MAX),
            })
            .collect(),
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

fn observation_control(
    observations: &Mutex<HashMap<u32, Arc<ObservationControl>>>,
    observation_id: u32,
) -> Result<Arc<ObservationControl>> {
    lock(observations)
        .get(&observation_id)
        .cloned()
        .ok_or_else(|| {
            ScannerError::lifecycle("control observation", "unknown observation session")
                .into_napi()
        })
}

fn router_solicitation_control(
    solicitations: &Mutex<HashMap<u32, Arc<RouterSolicitationControl>>>,
    solicitation_id: u32,
) -> Result<Arc<RouterSolicitationControl>> {
    lock(solicitations)
        .get(&solicitation_id)
        .cloned()
        .ok_or_else(|| {
            ScannerError::lifecycle("cancel router solicitation", "unknown router solicitation")
                .into_napi()
        })
}

fn path_control(
    paths: &Mutex<HashMap<u32, Arc<PathControl>>>,
    path_id: u32,
) -> Result<Arc<PathControl>> {
    lock(paths).get(&path_id).cloned().ok_or_else(|| {
        ScannerError::lifecycle("cancel path trace", "unknown path trace").into_napi()
    })
}

fn service_control(
    services: &Mutex<HashMap<u32, Arc<ServiceControl>>>,
    service_id: u32,
) -> Result<Arc<ServiceControl>> {
    lock(services).get(&service_id).cloned().ok_or_else(|| {
        ScannerError::lifecycle("cancel service identification", "unknown service operation")
            .into_napi()
    })
}

fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub struct InspectTask;

pub struct ObservationReadyTask {
    control: Arc<ObservationControl>,
}

impl Task for ObservationReadyTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        self.control.ready().map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

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
        rules: snapshot
            .rules
            .into_iter()
            .map(|value| NativeNetworkRule {
                family: u32::from(value.family),
                destination: value.destination.map(|address| address.to_string()),
                destination_prefix_length: u32::from(value.destination_prefix_length),
                source: value.source.map(|address| address.to_string()),
                source_prefix_length: u32::from(value.source_prefix_length),
                table: value.table,
                action: u32::from(value.action),
                priority: value.priority,
                input_interface: value.input_interface,
                output_interface: value.output_interface,
                firewall_mark: value.firewall_mark,
                firewall_mask: value.firewall_mask,
                ip_protocol: value.ip_protocol.map(u32::from),
            })
            .collect(),
        neighbors: snapshot
            .neighbors
            .into_iter()
            .map(|value| NativeNetworkNeighbor {
                family: u32::from(value.family),
                interface_index: value.interface_index,
                destination: value.destination.map(|address| address.to_string()),
                state: u32::from(value.state),
                flags: u32::from(value.flags),
                neighbor_type: u32::from(value.neighbor_type),
                link_layer_address: value.link_layer_address,
                probes: value.probes,
            })
            .collect(),
    }
}
