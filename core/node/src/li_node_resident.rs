// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::{
    NodeConfiguration, NodeDaemon, NodePrivateLocalServer, NodePrivateLocalServerHandle,
    NodePrivateRemoteServer, NodePrivateRemoteServerHandle,
};

// Names one run-control outcome after the bounded daemon cadence elapses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeResidentRunDecision {
    Tick,
    Stop,
}

// Supplies the exact stop signal and bounded cadence wait consumed by the resident loop.
pub trait NodeResidentRunControl: Send + Sync {
    // Reports whether an injected signal already requested clean shutdown.
    fn is_stop_requested(&self) -> Result<bool, NodeResidentError>;

    // Waits for the bounded cadence or returns promptly when shutdown is requested.
    fn wait(&self, cadence: Duration) -> Result<NodeResidentRunDecision, NodeResidentError>;

    // Requests clean shutdown and wakes any resident cadence wait.
    fn request_stop(&self) -> Result<(), NodeResidentError>;
}

// Provides one cloneable in-process signal that a native signal adapter may trigger.
#[derive(Default)]
pub struct NodeResidentRunSignal {
    stopped: AtomicBool,
    wait_lock: Mutex<()>,
    wait_condition: Condvar,
}

impl NodeResidentRunSignal {
    // Creates one unsignalled resident run control.
    pub const fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            wait_lock: Mutex::new(()),
            wait_condition: Condvar::new(),
        }
    }

    // Triggers the same clean stop path used by service and process signal composition.
    pub fn signal_stop(&self) -> Result<(), NodeResidentError> {
        self.request_stop()
    }
}

impl NodeResidentRunControl for NodeResidentRunSignal {
    // Reads the one-way stop signal without taking the cadence lock.
    fn is_stop_requested(&self) -> Result<bool, NodeResidentError> {
        Ok(self.stopped.load(Ordering::Acquire))
    }

    // Waits on a condition variable so a stop signal never waits for the full cadence.
    fn wait(&self, cadence: Duration) -> Result<NodeResidentRunDecision, NodeResidentError> {
        if self.stopped.load(Ordering::Acquire) {
            return Ok(NodeResidentRunDecision::Stop);
        }
        let guard = self
            .wait_lock
            .lock()
            .map_err(|_| NodeResidentError::RunControlFailed)?;
        let (_guard, _) = self
            .wait_condition
            .wait_timeout_while(guard, cadence, |_| !self.stopped.load(Ordering::Acquire))
            .map_err(|_| NodeResidentError::RunControlFailed)?;
        if self.stopped.load(Ordering::Acquire) {
            Ok(NodeResidentRunDecision::Stop)
        } else {
            Ok(NodeResidentRunDecision::Tick)
        }
    }

    // Publishes the one-way stop signal before waking every waiter.
    fn request_stop(&self) -> Result<(), NodeResidentError> {
        self.stopped.store(true, Ordering::Release);
        self.wait_condition.notify_all();
        Ok(())
    }
}

// Owns the minimum health and stop surface shared by local and remote listener handles.
pub trait NodeResidentListenerHandle: Send {
    // Reports whether this exact listener acceptance thread remains live.
    fn is_running(&self) -> bool;

    // Stops acceptance and joins every bounded worker owned by this listener.
    fn stop(&mut self) -> Result<(), NodeResidentError>;
}

// Starts the owner-only local private Node listener selected by composition.
pub trait NodeResidentLocalListenerProvider: Send + Sync {
    // Starts and returns one complete local listener lifecycle owner.
    fn start_local_listener(
        &self,
    ) -> Result<Box<dyn NodeResidentListenerHandle>, NodeResidentError>;
}

// Starts the mTLS remote private Node listener selected by composition.
pub trait NodeResidentRemoteListenerProvider: Send + Sync {
    // Starts and returns one complete remote listener lifecycle owner.
    fn start_remote_listener(
        &self,
    ) -> Result<Box<dyn NodeResidentListenerHandle>, NodeResidentError>;
}

impl NodeResidentLocalListenerProvider for NodePrivateLocalServer {
    // Starts the production Unix-domain listener and retains its concrete handle.
    fn start_local_listener(
        &self,
    ) -> Result<Box<dyn NodeResidentListenerHandle>, NodeResidentError> {
        self.start()
            .map(|handle| Box::new(handle) as Box<dyn NodeResidentListenerHandle>)
            .map_err(|_| NodeResidentError::LocalListenerStartFailed)
    }
}

impl NodeResidentListenerHandle for NodePrivateLocalServerHandle {
    // Delegates health observation to the concrete local listener owner.
    fn is_running(&self) -> bool {
        NodePrivateLocalServerHandle::is_running(self)
    }

    // Delegates bounded shutdown and maps native details into one resident failure.
    fn stop(&mut self) -> Result<(), NodeResidentError> {
        self.shutdown()
            .map_err(|_| NodeResidentError::LocalListenerStopFailed)
    }
}

impl NodeResidentRemoteListenerProvider for NodePrivateRemoteServer {
    // Starts the production bounded TCP listener and retains its concrete handle.
    fn start_remote_listener(
        &self,
    ) -> Result<Box<dyn NodeResidentListenerHandle>, NodeResidentError> {
        self.start()
            .map(|handle| Box::new(handle) as Box<dyn NodeResidentListenerHandle>)
            .map_err(|_| NodeResidentError::RemoteListenerStartFailed)
    }
}

impl NodeResidentListenerHandle for NodePrivateRemoteServerHandle {
    // Delegates health observation to the concrete remote listener owner.
    fn is_running(&self) -> bool {
        NodePrivateRemoteServerHandle::is_running(self)
    }

    // Delegates bounded shutdown and maps native details into one resident failure.
    fn stop(&mut self) -> Result<(), NodeResidentError> {
        self.shutdown()
            .map_err(|_| NodeResidentError::RemoteListenerStopFailed)
    }
}

// Owns one spawned resident-loop thread until its exact result is joined.
pub trait NodeResidentThreadHandle: Send {
    // Reports whether the resident loop has returned at this observation.
    fn is_finished(&self) -> bool;

    // Joins the thread once and returns its exact redacted loop result.
    fn join(&mut self) -> Result<(), NodeResidentError>;
}

// Spawns the resident loop through one injectable native-thread boundary.
pub trait NodeResidentThreadProvider: Send + Sync {
    // Starts one named task and transfers its complete join lifecycle to the caller.
    fn spawn(
        &self,
        task: Box<dyn FnOnce() -> Result<(), NodeResidentError> + Send>,
    ) -> Result<Box<dyn NodeResidentThreadHandle>, NodeResidentError>;
}

// Supplies the production named operating-system thread provider.
#[derive(Default)]
pub struct SystemNodeResidentThreadProvider;

impl NodeResidentThreadProvider for SystemNodeResidentThreadProvider {
    // Starts one named resident thread without detaching its join handle.
    fn spawn(
        &self,
        task: Box<dyn FnOnce() -> Result<(), NodeResidentError> + Send>,
    ) -> Result<Box<dyn NodeResidentThreadHandle>, NodeResidentError> {
        thread::Builder::new()
            .name("li_node_resident".to_string())
            .spawn(task)
            .map(|thread| {
                Box::new(SystemNodeResidentThreadHandle {
                    thread: Some(thread),
                }) as Box<dyn NodeResidentThreadHandle>
            })
            .map_err(|_| NodeResidentError::DaemonThreadStartFailed)
    }
}

// Retains one production resident thread until the owner joins it.
struct SystemNodeResidentThreadHandle {
    thread: Option<JoinHandle<Result<(), NodeResidentError>>>,
}

impl NodeResidentThreadHandle for SystemNodeResidentThreadHandle {
    // Reports the concrete thread completion state without consuming its result.
    fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    // Joins once and rejects a panic without retaining a native panic payload.
    fn join(&mut self) -> Result<(), NodeResidentError> {
        self.thread.take().map_or(Ok(()), |thread| {
            thread
                .join()
                .map_err(|_| NodeResidentError::DaemonThreadPanicked)?
        })
    }
}

// Names one stable resident start, loop, or shutdown failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeResidentError {
    AlreadyRunning,
    LocalListenerStartFailed,
    LocalListenerNotRunning,
    RemoteListenerStartFailed,
    RemoteListenerNotRunning,
    DaemonThreadStartFailed,
    DaemonThreadPanicked,
    DaemonTickFailed,
    RunControlFailed,
    LocalListenerStopFailed,
    RemoteListenerStopFailed,
    PartialStartRollbackFailed,
}

impl fmt::Display for NodeResidentError {
    // Presents fixed resident lifecycle language without paths, peers, events, or native text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => formatter.write_str("Node resident is already running"),
            Self::LocalListenerStartFailed => {
                formatter.write_str("Node local listener could not start")
            }
            Self::LocalListenerNotRunning => {
                formatter.write_str("Node local listener did not remain running")
            }
            Self::RemoteListenerStartFailed => {
                formatter.write_str("Node remote listener could not start")
            }
            Self::RemoteListenerNotRunning => {
                formatter.write_str("Node remote listener did not remain running")
            }
            Self::DaemonThreadStartFailed => {
                formatter.write_str("Node resident loop could not start")
            }
            Self::DaemonThreadPanicked => formatter.write_str("Node resident loop failed"),
            Self::DaemonTickFailed => formatter.write_str("Node resident cycle failed"),
            Self::RunControlFailed => formatter.write_str("Node resident run control failed"),
            Self::LocalListenerStopFailed => {
                formatter.write_str("Node local listener could not stop cleanly")
            }
            Self::RemoteListenerStopFailed => {
                formatter.write_str("Node remote listener could not stop cleanly")
            }
            Self::PartialStartRollbackFailed => {
                formatter.write_str("Node resident partial start could not be rolled back")
            }
        }
    }
}

impl Error for NodeResidentError {}

// Owns exactly one resident start boundary and prevents overlapping Node lifecycles.
pub struct NodeResident {
    cadence: Duration,
    daemon: Arc<NodeDaemon>,
    local_listener: Arc<dyn NodeResidentLocalListenerProvider>,
    remote_listener: Arc<dyn NodeResidentRemoteListenerProvider>,
    run_control: Arc<dyn NodeResidentRunControl>,
    threads: Arc<dyn NodeResidentThreadProvider>,
    running: Arc<AtomicBool>,
}

impl NodeResident {
    // Creates one inert resident owner from exact configuration and injected capabilities.
    pub fn new(
        configuration: &NodeConfiguration,
        daemon: Arc<NodeDaemon>,
        local_listener: Arc<dyn NodeResidentLocalListenerProvider>,
        remote_listener: Arc<dyn NodeResidentRemoteListenerProvider>,
        run_control: Arc<dyn NodeResidentRunControl>,
        threads: Arc<dyn NodeResidentThreadProvider>,
    ) -> Self {
        Self {
            cadence: configuration.daemon_cadence(),
            daemon,
            local_listener,
            remote_listener,
            run_control,
            threads,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    // Starts both listeners and the resident loop or restores the completely stopped state.
    pub fn start(&self) -> Result<NodeResidentHandle, NodeResidentError> {
        self.running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| NodeResidentError::AlreadyRunning)?;
        match self.start_owned() {
            Ok(handle) => Ok(handle),
            Err(error) => {
                self.running.store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    // Acquires local, remote, and thread resources in order with symmetric rollback.
    fn start_owned(&self) -> Result<NodeResidentHandle, NodeResidentError> {
        let local = self.local_listener.start_local_listener()?;
        if !local.is_running() {
            return stop_failed_start(
                None,
                Some(local),
                NodeResidentError::LocalListenerNotRunning,
            );
        }
        let remote = match self.remote_listener.start_remote_listener() {
            Ok(remote) => remote,
            Err(error) => return stop_failed_start(None, Some(local), error),
        };
        if !remote.is_running() {
            return stop_failed_start(
                Some(remote),
                Some(local),
                NodeResidentError::RemoteListenerNotRunning,
            );
        }
        let daemon = Arc::clone(&self.daemon);
        let run_control = Arc::clone(&self.run_control);
        let cadence = self.cadence;
        let thread = match self.threads.spawn(Box::new(move || {
            resident_loop(&daemon, &run_control, cadence)
        })) {
            Ok(thread) => thread,
            Err(error) => return stop_failed_start(Some(remote), Some(local), error),
        };
        Ok(NodeResidentHandle {
            local: Some(local),
            remote: Some(remote),
            run_control: Arc::clone(&self.run_control),
            thread: Some(thread),
            running: Arc::clone(&self.running),
        })
    }
}

// Retains both listener handles and the resident loop until one clean completion boundary.
pub struct NodeResidentHandle {
    local: Option<Box<dyn NodeResidentListenerHandle>>,
    remote: Option<Box<dyn NodeResidentListenerHandle>>,
    run_control: Arc<dyn NodeResidentRunControl>,
    thread: Option<Box<dyn NodeResidentThreadHandle>>,
    running: Arc<AtomicBool>,
}

impl NodeResidentHandle {
    // Reports true only while both listener owners and the resident loop remain active.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
            && self
                .local
                .as_ref()
                .is_some_and(|handle| handle.is_running())
            && self
                .remote
                .as_ref()
                .is_some_and(|handle| handle.is_running())
            && self
                .thread
                .as_ref()
                .is_some_and(|thread| !thread.is_finished())
    }

    // Waits for an injected stop or loop failure, then stops and joins both listeners.
    pub fn wait(&mut self) -> Result<(), NodeResidentError> {
        self.complete(false)
    }

    // Signals the loop, stops both listeners, and joins every retained owner exactly once.
    pub fn stop(&mut self) -> Result<(), NodeResidentError> {
        self.complete(true)
    }

    // Completes the one symmetric resident release path after optional explicit signalling.
    fn complete(&mut self, request_stop: bool) -> Result<(), NodeResidentError> {
        let mut result = Ok(());
        if request_stop {
            retain_first_error(&mut result, self.run_control.request_stop());
        }
        if let Some(thread) = &mut self.thread {
            retain_first_error(&mut result, thread.join());
        }
        self.thread = None;
        if let Some(remote) = &mut self.remote {
            retain_first_error(&mut result, remote.stop());
        }
        self.remote = None;
        if let Some(local) = &mut self.local {
            retain_first_error(&mut result, local.stop());
        }
        self.local = None;
        self.running.store(false, Ordering::Release);
        result
    }
}

impl Drop for NodeResidentHandle {
    // Completes clean stop and join even when the process owner leaves scope early.
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// Runs immediate and cadence-triggered NodeDaemon cycles until one exact stop signal.
fn resident_loop(
    daemon: &NodeDaemon,
    run_control: &Arc<dyn NodeResidentRunControl>,
    cadence: Duration,
) -> Result<(), NodeResidentError> {
    loop {
        if run_control.is_stop_requested()? {
            return Ok(());
        }
        let local = daemon
            .manager()
            .node(daemon.manager().local_node_id())
            .map_err(|_| NodeResidentError::DaemonTickFailed)?;
        let idempotency_key = format!(
            "li_node_hardware_refresh:{}:{}",
            daemon.manager().local_node_id().as_str(),
            local.revision()
        );
        daemon
            .tick(&idempotency_key)
            .map_err(|_| NodeResidentError::DaemonTickFailed)?;
        match run_control.wait(cadence)? {
            NodeResidentRunDecision::Tick => {}
            NodeResidentRunDecision::Stop => return Ok(()),
        }
    }
}

// Stops every resource acquired by a failed start and preserves rollback failure priority.
fn stop_failed_start(
    mut remote: Option<Box<dyn NodeResidentListenerHandle>>,
    mut local: Option<Box<dyn NodeResidentListenerHandle>>,
    start_error: NodeResidentError,
) -> Result<NodeResidentHandle, NodeResidentError> {
    let remote_result = remote.as_mut().map_or(Ok(()), |handle| handle.stop());
    let local_result = local.as_mut().map_or(Ok(()), |handle| handle.stop());
    if remote_result.is_err() || local_result.is_err() {
        Err(NodeResidentError::PartialStartRollbackFailed)
    } else {
        Err(start_error)
    }
}

// Retains the first lifecycle failure while still completing every later cleanup action.
fn retain_first_error(
    result: &mut Result<(), NodeResidentError>,
    next: Result<(), NodeResidentError>,
) {
    if result.is_ok() {
        *result = next;
    }
}
