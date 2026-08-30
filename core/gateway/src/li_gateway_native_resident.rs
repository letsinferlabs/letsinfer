// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::GatewayNativeServerError;

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

// Selects stable public or private language at the shared resident boundary.
#[derive(Clone, Copy)]
pub(crate) enum GatewayNativeServerSurface {
    Public,
    Private,
}

impl GatewayNativeServerSurface {
    // Returns the fixed listener thread name for this surface.
    const fn listener_thread_name(self) -> &'static str {
        match self {
            Self::Public => "li_gateway_public_listener",
            Self::Private => "li_gateway_private_listener",
        }
    }

    // Returns the fixed connection thread name for this surface.
    const fn connection_thread_name(self) -> &'static str {
        match self {
            Self::Public => "li_gateway_public_connection",
            Self::Private => "li_gateway_private_connection",
        }
    }

    // Returns one redacted permanent accept failure.
    const fn accept_error(self) -> GatewayNativeServerError {
        match self {
            Self::Public => {
                GatewayNativeServerError::new("public Gateway connection cannot be accepted")
            }
            Self::Private => {
                GatewayNativeServerError::new("private Gateway connection cannot be accepted")
            }
        }
    }

    // Returns one redacted listener-configuration failure.
    const fn listener_error(self) -> GatewayNativeServerError {
        match self {
            Self::Public => {
                GatewayNativeServerError::new("public Gateway listener cannot become nonblocking")
            }
            Self::Private => {
                GatewayNativeServerError::new("private Gateway listener cannot become nonblocking")
            }
        }
    }

    // Returns one redacted supervisor-spawn failure.
    const fn start_error(self) -> GatewayNativeServerError {
        match self {
            Self::Public => {
                GatewayNativeServerError::new("public Gateway listener cannot be started")
            }
            Self::Private => {
                GatewayNativeServerError::new("private Gateway listener cannot be started")
            }
        }
    }

    // Returns one redacted connection-registration failure.
    const fn registration_error(self) -> GatewayNativeServerError {
        match self {
            Self::Public => {
                GatewayNativeServerError::new("public Gateway connection cannot be registered")
            }
            Self::Private => {
                GatewayNativeServerError::new("private Gateway connection cannot be registered")
            }
        }
    }

    // Returns one redacted worker lifecycle failure.
    const fn worker_error(self) -> GatewayNativeServerError {
        match self {
            Self::Public => {
                GatewayNativeServerError::new("public Gateway connection worker failed")
            }
            Self::Private => {
                GatewayNativeServerError::new("private Gateway connection worker failed")
            }
        }
    }

    // Returns one redacted shutdown-state failure.
    const fn shutdown_error(self) -> GatewayNativeServerError {
        match self {
            Self::Public => {
                GatewayNativeServerError::new("public Gateway shutdown state is unavailable")
            }
            Self::Private => {
                GatewayNativeServerError::new("private Gateway shutdown state is unavailable")
            }
        }
    }
}

// Serves one accepted socket after the resident lifecycle owns its interruption handle.
pub(crate) trait GatewayNativeSocketWorker: Send + Sync {
    // Serves exactly one connection and returns only after its resources are released.
    fn serve(&self, connection: TcpStream);
}

// Abstracts only nonblocking accept so permanent listener failure is deterministic in tests.
trait GatewayNativeAccept: Send {
    // Enables bounded polling before the resident supervisor starts.
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;

    // Accepts one connection or reports that no connection is currently ready.
    fn accept(&self) -> io::Result<TcpStream>;
}

impl GatewayNativeAccept for TcpListener {
    // Delegates nonblocking configuration to the native listener.
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpListener::set_nonblocking(self, nonblocking)
    }

    // Returns one native accepted stream without retaining its peer address.
    fn accept(&self) -> io::Result<TcpStream> {
        TcpListener::accept(self).map(|(connection, _)| connection)
    }
}

// Owns stop, active-socket interruption, worker accounting, and supervisor completion.
struct GatewayNativeResidentState {
    surface: GatewayNativeServerSurface,
    stopping: AtomicBool,
    active_connections: AtomicUsize,
    rejected_connections: AtomicU64,
    next_connection_id: AtomicU64,
    connections: Mutex<BTreeMap<u64, TcpStream>>,
    completion: Mutex<GatewayNativeResidentCompletion>,
}

impl GatewayNativeResidentState {
    // Creates one empty resident state before its supervisor thread exists.
    fn new(surface: GatewayNativeServerSurface) -> Self {
        Self {
            surface,
            stopping: AtomicBool::new(false),
            active_connections: AtomicUsize::new(0),
            rejected_connections: AtomicU64::new(0),
            next_connection_id: AtomicU64::new(1),
            connections: Mutex::new(BTreeMap::new()),
            completion: Mutex::new(GatewayNativeResidentCompletion::default()),
        }
    }

    // Reserves one worker slot without temporarily exceeding the configured maximum.
    fn reserve_connection(&self, maximum_connections: usize) -> bool {
        let mut active = self.active_connections.load(Ordering::Acquire);
        loop {
            if active >= maximum_connections {
                return false;
            }
            match self.active_connections.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => active = observed,
            }
        }
    }

    // Registers one interruptible socket clone before its worker can start.
    fn register_connection(
        self: &Arc<Self>,
        connection: &TcpStream,
    ) -> Result<GatewayNativeConnectionGuard, GatewayNativeServerError> {
        let interrupt = connection
            .try_clone()
            .map_err(|_| self.surface.registration_error())?;
        let connection_id = self
            .next_connection_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |identifier| {
                identifier.checked_add(1)
            })
            .map_err(|_| self.surface.registration_error())?;
        self.connections
            .lock()
            .map_err(|_| self.surface.shutdown_error())?
            .insert(connection_id, interrupt);
        Ok(GatewayNativeConnectionGuard {
            connection_id,
            state: self.clone(),
        })
    }

    // Saturates the diagnostic rejection count rather than wrapping its meaning.
    fn record_rejected_connection(&self) {
        let _ =
            self.rejected_connections
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    Some(count.saturating_add(1))
                });
    }

    // Interrupts every registered socket without waiting behind worker completion.
    fn interrupt_connections(&self) -> Result<(), GatewayNativeServerError> {
        let connections = self
            .connections
            .lock()
            .map_err(|_| self.surface.shutdown_error())?;
        for connection in connections.values() {
            let _ = connection.shutdown(Shutdown::Both);
        }
        Ok(())
    }
}

// Caches one supervisor result so repeated joins never consume ownership twice.
#[derive(Default)]
struct GatewayNativeResidentCompletion {
    supervisor: Option<JoinHandle<Result<(), GatewayNativeServerError>>>,
    result: Option<Result<(), GatewayNativeServerError>>,
}

// Provides deterministic stop and join ownership for one resident listener.
pub struct GatewayNativeServerHandle {
    state: Arc<GatewayNativeResidentState>,
}

impl GatewayNativeServerHandle {
    // Requests stop and actively interrupts every accepted socket idempotently.
    pub fn stop(&self) -> Result<(), GatewayNativeServerError> {
        self.state.stopping.store(true, Ordering::Release);
        self.state.interrupt_connections()
    }

    // Stops and joins the supervisor plus every registered worker exactly once.
    pub fn join(&self) -> Result<(), GatewayNativeServerError> {
        self.stop()?;
        let mut completion = self
            .state
            .completion
            .lock()
            .map_err(|_| self.state.surface.shutdown_error())?;
        if let Some(result) = completion.result.as_ref() {
            return result.clone();
        }
        let supervisor = completion
            .supervisor
            .take()
            .ok_or_else(|| self.state.surface.shutdown_error())?;
        let result = supervisor
            .join()
            .map_err(|_| self.state.surface.worker_error())
            .and_then(|result| result);
        completion.result = Some(result.clone());
        result
    }

    // Returns whether shutdown has been requested or completed.
    pub fn is_stopping(&self) -> bool {
        self.state.stopping.load(Ordering::Acquire)
    }

    // Returns the exact number of currently registered workers.
    pub fn active_connections(&self) -> usize {
        self.state.active_connections.load(Ordering::Acquire)
    }

    // Returns the exact number of connections rejected at the worker bound.
    pub fn rejected_connections(&self) -> u64 {
        self.state.rejected_connections.load(Ordering::Acquire)
    }
}

impl Drop for GatewayNativeServerHandle {
    // Prevents accidental handle loss from detaching the listener or workers.
    fn drop(&mut self) {
        let _ = self.stop();
        let _ = self.join();
    }
}

// Releases one registry entry and worker slot on every worker exit or spawn failure.
struct GatewayNativeConnectionGuard {
    connection_id: u64,
    state: Arc<GatewayNativeResidentState>,
}

impl Drop for GatewayNativeConnectionGuard {
    // Removes the interrupt socket and releases its exact active slot.
    fn drop(&mut self) {
        match self.state.connections.lock() {
            Ok(mut connections) => {
                connections.remove(&self.connection_id);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&self.connection_id);
            }
        }
        self.state.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

// Starts one system listener under the shared resident ownership contract.
pub(crate) fn start_gateway_native_server(
    listener: TcpListener,
    maximum_connections: usize,
    surface: GatewayNativeServerSurface,
    worker: Arc<dyn GatewayNativeSocketWorker>,
) -> Result<GatewayNativeServerHandle, GatewayNativeServerError> {
    start_gateway_native_acceptor(Box::new(listener), maximum_connections, surface, worker)
}

// Starts one injected acceptor after nonblocking configuration is proven.
fn start_gateway_native_acceptor(
    listener: Box<dyn GatewayNativeAccept>,
    maximum_connections: usize,
    surface: GatewayNativeServerSurface,
    worker: Arc<dyn GatewayNativeSocketWorker>,
) -> Result<GatewayNativeServerHandle, GatewayNativeServerError> {
    listener
        .set_nonblocking(true)
        .map_err(|_| surface.listener_error())?;
    let state = Arc::new(GatewayNativeResidentState::new(surface));
    let resident_state = state.clone();
    let supervisor = thread::Builder::new()
        .name(surface.listener_thread_name().to_string())
        .spawn(move || {
            serve_gateway_native_acceptor(listener, maximum_connections, worker, resident_state)
        })
        .map_err(|_| surface.start_error())?;
    let mut completion = match state.completion.lock() {
        Ok(completion) => completion,
        Err(_) => {
            state.stopping.store(true, Ordering::Release);
            let _ = supervisor.join();
            return Err(surface.shutdown_error());
        }
    };
    completion.supervisor = Some(supervisor);
    drop(completion);
    Ok(GatewayNativeServerHandle { state })
}

// Polls accept, reaps finished workers, and joins every worker before returning.
fn serve_gateway_native_acceptor(
    listener: Box<dyn GatewayNativeAccept>,
    maximum_connections: usize,
    worker: Arc<dyn GatewayNativeSocketWorker>,
    state: Arc<GatewayNativeResidentState>,
) -> Result<(), GatewayNativeServerError> {
    let mut workers = Vec::new();
    let mut result = Ok(());
    while !state.stopping.load(Ordering::Acquire) {
        if let Err(error) = reap_workers(&mut workers, state.surface) {
            result = Err(error);
            break;
        }
        match listener.accept() {
            Ok(connection) => {
                if state.stopping.load(Ordering::Acquire) {
                    let _ = connection.shutdown(Shutdown::Both);
                    break;
                }
                if !state.reserve_connection(maximum_connections) {
                    state.record_rejected_connection();
                    let _ = connection.shutdown(Shutdown::Both);
                    continue;
                }
                if connection.set_nonblocking(false).is_err() {
                    state.active_connections.fetch_sub(1, Ordering::AcqRel);
                    let _ = connection.shutdown(Shutdown::Both);
                    result = Err(state.surface.registration_error());
                    break;
                }
                let guard = match state.register_connection(&connection) {
                    Ok(guard) => guard,
                    Err(error) => {
                        state.active_connections.fetch_sub(1, Ordering::AcqRel);
                        let _ = connection.shutdown(Shutdown::Both);
                        result = Err(error);
                        break;
                    }
                };
                if state.stopping.load(Ordering::Acquire) {
                    let _ = connection.shutdown(Shutdown::Both);
                    drop(guard);
                    break;
                }
                let worker = worker.clone();
                let thread = thread::Builder::new()
                    .name(state.surface.connection_thread_name().to_string())
                    .spawn(move || {
                        let _guard = guard;
                        worker.serve(connection);
                    });
                match thread {
                    Ok(thread) => workers.push(thread),
                    Err(_) => {
                        result = Err(state.surface.worker_error());
                        break;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                result = Err(state.surface.accept_error());
                break;
            }
        }
    }
    state.stopping.store(true, Ordering::Release);
    if state.interrupt_connections().is_err() && result.is_ok() {
        result = Err(state.surface.shutdown_error());
    }
    if let Err(error) = join_workers(workers, state.surface) {
        if result.is_ok() {
            result = Err(error);
        }
    }
    result
}

// Joins every worker that has already completed without detaching the remainder.
fn reap_workers(
    workers: &mut Vec<JoinHandle<()>>,
    surface: GatewayNativeServerSurface,
) -> Result<(), GatewayNativeServerError> {
    let mut active = Vec::with_capacity(workers.len());
    let mut result = Ok(());
    for worker in workers.drain(..) {
        if worker.is_finished() {
            if worker.join().is_err() {
                result = Err(surface.worker_error());
            }
        } else {
            active.push(worker);
        }
    }
    *workers = active;
    result
}

// Joins every remaining worker before the resident supervisor can complete.
fn join_workers(
    workers: Vec<JoinHandle<()>>,
    surface: GatewayNativeServerSurface,
) -> Result<(), GatewayNativeServerError> {
    let mut result = Ok(());
    for worker in workers {
        if worker.join().is_err() {
            result = Err(surface.worker_error());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Barrier;

    use super::*;

    // Fails one accept only after the test observes that polling began.
    struct FailingAcceptor {
        accepting: Arc<Barrier>,
    }

    impl GatewayNativeAccept for FailingAcceptor {
        // Accepts nonblocking mode without consulting a native descriptor.
        fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
            Ok(())
        }

        // Synchronizes once and then returns one permanent redacted accept failure.
        fn accept(&self) -> io::Result<TcpStream> {
            self.accepting.wait();
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "secret"))
        }
    }

    // Rejects all unreachable accepted connections in the injected failure test.
    struct UnusedWorker;

    impl GatewayNativeSocketWorker for UnusedWorker {
        // Panics if the failing acceptor fabricates an impossible stream.
        fn serve(&self, _connection: TcpStream) {
            panic!("failing acceptor cannot return a connection")
        }
    }

    // Proves permanent accept failure is redacted, joined, and cached across repeated joins.
    #[test]
    fn permanent_accept_failure_is_redacted_and_joined_once() {
        let accepting = Arc::new(Barrier::new(2));
        let handle = start_gateway_native_acceptor(
            Box::new(FailingAcceptor {
                accepting: accepting.clone(),
            }),
            1,
            GatewayNativeServerSurface::Public,
            Arc::new(UnusedWorker),
        )
        .expect("start resident listener");
        accepting.wait();

        let expected = Err(GatewayNativeServerError::new(
            "public Gateway connection cannot be accepted",
        ));
        assert_eq!(handle.join(), expected);
        assert_eq!(handle.join(), expected);
        assert!(handle.stop().is_ok());
    }

    // Proves one panicked worker cannot detach another worker during final cleanup.
    #[test]
    fn worker_join_failure_still_joins_every_worker() {
        let completed = Arc::new(AtomicBool::new(false));
        let failed = thread::spawn(|| panic!("injected worker failure"));
        let worker_completed = completed.clone();
        let successful = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            worker_completed.store(true, Ordering::Release);
        });

        let result = join_workers(vec![failed, successful], GatewayNativeServerSurface::Public);

        assert_eq!(
            result,
            Err(GatewayNativeServerError::new(
                "public Gateway connection worker failed",
            ))
        );
        assert!(completed.load(Ordering::Acquire));
    }
}
