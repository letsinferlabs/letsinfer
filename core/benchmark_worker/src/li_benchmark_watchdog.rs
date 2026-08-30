// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::OpenOptions;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use li_watchdog_manager::{
    decode_watchdog_protocol_frame, decode_watchdog_protocol_response,
    encode_watchdog_protocol_frame, encode_watchdog_protocol_request, WatchdogProtocolRequest,
    WatchdogProtocolRequestKind, WatchdogProtocolResolution, WatchdogProtocolResponse,
    WatchdogProtocolResponseKind, WatchdogSample, WatchdogSampleTelemetry, WATCHDOG_CLOCK_UNKNOWN,
    WATCHDOG_PERCENT_UNKNOWN, WATCHDOG_PROTOCOL_MAX_FRAME_BYTES, WATCHDOG_TEMP_UNKNOWN,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::BenchmarkWorkerError;

const WATCHDOG_REQUEST_ID: u64 = 1;
const WATCHDOG_MINIMUM_OBSERVATION_MILLISECONDS: u64 = 2_000;
const WATCHDOG_SETTLE_MILLISECONDS: u64 = 500;
const WATCHDOG_MAXIMUM_RAW_SAMPLES: usize = 86_400;
const WATCHDOG_MAXIMUM_HISTORY_FRAMES: usize = 676;
const WATCHDOG_MAXIMUM_TLS_BYTES: u64 = 128 * 1024;

const TELEMETRY_COLUMNS: [&str; 13] = [
    "elapsed_seconds",
    "gpu_usage_percent",
    "gpu_temperature_c",
    "cpu_usage_percent",
    "cpu_temperature_c",
    "cpu_clock_mhz",
    "gpu_clock_mhz",
    "vram_clock_mhz",
    "system_ram_clock_mhz",
    "nvme_usage_percent",
    "nvme_temperature_c",
    "nvme_read_kib_per_second",
    "nvme_write_kib_per_second",
];

// Stores one explicit authenticated local Watchdog telemetry endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeBenchmarkWatchdogInput {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) server_name: String,
    pub(crate) ca_file: String,
    pub(crate) controller_cert_file: String,
    pub(crate) controller_key_file: String,
    pub(crate) timeout_milliseconds: u64,
}

impl NativeBenchmarkWatchdogInput {
    // Creates one explicit local mTLS history source without endpoint or credential discovery.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: String,
        port: u16,
        server_name: String,
        ca_file: PathBuf,
        controller_cert_file: PathBuf,
        controller_key_file: PathBuf,
        timeout: Duration,
    ) -> Result<Self, BenchmarkWorkerError> {
        let timeout_milliseconds =
            u64::try_from(timeout.as_millis()).map_err(|_| watchdog_contract_error())?;
        let configuration = Self {
            host,
            port,
            server_name,
            ca_file: path_text(ca_file)?,
            controller_cert_file: path_text(controller_cert_file)?,
            controller_key_file: path_text(controller_key_file)?,
            timeout_milliseconds,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    // Requires one loopback endpoint and three distinct absolute credential references.
    pub(crate) fn validate(&self) -> Result<(), BenchmarkWorkerError> {
        let paths = [
            Path::new(&self.ca_file),
            Path::new(&self.controller_cert_file),
            Path::new(&self.controller_key_file),
        ];
        let distinct = paths
            .iter()
            .enumerate()
            .all(|(index, path)| paths.iter().skip(index + 1).all(|other| path != other));
        if self.host != "127.0.0.1"
            || self.port == 0
            || !valid_server_name(&self.server_name)
            || paths.iter().any(|path| !safe_absolute_file(path))
            || !distinct
            || !(1..=30_000).contains(&self.timeout_milliseconds)
        {
            return Err(watchdog_contract_error());
        }
        Ok(())
    }

    // Returns the explicit loopback socket selected by the sealed input.
    fn endpoint(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port)
    }

    // Returns the complete operation timeout selected by the sealed input.
    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_milliseconds)
    }

    // Returns the explicit loopback host without performing discovery.
    pub fn host(&self) -> &str {
        &self.host
    }

    // Returns the explicit Watchdog protocol port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    // Returns the exact TLS server identity verified during handshake.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    // Returns the exact pinned Watchdog CA file.
    pub fn ca_file(&self) -> &Path {
        Path::new(&self.ca_file)
    }

    // Returns the exact controller certificate file presented to Watchdog.
    pub fn controller_cert_file(&self) -> &Path {
        Path::new(&self.controller_cert_file)
    }

    // Returns the exact controller private-key file presented to Watchdog.
    pub fn controller_key_file(&self) -> &Path {
        Path::new(&self.controller_key_file)
    }

    // Returns the complete bounded history-query timeout.
    pub fn query_timeout(&self) -> Duration {
        self.timeout()
    }
}

// Supplies wall time and bounded settling without coupling execution tests to the host clock.
pub trait NativeBenchmarkClock: Send + Sync {
    // Returns positive Unix wall time in milliseconds.
    fn unix_milliseconds(&self) -> Result<u64, BenchmarkWorkerError>;

    // Waits until one absolute Unix-millisecond boundary or fails closed.
    fn wait_until(&self, unix_milliseconds: u64) -> Result<(), BenchmarkWorkerError>;
}

// Supplies production wall time and sleeping for exact telemetry measurement windows.
pub struct SystemNativeBenchmarkClock;

impl NativeBenchmarkClock for SystemNativeBenchmarkClock {
    // Reads positive Unix wall time without narrowing the native duration.
    fn unix_milliseconds(&self) -> Result<u64, BenchmarkWorkerError> {
        system_unix_milliseconds()
    }

    // Sleeps only for the positive remainder before the requested wall-clock boundary.
    fn wait_until(&self, unix_milliseconds: u64) -> Result<(), BenchmarkWorkerError> {
        let current = system_unix_milliseconds()?;
        if unix_milliseconds > current {
            thread::sleep(Duration::from_millis(unix_milliseconds - current));
        }
        Ok(())
    }
}

// Exchanges one typed raw-history request through an injected authenticated transport.
pub trait NativeBenchmarkWatchdogTransport: Send + Sync {
    // Returns the complete ordered response stream for one exact query request.
    fn query(
        &self,
        configuration: &NativeBenchmarkWatchdogInput,
        request: &WatchdogProtocolRequest,
    ) -> Result<Vec<WatchdogProtocolResponse>, BenchmarkWorkerError>;
}

// Supplies one complete retained raw sample range to benchmark execution.
pub trait NativeBenchmarkTelemetrySource: Send + Sync {
    // Returns every ordered one-second sample inside one inclusive exact query range.
    fn query_range(
        &self,
        start_unix_milliseconds: u64,
        end_unix_milliseconds: u64,
    ) -> Result<Vec<WatchdogSample>, BenchmarkWorkerError>;
}

// Adapts typed Watchdog protocol responses into strict complete raw history.
pub struct WatchdogBenchmarkTelemetrySource {
    configuration: NativeBenchmarkWatchdogInput,
    transport: Arc<dyn NativeBenchmarkWatchdogTransport>,
}

impl WatchdogBenchmarkTelemetrySource {
    // Creates one source from an explicit endpoint and injected protocol transport.
    pub fn new(
        configuration: NativeBenchmarkWatchdogInput,
        transport: Arc<dyn NativeBenchmarkWatchdogTransport>,
    ) -> Result<Self, BenchmarkWorkerError> {
        configuration.validate()?;
        Ok(Self {
            configuration,
            transport,
        })
    }
}

impl NativeBenchmarkTelemetrySource for WatchdogBenchmarkTelemetrySource {
    // Queries raw protocol-v3 history and rejects partial, ambiguous, or gapped evidence.
    fn query_range(
        &self,
        start_unix_milliseconds: u64,
        end_unix_milliseconds: u64,
    ) -> Result<Vec<WatchdogSample>, BenchmarkWorkerError> {
        validate_query_range(start_unix_milliseconds, end_unix_milliseconds)?;
        let request = WatchdogProtocolRequest::new(
            WATCHDOG_REQUEST_ID,
            WatchdogProtocolRequestKind::QueryRange {
                start_unix_milliseconds,
                end_unix_milliseconds,
                resolution: WatchdogProtocolResolution::RawOneSecond,
            },
        )
        .map_err(|_| watchdog_contract_error())?;
        let responses = self.transport.query(&self.configuration, &request)?;
        let mut samples = Vec::new();
        let mut complete = None;
        for response in responses {
            if response.request_id() != WATCHDOG_REQUEST_ID || complete.is_some() {
                return Err(watchdog_history_error());
            }
            match response.kind() {
                WatchdogProtocolResponseKind::HistoryBatch(batch) => {
                    if samples
                        .len()
                        .checked_add(batch.len())
                        .is_none_or(|length| length > WATCHDOG_MAXIMUM_RAW_SAMPLES)
                    {
                        return Err(watchdog_history_error());
                    }
                    samples.extend(batch.iter().cloned());
                }
                WatchdogProtocolResponseKind::HistoryComplete { through_sequence } => {
                    complete = Some(*through_sequence);
                }
                WatchdogProtocolResponseKind::Gap { .. } => return Err(watchdog_history_error()),
                WatchdogProtocolResponseKind::Error { .. } => {
                    return Err(watchdog_transport_error())
                }
                _ => return Err(watchdog_history_error()),
            }
        }
        validate_history(
            &samples,
            complete.ok_or_else(watchdog_history_error)?,
            start_unix_milliseconds,
            end_unix_milliseconds,
        )?;
        Ok(samples)
    }
}

// Supplies the production TLS 1.3 mutual-authentication Watchdog transport.
pub struct SystemNativeBenchmarkWatchdogTransport {
    client: Arc<ClientConfig>,
}

impl SystemNativeBenchmarkWatchdogTransport {
    // Loads owner-only trust and controller identity material before benchmark execution.
    pub fn load(
        configuration: &NativeBenchmarkWatchdogInput,
        owner_user_id: u32,
    ) -> Result<Self, BenchmarkWorkerError> {
        configuration.validate()?;
        let ca = read_private_tls_file(Path::new(&configuration.ca_file), owner_user_id)?;
        let certificate = read_private_tls_file(
            Path::new(&configuration.controller_cert_file),
            owner_user_id,
        )?;
        let mut private_key =
            read_private_tls_file(Path::new(&configuration.controller_key_file), owner_user_id)?;
        let result = tls_client_configuration(&ca, &certificate, &private_key);
        private_key.fill(0);
        result.map(|client| Self {
            client: Arc::new(client),
        })
    }
}

impl NativeBenchmarkWatchdogTransport for SystemNativeBenchmarkWatchdogTransport {
    // Streams every bounded history frame through one authenticated local connection.
    fn query(
        &self,
        configuration: &NativeBenchmarkWatchdogInput,
        request: &WatchdogProtocolRequest,
    ) -> Result<Vec<WatchdogProtocolResponse>, BenchmarkWorkerError> {
        configuration.validate()?;
        let payload =
            encode_watchdog_protocol_request(request).map_err(|_| watchdog_contract_error())?;
        let frame =
            encode_watchdog_protocol_frame(&payload).map_err(|_| watchdog_contract_error())?;
        let deadline = Instant::now()
            .checked_add(configuration.timeout())
            .ok_or_else(watchdog_contract_error)?;
        let socket =
            TcpStream::connect_timeout(&configuration.endpoint(), remaining_duration(deadline)?)
                .map_err(|_| watchdog_transport_error())?;
        configure_socket_timeout(&socket, deadline)?;
        let server_name = ServerName::try_from(configuration.server_name.clone())
            .map_err(|_| watchdog_contract_error())?;
        let connection = ClientConnection::new(self.client.clone(), server_name)
            .map_err(|_| watchdog_transport_error())?;
        let mut stream = StreamOwned::new(connection, socket);
        complete_handshake(&mut stream, deadline)?;
        write_all(&mut stream, &frame, deadline)?;
        let mut responses = Vec::new();
        for _ in 0..WATCHDOG_MAXIMUM_HISTORY_FRAMES {
            let response = read_response(&mut stream, deadline)?;
            let terminal = matches!(
                response.kind(),
                WatchdogProtocolResponseKind::HistoryComplete { .. }
                    | WatchdogProtocolResponseKind::Gap { .. }
                    | WatchdogProtocolResponseKind::Error { .. }
            );
            responses.push(response);
            if terminal {
                let _ = stream.sock.shutdown(Shutdown::Both);
                return Ok(responses);
            }
        }
        let _ = stream.sock.shutdown(Shutdown::Both);
        Err(watchdog_transport_error())
    }
}

// Carries the exact schema-8 timeline and maxima projection for one cell.
#[derive(Debug, PartialEq)]
pub(crate) struct NativeBenchmarkTelemetrySummary {
    maxima: [Option<f64>; 12],
    samples: Vec<String>,
}

impl NativeBenchmarkTelemetrySummary {
    // Applies every oracle-compatible maximum and the non-empty timeline to one result object.
    pub(crate) fn apply(&self, result: &mut Map<String, Value>) {
        let maximum_fields = [
            "max_gpu_usage_percent",
            "max_gpu_temperature_c",
            "max_cpu_usage_percent",
            "max_cpu_temperature_c",
            "max_cpu_clock_mhz",
            "max_gpu_clock_mhz",
            "max_vram_clock_mhz",
            "max_system_ram_clock_mhz",
            "max_nvme_usage_percent",
            "max_nvme_temperature_c",
            "max_nvme_read_kib_per_second",
            "max_nvme_write_kib_per_second",
        ];
        for (index, field) in maximum_fields.iter().enumerate() {
            let value = match self.maxima[index] {
                Some(value) => json!(value),
                None if index < 4 => Value::Null,
                None => json!(-1),
            };
            result.insert((*field).to_string(), value);
        }
        result.insert(
            "telemetry".to_string(),
            json!({
                "interval_seconds": 1,
                "columns": TELEMETRY_COLUMNS,
                "samples": self.samples
            }),
        );
    }
}

// Captures one exact cell interval, settles the raw ring, and compacts its complete history.
pub(crate) fn collect_cell_telemetry(
    clock: &dyn NativeBenchmarkClock,
    source: &dyn NativeBenchmarkTelemetrySource,
    measurement_started_unix_milliseconds: u64,
    measurement_ended_unix_milliseconds: u64,
) -> Result<NativeBenchmarkTelemetrySummary, BenchmarkWorkerError> {
    if measurement_started_unix_milliseconds == 0
        || measurement_ended_unix_milliseconds < measurement_started_unix_milliseconds
    {
        return Err(watchdog_clock_error());
    }
    let observation_ended = measurement_started_unix_milliseconds
        .checked_add(WATCHDOG_MINIMUM_OBSERVATION_MILLISECONDS)
        .map(|minimum| minimum.max(measurement_ended_unix_milliseconds))
        .ok_or_else(watchdog_clock_error)?;
    let settle_until = observation_ended
        .checked_add(WATCHDOG_SETTLE_MILLISECONDS)
        .ok_or_else(watchdog_clock_error)?;
    clock.wait_until(settle_until)?;
    let samples = source.query_range(measurement_started_unix_milliseconds, observation_ended)?;
    compact_watchdog_history(&samples, measurement_started_unix_milliseconds)
}

// Compacts strict native samples exactly like benchmark_record.watchdog_summary.
fn compact_watchdog_history(
    samples: &[WatchdogSample],
    measurement_started_unix_milliseconds: u64,
) -> Result<NativeBenchmarkTelemetrySummary, BenchmarkWorkerError> {
    if samples.is_empty() {
        return Err(watchdog_history_error());
    }
    let mut compact = Vec::with_capacity(samples.len());
    let mut maxima = [None; 12];
    for sample in samples {
        let elapsed = sample
            .unix_milliseconds()
            .checked_sub(measurement_started_unix_milliseconds)
            .ok_or_else(watchdog_history_error)? as f64
            / 1_000.0;
        let values = telemetry_values(sample.telemetry())?;
        for (maximum, observed) in maxima.iter_mut().zip(values) {
            if let Some(observed) = observed {
                *maximum = Some(maximum.map_or(observed, |current: f64| current.max(observed)));
            }
        }
        let mut fields = Vec::with_capacity(TELEMETRY_COLUMNS.len());
        fields.push(compact_number(elapsed));
        fields.extend(values.map(|value| value.map_or_else(String::new, compact_number)));
        compact.push(fields.join(","));
    }
    Ok(NativeBenchmarkTelemetrySummary {
        maxima,
        samples: compact,
    })
}

// Projects one complete Watchdog sample into the schema-8 telemetry column order.
fn telemetry_values(
    telemetry: &WatchdogSampleTelemetry,
) -> Result<[Option<f64>; 12], BenchmarkWorkerError> {
    let gpu_usage = percent_value(telemetry.gpu_percent)?;
    let cpu_usage = percent_value(telemetry.cpu_percent)?;
    let gpu_temperature = temperature_value(telemetry.gpu_temp_deci_c, false)?;
    let cpu_temperature = temperature_value(telemetry.system_temp_deci_c, false)?;
    let nvme_usage = percent_value(telemetry.disk_percent)?;
    let nvme_temperature = temperature_value(telemetry.nvme_temp_deci_c, true)?;
    let values = [
        gpu_usage,
        gpu_temperature,
        cpu_usage,
        cpu_temperature,
        clock_value(telemetry.cpu_clock_mhz)?,
        clock_value(telemetry.gpu_clock_mhz)?,
        clock_value(telemetry.vram_clock_mhz)?,
        clock_value(telemetry.system_ram_clock_mhz)?,
        nvme_usage,
        nvme_temperature,
        Some(f64::from(telemetry.disk_read_kib_s)),
        Some(f64::from(telemetry.disk_write_kib_s)),
    ];
    Ok(values)
}

// Converts one native utilization percentage while preserving its unknown sentinel.
fn percent_value(value: u8) -> Result<Option<f64>, BenchmarkWorkerError> {
    if value == WATCHDOG_PERCENT_UNKNOWN {
        Ok(None)
    } else if value <= 100 {
        Ok(Some(f64::from(value)))
    } else {
        Err(watchdog_history_error())
    }
}

// Converts one native deci-Celsius temperature while preserving oracle unknown semantics.
fn temperature_value(value: i16, nvme: bool) -> Result<Option<f64>, BenchmarkWorkerError> {
    if value == WATCHDOG_TEMP_UNKNOWN || (nvme && value == -1) {
        Ok(None)
    } else if (-1_000..=2_500).contains(&value) {
        Ok(Some(f64::from(value) / 10.0))
    } else {
        Err(watchdog_history_error())
    }
}

// Converts one positive native MHz value while preserving its unknown sentinel.
fn clock_value(value: u32) -> Result<Option<f64>, BenchmarkWorkerError> {
    if value == WATCHDOG_CLOCK_UNKNOWN {
        Ok(None)
    } else if value > 0 {
        Ok(Some(f64::from(value)))
    } else {
        Err(watchdog_history_error())
    }
}

// Formats one finite timeline value to the oracle's compact three-decimal representation.
fn compact_number(value: f64) -> String {
    let mut value = format!("{value:.3}");
    while value.contains('.') && value.ends_with('0') {
        value.pop();
    }
    if value.ends_with('.') {
        value.pop();
    }
    value
}

// Validates one inclusive raw query against the resident 24-hour ring bound.
fn validate_query_range(
    start_unix_milliseconds: u64,
    end_unix_milliseconds: u64,
) -> Result<(), BenchmarkWorkerError> {
    let bucket_count = end_unix_milliseconds
        .checked_div(1_000)
        .and_then(|end| end.checked_sub(start_unix_milliseconds / 1_000))
        .and_then(|difference| difference.checked_add(1));
    if start_unix_milliseconds == 0
        || end_unix_milliseconds < start_unix_milliseconds
        || bucket_count.is_none_or(|count| count > WATCHDOG_MAXIMUM_RAW_SAMPLES as u64)
    {
        return Err(watchdog_contract_error());
    }
    Ok(())
}

// Validates complete non-empty history with no duplicate, internal gap, or range drift.
fn validate_history(
    samples: &[WatchdogSample],
    through_sequence: u64,
    start_unix_milliseconds: u64,
    end_unix_milliseconds: u64,
) -> Result<(), BenchmarkWorkerError> {
    let Some(last) = samples.last() else {
        return Err(watchdog_history_error());
    };
    if samples.len() > WATCHDOG_MAXIMUM_RAW_SAMPLES
        || through_sequence < last.sequence()
        || samples.iter().any(|sample| {
            sample.unix_milliseconds() < start_unix_milliseconds
                || sample.unix_milliseconds() > end_unix_milliseconds
        })
    {
        return Err(watchdog_history_error());
    }
    for pair in samples.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if previous.sequence().checked_add(1) != Some(current.sequence())
            || current.unix_milliseconds() <= previous.unix_milliseconds()
            || current.unix_milliseconds() / 1_000 > previous.unix_milliseconds() / 1_000 + 1
        {
            return Err(watchdog_history_error());
        }
    }
    Ok(())
}

// Loads one bounded single-link owner-private TLS file without following its final path.
fn read_private_tls_file(path: &Path, owner_user_id: u32) -> Result<Vec<u8>, BenchmarkWorkerError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| watchdog_transport_error())?;
    let metadata = file.metadata().map_err(|_| watchdog_transport_error())?;
    if !metadata.is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > WATCHDOG_MAXIMUM_TLS_BYTES
    {
        return Err(watchdog_transport_error());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| watchdog_transport_error())?;
    if bytes.len() as u64 != metadata.len() {
        bytes.fill(0);
        return Err(watchdog_transport_error());
    }
    Ok(bytes)
}

// Builds one TLS 1.3 client from an exact CA and controller certificate/key set.
fn tls_client_configuration(
    ca: &[u8],
    controller_certificate: &[u8],
    controller_private_key: &[u8],
) -> Result<ClientConfig, BenchmarkWorkerError> {
    let ca_certificates = pem_certificates(ca)?;
    let controller_certificates = pem_certificates(controller_certificate)?;
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(controller_private_key))
        .map_err(|_| watchdog_transport_error())?
        .ok_or_else(watchdog_transport_error)?;
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(ca_certificates);
    if added == 0 || ignored != 0 || controller_certificates.is_empty() {
        return Err(watchdog_transport_error());
    }
    ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(controller_certificates, private_key)
        .map_err(|_| watchdog_transport_error())
}

// Parses every PEM certificate without admitting malformed or partial input.
fn pem_certificates(
    source: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, BenchmarkWorkerError> {
    rustls_pemfile::certs(&mut Cursor::new(source))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| watchdog_transport_error())
}

// Completes the client handshake under one absolute operation deadline.
fn complete_handshake(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Instant,
) -> Result<(), BenchmarkWorkerError> {
    while stream.conn.is_handshaking() {
        configure_socket_timeout(&stream.sock, deadline)?;
        let progress = stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|_| watchdog_transport_error())?;
        if progress == (0, 0) && stream.conn.is_handshaking() {
            return Err(watchdog_transport_error());
        }
    }
    Ok(())
}

// Writes one complete framed query while reapplying the shared deadline.
fn write_all(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    source: &[u8],
    deadline: Instant,
) -> Result<(), BenchmarkWorkerError> {
    let mut offset = 0;
    while offset < source.len() {
        configure_socket_timeout(&stream.sock, deadline)?;
        match stream.write(&source[offset..]) {
            Ok(0) => return Err(watchdog_transport_error()),
            Ok(count) if count <= source.len() - offset => offset += count,
            Ok(_) => return Err(watchdog_transport_error()),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(watchdog_transport_error()),
        }
    }
    configure_socket_timeout(&stream.sock, deadline)?;
    stream.flush().map_err(|_| watchdog_transport_error())
}

// Reads and decodes one bounded framed response under the shared deadline.
fn read_response(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Instant,
) -> Result<WatchdogProtocolResponse, BenchmarkWorkerError> {
    let mut header = [0_u8; 4];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > WATCHDOG_PROTOCOL_MAX_FRAME_BYTES {
        return Err(watchdog_transport_error());
    }
    let mut frame = vec![0_u8; length + 4];
    frame[..4].copy_from_slice(&header);
    read_exact(stream, &mut frame[4..], deadline)?;
    let payload = decode_watchdog_protocol_frame(&frame).map_err(|_| watchdog_transport_error())?;
    decode_watchdog_protocol_response(payload).map_err(|_| watchdog_transport_error())
}

// Reads every requested byte while preserving the one absolute deadline.
fn read_exact(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    destination: &mut [u8],
    deadline: Instant,
) -> Result<(), BenchmarkWorkerError> {
    let mut offset = 0;
    while offset < destination.len() {
        configure_socket_timeout(&stream.sock, deadline)?;
        match stream.read(&mut destination[offset..]) {
            Ok(0) => return Err(watchdog_transport_error()),
            Ok(count) if count <= destination.len() - offset => offset += count,
            Ok(_) => return Err(watchdog_transport_error()),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(watchdog_transport_error()),
        }
    }
    Ok(())
}

// Applies the positive remaining operation duration to both socket directions.
fn configure_socket_timeout(
    socket: &TcpStream,
    deadline: Instant,
) -> Result<(), BenchmarkWorkerError> {
    let remaining = remaining_duration(deadline)?;
    socket
        .set_read_timeout(Some(remaining))
        .and_then(|()| socket.set_write_timeout(Some(remaining)))
        .map_err(|_| watchdog_transport_error())
}

// Returns the positive remainder before one monotonic deadline.
fn remaining_duration(deadline: Instant) -> Result<Duration, BenchmarkWorkerError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(watchdog_transport_error)
}

// Reads positive wall time in Unix milliseconds with checked narrowing.
fn system_unix_milliseconds() -> Result<u64, BenchmarkWorkerError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| watchdog_clock_error())?
        .as_millis();
    u64::try_from(milliseconds)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(watchdog_clock_error)
}

// Returns whether one explicit TLS name is a bounded canonical DNS or IP identity.
fn valid_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
        && ServerName::try_from(value.to_string()).is_ok()
}

// Returns whether one path is absolute, bounded, and free of parent traversal.
fn safe_absolute_file(value: &Path) -> bool {
    value.as_os_str().len() <= 4_096
        && value.is_absolute()
        && value
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && value.file_name().is_some()
}

// Converts one explicit UTF-8 path into its sealed wire representation.
fn path_text(value: PathBuf) -> Result<String, BenchmarkWorkerError> {
    value
        .into_os_string()
        .into_string()
        .map_err(|_| watchdog_contract_error())
}

// Returns one stable explicit Watchdog configuration failure.
const fn watchdog_contract_error() -> BenchmarkWorkerError {
    BenchmarkWorkerError::invalid("benchmark Watchdog configuration is invalid")
}

// Returns one stable wall-clock or settlement failure.
const fn watchdog_clock_error() -> BenchmarkWorkerError {
    BenchmarkWorkerError::invalid("benchmark telemetry clock failed")
}

// Returns one stable authenticated Watchdog transport failure.
const fn watchdog_transport_error() -> BenchmarkWorkerError {
    BenchmarkWorkerError::invalid("benchmark Watchdog telemetry transport failed")
}

// Returns one stable incomplete, ambiguous, or gapped history failure.
const fn watchdog_history_error() -> BenchmarkWorkerError {
    BenchmarkWorkerError::invalid("benchmark Watchdog telemetry history is incomplete")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Retains deterministic typed responses and records every raw range request.
    struct MockWatchdogTransport {
        responses: Result<Vec<WatchdogProtocolResponse>, BenchmarkWorkerError>,
        queries: Mutex<Vec<(u64, u64, WatchdogProtocolResolution)>>,
    }

    impl MockWatchdogTransport {
        // Creates one deterministic successful or failed protocol transport.
        fn new(responses: Result<Vec<WatchdogProtocolResponse>, BenchmarkWorkerError>) -> Self {
            Self {
                responses,
                queries: Mutex::new(Vec::new()),
            }
        }
    }

    impl NativeBenchmarkWatchdogTransport for MockWatchdogTransport {
        // Records the exact typed request before replaying configured responses.
        fn query(
            &self,
            _configuration: &NativeBenchmarkWatchdogInput,
            request: &WatchdogProtocolRequest,
        ) -> Result<Vec<WatchdogProtocolResponse>, BenchmarkWorkerError> {
            let WatchdogProtocolRequestKind::QueryRange {
                start_unix_milliseconds,
                end_unix_milliseconds,
                resolution,
            } = request.kind()
            else {
                return Err(watchdog_contract_error());
            };
            self.queries.lock().expect("queries").push((
                *start_unix_milliseconds,
                *end_unix_milliseconds,
                *resolution,
            ));
            self.responses.clone()
        }
    }

    // Records settlement and creates equivalent telemetry for every absolute replay window.
    struct MockTimeAndSource {
        waits: Mutex<Vec<u64>>,
        queries: Mutex<Vec<(u64, u64)>>,
    }

    impl MockTimeAndSource {
        // Creates one empty deterministic time and history observation log.
        fn new() -> Self {
            Self {
                waits: Mutex::new(Vec::new()),
                queries: Mutex::new(Vec::new()),
            }
        }
    }

    impl NativeBenchmarkClock for MockTimeAndSource {
        // Provides one unused positive wall-clock value for trait completeness.
        fn unix_milliseconds(&self) -> Result<u64, BenchmarkWorkerError> {
            Ok(1)
        }

        // Records the exact settlement boundary without consuming wall time.
        fn wait_until(&self, unix_milliseconds: u64) -> Result<(), BenchmarkWorkerError> {
            self.waits.lock().expect("waits").push(unix_milliseconds);
            Ok(())
        }
    }

    impl NativeBenchmarkTelemetrySource for MockTimeAndSource {
        // Returns the same relative one-second values for every absolute replay window.
        fn query_range(
            &self,
            start_unix_milliseconds: u64,
            end_unix_milliseconds: u64,
        ) -> Result<Vec<WatchdogSample>, BenchmarkWorkerError> {
            self.queries
                .lock()
                .expect("queries")
                .push((start_unix_milliseconds, end_unix_milliseconds));
            [0_u64, 1_000, 2_000]
                .into_iter()
                .enumerate()
                .map(|(index, offset)| {
                    sample(index as u64 + 1, start_unix_milliseconds + offset, 0)
                })
                .collect()
        }
    }

    // Creates one explicit local endpoint fixture without touching its credential files.
    fn configuration() -> NativeBenchmarkWatchdogInput {
        NativeBenchmarkWatchdogInput::new(
            "127.0.0.1".to_string(),
            9443,
            "localhost".to_string(),
            PathBuf::from("/private/tmp/watchdog-ca.pem"),
            PathBuf::from("/private/tmp/watchdog-controller.pem"),
            PathBuf::from("/private/tmp/watchdog-controller.key"),
            Duration::from_secs(1),
        )
        .expect("configuration")
    }

    // Creates one complete Watchdog sample with an optional deterministic metric increase.
    fn sample(
        sequence: u64,
        unix_milliseconds: u64,
        increase: u8,
    ) -> Result<WatchdogSample, BenchmarkWorkerError> {
        WatchdogSample::with_telemetry(
            sequence,
            unix_milliseconds,
            sequence,
            WatchdogSampleTelemetry {
                cpu_percent: 40 + increase,
                gpu_percent: 80 + increase,
                disk_percent: 12 + increase,
                system_temp_deci_c: 500 + i16::from(increase),
                gpu_temp_deci_c: 600 + i16::from(increase),
                nvme_temp_deci_c: 410 + i16::from(increase),
                disk_read_kib_s: 100 + u32::from(increase),
                disk_write_kib_s: 50 + u32::from(increase),
                cpu_clock_mhz: 3_200 + u32::from(increase),
                gpu_clock_mhz: 1_500 + u32::from(increase),
                vram_clock_mhz: 2_000 + u32::from(increase),
                system_ram_clock_mhz: 4_800 + u32::from(increase),
                ..WatchdogSampleTelemetry::default()
            },
        )
        .map_err(|_| watchdog_history_error())
    }

    // Creates one closed typed response stream for the selected samples.
    fn responses(samples: Vec<WatchdogSample>) -> Vec<WatchdogProtocolResponse> {
        let through = samples.last().map_or(1, WatchdogSample::sequence);
        vec![
            WatchdogProtocolResponse::new(
                WATCHDOG_REQUEST_ID,
                WatchdogProtocolResponseKind::HistoryBatch(samples),
            )
            .expect("batch"),
            WatchdogProtocolResponse::new(
                WATCHDOG_REQUEST_ID,
                WatchdogProtocolResponseKind::HistoryComplete {
                    through_sequence: through,
                },
            )
            .expect("complete"),
        ]
    }

    // Matches the Python oracle's raw query, compact timeline, and exact maxima projection.
    #[test]
    fn watchdog_history_matches_oracle_timeline_and_maxima() {
        let transport = Arc::new(MockWatchdogTransport::new(Ok(responses(vec![
            sample(7, 1_000, 0).expect("first"),
            sample(8, 2_000, 5).expect("second"),
            sample(9, 3_000, 2).expect("third"),
        ]))));
        let source = WatchdogBenchmarkTelemetrySource::new(configuration(), transport.clone())
            .expect("source");
        let samples = source.query_range(1_000, 3_000).expect("history");
        assert_eq!(
            transport.queries.lock().expect("queries").as_slice(),
            [(1_000, 3_000, WatchdogProtocolResolution::RawOneSecond)]
        );
        let summary = compact_watchdog_history(&samples, 1_000).expect("summary");
        assert_eq!(
            summary.samples,
            [
                "0,80,60,40,50,3200,1500,2000,4800,12,41,100,50",
                "1,85,60.5,45,50.5,3205,1505,2005,4805,17,41.5,105,55",
                "2,82,60.2,42,50.2,3202,1502,2002,4802,14,41.2,102,52"
            ]
        );
        let mut result = Map::new();
        summary.apply(&mut result);
        assert_eq!(result["max_gpu_usage_percent"], 85.0);
        assert_eq!(result["max_gpu_temperature_c"], 60.5);
        assert_eq!(result["max_cpu_clock_mhz"], 3_205.0);
        assert_eq!(result["max_nvme_write_kib_per_second"], 55.0);
        assert_eq!(result["telemetry"]["interval_seconds"], 1);
    }

    // Fails closed for provider failure, protocol gaps, empty history, duplicates, and drift.
    #[test]
    fn watchdog_history_rejects_incomplete_and_failed_flows() {
        let provider = Arc::new(MockWatchdogTransport::new(Err(watchdog_transport_error())));
        let source = WatchdogBenchmarkTelemetrySource::new(configuration(), provider)
            .expect("provider source");
        assert_eq!(
            source
                .query_range(1_000, 3_000)
                .expect_err("provider")
                .reason(),
            "benchmark Watchdog telemetry transport failed"
        );

        let gap = vec![WatchdogProtocolResponse::new(
            WATCHDOG_REQUEST_ID,
            WatchdogProtocolResponseKind::Gap {
                first_missing_sequence: 8,
                latest_sequence: 9,
            },
        )
        .expect("gap")];
        let cases = [
            gap,
            vec![WatchdogProtocolResponse::new(
                WATCHDOG_REQUEST_ID,
                WatchdogProtocolResponseKind::HistoryComplete {
                    through_sequence: 9,
                },
            )
            .expect("empty")],
            responses(vec![
                sample(7, 1_000, 0).expect("duplicate first"),
                sample(7, 2_000, 0).expect("duplicate second"),
            ]),
            responses(vec![
                sample(7, 1_000, 0).expect("gap first"),
                sample(9, 2_000, 0).expect("gap second"),
            ]),
            responses(vec![sample(7, 4_000, 0).expect("outside")]),
        ];
        for case in cases {
            let source = WatchdogBenchmarkTelemetrySource::new(
                configuration(),
                Arc::new(MockWatchdogTransport::new(Ok(case))),
            )
            .expect("source");
            assert_eq!(
                source
                    .query_range(1_000, 3_000)
                    .expect_err("incomplete")
                    .reason(),
                "benchmark Watchdog telemetry history is incomplete"
            );
        }
    }

    // Replays identical relative evidence while enforcing settlement and retained-range bounds.
    #[test]
    fn watchdog_measurement_replays_with_injected_time_and_bounds() {
        let source = MockTimeAndSource::new();
        let first = collect_cell_telemetry(&source, &source, 1_000, 1_500).expect("first");
        let second = collect_cell_telemetry(&source, &source, 10_000, 10_500).expect("replay");
        assert_eq!(first, second);
        assert_eq!(
            source.waits.lock().expect("waits").as_slice(),
            [3_500, 12_500]
        );
        assert_eq!(
            source.queries.lock().expect("queries").as_slice(),
            [(1_000, 3_000), (10_000, 12_000)]
        );

        let transport = Arc::new(MockWatchdogTransport::new(Ok(Vec::new())));
        let history = WatchdogBenchmarkTelemetrySource::new(configuration(), transport.clone())
            .expect("history");
        assert!(history.query_range(0, 1).is_err());
        assert!(history.query_range(2, 1).is_err());
        assert!(history.query_range(1_000, 86_401_000).is_err());
        assert!(transport.queries.lock().expect("queries").is_empty());
    }
}
