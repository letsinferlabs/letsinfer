// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    WatchdogError, WatchdogProtocolResidentLifecycle, WatchdogProtocolResidentStatus,
    WatchdogSample, WatchdogSampleTelemetry, WATCHDOG_GPU_ENGINES, WATCHDOG_MAX_CPU_CORES,
};
use li_core_interface::{InstallationId, NodeId, Sha256Digest};

pub const WATCHDOG_PROTOCOL_VERSION: u32 = 3;
pub const WATCHDOG_PROTOCOL_MAX_FRAME_BYTES: usize = 65_536;
pub const WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES: usize = 128;

const MAX_PROTOBUF_FIELDS: usize = 256;
const MAX_ERROR_MESSAGE_BYTES: usize = 500;
const MAX_STATUS_TEXT_BYTES: usize = 127;

// Identifies one retained telemetry resolution in protocol version three.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogProtocolResolution {
    RawOneSecond,
    OneMinute,
    FifteenMinutes,
}

impl WatchdogProtocolResolution {
    // Returns the exact protobuf enum value used by the C protocol.
    const fn wire_value(self) -> u64 {
        match self {
            Self::RawOneSecond => 1,
            Self::OneMinute => 2,
            Self::FifteenMinutes => 3,
        }
    }

    // Parses one closed protobuf enum value.
    fn from_wire(value: u64) -> Result<Self, WatchdogError> {
        match value {
            1 => Ok(Self::RawOneSecond),
            2 => Ok(Self::OneMinute),
            3 => Ok(Self::FifteenMinutes),
            _ => Err(protocol_error("telemetry resolution is unsupported")),
        }
    }
}

// Describes one closed request payload accepted by protocol version three.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogProtocolRequestKind {
    GetLatest,
    Subscribe {
        history_seconds: u32,
    },
    QueryRange {
        start_unix_milliseconds: u64,
        end_unix_milliseconds: u64,
        resolution: WatchdogProtocolResolution,
    },
    GetCapabilities,
    Ping {
        nonce: u64,
    },
    GetSiteStatus,
    GetResidentStatus,
}

// Binds one caller request identity to exactly one protocol operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtocolRequest {
    request_id: u64,
    kind: WatchdogProtocolRequestKind,
}

impl WatchdogProtocolRequest {
    // Creates one request after validating operation-specific ordering.
    pub fn new(request_id: u64, kind: WatchdogProtocolRequestKind) -> Result<Self, WatchdogError> {
        if let WatchdogProtocolRequestKind::QueryRange {
            start_unix_milliseconds,
            end_unix_milliseconds,
            ..
        } = &kind
        {
            if end_unix_milliseconds < start_unix_milliseconds {
                return Err(protocol_error("telemetry query range is reversed"));
            }
        }
        Ok(Self { request_id, kind })
    }

    // Returns the caller-selected request identity.
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    // Returns the exact typed request operation.
    pub const fn kind(&self) -> &WatchdogProtocolRequestKind {
        &self.kind
    }
}

// Carries the fixed protocol capability response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtocolCapabilities {
    sample_interval_milliseconds: u32,
    flush_interval_milliseconds: u32,
    physical_gpu_count: u32,
}

impl WatchdogProtocolCapabilities {
    // Creates one positive sampling and flush contract for protocol version three.
    pub fn new(
        sample_interval_milliseconds: u32,
        flush_interval_milliseconds: u32,
        physical_gpu_count: u32,
    ) -> Result<Self, WatchdogError> {
        if sample_interval_milliseconds == 0 || flush_interval_milliseconds == 0 {
            return Err(protocol_error("protocol intervals must be positive"));
        }
        Ok(Self {
            sample_interval_milliseconds,
            flush_interval_milliseconds,
            physical_gpu_count,
        })
    }

    // Returns the native sampling interval.
    pub const fn sample_interval_milliseconds(&self) -> u32 {
        self.sample_interval_milliseconds
    }

    // Returns the durable flush interval.
    pub const fn flush_interval_milliseconds(&self) -> u32 {
        self.flush_interval_milliseconds
    }

    // Returns the number of physical GPUs visible to the provider.
    pub const fn physical_gpu_count(&self) -> u32 {
        self.physical_gpu_count
    }
}

// Carries the established site status fields returned by the C server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtocolSiteStatus {
    release: String,
    model: String,
    engine: String,
    runtime_name: String,
    runtime_version: String,
    manifest_sha256: String,
    cache_provider: String,
    cache_persistent: bool,
    inference_port: u32,
    maximum_connections: u32,
    maximum_active_requests: u32,
    maximum_context_tokens: u32,
    service_state: String,
    engine_state: String,
    protection_phase: String,
    protection_armed: bool,
    trip_latched: bool,
    container_name: String,
    installation_id: String,
}

impl WatchdogProtocolSiteStatus {
    // Creates one closed status document from the exact protocol-v3 field set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        release: String,
        model: String,
        engine: String,
        runtime_name: String,
        runtime_version: String,
        manifest_sha256: String,
        cache_provider: String,
        cache_persistent: bool,
        inference_port: u32,
        maximum_connections: u32,
        maximum_active_requests: u32,
        maximum_context_tokens: u32,
        service_state: String,
        engine_state: String,
        protection_phase: String,
        protection_armed: bool,
        trip_latched: bool,
        container_name: String,
        installation_id: String,
    ) -> Result<Self, WatchdogError> {
        for value in [
            &release,
            &model,
            &engine,
            &runtime_name,
            &runtime_version,
            &cache_provider,
            &service_state,
            &engine_state,
            &protection_phase,
        ] {
            validate_status_text(value)?;
        }
        if !container_name.is_empty() {
            validate_status_text(&container_name)?;
        }
        validate_lower_hex(&manifest_sha256, 64, "manifest digest is invalid")?;
        validate_lower_hex(&installation_id, 64, "installation identity is invalid")?;
        if !(1..=65_535).contains(&inference_port)
            || maximum_connections == 0
            || maximum_active_requests == 0
            || maximum_context_tokens == 0
        {
            return Err(protocol_error("site status capacity is invalid"));
        }
        Ok(Self {
            release,
            model,
            engine,
            runtime_name,
            runtime_version,
            manifest_sha256,
            cache_provider,
            cache_persistent,
            inference_port,
            maximum_connections,
            maximum_active_requests,
            maximum_context_tokens,
            service_state,
            engine_state,
            protection_phase,
            protection_armed,
            trip_latched,
            container_name,
            installation_id,
        })
    }

    // Returns the exact Core release identity.
    pub fn release(&self) -> &str {
        &self.release
    }

    // Returns the logical model name.
    pub fn model(&self) -> &str {
        &self.model
    }

    // Returns the serving engine identity.
    pub fn engine(&self) -> &str {
        &self.engine
    }

    // Returns the runtime candidate identity.
    pub fn runtime_name(&self) -> &str {
        &self.runtime_name
    }

    // Returns the runtime version.
    pub fn runtime_version(&self) -> &str {
        &self.runtime_version
    }

    // Returns the exact runtime manifest digest.
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    // Returns the selected cache provider.
    pub fn cache_provider(&self) -> &str {
        &self.cache_provider
    }

    // Returns whether the runtime cache is persistent.
    pub const fn cache_persistent(&self) -> bool {
        self.cache_persistent
    }

    // Returns the private inference endpoint port.
    pub const fn inference_port(&self) -> u32 {
        self.inference_port
    }

    // Returns the runtime connection bound.
    pub const fn maximum_connections(&self) -> u32 {
        self.maximum_connections
    }

    // Returns the active request bound.
    pub const fn maximum_active_requests(&self) -> u32 {
        self.maximum_active_requests
    }

    // Returns the context-token bound.
    pub const fn maximum_context_tokens(&self) -> u32 {
        self.maximum_context_tokens
    }

    // Returns the placement-group service state.
    pub fn service_state(&self) -> &str {
        &self.service_state
    }

    // Returns the selected engine placement state.
    pub fn engine_state(&self) -> &str {
        &self.engine_state
    }

    // Returns the current placement protection phase.
    pub fn protection_phase(&self) -> &str {
        &self.protection_phase
    }

    // Returns whether process protection is armed.
    pub const fn protection_armed(&self) -> bool {
        self.protection_armed
    }

    // Returns whether a protection trip remains latched.
    pub const fn trip_latched(&self) -> bool {
        self.trip_latched
    }

    // Returns the exact protected container name.
    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    // Returns the exact Core installation identity.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }
}

// Describes exactly one response payload inside a protocol-v3 envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogProtocolResponseKind {
    Latest(WatchdogSample),
    HistoryBatch(Vec<WatchdogSample>),
    HistoryComplete {
        through_sequence: u64,
    },
    Live(WatchdogSample),
    Capabilities(WatchdogProtocolCapabilities),
    Gap {
        first_missing_sequence: u64,
        latest_sequence: u64,
    },
    Error {
        code: u32,
        message: String,
    },
    Pong {
        nonce: u64,
    },
    SiteStatus(WatchdogProtocolSiteStatus),
    ResidentStatus(WatchdogProtocolResidentStatus),
}

// Binds one response body to the request it completes or streams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtocolResponse {
    request_id: u64,
    kind: WatchdogProtocolResponseKind,
}

impl WatchdogProtocolResponse {
    // Creates one response after validating bounded body-specific invariants.
    pub fn new(request_id: u64, kind: WatchdogProtocolResponseKind) -> Result<Self, WatchdogError> {
        match &kind {
            WatchdogProtocolResponseKind::HistoryBatch(samples)
                if samples.is_empty() || samples.len() > WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES =>
            {
                return Err(protocol_error("history batch size is invalid"))
            }
            WatchdogProtocolResponseKind::Gap {
                first_missing_sequence,
                latest_sequence,
            } if *first_missing_sequence == 0 || *latest_sequence < *first_missing_sequence => {
                return Err(protocol_error("telemetry gap range is invalid"))
            }
            WatchdogProtocolResponseKind::Error { code, message }
                if *code == 0
                    || message.is_empty()
                    || message.len() > MAX_ERROR_MESSAGE_BYTES
                    || message.bytes().any(|byte| byte.is_ascii_control()) =>
            {
                return Err(protocol_error("protocol error body is invalid"))
            }
            _ => {}
        }
        Ok(Self { request_id, kind })
    }

    // Returns the request identity carried by the envelope.
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    // Returns the exact typed response body.
    pub const fn kind(&self) -> &WatchdogProtocolResponseKind {
        &self.kind
    }
}

// Encodes one typed request using the exact protocol-v3 field identities.
pub fn encode_watchdog_protocol_request(
    request: &WatchdogProtocolRequest,
) -> Result<Vec<u8>, WatchdogError> {
    let (field, nested) = match request.kind() {
        WatchdogProtocolRequestKind::GetLatest => (10, Vec::new()),
        WatchdogProtocolRequestKind::Subscribe { history_seconds } => {
            let mut nested = ProtobufWriter::new(WATCHDOG_PROTOCOL_MAX_FRAME_BYTES);
            nested.write_uint(1, u64::from(*history_seconds))?;
            (11, nested.finish()?)
        }
        WatchdogProtocolRequestKind::QueryRange {
            start_unix_milliseconds,
            end_unix_milliseconds,
            resolution,
        } => {
            if end_unix_milliseconds < start_unix_milliseconds {
                return Err(protocol_error("telemetry query range is reversed"));
            }
            let mut nested = ProtobufWriter::new(WATCHDOG_PROTOCOL_MAX_FRAME_BYTES);
            nested.write_uint(1, *start_unix_milliseconds)?;
            nested.write_uint(2, *end_unix_milliseconds)?;
            nested.write_uint(3, resolution.wire_value())?;
            (12, nested.finish()?)
        }
        WatchdogProtocolRequestKind::GetCapabilities => (13, Vec::new()),
        WatchdogProtocolRequestKind::Ping { nonce } => {
            let mut nested = ProtobufWriter::new(WATCHDOG_PROTOCOL_MAX_FRAME_BYTES);
            nested.write_uint(1, *nonce)?;
            (14, nested.finish()?)
        }
        WatchdogProtocolRequestKind::GetSiteStatus => (15, Vec::new()),
        WatchdogProtocolRequestKind::GetResidentStatus => (16, Vec::new()),
    };
    let mut writer = ProtobufWriter::new(WATCHDOG_PROTOCOL_MAX_FRAME_BYTES);
    if request.request_id() != 0 {
        writer.write_uint(1, request.request_id())?;
    }
    writer.write_message(field, &nested)?;
    writer.finish()
}

// Decodes one closed protocol-v3 request and rejects every unknown or duplicate field.
pub fn decode_watchdog_protocol_request(
    payload: &[u8],
) -> Result<WatchdogProtocolRequest, WatchdogError> {
    validate_payload_size(payload)?;
    let fields = parse_protobuf_fields(payload)?;
    reject_unknown_fields(&fields, &[1, 10, 11, 12, 13, 14, 15, 16])?;
    let request_id = optional_unique_uint(&fields, 1)?.unwrap_or(0);
    let bodies = fields
        .iter()
        .filter(|field| (10..=16).contains(&field.number))
        .collect::<Vec<_>>();
    if bodies.len() != 1 {
        return Err(protocol_error("request must contain exactly one operation"));
    }
    let body = message_value(bodies[0])?;
    let kind = match bodies[0].number {
        10 => {
            require_empty_message(body)?;
            WatchdogProtocolRequestKind::GetLatest
        }
        11 => decode_subscribe_request(body)?,
        12 => decode_query_request(body)?,
        13 => {
            require_empty_message(body)?;
            WatchdogProtocolRequestKind::GetCapabilities
        }
        14 => decode_ping_request(body)?,
        15 => {
            require_empty_message(body)?;
            WatchdogProtocolRequestKind::GetSiteStatus
        }
        16 => {
            require_empty_message(body)?;
            WatchdogProtocolRequestKind::GetResidentStatus
        }
        _ => return Err(protocol_error("request operation is unsupported")),
    };
    WatchdogProtocolRequest::new(request_id, kind)
}

// Encodes one typed response using the exact protocol-v3 field identities.
pub fn encode_watchdog_protocol_response(
    response: &WatchdogProtocolResponse,
) -> Result<Vec<u8>, WatchdogError> {
    let (field, body) = match response.kind() {
        WatchdogProtocolResponseKind::Latest(sample) => (10, encode_telemetry(sample)?),
        WatchdogProtocolResponseKind::HistoryBatch(samples) => {
            if samples.is_empty() || samples.len() > WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES {
                return Err(protocol_error("history batch size is invalid"));
            }
            let mut body = ProtobufWriter::new(WATCHDOG_PROTOCOL_MAX_FRAME_BYTES - 32);
            for sample in samples {
                body.write_message(1, &encode_telemetry(sample)?)?;
            }
            (11, body.finish()?)
        }
        WatchdogProtocolResponseKind::HistoryComplete { through_sequence } => {
            let mut body = ProtobufWriter::new(16);
            body.write_uint(1, *through_sequence)?;
            (12, body.finish()?)
        }
        WatchdogProtocolResponseKind::Live(sample) => (13, encode_telemetry(sample)?),
        WatchdogProtocolResponseKind::Capabilities(capabilities) => {
            (14, encode_capabilities(capabilities)?)
        }
        WatchdogProtocolResponseKind::Gap {
            first_missing_sequence,
            latest_sequence,
        } => {
            if *first_missing_sequence == 0 || latest_sequence < first_missing_sequence {
                return Err(protocol_error("telemetry gap range is invalid"));
            }
            let mut body = ProtobufWriter::new(32);
            body.write_uint(1, *first_missing_sequence)?;
            body.write_uint(2, *latest_sequence)?;
            (15, body.finish()?)
        }
        WatchdogProtocolResponseKind::Error { code, message } => {
            if *code == 0
                || message.is_empty()
                || message.len() > MAX_ERROR_MESSAGE_BYTES
                || message.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(protocol_error("protocol error body is invalid"));
            }
            let mut body = ProtobufWriter::new(512);
            body.write_uint(1, u64::from(*code))?;
            body.write_message(2, message.as_bytes())?;
            (16, body.finish()?)
        }
        WatchdogProtocolResponseKind::Pong { nonce } => {
            let mut body = ProtobufWriter::new(16);
            body.write_uint(1, *nonce)?;
            (17, body.finish()?)
        }
        WatchdogProtocolResponseKind::SiteStatus(status) => (18, encode_site_status(status)?),
        WatchdogProtocolResponseKind::ResidentStatus(status) => {
            (19, encode_resident_status(status)?)
        }
    };
    encode_envelope(response.request_id(), field, &body)
}

// Decodes one closed protocol-v3 response and rejects every unknown or duplicate field.
pub fn decode_watchdog_protocol_response(
    payload: &[u8],
) -> Result<WatchdogProtocolResponse, WatchdogError> {
    validate_payload_size(payload)?;
    let fields = parse_protobuf_fields(payload)?;
    reject_unknown_fields(&fields, &[1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19])?;
    let request_id = optional_unique_uint(&fields, 1)?.unwrap_or(0);
    let bodies = fields
        .iter()
        .filter(|field| (10..=19).contains(&field.number))
        .collect::<Vec<_>>();
    if bodies.len() != 1 {
        return Err(protocol_error("response must contain exactly one body"));
    }
    let body = message_value(bodies[0])?;
    let kind = match bodies[0].number {
        10 => WatchdogProtocolResponseKind::Latest(decode_telemetry(body)?),
        11 => WatchdogProtocolResponseKind::HistoryBatch(decode_history_batch(body)?),
        12 => {
            let fields = closed_message_fields(body, &[1])?;
            WatchdogProtocolResponseKind::HistoryComplete {
                through_sequence: required_unique_uint(&fields, 1)?,
            }
        }
        13 => WatchdogProtocolResponseKind::Live(decode_telemetry(body)?),
        14 => WatchdogProtocolResponseKind::Capabilities(decode_capabilities(body)?),
        15 => {
            let fields = closed_message_fields(body, &[1, 2])?;
            WatchdogProtocolResponseKind::Gap {
                first_missing_sequence: required_unique_uint(&fields, 1)?,
                latest_sequence: required_unique_uint(&fields, 2)?,
            }
        }
        16 => {
            let fields = closed_message_fields(body, &[1, 2])?;
            WatchdogProtocolResponseKind::Error {
                code: bounded_u32(required_unique_uint(&fields, 1)?, "error code overflowed")?,
                message: bounded_utf8(
                    required_unique_message(&fields, 2)?,
                    MAX_ERROR_MESSAGE_BYTES,
                    "protocol error message is invalid",
                )?,
            }
        }
        17 => {
            let fields = closed_message_fields(body, &[1])?;
            WatchdogProtocolResponseKind::Pong {
                nonce: required_unique_uint(&fields, 1)?,
            }
        }
        18 => WatchdogProtocolResponseKind::SiteStatus(decode_site_status(body)?),
        19 => WatchdogProtocolResponseKind::ResidentStatus(decode_resident_status(body)?),
        _ => return Err(protocol_error("response body is unsupported")),
    };
    WatchdogProtocolResponse::new(request_id, kind)
}

// Prefixes one payload with the exact four-byte big-endian Watchdog frame length.
pub fn encode_watchdog_protocol_frame(payload: &[u8]) -> Result<Vec<u8>, WatchdogError> {
    validate_payload_size(payload)?;
    let length = u32::try_from(payload.len())
        .map_err(|_| protocol_error("protocol frame length overflowed"))?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

// Extracts exactly one complete frame and rejects truncated or trailing bytes.
pub fn decode_watchdog_protocol_frame(frame: &[u8]) -> Result<&[u8], WatchdogError> {
    if frame.len() < 4 {
        return Err(protocol_error("protocol frame header is truncated"));
    }
    let length =
        u32::from_be_bytes(frame[..4].try_into().expect("fixed protocol frame header")) as usize;
    if length == 0 || length > WATCHDOG_PROTOCOL_MAX_FRAME_BYTES {
        return Err(protocol_error("protocol frame length is invalid"));
    }
    if frame.len() != length + 4 {
        return Err(protocol_error(
            "protocol frame is truncated or has trailing bytes",
        ));
    }
    Ok(&frame[4..])
}

// Encodes one response envelope under the global frame payload bound.
fn encode_envelope(
    request_id: u64,
    body_field: u32,
    body: &[u8],
) -> Result<Vec<u8>, WatchdogError> {
    let mut writer = ProtobufWriter::new(WATCHDOG_PROTOCOL_MAX_FRAME_BYTES);
    if request_id != 0 {
        writer.write_uint(1, request_id)?;
    }
    writer.write_message(body_field, body)?;
    writer.finish()
}

// Decodes the optional bounded subscribe history request.
fn decode_subscribe_request(payload: &[u8]) -> Result<WatchdogProtocolRequestKind, WatchdogError> {
    let fields = closed_message_fields(payload, &[1])?;
    let history_seconds = optional_unique_uint(&fields, 1)?.unwrap_or(0);
    Ok(WatchdogProtocolRequestKind::Subscribe {
        history_seconds: bounded_u32(history_seconds, "subscription history overflowed")?,
    })
}

// Decodes one closed ordered history range request.
fn decode_query_request(payload: &[u8]) -> Result<WatchdogProtocolRequestKind, WatchdogError> {
    let fields = closed_message_fields(payload, &[1, 2, 3])?;
    let start_unix_milliseconds = optional_unique_uint(&fields, 1)?.unwrap_or(0);
    let end_unix_milliseconds = optional_unique_uint(&fields, 2)?.unwrap_or(0);
    let resolution = WatchdogProtocolResolution::from_wire(required_unique_uint(&fields, 3)?)?;
    if end_unix_milliseconds < start_unix_milliseconds {
        return Err(protocol_error("telemetry query range is reversed"));
    }
    Ok(WatchdogProtocolRequestKind::QueryRange {
        start_unix_milliseconds,
        end_unix_milliseconds,
        resolution,
    })
}

// Decodes the optional ping nonce without widening its field vocabulary.
fn decode_ping_request(payload: &[u8]) -> Result<WatchdogProtocolRequestKind, WatchdogError> {
    let fields = closed_message_fields(payload, &[1])?;
    Ok(WatchdogProtocolRequestKind::Ping {
        nonce: optional_unique_uint(&fields, 1)?.unwrap_or(0),
    })
}

// Encodes the complete fixed telemetry sample field set.
fn encode_telemetry(sample: &WatchdogSample) -> Result<Vec<u8>, WatchdogError> {
    let telemetry = sample.telemetry();
    let mut writer = ProtobufWriter::new(384);
    writer.write_uint(1, sample.sequence())?;
    writer.write_uint(2, sample.unix_milliseconds())?;
    writer.write_uint(3, sample.monotonic_milliseconds())?;
    writer.write_uint(4, u64::from(telemetry.flags))?;
    writer.write_uint(5, u64::from(telemetry.cpu_percent))?;
    let mut cpu = ProtobufWriter::new(WATCHDOG_MAX_CPU_CORES * 2);
    for value in telemetry
        .cpu_core_percent
        .iter()
        .take(usize::from(telemetry.cpu_core_count))
    {
        cpu.write_varint(u64::from(*value))?;
    }
    writer.write_message(6, &cpu.finish()?)?;
    writer.write_uint(7, u64::from(telemetry.memory_percent))?;
    writer.write_uint(8, u64::from(telemetry.disk_percent))?;
    writer.write_message(9, &encode_gpu(telemetry)?)?;
    writer.write_sint32(10, i32::from(telemetry.system_temp_deci_c))?;
    writer.write_sint32(11, i32::from(telemetry.nvme_temp_deci_c))?;
    writer.write_uint(12, u64::from(telemetry.load1_centi))?;
    writer.write_uint(13, u64::from(telemetry.memory_used_mib))?;
    writer.write_uint(14, u64::from(telemetry.memory_total_mib))?;
    writer.write_uint(15, u64::from(telemetry.disk_used_mib))?;
    writer.write_uint(16, u64::from(telemetry.disk_total_mib))?;
    writer.write_uint(17, u64::from(telemetry.network_rx_kib_s))?;
    writer.write_uint(18, u64::from(telemetry.network_tx_kib_s))?;
    writer.write_uint(19, u64::from(telemetry.disk_read_kib_s))?;
    writer.write_uint(20, u64::from(telemetry.disk_write_kib_s))?;
    writer.write_uint(21, u64::from(telemetry.workload_id))?;
    writer.write_uint(22, u64::from(telemetry.workload_type))?;
    writer.write_uint(23, u64::from(telemetry.cpu_clock_mhz))?;
    writer.write_uint(24, u64::from(telemetry.system_ram_clock_mhz))?;
    writer.write_uint(25, u64::from(telemetry.active_requests))?;
    writer.write_uint(26, u64::from(telemetry.queued_requests))?;
    for (field, value) in [
        (27, telemetry.requests_received),
        (28, telemetry.requests_admitted),
        (29, telemetry.requests_completed),
        (30, telemetry.requests_failed),
        (31, telemetry.requests_cancelled),
        (32, telemetry.requests_retried),
        (33, telemetry.input_tokens),
        (34, telemetry.output_tokens),
        (35, telemetry.cached_tokens),
        (36, telemetry.queue_milliseconds),
        (37, telemetry.ttft_milliseconds),
        (38, telemetry.decode_milliseconds),
        (39, telemetry.exact_token_requests),
        (40, telemetry.prefix_cache_hits),
        (41, telemetry.usage_records_dropped),
        (42, telemetry.usage_write_errors),
    ] {
        writer.write_uint(field, value)?;
    }
    writer.write_uint(43, u64::from(telemetry.connected_clients))?;
    writer.finish()
}

// Encodes the fixed nested GPU field set.
fn encode_gpu(telemetry: &WatchdogSampleTelemetry) -> Result<Vec<u8>, WatchdogError> {
    let mut writer = ProtobufWriter::new(64);
    writer.write_uint(1, u64::from(telemetry.gpu_percent))?;
    writer.write_uint(2, u64::from(telemetry.gpu_memory_percent))?;
    let mut engines = ProtobufWriter::new(WATCHDOG_GPU_ENGINES * 2);
    for value in telemetry.gpu_engine_percent {
        engines.write_varint(u64::from(value))?;
    }
    writer.write_message(3, &engines.finish()?)?;
    writer.write_sint32(4, i32::from(telemetry.gpu_temp_deci_c))?;
    writer.write_uint(5, u64::from(telemetry.power_deci_w))?;
    writer.write_uint(6, u64::from(telemetry.gpu_clock_mhz))?;
    writer.write_uint(7, u64::from(telemetry.vram_clock_mhz))?;
    writer.finish()
}

// Decodes the complete fixed telemetry field set into the existing sample contract.
fn decode_telemetry(payload: &[u8]) -> Result<WatchdogSample, WatchdogError> {
    let allowed = (1_u32..=43).collect::<Vec<_>>();
    let fields = closed_message_fields(payload, &allowed)?;
    let cpu = decode_packed_u8(required_unique_message(&fields, 6)?, WATCHDOG_MAX_CPU_CORES)?;
    let gpu_fields =
        closed_message_fields(required_unique_message(&fields, 9)?, &[1, 2, 3, 4, 5, 6, 7])?;
    let engines = decode_packed_u8(
        required_unique_message(&gpu_fields, 3)?,
        WATCHDOG_GPU_ENGINES,
    )?;
    if engines.len() != WATCHDOG_GPU_ENGINES {
        return Err(protocol_error("GPU engine vector has the wrong length"));
    }
    let mut telemetry = WatchdogSampleTelemetry {
        cpu_core_count: u8::try_from(cpu.len()).expect("bounded CPU core vector"),
        flags: bounded_u8(required_unique_uint(&fields, 4)?, "sample flags overflowed")?,
        cpu_percent: bounded_u8(required_unique_uint(&fields, 5)?, "CPU percent overflowed")?,
        gpu_percent: bounded_u8(
            required_unique_uint(&gpu_fields, 1)?,
            "GPU percent overflowed",
        )?,
        memory_percent: bounded_u8(
            required_unique_uint(&fields, 7)?,
            "memory percent overflowed",
        )?,
        disk_percent: bounded_u8(required_unique_uint(&fields, 8)?, "disk percent overflowed")?,
        gpu_memory_percent: bounded_u8(
            required_unique_uint(&gpu_fields, 2)?,
            "GPU memory percent overflowed",
        )?,
        workload_type: bounded_u8(
            required_unique_uint(&fields, 22)?,
            "workload type overflowed",
        )?,
        system_temp_deci_c: decode_sint16(required_unique_uint(&fields, 10)?)?,
        gpu_temp_deci_c: decode_sint16(required_unique_uint(&gpu_fields, 4)?)?,
        nvme_temp_deci_c: decode_sint16(required_unique_uint(&fields, 11)?)?,
        power_deci_w: bounded_u16(
            required_unique_uint(&gpu_fields, 5)?,
            "GPU power overflowed",
        )?,
        load1_centi: bounded_u16(
            required_unique_uint(&fields, 12)?,
            "load average overflowed",
        )?,
        memory_used_mib: bounded_u32(required_unique_uint(&fields, 13)?, "memory use overflowed")?,
        memory_total_mib: bounded_u32(
            required_unique_uint(&fields, 14)?,
            "memory capacity overflowed",
        )?,
        disk_used_mib: bounded_u32(required_unique_uint(&fields, 15)?, "disk use overflowed")?,
        disk_total_mib: bounded_u32(
            required_unique_uint(&fields, 16)?,
            "disk capacity overflowed",
        )?,
        network_rx_kib_s: bounded_u32(
            required_unique_uint(&fields, 17)?,
            "network receive overflowed",
        )?,
        network_tx_kib_s: bounded_u32(
            required_unique_uint(&fields, 18)?,
            "network transmit overflowed",
        )?,
        disk_read_kib_s: bounded_u32(required_unique_uint(&fields, 19)?, "disk read overflowed")?,
        disk_write_kib_s: bounded_u32(required_unique_uint(&fields, 20)?, "disk write overflowed")?,
        workload_id: bounded_u32(
            required_unique_uint(&fields, 21)?,
            "workload identity overflowed",
        )?,
        cpu_clock_mhz: bounded_u32(required_unique_uint(&fields, 23)?, "CPU clock overflowed")?,
        gpu_clock_mhz: bounded_u32(
            required_unique_uint(&gpu_fields, 6)?,
            "GPU clock overflowed",
        )?,
        vram_clock_mhz: bounded_u32(
            required_unique_uint(&gpu_fields, 7)?,
            "VRAM clock overflowed",
        )?,
        system_ram_clock_mhz: bounded_u32(
            required_unique_uint(&fields, 24)?,
            "RAM clock overflowed",
        )?,
        active_requests: bounded_u32(
            required_unique_uint(&fields, 25)?,
            "active requests overflowed",
        )?,
        queued_requests: bounded_u32(
            required_unique_uint(&fields, 26)?,
            "queued requests overflowed",
        )?,
        connected_clients: bounded_u32(
            required_unique_uint(&fields, 43)?,
            "connected clients overflowed",
        )?,
        requests_received: required_unique_uint(&fields, 27)?,
        requests_admitted: required_unique_uint(&fields, 28)?,
        requests_completed: required_unique_uint(&fields, 29)?,
        requests_failed: required_unique_uint(&fields, 30)?,
        requests_cancelled: required_unique_uint(&fields, 31)?,
        requests_retried: required_unique_uint(&fields, 32)?,
        input_tokens: required_unique_uint(&fields, 33)?,
        output_tokens: required_unique_uint(&fields, 34)?,
        cached_tokens: required_unique_uint(&fields, 35)?,
        queue_milliseconds: required_unique_uint(&fields, 36)?,
        ttft_milliseconds: required_unique_uint(&fields, 37)?,
        decode_milliseconds: required_unique_uint(&fields, 38)?,
        exact_token_requests: required_unique_uint(&fields, 39)?,
        prefix_cache_hits: required_unique_uint(&fields, 40)?,
        usage_records_dropped: required_unique_uint(&fields, 41)?,
        usage_write_errors: required_unique_uint(&fields, 42)?,
        ..WatchdogSampleTelemetry::default()
    };
    telemetry.cpu_core_percent[..cpu.len()].copy_from_slice(&cpu);
    telemetry
        .gpu_engine_percent
        .copy_from_slice(engines.as_slice());
    WatchdogSample::with_telemetry(
        required_unique_uint(&fields, 1)?,
        required_unique_uint(&fields, 2)?,
        required_unique_uint(&fields, 3)?,
        telemetry,
    )
}

// Decodes one bounded history batch with at least one telemetry sample.
fn decode_history_batch(payload: &[u8]) -> Result<Vec<WatchdogSample>, WatchdogError> {
    let fields = closed_message_fields(payload, &[1])?;
    let samples = fields
        .iter()
        .map(|field| message_value(field).and_then(decode_telemetry))
        .collect::<Result<Vec<_>, _>>()?;
    if samples.is_empty() || samples.len() > WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES {
        return Err(protocol_error("history batch size is invalid"));
    }
    Ok(samples)
}

// Encodes the exact fixed capability body emitted by the C implementation.
fn encode_capabilities(
    capabilities: &WatchdogProtocolCapabilities,
) -> Result<Vec<u8>, WatchdogError> {
    let mut body = ProtobufWriter::new(64);
    body.write_uint(1, u64::from(WATCHDOG_PROTOCOL_VERSION))?;
    body.write_uint(2, u64::from(capabilities.sample_interval_milliseconds))?;
    body.write_uint(3, u64::from(capabilities.flush_interval_milliseconds))?;
    body.write_uint(4, WATCHDOG_MAX_CPU_CORES as u64)?;
    for resolution in [
        WatchdogProtocolResolution::RawOneSecond,
        WatchdogProtocolResolution::OneMinute,
        WatchdogProtocolResolution::FifteenMinutes,
    ] {
        body.write_uint(5, resolution.wire_value())?;
    }
    body.write_uint(6, 1)?;
    body.write_uint(7, u64::from(capabilities.physical_gpu_count))?;
    body.finish()
}

// Decodes and verifies the exact fixed protocol-v3 capability body.
fn decode_capabilities(payload: &[u8]) -> Result<WatchdogProtocolCapabilities, WatchdogError> {
    let fields = closed_message_fields(payload, &[1, 2, 3, 4, 5, 6, 7])?;
    if required_unique_uint(&fields, 1)? != u64::from(WATCHDOG_PROTOCOL_VERSION)
        || required_unique_uint(&fields, 4)? != WATCHDOG_MAX_CPU_CORES as u64
        || required_unique_uint(&fields, 6)? != 1
    {
        return Err(protocol_error("protocol capabilities identity is invalid"));
    }
    let resolutions = fields
        .iter()
        .filter(|field| field.number == 5)
        .map(uint_value)
        .collect::<Result<Vec<_>, _>>()?;
    if resolutions != [1, 2, 3] {
        return Err(protocol_error("protocol resolutions are invalid"));
    }
    WatchdogProtocolCapabilities::new(
        bounded_u32(
            required_unique_uint(&fields, 2)?,
            "sample interval overflowed",
        )?,
        bounded_u32(
            required_unique_uint(&fields, 3)?,
            "flush interval overflowed",
        )?,
        bounded_u32(required_unique_uint(&fields, 7)?, "GPU count overflowed")?,
    )
}

// Encodes the complete established site status body.
fn encode_site_status(status: &WatchdogProtocolSiteStatus) -> Result<Vec<u8>, WatchdogError> {
    let mut body = ProtobufWriter::new(2_304);
    for (field, value) in [
        (1, status.release.as_str()),
        (2, status.model.as_str()),
        (3, status.engine.as_str()),
        (4, status.runtime_name.as_str()),
        (5, status.runtime_version.as_str()),
        (6, status.manifest_sha256.as_str()),
        (7, status.cache_provider.as_str()),
    ] {
        body.write_message(field, value.as_bytes())?;
    }
    body.write_uint(8, u64::from(status.cache_persistent))?;
    body.write_uint(9, u64::from(status.inference_port))?;
    body.write_uint(10, u64::from(status.maximum_connections))?;
    body.write_uint(11, u64::from(status.maximum_active_requests))?;
    body.write_uint(12, u64::from(status.maximum_context_tokens))?;
    for (field, value) in [
        (13, status.service_state.as_str()),
        (14, status.engine_state.as_str()),
        (15, status.protection_phase.as_str()),
    ] {
        body.write_message(field, value.as_bytes())?;
    }
    body.write_uint(16, u64::from(status.protection_armed))?;
    body.write_uint(17, u64::from(status.trip_latched))?;
    body.write_message(18, status.container_name.as_bytes())?;
    body.write_message(19, status.installation_id.as_bytes())?;
    body.finish()
}

// Decodes the complete established site status body.
fn decode_site_status(payload: &[u8]) -> Result<WatchdogProtocolSiteStatus, WatchdogError> {
    let fields = closed_message_fields(payload, &(1_u32..=19).collect::<Vec<_>>())?;
    WatchdogProtocolSiteStatus::new(
        status_text(&fields, 1)?,
        status_text(&fields, 2)?,
        status_text(&fields, 3)?,
        status_text(&fields, 4)?,
        status_text(&fields, 5)?,
        status_text(&fields, 6)?,
        status_text(&fields, 7)?,
        decode_bool(required_unique_uint(&fields, 8)?)?,
        bounded_u32(
            required_unique_uint(&fields, 9)?,
            "inference port overflowed",
        )?,
        bounded_u32(
            required_unique_uint(&fields, 10)?,
            "connection bound overflowed",
        )?,
        bounded_u32(
            required_unique_uint(&fields, 11)?,
            "active request bound overflowed",
        )?,
        bounded_u32(
            required_unique_uint(&fields, 12)?,
            "context bound overflowed",
        )?,
        status_text(&fields, 13)?,
        status_text(&fields, 14)?,
        status_text(&fields, 15)?,
        decode_bool(required_unique_uint(&fields, 16)?)?,
        decode_bool(required_unique_uint(&fields, 17)?)?,
        status_text_allow_empty(&fields, 18)?,
        status_text(&fields, 19)?,
    )
}

// Encodes one idle-safe resident identity without placement or controller state.
fn encode_resident_status(
    status: &WatchdogProtocolResidentStatus,
) -> Result<Vec<u8>, WatchdogError> {
    let mut body = ProtobufWriter::new(256);
    body.write_message(1, status.node_id().as_str().as_bytes())?;
    body.write_message(2, status.core_release().as_bytes())?;
    body.write_message(3, status.core_source_identity().as_str().as_bytes())?;
    body.write_message(4, status.installation_id().as_str().as_bytes())?;
    body.write_uint(5, status.lifecycle().wire_value())?;
    body.finish()
}

// Decodes one closed resident identity and re-applies every typed boundary invariant.
fn decode_resident_status(payload: &[u8]) -> Result<WatchdogProtocolResidentStatus, WatchdogError> {
    let fields = closed_message_fields(payload, &[1, 2, 3, 4, 5])?;
    let node_id = bounded_utf8(
        required_unique_message(&fields, 1)?,
        32,
        "resident Node identity is invalid",
    )?;
    let core_release = bounded_utf8(
        required_unique_message(&fields, 2)?,
        MAX_STATUS_TEXT_BYTES,
        "resident Core release is invalid",
    )?;
    let core_source_identity = bounded_utf8(
        required_unique_message(&fields, 3)?,
        64,
        "resident Core source identity is invalid",
    )?;
    let installation_id = bounded_utf8(
        required_unique_message(&fields, 4)?,
        64,
        "resident installation identity is invalid",
    )?;
    let lifecycle =
        WatchdogProtocolResidentLifecycle::from_wire(required_unique_uint(&fields, 5)?)?;
    let status = WatchdogProtocolResidentStatus::ready(
        NodeId::parse(&node_id).map_err(|_| protocol_error("resident Node identity is invalid"))?,
        core_release,
        Sha256Digest::parse(&core_source_identity)
            .map_err(|_| protocol_error("resident Core source identity is invalid"))?,
        InstallationId::parse(&installation_id)
            .map_err(|_| protocol_error("resident installation identity is invalid"))?,
    )?;
    if status.lifecycle() != lifecycle {
        return Err(protocol_error("resident lifecycle is invalid"));
    }
    Ok(status)
}

// Decodes one bounded site-status UTF-8 field.
fn status_text(fields: &[ProtobufField<'_>], number: u32) -> Result<String, WatchdogError> {
    bounded_utf8(
        required_unique_message(fields, number)?,
        MAX_STATUS_TEXT_BYTES,
        "site status text is invalid",
    )
}

// Decodes the one site-status field that is empty when no container is active.
fn status_text_allow_empty(
    fields: &[ProtobufField<'_>],
    number: u32,
) -> Result<String, WatchdogError> {
    let value = required_unique_message(fields, number)?;
    if value.is_empty() {
        return Ok(String::new());
    }
    bounded_utf8(value, MAX_STATUS_TEXT_BYTES, "site status text is invalid")
}

// Owns bounded protobuf output without allocation growth beyond its selected contract.
struct ProtobufWriter {
    output: Vec<u8>,
    maximum_bytes: usize,
}

impl ProtobufWriter {
    // Creates one empty writer under an exact byte bound.
    fn new(maximum_bytes: usize) -> Self {
        Self {
            output: Vec::new(),
            maximum_bytes,
        }
    }

    // Appends one canonical unsigned protobuf field.
    fn write_uint(&mut self, field: u32, value: u64) -> Result<(), WatchdogError> {
        self.write_key(field, 0)?;
        self.write_varint(value)
    }

    // Appends one canonical signed zigzag protobuf field.
    fn write_sint32(&mut self, field: u32, value: i32) -> Result<(), WatchdogError> {
        let encoded = ((value as u32) << 1) ^ ((value >> 31) as u32);
        self.write_uint(field, u64::from(encoded))
    }

    // Appends one canonical length-delimited protobuf field.
    fn write_message(&mut self, field: u32, value: &[u8]) -> Result<(), WatchdogError> {
        self.write_key(field, 2)?;
        self.write_varint(value.len() as u64)?;
        self.write_raw(value)
    }

    // Appends one canonical protobuf key.
    fn write_key(&mut self, field: u32, wire: u8) -> Result<(), WatchdogError> {
        if field == 0 || field > 0x1fff_ffff || !matches!(wire, 0 | 2) {
            return Err(protocol_error("protobuf key is invalid"));
        }
        self.write_varint((u64::from(field) << 3) | u64::from(wire))
    }

    // Appends one canonical unsigned protobuf varint.
    fn write_varint(&mut self, mut value: u64) -> Result<(), WatchdogError> {
        while value >= 0x80 {
            self.write_byte(((value as u8) & 0x7f) | 0x80)?;
            value >>= 7;
        }
        self.write_byte(value as u8)
    }

    // Appends one byte under the writer's exact capacity.
    fn write_byte(&mut self, value: u8) -> Result<(), WatchdogError> {
        if self.output.len() >= self.maximum_bytes {
            return Err(protocol_error("protobuf output exceeded its bound"));
        }
        self.output.push(value);
        Ok(())
    }

    // Appends one byte slice under the writer's exact capacity.
    fn write_raw(&mut self, value: &[u8]) -> Result<(), WatchdogError> {
        if value.len() > self.maximum_bytes.saturating_sub(self.output.len()) {
            return Err(protocol_error("protobuf output exceeded its bound"));
        }
        self.output.extend_from_slice(value);
        Ok(())
    }

    // Returns the complete bounded protobuf bytes.
    fn finish(self) -> Result<Vec<u8>, WatchdogError> {
        if self.output.len() > self.maximum_bytes {
            return Err(protocol_error("protobuf output exceeded its bound"));
        }
        Ok(self.output)
    }
}

// Identifies one parsed protobuf value without permitting unsupported wire types.
#[derive(Clone, Copy)]
enum ProtobufValue<'a> {
    Uint(u64),
    Message(&'a [u8]),
}

// Stores one parsed protobuf field and its exact wire value.
#[derive(Clone, Copy)]
struct ProtobufField<'a> {
    number: u32,
    value: ProtobufValue<'a>,
}

// Parses one closed sequence of canonical varint and length-delimited fields.
fn parse_protobuf_fields(payload: &[u8]) -> Result<Vec<ProtobufField<'_>>, WatchdogError> {
    let mut offset = 0_usize;
    let mut fields = Vec::new();
    while offset < payload.len() {
        let key = read_varint(payload, &mut offset)?;
        let number = u32::try_from(key >> 3)
            .map_err(|_| protocol_error("protobuf field identity overflowed"))?;
        let wire = (key & 7) as u8;
        if number == 0 {
            return Err(protocol_error("protobuf field zero is invalid"));
        }
        let value = match wire {
            0 => ProtobufValue::Uint(read_varint(payload, &mut offset)?),
            2 => {
                let length = usize::try_from(read_varint(payload, &mut offset)?)
                    .map_err(|_| protocol_error("protobuf message length overflowed"))?;
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| protocol_error("protobuf message length overflowed"))?;
                if end > payload.len() {
                    return Err(protocol_error("protobuf message is truncated"));
                }
                let value = &payload[offset..end];
                offset = end;
                ProtobufValue::Message(value)
            }
            _ => return Err(protocol_error("protobuf wire type is unsupported")),
        };
        fields.push(ProtobufField { number, value });
        if fields.len() > MAX_PROTOBUF_FIELDS {
            return Err(protocol_error("protobuf field count exceeded its bound"));
        }
    }
    Ok(fields)
}

// Reads one canonical bounded unsigned protobuf varint.
fn read_varint(payload: &[u8], offset: &mut usize) -> Result<u64, WatchdogError> {
    let start = *offset;
    let mut value = 0_u64;
    for index in 0..10 {
        let byte = *payload
            .get(*offset)
            .ok_or_else(|| protocol_error("protobuf varint is truncated"))?;
        *offset += 1;
        if index == 9 && byte > 1 {
            return Err(protocol_error("protobuf varint overflowed"));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if *offset - start != canonical_varint_length(value) {
                return Err(protocol_error("protobuf varint is not canonical"));
            }
            return Ok(value);
        }
    }
    Err(protocol_error("protobuf varint is oversized"))
}

// Returns the minimal byte count for one unsigned protobuf varint.
fn canonical_varint_length(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

// Parses one nested message and rejects every field outside its exact vocabulary.
fn closed_message_fields<'a>(
    payload: &'a [u8],
    allowed: &[u32],
) -> Result<Vec<ProtobufField<'a>>, WatchdogError> {
    let fields = parse_protobuf_fields(payload)?;
    reject_unknown_fields(&fields, allowed)?;
    Ok(fields)
}

// Rejects every parsed field outside one exact vocabulary.
fn reject_unknown_fields(
    fields: &[ProtobufField<'_>],
    allowed: &[u32],
) -> Result<(), WatchdogError> {
    if fields.iter().any(|field| !allowed.contains(&field.number)) {
        return Err(protocol_error(
            "protobuf document contains an unknown field",
        ));
    }
    Ok(())
}

// Returns one optional unique unsigned field.
fn optional_unique_uint(
    fields: &[ProtobufField<'_>],
    number: u32,
) -> Result<Option<u64>, WatchdogError> {
    let matches = fields
        .iter()
        .filter(|field| field.number == number)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [field] => uint_value(field).map(Some),
        _ => Err(protocol_error("protobuf unsigned field is duplicated")),
    }
}

// Returns one required unique unsigned field.
fn required_unique_uint(fields: &[ProtobufField<'_>], number: u32) -> Result<u64, WatchdogError> {
    optional_unique_uint(fields, number)?
        .ok_or_else(|| protocol_error("required protobuf unsigned field is missing"))
}

// Returns one required unique message field.
fn required_unique_message<'a>(
    fields: &[ProtobufField<'a>],
    number: u32,
) -> Result<&'a [u8], WatchdogError> {
    let matches = fields
        .iter()
        .filter(|field| field.number == number)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [field] => message_value(field),
        [] => Err(protocol_error("required protobuf message field is missing")),
        _ => Err(protocol_error("protobuf message field is duplicated")),
    }
}

// Returns one unsigned value with strict wire-type checking.
fn uint_value(field: &ProtobufField<'_>) -> Result<u64, WatchdogError> {
    match field.value {
        ProtobufValue::Uint(value) => Ok(value),
        ProtobufValue::Message(_) => Err(protocol_error("protobuf field has the wrong wire type")),
    }
}

// Returns one message value with strict wire-type checking.
fn message_value<'a>(field: &ProtobufField<'a>) -> Result<&'a [u8], WatchdogError> {
    match field.value {
        ProtobufValue::Message(value) => Ok(value),
        ProtobufValue::Uint(_) => Err(protocol_error("protobuf field has the wrong wire type")),
    }
}

// Requires one marker message to contain no fields or trailing bytes.
fn require_empty_message(payload: &[u8]) -> Result<(), WatchdogError> {
    if !payload.is_empty() {
        return Err(protocol_error("marker protobuf message must be empty"));
    }
    Ok(())
}

// Decodes one packed vector of canonical bounded byte values.
fn decode_packed_u8(payload: &[u8], maximum_values: usize) -> Result<Vec<u8>, WatchdogError> {
    let mut offset = 0;
    let mut values = Vec::new();
    while offset < payload.len() {
        values.push(bounded_u8(
            read_varint(payload, &mut offset)?,
            "packed metric overflowed",
        )?);
        if values.len() > maximum_values {
            return Err(protocol_error("packed metric count exceeded its bound"));
        }
    }
    Ok(values)
}

// Converts one zigzag-encoded protobuf value into the native signed temperature width.
fn decode_sint16(value: u64) -> Result<i16, WatchdogError> {
    let value = u32::try_from(value).map_err(|_| protocol_error("signed metric overflowed"))?;
    let decoded = ((value >> 1) as i32) ^ -((value & 1) as i32);
    i16::try_from(decoded).map_err(|_| protocol_error("signed metric exceeds its native width"))
}

// Decodes one protobuf boolean without accepting a non-canonical numeric truth value.
fn decode_bool(value: u64) -> Result<bool, WatchdogError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(protocol_error("protobuf boolean is invalid")),
    }
}

// Converts one protobuf integer into the fixed native byte width.
fn bounded_u8(value: u64, reason: &'static str) -> Result<u8, WatchdogError> {
    u8::try_from(value).map_err(|_| protocol_error(reason))
}

// Converts one protobuf integer into the fixed native two-byte width.
fn bounded_u16(value: u64, reason: &'static str) -> Result<u16, WatchdogError> {
    u16::try_from(value).map_err(|_| protocol_error(reason))
}

// Converts one protobuf integer into the fixed native four-byte width.
fn bounded_u32(value: u64, reason: &'static str) -> Result<u32, WatchdogError> {
    u32::try_from(value).map_err(|_| protocol_error(reason))
}

// Converts one bounded message field into strict non-control UTF-8.
fn bounded_utf8(
    value: &[u8],
    maximum_bytes: usize,
    reason: &'static str,
) -> Result<String, WatchdogError> {
    if value.is_empty() || value.len() > maximum_bytes {
        return Err(protocol_error(reason));
    }
    let value = String::from_utf8(value.to_vec()).map_err(|_| protocol_error(reason))?;
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(protocol_error(reason));
    }
    Ok(value)
}

// Requires one site status value to match the C server's visible vocabulary.
fn validate_status_text(value: &str) -> Result<(), WatchdogError> {
    if value.is_empty()
        || value.len() > MAX_STATUS_TEXT_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
        })
    {
        return Err(protocol_error("site status text is invalid"));
    }
    Ok(())
}

// Requires one lowercase fixed-width hexadecimal identity.
fn validate_lower_hex(
    value: &str,
    length: usize,
    reason: &'static str,
) -> Result<(), WatchdogError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(protocol_error(reason));
    }
    Ok(())
}

// Requires one nonempty payload under the global protocol frame bound.
fn validate_payload_size(payload: &[u8]) -> Result<(), WatchdogError> {
    if payload.is_empty() || payload.len() > WATCHDOG_PROTOCOL_MAX_FRAME_BYTES {
        return Err(protocol_error("protocol payload size is invalid"));
    }
    Ok(())
}

// Creates one stable redacted protocol-v3 contract failure.
const fn protocol_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("protocol v3", reason)
}
