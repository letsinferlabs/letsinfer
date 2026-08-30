// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{InstallationId, NodeId, Sha256Digest};
use li_watchdog_manager::{
    decode_watchdog_protocol_frame, decode_watchdog_protocol_request,
    decode_watchdog_protocol_response, encode_watchdog_protocol_frame,
    encode_watchdog_protocol_request, encode_watchdog_protocol_response,
    WatchdogProtocolCapabilities, WatchdogProtocolRequest, WatchdogProtocolRequestKind,
    WatchdogProtocolResidentStatus, WatchdogProtocolResolution, WatchdogProtocolResponse,
    WatchdogProtocolResponseKind, WatchdogProtocolSiteStatus, WatchdogSample,
    WatchdogSampleTelemetry, WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES,
    WATCHDOG_PROTOCOL_MAX_FRAME_BYTES, WATCHDOG_PROTOCOL_VERSION,
};

const LI_WATCHDOG_PROTOCOL_C_SAMPLE_FIXTURE: &str = "080752a301080910c9843d1889897a200f2813320501027fff01382740314a1a081d103b1a08030405068001fe0120fc0a28940330d00c38b50d50c90158dd0460f90368de0470c30578a80680018d078801f2079001d7089801bc09a001a10aa801860bb00103b801eb0bc0019a0ec80113d00114d80116e00117e80118f00119f8011a80021b88021c90021d98021ea0021fa80220b00221b80222c00223c80224d00225d80215";
const LI_WATCHDOG_PROTOCOL_SCHEMA: &str =
    include_str!("../../../schemas/watchdog/li_watchdog_protocol_v1.proto");

// Binds the long-lived schema-file identity to the production protocol-v3 readiness fields.
#[test]
fn checked_in_protocol_schema_carries_resident_readiness() {
    for required in [
        "package letsinfer.watchdog.v1;",
        "GetResidentStatusRequest get_resident_status = 16;",
        "ResidentStatus resident_status = 19;",
        "message GetResidentStatusRequest {}",
        "RESIDENT_LIFECYCLE_READY = 1;",
        "string node_id = 1;",
        "string core_release = 2;",
        "string core_source_identity = 3;",
        "string installation_id = 4;",
        "ResidentLifecycle lifecycle = 5;",
    ] {
        assert!(
            LI_WATCHDOG_PROTOCOL_SCHEMA.contains(required),
            "Watchdog protocol schema is missing {required}"
        );
    }
    assert_eq!(WATCHDOG_PROTOCOL_VERSION, 3);
}

// Reproduces the established C query fixture and every typed request operation exactly.
#[test]
fn protocol_v3_requests_match_the_c_fixture_and_round_trip() {
    let fixture = [
        0x08, 0x07, 0x62, 0x08, 0x08, 0xe8, 0x07, 0x10, 0xd0, 0x0f, 0x18, 0x01,
    ];
    let query = WatchdogProtocolRequest::new(
        7,
        WatchdogProtocolRequestKind::QueryRange {
            start_unix_milliseconds: 1_000,
            end_unix_milliseconds: 2_000,
            resolution: WatchdogProtocolResolution::RawOneSecond,
        },
    )
    .unwrap();
    assert_eq!(encode_watchdog_protocol_request(&query).unwrap(), fixture);
    assert_eq!(decode_watchdog_protocol_request(&fixture).unwrap(), query);

    let requests = [
        WatchdogProtocolRequest::new(0, WatchdogProtocolRequestKind::GetLatest).unwrap(),
        WatchdogProtocolRequest::new(
            2,
            WatchdogProtocolRequestKind::Subscribe {
                history_seconds: 900,
            },
        )
        .unwrap(),
        WatchdogProtocolRequest::new(
            3,
            WatchdogProtocolRequestKind::QueryRange {
                start_unix_milliseconds: 4_000,
                end_unix_milliseconds: 5_000,
                resolution: WatchdogProtocolResolution::OneMinute,
            },
        )
        .unwrap(),
        WatchdogProtocolRequest::new(4, WatchdogProtocolRequestKind::GetCapabilities).unwrap(),
        WatchdogProtocolRequest::new(5, WatchdogProtocolRequestKind::Ping { nonce: u64::MAX })
            .unwrap(),
        WatchdogProtocolRequest::new(6, WatchdogProtocolRequestKind::GetSiteStatus).unwrap(),
        WatchdogProtocolRequest::new(7, WatchdogProtocolRequestKind::GetResidentStatus).unwrap(),
    ];
    for request in requests {
        let payload = encode_watchdog_protocol_request(&request).unwrap();
        assert_eq!(decode_watchdog_protocol_request(&payload).unwrap(), request);
        let frame = encode_watchdog_protocol_frame(&payload).unwrap();
        assert_eq!(decode_watchdog_protocol_frame(&frame).unwrap(), payload);
    }
    assert_eq!(WATCHDOG_PROTOCOL_VERSION, 3);
}

// Preserves every version-two telemetry field through the closed protocol-v3 envelope.
#[test]
fn protocol_v3_preserves_complete_telemetry() {
    let sample = complete_sample(9);
    let c_fixture_response =
        WatchdogProtocolResponse::new(7, WatchdogProtocolResponseKind::Latest(sample.clone()))
            .unwrap();
    assert_eq!(
        encode_watchdog_protocol_response(&c_fixture_response).unwrap(),
        decode_hex_fixture(LI_WATCHDOG_PROTOCOL_C_SAMPLE_FIXTURE)
    );
    for kind in [
        WatchdogProtocolResponseKind::Latest(sample.clone()),
        WatchdogProtocolResponseKind::Live(sample),
    ] {
        let response = WatchdogProtocolResponse::new(7, kind).unwrap();
        let payload = encode_watchdog_protocol_response(&response).unwrap();
        assert_eq!(
            decode_watchdog_protocol_response(&payload).unwrap(),
            response
        );
    }
}

// Round-trips every closed response shape including the maximum accepted history batch.
#[test]
fn protocol_v3_round_trips_every_response_shape_and_bound() {
    let status = WatchdogProtocolSiteStatus::new(
        "v0.11.0-rc.99".to_string(),
        "fixture-model".to_string(),
        "dwarfstar".to_string(),
        "fixture-runtime".to_string(),
        "0.11.0-rc.2".to_string(),
        "1".repeat(64),
        "dwarfstar-native".to_string(),
        true,
        8_000,
        64,
        16,
        557_056,
        "running".to_string(),
        "running".to_string(),
        "armed".to_string(),
        true,
        false,
        String::new(),
        "2".repeat(64),
    )
    .unwrap();
    let responses = [
        WatchdogProtocolResponse::new(
            1,
            WatchdogProtocolResponseKind::HistoryComplete {
                through_sequence: 999,
            },
        )
        .unwrap(),
        WatchdogProtocolResponse::new(
            2,
            WatchdogProtocolResponseKind::Capabilities(
                WatchdogProtocolCapabilities::new(1_000, 10_000, 8).unwrap(),
            ),
        )
        .unwrap(),
        WatchdogProtocolResponse::new(
            3,
            WatchdogProtocolResponseKind::Gap {
                first_missing_sequence: 8,
                latest_sequence: 11,
            },
        )
        .unwrap(),
        WatchdogProtocolResponse::new(
            4,
            WatchdogProtocolResponseKind::Error {
                code: 404,
                message: "history_unavailable".to_string(),
            },
        )
        .unwrap(),
        WatchdogProtocolResponse::new(5, WatchdogProtocolResponseKind::Pong { nonce: u64::MAX })
            .unwrap(),
        WatchdogProtocolResponse::new(6, WatchdogProtocolResponseKind::SiteStatus(status)).unwrap(),
        WatchdogProtocolResponse::new(
            7,
            WatchdogProtocolResponseKind::ResidentStatus(
                WatchdogProtocolResidentStatus::ready(
                    NodeId::parse(&"3".repeat(32)).unwrap(),
                    "v0.11.0-rc.99".to_string(),
                    Sha256Digest::parse(&"5".repeat(64)).unwrap(),
                    InstallationId::parse(&"4".repeat(64)).unwrap(),
                )
                .unwrap(),
            ),
        )
        .unwrap(),
    ];
    for response in responses {
        let payload = encode_watchdog_protocol_response(&response).unwrap();
        assert_eq!(
            decode_watchdog_protocol_response(&payload).unwrap(),
            response
        );
    }

    let history = (1..=WATCHDOG_PROTOCOL_MAX_BATCH_SAMPLES)
        .map(|sequence| complete_sample(sequence as u64))
        .collect();
    let response =
        WatchdogProtocolResponse::new(9, WatchdogProtocolResponseKind::HistoryBatch(history))
            .unwrap();
    let payload = encode_watchdog_protocol_response(&response).unwrap();
    assert!(payload.len() <= WATCHDOG_PROTOCOL_MAX_FRAME_BYTES);
    assert_eq!(
        decode_watchdog_protocol_response(&payload).unwrap(),
        response
    );
}

// Fails closed on unknown, duplicate, noncanonical, truncated, trailing, and oversized bytes.
#[test]
fn protocol_v3_rejects_every_closed_wire_failure_class() {
    let malformed_requests = [
        vec![],
        vec![0x52, 0x00, 0x10, 0x00],
        vec![0x08, 0x01, 0x08, 0x01, 0x52, 0x00],
        vec![0x52, 0x00, 0x6a, 0x00],
        vec![0x5a, 0x04, 0x08, 0x01, 0x08, 0x01],
        vec![0x5a, 0x02, 0x10, 0x00],
        vec![0x0a, 0x00, 0x52, 0x00],
        vec![0x08, 0x80, 0x00, 0x52, 0x00],
        vec![0x52, 0x01],
        vec![0x00, 0x00, 0x52, 0x00],
    ];
    for malformed in malformed_requests {
        assert!(decode_watchdog_protocol_request(&malformed).is_err());
    }
    assert!(
        decode_watchdog_protocol_request(&vec![0; WATCHDOG_PROTOCOL_MAX_FRAME_BYTES + 1]).is_err()
    );

    let response =
        WatchdogProtocolResponse::new(1, WatchdogProtocolResponseKind::Pong { nonce: 4 }).unwrap();
    let mut duplicate_body = encode_watchdog_protocol_response(&response).unwrap();
    duplicate_body.extend_from_slice(&[0x8a, 0x01, 0x02, 0x08, 0x04]);
    assert!(decode_watchdog_protocol_response(&duplicate_body).is_err());

    let payload = encode_watchdog_protocol_request(
        &WatchdogProtocolRequest::new(1, WatchdogProtocolRequestKind::GetLatest).unwrap(),
    )
    .unwrap();
    let mut trailing = encode_watchdog_protocol_frame(&payload).unwrap();
    trailing.push(0);
    assert!(decode_watchdog_protocol_frame(&trailing).is_err());
    assert!(decode_watchdog_protocol_frame(&[0, 0, 0]).is_err());
    assert!(decode_watchdog_protocol_frame(&[0, 0, 0, 0]).is_err());
    assert!(
        encode_watchdog_protocol_frame(&vec![0; WATCHDOG_PROTOCOL_MAX_FRAME_BYTES + 1]).is_err()
    );
}

// Creates one sample whose non-default values expose every telemetry field mapping.
fn complete_sample(sequence: u64) -> WatchdogSample {
    let mut telemetry = WatchdogSampleTelemetry {
        cpu_core_count: 4,
        flags: 15,
        cpu_percent: 19,
        gpu_percent: 29,
        memory_percent: 39,
        disk_percent: 49,
        gpu_memory_percent: 59,
        workload_type: 3,
        system_temp_deci_c: -101,
        gpu_temp_deci_c: 702,
        nvme_temp_deci_c: -303,
        power_deci_w: 404,
        load1_centi: 505,
        memory_used_mib: 606,
        memory_total_mib: 707,
        disk_used_mib: 808,
        disk_total_mib: 909,
        network_rx_kib_s: 1_010,
        network_tx_kib_s: 1_111,
        disk_read_kib_s: 1_212,
        disk_write_kib_s: 1_313,
        workload_id: 1_414,
        cpu_clock_mhz: 1_515,
        gpu_clock_mhz: 1_616,
        vram_clock_mhz: 1_717,
        system_ram_clock_mhz: 1_818,
        active_requests: 19,
        queued_requests: 20,
        connected_clients: 21,
        requests_received: 22,
        requests_admitted: 23,
        requests_completed: 24,
        requests_failed: 25,
        requests_cancelled: 26,
        requests_retried: 27,
        input_tokens: 28,
        output_tokens: 29,
        cached_tokens: 30,
        queue_milliseconds: 31,
        ttft_milliseconds: 32,
        decode_milliseconds: 33,
        exact_token_requests: 34,
        prefix_cache_hits: 35,
        usage_records_dropped: 36,
        usage_write_errors: 37,
        ..WatchdogSampleTelemetry::default()
    };
    telemetry.cpu_core_percent[..4].copy_from_slice(&[1, 2, 127, 255]);
    telemetry
        .gpu_engine_percent
        .copy_from_slice(&[3, 4, 5, 6, 128, 254]);
    WatchdogSample::with_telemetry(
        sequence,
        1_000_000 + sequence,
        2_000_000 + sequence,
        telemetry,
    )
    .unwrap()
}

// Decodes one checked-in byte-exact C encoder fixture.
fn decode_hex_fixture(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}
