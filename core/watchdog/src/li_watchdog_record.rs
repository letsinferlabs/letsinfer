// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    WatchdogError, WatchdogSample, WatchdogSampleTelemetry, WATCHDOG_GPU_ENGINES,
    WATCHDOG_MAX_CPU_CORES,
};

pub const WATCHDOG_RECORD_BYTES: usize = 284;

const WATCHDOG_RECORD_MAGIC: u32 = 0x3152_494c;
const WATCHDOG_RECORD_VERSION: u16 = 2;
const WATCHDOG_RECORD_CRC_OFFSET: usize = 280;

// Encodes one sample into the established Watchdog record-v2 byte layout.
pub fn encode_watchdog_record(
    sample: &WatchdogSample,
) -> Result<[u8; WATCHDOG_RECORD_BYTES], WatchdogError> {
    let telemetry = sample.telemetry();
    if usize::from(telemetry.cpu_core_count) > WATCHDOG_MAX_CPU_CORES {
        return Err(record_error());
    }

    let mut output = [0_u8; WATCHDOG_RECORD_BYTES];
    put_u32(&mut output, 0, WATCHDOG_RECORD_MAGIC);
    put_u16(&mut output, 4, WATCHDOG_RECORD_VERSION);
    put_u16(&mut output, 6, WATCHDOG_RECORD_BYTES as u16);
    put_u64(&mut output, 8, sample.sequence());
    put_u64(&mut output, 16, sample.unix_milliseconds());
    put_u64(&mut output, 24, sample.monotonic_milliseconds());
    output[32] = telemetry.cpu_core_count;
    output[33] = telemetry.flags;
    output[34] = telemetry.cpu_percent;
    output[35] = telemetry.gpu_percent;
    output[36] = telemetry.memory_percent;
    output[37] = telemetry.disk_percent;
    output[38] = telemetry.gpu_memory_percent;
    output[39] = telemetry.workload_type;
    output[40..72].copy_from_slice(&telemetry.cpu_core_percent);
    output[72..78].copy_from_slice(&telemetry.gpu_engine_percent);
    put_u16(&mut output, 78, telemetry.system_temp_deci_c as u16);
    put_u16(&mut output, 80, telemetry.gpu_temp_deci_c as u16);
    put_u16(&mut output, 82, telemetry.nvme_temp_deci_c as u16);
    put_u16(&mut output, 84, telemetry.power_deci_w);
    put_u16(&mut output, 86, telemetry.load1_centi);
    put_u32(&mut output, 88, telemetry.memory_used_mib);
    put_u32(&mut output, 92, telemetry.memory_total_mib);
    put_u32(&mut output, 96, telemetry.disk_used_mib);
    put_u32(&mut output, 100, telemetry.disk_total_mib);
    put_u32(&mut output, 104, telemetry.network_rx_kib_s);
    put_u32(&mut output, 108, telemetry.network_tx_kib_s);
    put_u32(&mut output, 112, telemetry.disk_read_kib_s);
    put_u32(&mut output, 116, telemetry.disk_write_kib_s);
    put_u32(&mut output, 120, telemetry.workload_id);
    put_u32(&mut output, 124, telemetry.cpu_clock_mhz);
    put_u32(&mut output, 128, telemetry.gpu_clock_mhz);
    put_u32(&mut output, 132, telemetry.vram_clock_mhz);
    put_u32(&mut output, 136, telemetry.system_ram_clock_mhz);
    put_u32(&mut output, 140, telemetry.active_requests);
    put_u32(&mut output, 144, telemetry.queued_requests);
    put_u64(&mut output, 148, telemetry.requests_received);
    put_u64(&mut output, 156, telemetry.requests_admitted);
    put_u64(&mut output, 164, telemetry.requests_completed);
    put_u64(&mut output, 172, telemetry.requests_failed);
    put_u64(&mut output, 180, telemetry.requests_cancelled);
    put_u64(&mut output, 188, telemetry.requests_retried);
    put_u64(&mut output, 196, telemetry.input_tokens);
    put_u64(&mut output, 204, telemetry.output_tokens);
    put_u64(&mut output, 212, telemetry.cached_tokens);
    put_u64(&mut output, 220, telemetry.queue_milliseconds);
    put_u64(&mut output, 228, telemetry.ttft_milliseconds);
    put_u64(&mut output, 236, telemetry.decode_milliseconds);
    put_u64(&mut output, 244, telemetry.exact_token_requests);
    put_u64(&mut output, 252, telemetry.prefix_cache_hits);
    put_u64(&mut output, 260, telemetry.usage_records_dropped);
    put_u64(&mut output, 268, telemetry.usage_write_errors);
    put_u32(&mut output, 276, telemetry.connected_clients);
    let checksum = watchdog_crc32(&output[..WATCHDOG_RECORD_CRC_OFFSET]);
    put_u32(&mut output, WATCHDOG_RECORD_CRC_OFFSET, checksum);
    Ok(output)
}

// Decodes one exact Watchdog record-v2 payload after its CRC verifies.
pub fn decode_watchdog_record(input: &[u8]) -> Result<WatchdogSample, WatchdogError> {
    if input.len() != WATCHDOG_RECORD_BYTES
        || get_u32(input, 0) != WATCHDOG_RECORD_MAGIC
        || get_u16(input, 4) != WATCHDOG_RECORD_VERSION
        || usize::from(get_u16(input, 6)) != WATCHDOG_RECORD_BYTES
        || get_u32(input, WATCHDOG_RECORD_CRC_OFFSET)
            != watchdog_crc32(&input[..WATCHDOG_RECORD_CRC_OFFSET])
        || usize::from(input[32]) > WATCHDOG_MAX_CPU_CORES
    {
        return Err(record_error());
    }

    let mut telemetry = WatchdogSampleTelemetry {
        cpu_core_count: input[32],
        flags: input[33],
        cpu_percent: input[34],
        gpu_percent: input[35],
        memory_percent: input[36],
        disk_percent: input[37],
        gpu_memory_percent: input[38],
        workload_type: input[39],
        system_temp_deci_c: get_u16(input, 78) as i16,
        gpu_temp_deci_c: get_u16(input, 80) as i16,
        nvme_temp_deci_c: get_u16(input, 82) as i16,
        power_deci_w: get_u16(input, 84),
        load1_centi: get_u16(input, 86),
        memory_used_mib: get_u32(input, 88),
        memory_total_mib: get_u32(input, 92),
        disk_used_mib: get_u32(input, 96),
        disk_total_mib: get_u32(input, 100),
        network_rx_kib_s: get_u32(input, 104),
        network_tx_kib_s: get_u32(input, 108),
        disk_read_kib_s: get_u32(input, 112),
        disk_write_kib_s: get_u32(input, 116),
        workload_id: get_u32(input, 120),
        cpu_clock_mhz: get_u32(input, 124),
        gpu_clock_mhz: get_u32(input, 128),
        vram_clock_mhz: get_u32(input, 132),
        system_ram_clock_mhz: get_u32(input, 136),
        active_requests: get_u32(input, 140),
        queued_requests: get_u32(input, 144),
        connected_clients: get_u32(input, 276),
        requests_received: get_u64(input, 148),
        requests_admitted: get_u64(input, 156),
        requests_completed: get_u64(input, 164),
        requests_failed: get_u64(input, 172),
        requests_cancelled: get_u64(input, 180),
        requests_retried: get_u64(input, 188),
        input_tokens: get_u64(input, 196),
        output_tokens: get_u64(input, 204),
        cached_tokens: get_u64(input, 212),
        queue_milliseconds: get_u64(input, 220),
        ttft_milliseconds: get_u64(input, 228),
        decode_milliseconds: get_u64(input, 236),
        exact_token_requests: get_u64(input, 244),
        prefix_cache_hits: get_u64(input, 252),
        usage_records_dropped: get_u64(input, 260),
        usage_write_errors: get_u64(input, 268),
        ..WatchdogSampleTelemetry::default()
    };
    telemetry
        .cpu_core_percent
        .copy_from_slice(&input[40..40 + WATCHDOG_MAX_CPU_CORES]);
    telemetry
        .gpu_engine_percent
        .copy_from_slice(&input[72..72 + WATCHDOG_GPU_ENGINES]);
    WatchdogSample::from_record(
        get_u64(input, 8),
        get_u64(input, 16),
        get_u64(input, 24),
        telemetry,
    )
}

// Computes the exact reflected IEEE CRC-32 used by the C record implementation.
pub fn watchdog_crc32(input: &[u8]) -> u32 {
    let mut checksum = u32::MAX;
    for byte in input {
        checksum ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(checksum & 1);
            checksum = (checksum >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !checksum
}

// Writes one little-endian unsigned 16-bit value at a fixed record offset.
fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

// Writes one little-endian unsigned 32-bit value at a fixed record offset.
fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

// Writes one little-endian unsigned 64-bit value at a fixed record offset.
fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

// Reads one little-endian unsigned 16-bit value from a verified record offset.
fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        input[offset..offset + 2]
            .try_into()
            .expect("verified record"),
    )
}

// Reads one little-endian unsigned 32-bit value from a verified record offset.
fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("verified record"),
    )
}

// Reads one little-endian unsigned 64-bit value from a verified record offset.
fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("verified record"),
    )
}

// Returns one stable failure for malformed or incompatible native record bytes.
fn record_error() -> WatchdogError {
    WatchdogError::InvalidContract {
        reason: "Watchdog sample record is corrupt or incompatible",
    }
}
