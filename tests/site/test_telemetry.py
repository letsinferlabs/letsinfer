# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import os
import pathlib
import struct
import tempfile
import unittest
import zlib

from core.site.telemetry import (
    COUNTER_FIELDS,
    RAW_RING_CAPACITY,
    RECORD_BYTES,
    TelemetryAggregator,
    TelemetryError,
    decode_watchdog_record,
    read_latest_watchdog_sample,
)


MEMBER = "1" * 32


def record(*, sequence: int = 7, unix_ms: int = 1_700_000_000_000, counters: int = 10) -> bytes:
    value = bytearray(RECORD_BYTES)
    struct.pack_into("<IHHQQQ", value, 0, 0x3152494C, 1, RECORD_BYTES, sequence, unix_ms, 1234)
    value[32:40] = bytes((2, 1 << 3, 50, 60, 70, 80, 90, 1))
    value[40:42] = bytes((40, 60))
    value[72:78] = bytes((60, 50, 0, 0, 0, 0))
    struct.pack_into("<hhhHH", value, 78, 400, 550, -32768, 700, 125)
    for offset, amount in zip(range(88, 120, 4), range(100, 108)):
        struct.pack_into("<I", value, offset, amount)
    struct.pack_into("<IIIII", value, 120, 9, 3200, 1200, 0xFFFFFFFF, 0xFFFFFFFF)
    struct.pack_into("<II", value, 140, 2, 3)
    for offset in range(148, 276, 8):
        struct.pack_into("<Q", value, offset, counters)
    struct.pack_into("<I", value, 276, zlib.crc32(value[:276]))
    return bytes(value)


class TelemetryTests(unittest.TestCase):
    def test_watchdog_record_decodes_exact_counters_and_unknowns(self) -> None:
        sample = decode_watchdog_record(record(), member_id=MEMBER)
        self.assertEqual(sample["system"]["cpu_core_percent"], [40, 60])
        self.assertEqual(sample["system"]["nvme_temp_deci_c"], -1)
        self.assertEqual(sample["system"]["vram_clock_mhz"], -1)
        self.assertEqual(sample["inference"]["active_requests"], 2)
        self.assertEqual(sample["inference"][COUNTER_FIELDS[-1]], 10)
        damaged = bytearray(record())
        damaged[50] ^= 1
        with self.assertRaisesRegex(TelemetryError, "corrupt"):
            decode_watchdog_record(bytes(damaged), member_id=MEMBER)

    def test_reader_uses_only_fresh_private_fixed_ring_records(self) -> None:
        now_ms = 1_700_000_000_000
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "raw.ring"
            with path.open("wb") as handle:
                handle.truncate(RAW_RING_CAPACITY * RECORD_BYTES)
                bucket = now_ms // 1000
                handle.seek((bucket % RAW_RING_CAPACITY) * RECORD_BYTES)
                handle.write(record(unix_ms=now_ms))
            path.chmod(0o640)
            sample = read_latest_watchdog_sample(
                path, member_id=MEMBER, now_unix_ms=now_ms + 500
            )
            self.assertEqual(sample["sequence"], 7)
            with self.assertRaisesRegex(TelemetryError, "fresh"):
                read_latest_watchdog_sample(
                    path, member_id=MEMBER, now_unix_ms=now_ms + 6000
                )
            path.chmod(0o660)
            with self.assertRaisesRegex(TelemetryError, "ownership"):
                read_latest_watchdog_sample(path, member_id=MEMBER, now_unix_ms=now_ms)

    def test_aggregate_is_bounded_and_compensates_counter_resets(self) -> None:
        current = [1_700_000_000.0]
        aggregate = TelemetryAggregator(clock=lambda: current[0])
        first = decode_watchdog_record(
            record(unix_ms=int(current[0] * 1000), counters=10), member_id=MEMBER
        )
        snapshot = aggregate.update(first)
        self.assertEqual(snapshot["aggregate"]["requests_received"], 10)
        self.assertEqual(
            aggregate.update(first)["aggregate"]["requests_received"], 10
        )
        current[0] += 1
        reset = decode_watchdog_record(
            record(sequence=8, unix_ms=int(current[0] * 1000), counters=2),
            member_id=MEMBER,
        )
        reset["monotonic_ms"] = first["monotonic_ms"] + 1000
        snapshot = aggregate.update(reset)
        self.assertEqual(snapshot["aggregate"]["requests_received"], 12)
        self.assertNotIn("members", aggregate.recent()[-1])
        replay = decode_watchdog_record(
            record(sequence=7, unix_ms=int(current[0] * 1000), counters=11),
            member_id=MEMBER,
        )
        replay["monotonic_ms"] = reset["monotonic_ms"] + 1
        with self.assertRaisesRegex(TelemetryError, "did not advance"):
            aggregate.update(replay)
        current[0] += 6
        self.assertTrue(aggregate.snapshot()["members"][0]["stale"])
        reset["unix_ms"] = int((current[0] - 10) * 1000)
        with self.assertRaisesRegex(TelemetryError, "stale"):
            aggregate.update(reset)

    def test_aggregate_exposes_exact_wall_and_service_rates(self) -> None:
        current = [1_700_000_000.0]
        aggregate = TelemetryAggregator(clock=lambda: current[0])
        first = decode_watchdog_record(
            record(unix_ms=int(current[0] * 1000), counters=10), member_id=MEMBER
        )
        self.assertIsNone(
            aggregate.update(first)["aggregate"]["rates"]["output_tokens_per_second"]
        )
        current[0] += 1
        second = decode_watchdog_record(
            record(sequence=8, unix_ms=int(current[0] * 1000), counters=10),
            member_id=MEMBER,
        )
        second["monotonic_ms"] = first["monotonic_ms"] + 1000
        second["inference"].update(
            {
                "requests_received": 12,
                "requests_admitted": 12,
                "requests_completed": 12,
                "input_tokens": 1010,
                "output_tokens": 30,
                "cached_tokens": 12,
                "ttft_milliseconds": 210,
                "decode_milliseconds": 1010,
                "exact_token_requests": 12,
                "prefix_cache_hits": 11,
            }
        )
        snapshot = aggregate.update(second)
        rates = snapshot["aggregate"]["rates"]
        self.assertEqual(snapshot["schema_version"], 2)
        self.assertEqual(rates["requests_per_second"], 2.0)
        self.assertEqual(rates["output_tokens_per_second"], 20.0)
        self.assertEqual(rates["aggregate_tokens_per_second"], 20.0)
        self.assertEqual(rates["decode_tokens_per_second"], 20.0)
        self.assertEqual(rates["prefill_tokens_per_second"], 4990.0)
        self.assertEqual(rates["average_ttft_milliseconds"], 100.0)
        self.assertEqual(rates["prefix_cache_hit_ratio"], 0.5)
        self.assertEqual(snapshot["members"][0]["rates"], rates)

        current[0] += 1
        after_reboot = decode_watchdog_record(
            record(sequence=9, unix_ms=int(current[0] * 1000), counters=11),
            member_id=MEMBER,
        )
        after_reboot["monotonic_ms"] = 5
        reboot_snapshot = aggregate.update(after_reboot)
        self.assertEqual(
            reboot_snapshot["aggregate"]["rates"]["requests_per_second"],
            11.0,
        )

    def test_live_token_deltas_expose_rates_before_request_completion(self) -> None:
        current = [1_700_000_000.0]
        aggregate = TelemetryAggregator(clock=lambda: current[0])
        first = decode_watchdog_record(
            record(unix_ms=int(current[0] * 1000), counters=0), member_id=MEMBER
        )
        first["inference"]["active_requests"] = 1
        aggregate.update(first)
        current[0] += 1
        second = decode_watchdog_record(
            record(sequence=8, unix_ms=int(current[0] * 1000), counters=0),
            member_id=MEMBER,
        )
        second["monotonic_ms"] = first["monotonic_ms"] + 1_000
        second["inference"].update({
            "active_requests": 1,
            "input_tokens": 40,
            "output_tokens": 12,
            "cached_tokens": 10,
        })
        rates = aggregate.update(second)["aggregate"]["rates"]
        self.assertEqual(rates["output_tokens_per_second"], 12.0)
        self.assertEqual(rates["aggregate_tokens_per_second"], 12.0)
        self.assertEqual(rates["decode_tokens_per_second"], 12.0)
        self.assertEqual(rates["prefill_tokens_per_second"], 30.0)

    def test_removed_members_are_pruned_and_history_uses_wall_time(self) -> None:
        current = [1_700_000_000.0]
        aggregate = TelemetryAggregator(clock=lambda: current[0])
        first = decode_watchdog_record(
            record(unix_ms=int(current[0] * 1000), counters=10), member_id=MEMBER
        )
        aggregate.update(first)
        current[0] += 4
        second_member = "2" * 32
        second = decode_watchdog_record(
            record(sequence=8, unix_ms=int(current[0] * 1000), counters=3),
            member_id=second_member,
        )
        aggregate.update(second)
        self.assertEqual(len(aggregate.recent(seconds=2)), 1)
        aggregate.reconcile_members({second_member})
        snapshot = aggregate.snapshot()
        self.assertEqual(
            [row["sample"]["member_id"] for row in snapshot["members"]],
            [second_member],
        )
        self.assertEqual(snapshot["aggregate"]["requests_received"], 3)
        with self.assertRaisesRegex(TelemetryError, "identities"):
            aggregate.reconcile_members({"invalid"})


if __name__ == "__main__":
    unittest.main()
