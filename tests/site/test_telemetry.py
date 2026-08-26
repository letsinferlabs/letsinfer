# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import os
import pathlib
import json
import struct
import tempfile
import threading
import time
import unittest
import zlib
from types import SimpleNamespace
from unittest import mock

from core import cli as letsinfer
from core.site.telemetry import (
    COUNTER_FIELDS,
    RAW_RING_CAPACITY,
    RECORD_BYTES,
    TelemetryAggregator,
    TelemetryError,
    TelemetryPublisher,
    _protobuf_message,
    _protobuf_uint,
    decode_watchdog_protocol_sample,
    decode_watchdog_record,
    read_latest_watchdog_sample,
)


MEMBER = "1" * 32


def record(*, sequence: int = 7, unix_ms: int = 1_700_000_000_000, counters: int = 10) -> bytes:
    value = bytearray(RECORD_BYTES)
    struct.pack_into("<IHHQQQ", value, 0, 0x3152494C, 2, RECORD_BYTES, sequence, unix_ms, 1234)
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
    struct.pack_into("<I", value, 276, 4)
    struct.pack_into("<I", value, 280, zlib.crc32(value[:280]))
    return bytes(value)


def protocol_payload(
    *, sequence: int = 7, unix_ms: int = 1_700_000_000_000,
    active: int = 1, output_tokens: int = 10,
) -> bytes:
    def sint(value: int) -> int:
        return (value << 1) ^ (value >> 31)

    gpu = b"".join((
        _protobuf_uint(1, 60),
        _protobuf_uint(2, 70),
        _protobuf_message(3, b"\x3c\x32\x00\x00\x00\x00"),
        _protobuf_uint(4, sint(550)),
        _protobuf_uint(5, 700),
        _protobuf_uint(6, 1200),
        _protobuf_uint(7, 1600),
    ))
    values = [
        (1, sequence), (2, unix_ms), (3, sequence * 1000), (4, (1 << 1) | (1 << 3)),
        (5, 50), (7, 70), (8, 80), (10, sint(400)), (11, sint(-32768)),
        (12, 125), (13, 100), (14, 200), (15, 300), (16, 400),
        (17, 10), (18, 20), (19, 30), (20, 40), (21, 9), (22, 1),
        (23, 3200), (24, 4266), (25, active), (26, 0), (43, 2),
    ]
    payload = b"".join(_protobuf_uint(field, value) for field, value in values)
    payload += _protobuf_message(6, b"\x28\x3c") + _protobuf_message(9, gpu)
    counters = [1, 1, 0, 0, 0, 0, 40, output_tokens, 0, 0, 0, 0, 0, 0, 0, 0]
    payload += b"".join(
        _protobuf_uint(field, value)
        for field, value in zip(range(27, 43), counters)
    )
    return payload


class TelemetryTests(unittest.TestCase):
    def test_cli_reads_active_request_and_live_rate_from_site_aggregate(self) -> None:
        samples = [
            decode_watchdog_protocol_sample(
                protocol_payload(sequence=7, active=1, output_tokens=1), member_id=MEMBER
            ),
            decode_watchdog_protocol_sample(
                protocol_payload(
                    sequence=8,
                    unix_ms=1_700_000_001_000,
                    active=1,
                    output_tokens=12,
                ),
                member_id=MEMBER,
            ),
        ]
        clock = [samples[0]["unix_ms"] / 1000]
        site = TelemetryAggregator(clock=lambda: clock[0])
        site.update(samples[0])
        clock[0] = samples[1]["unix_ms"] / 1000
        expected = site.update(samples[1])["aggregate"]
        other_member = {
            **samples[1],
            "member_id": "0" * 32,
            "system": {**samples[1]["system"], "gpu_percent": 1},
        }

        class Response:
            status = 200

            def read(self, _: int) -> bytes:
                return json.dumps({
                    "telemetry": {
                        "aggregate": expected,
                        "members": [
                            {"stale": False, "sample": other_member},
                            {"stale": False, "sample": samples[1]},
                        ],
                    }
                }).encode()

        connection = mock.Mock()
        connection.getresponse.return_value = Response()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            paths = [
                root / name
                for name in ("controller-ca.crt", "client.crt", "client.key")
            ]
            for path in paths:
                path.write_text("fixture", encoding="ascii")
            context = mock.Mock()
            context_factory = mock.Mock(return_value=context)
            with (
                mock.patch.object(
                    letsinfer.ssl, "create_default_context", context_factory
                ),
                mock.patch.object(letsinfer.http.client, "HTTPSConnection", return_value=connection),
            ):
                aggregate = letsinfer._local_controller_telemetry(
                    {
                        "watchdog_controller_ca_file": str(paths[0]),
                        "watchdog_local_controller_cert_file": str(paths[1]),
                        "watchdog_local_controller_key_file": str(paths[2]),
                    },
                    preferred_member_id=MEMBER,
                )
        context_factory.assert_called_once_with(cafile=str(paths[0].resolve()))
        connection.request.assert_called_once_with(
            "GET", "/control/v1/telemetry?history=0"
        )
        self.assertEqual(aggregate["active_requests"], 1)
        self.assertEqual(aggregate["connected_clients"], 2)
        self.assertEqual(aggregate["rates"]["output_tokens_per_second"], 11.0)
        self.assertTrue(aggregate["fresh"])
        self.assertEqual(aggregate["sample_member_id"], MEMBER)
        self.assertEqual(aggregate["sample_sequence"], 8)
        self.assertEqual(aggregate["system"]["gpu_percent"], 60)

    def test_native_live_sample_decodes_before_durable_ring_flush(self) -> None:
        sample = decode_watchdog_protocol_sample(
            protocol_payload(active=1, output_tokens=12), member_id=MEMBER
        )
        self.assertEqual(sample["inference"]["active_requests"], 1)
        self.assertEqual(sample["inference"]["connected_clients"], 2)
        self.assertEqual(sample["inference"]["output_tokens"], 12)
        self.assertEqual(sample["system"]["nvme_temp_deci_c"], -1)

    def test_child_status_reads_its_own_watchdog_ring(self) -> None:
        local = decode_watchdog_protocol_sample(
            protocol_payload(sequence=9, unix_ms=int(time.time() * 1000)),
            member_id=MEMBER,
        )
        local["system"]["gpu_percent"] = 67
        identity = type("Identity", (), {"member_id": MEMBER})()
        with mock.patch.object(
            letsinfer,
            "watchdog_live_samples",
            return_value=iter((local,)),
        ) as read:
            telemetry = letsinfer._local_watchdog_telemetry(identity)
        read.assert_called_once_with(
            member_id=MEMBER,
            port=letsinfer.WATCHDOG_TELEMETRY_PORT,
            ca_file=letsinfer.default_watchdog_controller_ca_path(),
            controller_cert_file=letsinfer.default_watchdog_local_controller_cert_path(),
            controller_key_file=letsinfer.default_watchdog_local_controller_key_path(),
            stop_event=mock.ANY,
        )
        self.assertIsNotNone(telemetry)
        assert telemetry is not None
        self.assertTrue(telemetry["fresh"])
        self.assertEqual(telemetry["sample_member_id"], MEMBER)
        self.assertEqual(telemetry["system"]["gpu_percent"], 67)

    def test_publisher_forwards_live_samples_without_reading_the_ring(self) -> None:
        samples = [
            decode_watchdog_protocol_sample(
                protocol_payload(sequence=7, active=1, output_tokens=1), member_id=MEMBER
            ),
            decode_watchdog_protocol_sample(
                protocol_payload(sequence=8, active=0, output_tokens=8), member_id=MEMBER
            ),
        ]
        accepted: list[dict[str, object]] = []
        identity = SimpleNamespace(member_id=MEMBER)

        def live(**_: object):
            yield from samples

        with (
            mock.patch("core.site.telemetry.watchdog_live_samples", side_effect=live),
            mock.patch("core.site.telemetry.signed_sample") as signer,
        ):
            publisher = TelemetryPublisher(
                identity,
                watchdog_port=9768,
                watchdog_ca_file=pathlib.Path("ca"),
                watchdog_controller_cert_file=pathlib.Path("cert"),
                watchdog_controller_key_file=pathlib.Path("key"),
                local_accept=lambda document, _: accepted.append(dict(document)),
            )
            publisher.start()
            deadline = time.monotonic() + 1
            while len(accepted) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(publisher.alive())
            publisher.close()
            self.assertFalse(publisher.alive())
            signer.assert_not_called()
        self.assertEqual(
            [row["inference"]["active_requests"] for row in accepted], [1, 0]
        )

    def test_remote_publisher_keeps_signed_transport(self) -> None:
        sample = decode_watchdog_protocol_sample(
            protocol_payload(sequence=9), member_id=MEMBER
        )
        document = {"protocol": "signed", "sample": sample, "signature": "value"}
        posted: list[dict[str, object]] = []
        identity = SimpleNamespace(member_id=MEMBER)

        def live(**_: object):
            yield sample

        with (
            mock.patch("core.site.telemetry.watchdog_live_samples", side_effect=live),
            mock.patch(
                "core.site.telemetry.signed_sample", return_value=document
            ) as signer,
            mock.patch(
                "core.site.telemetry.post_member_sample",
                side_effect=lambda _endpoint, **values: posted.append(values),
            ) as post,
        ):
            publisher = TelemetryPublisher(
                identity,
                watchdog_port=9768,
                watchdog_ca_file=pathlib.Path("ca"),
                watchdog_controller_cert_file=pathlib.Path("cert"),
                watchdog_controller_key_file=pathlib.Path("key"),
                endpoint="https://coordinator.local:9770",
            )
            publisher.start()
            deadline = time.monotonic() + 1
            while not posted and time.monotonic() < deadline:
                time.sleep(0.01)
            publisher.close()
            signer.assert_called_once_with(sample)
            post.assert_called_once()
        self.assertEqual(posted[0]["document"], document)

    def test_watchdog_record_decodes_exact_counters_and_unknowns(self) -> None:
        sample = decode_watchdog_record(record(), member_id=MEMBER)
        self.assertEqual(sample["system"]["cpu_core_percent"], [40, 60])
        self.assertEqual(sample["system"]["nvme_temp_deci_c"], -1)
        self.assertEqual(sample["system"]["vram_clock_mhz"], -1)
        self.assertEqual(sample["inference"]["active_requests"], 2)
        self.assertEqual(sample["inference"]["connected_clients"], 4)
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
