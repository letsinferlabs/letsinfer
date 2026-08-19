# SPDX-License-Identifier: AGPL-3.0-only
"""SGLang HiCache storage backed by the Let's Infer Rust prefix store.

SGLang owns the host/device pools and supplies its exact page identities. This
adapter persists each opaque page as one integrity-checked Let's Infer record;
the engine key remains authoritative and a partial record is always a miss.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import struct
from typing import Any

import torch
from letsinfer_prefix_store import PrefixStore
from sglang.srt.mem_cache.hicache_storage import (
    HiCacheStorage,
    PoolHitPolicy,
    PoolName,
    PoolTransfer,
    PoolTransferResult,
)


LOGGER = logging.getLogger(__name__)
PROTOCOL = "letsinfer-sglang-page-v1"


def _positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _nonnegative_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _pool_name(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _record_tokens(pool: str, key: str) -> list[int]:
    if not isinstance(key, str) or not key:
        raise ValueError("SGLang cache key must be a non-empty string")
    raw = b"letsinfer-sglang-page-v1\0" + pool.encode("utf-8") + b"\0" + key.encode(
        "utf-8"
    )
    raw += b"\0" * (-len(raw) % 4)
    return list(struct.unpack(f"<{len(raw) // 4}I", raw))


def _fingerprint(storage_config: Any) -> bytes:
    identity = {
        "protocol": PROTOCOL,
        "model": storage_config.model_name,
        "tp_rank": storage_config.tp_rank,
        "tp_size": storage_config.tp_size,
        "pp_rank": storage_config.pp_rank,
        "pp_size": storage_config.pp_size,
        "attn_cp_rank": storage_config.attn_cp_rank,
        "attn_cp_size": storage_config.attn_cp_size,
        "is_mla_model": storage_config.is_mla_model,
        "page_first": storage_config.is_page_first_layout,
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()


class LetsInferHiCacheStorage(HiCacheStorage):
    """Exact, bounded, restart-durable SGLang page storage."""

    def __init__(self, storage_config: Any, _factory_kwargs: Any = None):
        extra = storage_config.extra_config or {}
        capacity_bytes = _positive_int(extra.get("capacity_bytes"), "capacity_bytes")
        ttl_seconds = _positive_int(extra.get("ttl_seconds"), "ttl_seconds")
        resident_capacity_bytes = _nonnegative_int(
            extra.get("resident_capacity_bytes", 0), "resident_capacity_bytes"
        )
        root = os.environ.get("LETSINFER_PREFIX_STORE_DIR")
        if not root:
            raise ValueError("LETSINFER_PREFIX_STORE_DIR is required")
        direct_reads = extra.get("direct_reads", True)
        if not isinstance(direct_reads, bool):
            raise ValueError("direct_reads must be boolean")
        self._fingerprint = _fingerprint(storage_config)
        self._store = PrefixStore(
            root,
            capacity_bytes,
            ttl_seconds,
            1,
            resident_capacity_bytes,
            direct_reads,
        )
        self.registered_pools: dict[Any, Any] = {}

    def _reader(self, pool: str, key: str):
        tokens = _record_tokens(pool, key)
        reader = self._store.longest_prefix(self._fingerprint, tokens, len(tokens))
        if reader is not None and reader.token_count != len(tokens):
            reader.close()
            return None
        return reader

    def _exists(self, pool: str, key: str) -> bool:
        try:
            reader = self._reader(pool, key)
            if reader is None:
                return False
            reader.close()
            return True
        except Exception as error:  # Corruption or IO failure is a safe miss.
            LOGGER.warning("Let's Infer cache lookup failed for %s: %s", key, error)
            return False

    def exists(self, key: str) -> bool:
        return self._exists(_pool_name(PoolName.KV), key)

    def _get_page(self, pool: str, key: str, target: torch.Tensor):
        reader = None
        try:
            if not target.is_contiguous() or target.device.type != "cpu":
                return None
            reader = self._reader(pool, key)
            if reader is None or reader.region_names != ["page"]:
                return None
            byte_count = target.numel() * target.element_size()
            if reader.region_byte_count(0) != byte_count:
                return None
            destination = target.view(torch.uint8).numpy()
            reader.read_region_into(0, destination)
            self._store.touch(reader)
            return target
        except Exception as error:
            LOGGER.warning("Let's Infer cache read failed for %s: %s", key, error)
            return None
        finally:
            if reader is not None:
                reader.close()

    def get(
        self,
        key: str,
        target_location: torch.Tensor | None = None,
        target_sizes: Any = None,
    ):
        del target_sizes
        if target_location is None:
            return None
        return self._get_page(_pool_name(PoolName.KV), key, target_location)

    def batch_get(self, keys, target_locations=None, target_sizes=None):
        del target_sizes
        targets = target_locations or [None] * len(keys)
        return [self.get(key, target) for key, target in zip(keys, targets)]

    def _set_page(self, pool: str, key: str, value: torch.Tensor) -> bool:
        try:
            if value.device.type != "cpu":
                return False
            if self._exists(pool, key):
                return True
            page = value.contiguous().view(torch.uint8)
            tokens = _record_tokens(pool, key)
            writer = self._store.begin_capture(
                self._fingerprint, tokens, [("page", page.numel())]
            )
            if writer is None:
                return self._exists(pool, key)
            writer.write_region_from(0, page.numpy())
            writer.commit_sync()
            return True
        except Exception as error:
            LOGGER.warning("Let's Infer cache write failed for %s: %s", key, error)
            return False

    def set(
        self,
        key: str,
        value: torch.Tensor | None = None,
        target_location: Any = None,
        target_sizes: Any = None,
    ) -> bool:
        del target_location, target_sizes
        return value is not None and self._set_page(_pool_name(PoolName.KV), key, value)

    def batch_set(
        self,
        keys,
        values=None,
        target_locations=None,
        target_sizes=None,
    ) -> bool:
        del target_locations, target_sizes
        return values is not None and all(
            self.set(key, value) for key, value in zip(keys, values)
        )

    def batch_exists_v2(self, keys, pool_transfers=None, extra_info=None):
        del extra_info
        kv_pool = _pool_name(PoolName.KV)
        kv_pages = next(
            (index for index, key in enumerate(keys) if not self._exists(kv_pool, key)),
            len(keys),
        )
        hits = {kv_pool: kv_pages} if kv_pages else {}
        final_pages = kv_pages
        for transfer in pool_transfers or []:
            if final_pages == 0:
                break
            pool = _pool_name(transfer.name)
            if transfer.hit_policy == PoolHitPolicy.ALL_PAGES:
                boundary = next(
                    (
                        index
                        for index in range(kv_pages)
                        if not self._exists(pool, keys[index])
                    ),
                    kv_pages,
                )
            else:
                trailing = max(1, len(transfer.keys) if transfer.keys else 1)
                boundary = 0
                for prefix_len in range(kv_pages, 0, -1):
                    if all(
                        self._exists(pool, keys[index])
                        for index in range(max(0, prefix_len - trailing), prefix_len)
                    ):
                        boundary = prefix_len
                        break
            if boundary:
                hits[pool] = boundary
            final_pages = min(final_pages, boundary)
        return PoolTransferResult(final_pages, hits)

    def _transfer_io(self, transfers: list[PoolTransfer], read: bool):
        results: dict[str, list[bool]] = {}
        for transfer in transfers:
            pool = _pool_name(transfer.name)
            host_pool = self.registered_pools[transfer.name]
            keys = transfer.keys or []
            page_size = getattr(host_pool, "page_size", 1) or 1
            indices = transfer.host_indices
            if indices is None or indices.numel() != len(keys) * page_size:
                results[transfer.name] = [False] * len(keys)
                continue
            rows = []
            for index, key in enumerate(keys):
                page_offset = indices[index * page_size].item()
                if read:
                    page = host_pool.get_dummy_flat_data_page()
                    loaded = self._get_page(pool, key, page)
                    if loaded is not None:
                        host_pool.set_from_flat_data_page(page_offset, loaded)
                    rows.append(loaded is not None)
                else:
                    page = host_pool.get_data_page(page_offset, flat=True)
                    rows.append(self._set_page(pool, key, page))
            results[transfer.name] = rows
        return results

    def batch_get_v2(self, transfers, extra_info=None):
        del extra_info
        return self._transfer_io(transfers, True)

    def batch_set_v2(self, transfers, extra_info=None):
        del extra_info
        return self._transfer_io(transfers, False)

    def clear(self) -> bool:
        # The CLI clears a stopped runtime's dedicated store directory. Doing
        # it in-process could race active readers, so fail closed here.
        return False

    def get_stats(self):
        return self._store.statistics()
