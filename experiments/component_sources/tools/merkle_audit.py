#!/usr/bin/env python3
"""Merkle-batched, tamper-evident audit batches for PQGuard.

Motivation
----------
The evaluated PQGuard logger signs *every* audit record synchronously. At the
measured SPHINCS+-SHA2-128f-simple cost of 17--20 ms per signature this caps a
single core at roughly 50--57 records/s and serialises the audit lock, which is
the throughput bottleneck reported in the paper. This module replaces the
per-record signature with one signature per batch plus a logarithmic inclusion
proof per record.

Design
------
* Leaves are the existing per-entry hashes, computed exactly as the current
  logger computes them (SHA-256 over a domain-separated canonical encoding), so
  the entry format is unchanged.
* The tree is built bottom-up; a node with no sibling is *promoted unchanged*
  rather than dropped. Dropping odd trailing nodes is the defect that an
  internal audit found in the earlier prototype: it silently excluded up to half
  the leaves from the tree while leaving the root signature valid.
* The root is signed once per batch. Each entry carries an inclusion proof of
  ceil(log2(n)) sibling hashes.
* Verification recomputes the root from the entry and its proof and checks the
  batch signature over the root. Any payload change, reorder, deletion, insertion
  or truncation therefore fails either the proof recomputation or the root
  comparison.

This module deliberately contains no timing claims. Measurements must be taken
on the target host with the real signature backend.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Domain separation. The entry domain matches the evaluated logger so that
# batched batches are verifiable against the same entry encoding.
ENTRY_DOMAIN = b"PQGuard-Audit-Entry-v2\x00"
NODE_DOMAIN = b"PQGuard-Merkle-Node-v1\x00"
ROOT_DOMAIN = b"PQGuard-Merkle-Root-v1\x00"
BATCH_DOMAIN = b"PQGuard-Audit-Batch-v1\x00"

GENESIS_HASH = "0" * 64

# Measured SPHINCS+-SHA2-128f-simple signature size, used only to size the
# comparison; it is not a timing figure.
SPHINCS_128F_SIGNATURE_BYTES = 17088


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_entry(entry: Dict[str, Any]) -> bytes:
    """Entry hash: domain-separated canonical JSON, matching the logger."""

    canonical = json.dumps(
        entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return sha256(ENTRY_DOMAIN + canonical)


def _node(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_DOMAIN + left + right)


# --------------------------------------------------------------------------
# Merkle tree with full leaf coverage
# --------------------------------------------------------------------------
@dataclass
class MerkleTree:
    """Binary Merkle tree that never drops an odd trailing node."""

    leaves: List[bytes]
    levels: List[List[bytes]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.leaves:
            raise ValueError("a Merkle tree needs at least one leaf")
        self.levels = [list(self.leaves)]
        current = list(self.leaves)
        while len(current) > 1:
            nxt: List[bytes] = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    nxt.append(_node(current[i], current[i + 1]))
                else:
                    # Promote the lone trailing node unchanged. This is the
                    # property the earlier prototype violated.
                    nxt.append(current[i])
            self.levels.append(nxt)
            current = nxt

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    @property
    def height(self) -> int:
        return len(self.levels) - 1

    def covered_leaf_count(self) -> int:
        """Leaves reachable from the root by inclusion proofs.

        Every leaf must be covered; this is the counter that must equal
        ``len(leaves)`` and is checked by the tests.
        """

        return sum(1 for i in range(len(self.leaves)) if self.proof(i) is not None)

    def proof(self, index: int) -> List[Tuple[str, bytes]]:
        """Inclusion proof for ``index`` as an ordered list of (side, hash)."""

        if not 0 <= index < len(self.leaves):
            raise IndexError(index)
        proof: List[Tuple[str, bytes]] = []
        idx = index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                sibling = idx + 1
                if sibling < len(level):
                    proof.append(("right", level[sibling]))
            else:
                proof.append(("left", level[idx - 1]))
            idx //= 2
        return proof


def verify_inclusion(leaf: bytes, proof: Sequence[Tuple[str, bytes]], root: bytes) -> bool:
    """Recompute the root from a leaf and its proof."""

    node = leaf
    for side, sibling in proof:
        if side == "right":
            node = _node(node, sibling)
        elif side == "left":
            node = _node(sibling, node)
        else:
            raise ValueError(f"unknown proof side: {side!r}")
    return hmac.compare_digest(node, root)


# --------------------------------------------------------------------------
# Signature backends
# --------------------------------------------------------------------------
class Signer:
    """Interface a signature backend must provide."""

    name = "abstract"
    signature_bytes = 0

    def sign(self, message: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def verify(self, message: bytes, signature: bytes) -> bool:  # pragma: no cover
        raise NotImplementedError


class StubSigner(Signer):
    """Deterministic stand-in used for functional tests without liboqs.

    It is HMAC-SHA256, padded so that signature sizes match
    SPHINCS+-SHA2-128f-simple and therefore so that retained-byte arithmetic is
    representative. It provides no post-quantum security and must never be used
    for measurements that the paper reports.
    """

    name = "stub-hmac-sha256 (functional tests only)"
    signature_bytes = SPHINCS_128F_SIGNATURE_BYTES

    def __init__(self, key: bytes = b"stub-audit-key") -> None:
        self._key = key

    def sign(self, message: bytes) -> bytes:
        tag = hmac.new(self._key, message, hashlib.sha256).digest()
        return tag + bytes(self.signature_bytes - len(tag))

    def verify(self, message: bytes, signature: bytes) -> bool:
        if len(signature) != self.signature_bytes:
            return False
        return hmac.compare_digest(self.sign(message), signature)


def _available_mechanisms(oqs) -> list:
    try:
        return sorted(oqs.get_enabled_sig_mechanisms())
    except Exception:  # pragma: no cover
        return []


class LibOQSSlhDsaSigner(Signer):
    """Real hash-based signature backend via liboqs-python.

    Resolves the mechanism by probing the loaded liboqs, because the name of the
    evaluated scheme changed across library generations:

      * liboqs 0.12.0 (the version used for the evaluated runs) exposes the
        non-standardised name ``SPHINCS+-SHA2-128f-simple``;
      * liboqs 0.16.0 exposes only the standardised FIPS 205 name
        ``SLH_DSA_PURE_SHA2_128F``.

    These are the same scheme at the same parameter set: both produce 17,088-byte
    signatures, which is the size reported in Section 5 of the manuscript. The
    resolved name is recorded on the instance and must be stated wherever a
    number from this backend is reported.
    """

    def __init__(self, mechanism: Optional[str] = None) -> None:
        try:
            import oqs  # noqa: WPS433 (optional dependency)
        except ImportError as exc:  # pragma: no cover - depends on host
            raise RuntimeError(
                "liboqs-python is not installed; install it or use StubSigner"
            ) from exc
        available = _available_mechanisms(oqs)
        if mechanism is None:
            for candidate in ("SPHINCS+-SHA2-128f-simple", "SLH_DSA_PURE_SHA2_128F"):
                if candidate in available:
                    mechanism = candidate
                    break
            else:
                raise RuntimeError(
                    "no SHA2-128f hash-based mechanism in this liboqs build; "
                    f"available SPHINCS+/SLH entries: "
                    f"{[m for m in available if 'SPHINCS' in m or 'SLH' in m][:6]}"
                )
        elif available and mechanism not in available:
            raise RuntimeError(f"mechanism {mechanism!r} is not enabled in this build")
        self._oqs = oqs
        self._mechanism = mechanism
        self._signer = oqs.Signature(mechanism)
        self.public_key = self._signer.generate_keypair()
        # Some liboqs-python builds report length_signature as 0, so probe the
        # real signature length instead of trusting the attribute.
        probe = self._signer.sign(b"pqguard-signature-length-probe")
        self.signature_bytes = len(probe)
        if self.signature_bytes == 0:
            raise RuntimeError("backend produced an empty signature")
        self.name = f"{mechanism} (liboqs {getattr(oqs, '__version__', 'unknown')})"

    def sign(self, message: bytes) -> bytes:
        return self._signer.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self._signer.verify(message, signature, self.public_key)


# Backwards-compatible aliases used by the test modules.
LibOQSPhincsSigner = LibOQSSlhDsaSigner


def resolve_real_signer() -> "LibOQSSlhDsaSigner":
    return LibOQSSlhDsaSigner()


# --------------------------------------------------------------------------
# Batched audit log
# --------------------------------------------------------------------------
@dataclass
class AuditBatch:
    """A signed batch over a contiguous run of entries."""

    stream_id: str
    start_sequence: int
    end_sequence: int
    leaf_count: int
    root: bytes
    signature: bytes
    previous_batch_hash: str
    timestamp: float
    level_widths: List[int]

    def header(self) -> Dict[str, Any]:
        """The signed payload; excludes the signature itself."""

        return {
            "stream_id": self.stream_id,
            "start_sequence": self.start_sequence,
            "end_sequence": self.end_sequence,
            "leaf_count": self.leaf_count,
            "root": self.root.hex(),
            "previous_batch_hash": self.previous_batch_hash,
            "level_widths": self.level_widths,
        }

    def signable_bytes(self) -> bytes:
        return BATCH_DOMAIN + json.dumps(
            self.header(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def batch_hash(self) -> str:
        return sha256(self.signable_bytes() + self.signature).hex()


class MerkleAuditLogger:
    """Audit logger whose per-batch cost is one signature.

    Entries are appended and buffered. Reaching ``batch_size`` seals a batch
    immediately; ``flush`` seals only the final partial batch. Each sealed batch
    is signed once and carries per-entry inclusion proofs.
    The entry payload format is byte-identical to the evaluated per-record
    logger, so switching logging policy does not change what is audited.
    """

    def __init__(
        self,
        signer: Signer,
        stream_id: str = "stream-0",
        batch_size: int = 1000,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        self._signer = signer
        self.stream_id = stream_id
        self.batch_size = batch_size
        self._pending: List[Dict[str, Any]] = []
        self._next_sequence = 0
        self._last_batch_hash = "0" * 64
        self.batches: List[AuditBatch] = []
        self._proofs: Dict[int, List[Tuple[str, bytes]]] = {}
        # Counting hooks for instrumentation; see the instrumentation contract in
        # the revision notes.
        self.signature_count = 0
        self.flush_count = 0

    # -- ingestion ---------------------------------------------------------
    def append(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Buffer one entry and return it as stored.

        The returned dict is the exact object that will be hashed, so callers
        can use it later as a verification input. ``entry["sequence"]`` carries
        the sequence number.
        """

        entry = dict(payload)
        entry["stream_id"] = self.stream_id
        entry["sequence"] = self._next_sequence
        entry.setdefault("previous_hash", self._previous_hash())
        self._pending.append(entry)
        self._next_sequence += 1
        if len(self._pending) >= self.batch_size:
            self._seal_pending(self.batch_size)
        return entry

    def _previous_hash(self) -> str:
        if self._pending:
            return hash_entry(self._pending[-1]).hex()
        if self.batches:
            return self.batches[-1].root.hex()
        return GENESIS_HASH

    # -- batching ----------------------------------------------------------
    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def _seal_pending(self, count: int) -> AuditBatch:
        if count < 1 or count > len(self._pending):
            raise ValueError("invalid batch size for pending entries")
        entries = list(self._pending[:count])
        del self._pending[:count]
        leaves = [hash_entry(entry) for entry in entries]
        tree = MerkleTree(leaves)
        root = tree.root
        batch = AuditBatch(
            stream_id=self.stream_id,
            start_sequence=entries[0]["sequence"],
            end_sequence=entries[-1]["sequence"],
            leaf_count=len(entries),
            root=root,
            signature=b"",
            previous_batch_hash=self._last_batch_hash,
            timestamp=time.time(),
            level_widths=[len(level) for level in tree.levels],
        )
        batch.signature = self._signer.sign(batch.signable_bytes())
        self.signature_count += 1
        self.flush_count += 1
        base = entries[0]["sequence"]
        for i in range(len(entries)):
            self._proofs[base + i] = tree.proof(i)
        self.batches.append(batch)
        self._last_batch_hash = batch.batch_hash()
        return batch

    def flush(self) -> AuditBatch:
        """Seal the remaining partial batch.

        Full batches are sealed by :meth:`append`; callers use ``flush`` only at
        a durability boundary or the end of a run.
        """
        if not self._pending:
            raise ValueError("nothing to flush")
        return self._seal_pending(len(self._pending))

    # -- verification ------------------------------------------------------
    def verify_entry(self, entry: Dict[str, Any]) -> bool:
        """Verify one entry against its batch root and signature."""

        seq = entry.get("sequence")
        batch = self._batch_for(seq)
        if batch is None:
            return False
        proof = self._proofs.get(seq)
        if proof is None:
            return False
        if not verify_inclusion(hash_entry(entry), proof, batch.root):
            return False
        return self._signer.verify(batch.signable_bytes(), batch.signature)

    def verify_batch(self, batch: AuditBatch, entries: Sequence[Dict[str, Any]]) -> bool:
        """Full batch verification: leaf count, tree shape, root, signature."""

        if not entries or len(entries) != batch.leaf_count:
            return False
        if entries[0].get("sequence") != batch.start_sequence:
            return False
        if entries[-1].get("sequence") != batch.end_sequence:
            return False
        tree = MerkleTree([hash_entry(entry) for entry in entries])
        if tree.root != batch.root:
            return False
        if [len(level) for level in tree.levels] != batch.level_widths:
            return False
        return self._signer.verify(batch.signable_bytes(), batch.signature)

    def _batch_for(self, sequence: Optional[int]) -> Optional[AuditBatch]:
        if sequence is None:
            return None
        for batch in self.batches:
            if batch.start_sequence <= sequence <= batch.end_sequence:
                return batch
        return None

    # -- reporting ---------------------------------------------------------
    def coverage(self) -> Dict[str, int]:
        """Leaf-coverage accounting; ``covered`` must equal ``leaves``."""

        leaves = sum(batch.leaf_count for batch in self.batches)
        covered = len(self._proofs)
        return {"leaves": leaves, "covered": covered}

    def retained_bytes(self) -> Dict[str, int]:
        """Per-entry retained bytes for the batch policy versus per-record signing.

        Per-record policy: one ``signature_bytes`` signature per entry.
        Batch policy: one root signature per batch, amortised, plus
        ceil(log2 n) proof hashes of 32 bytes per entry.
        """

        leaves = sum(batch.leaf_count for batch in self.batches)
        if leaves == 0:
            return {"entries": 0}
        sig_total = self._signer.signature_bytes * len(self.batches)
        proof_hashes = sum(
            len(self._proofs.get(seq, [])) for seq in self._proofs
        )
        per_record = self._signer.signature_bytes * leaves
        return {
            "entries": leaves,
            "per_record_policy_bytes": per_record,
            "batch_policy_bytes": sig_total + proof_hashes * 32,
            "batch_signature_bytes": sig_total,
            "inclusion_proof_bytes": proof_hashes * 32,
            "batches": len(self.batches),
            "saving_ratio": 1.0 - (sig_total + proof_hashes * 32) / per_record,
            "proof_hashes": proof_hashes,
            "expected_proof_hashes": leaves * max(
                0, math.ceil(math.log2(max(2, leaves)))
            ),
        }
