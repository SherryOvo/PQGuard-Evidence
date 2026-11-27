#!/usr/bin/env python3
"""Correct X25519+ML-KEM-768 hybrid key-establishment benchmark.

Why this file exists
--------------------
The earlier prototype (`PQGuard_WAN_Experiment/.../oracle_run.py`,
``run_hybrid_benchmark``) contained two defects that the internal audit of
2026-09-04 identified and that inspection confirms:

1. The pure-ML-KEM decapsulation loop generated a *fresh* key pair and then
   decapsulated a ciphertext encapsulated to a *different* public key, so the
   shared secrets never matched and the timed path was not a valid exchange.
2. The hybrid loop encapsulated inside a 100-iteration timing loop and then
   decapsulated, once, whichever ciphertext remained from the last iteration,
   against an unrelated secret key. The two sides' secrets were never compared,
   so nothing established that both parties derive the same key.

This module fixes both. Every key pair is used only with its own ciphertext,
each timed iteration performs one complete valid operation, and every path
asserts that both parties derive the same secret. If any agreement check fails
the script raises instead of emitting results.

Scope note: this is a *primitive-level* benchmark of the key establishment, not
a TLS handshake. It does not negotiate, authenticate, or exercise a TLS stack,
so its numbers must not be presented as a hybrid-TLS measurement.

Requires liboqs-python (ML-KEM-768) and the ``cryptography`` package (X25519,
HKDF-SHA256).

Run:
    python3 tools/hybrid_kem_benchmark.py --repeats 200 --json-out hybrid.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from typing import Any, Callable, Dict, List, Sequence, Tuple

HYBRID_SALT = b"pq-hybrid-v1"
HYBRID_INFO = b"X25519MLKEM768"
MECHANISM = "ML-KEM-768"


def _load_backends():
    try:
        import oqs
    except ImportError as exc:  # pragma: no cover - host dependent
        raise SystemExit(
            "liboqs-python is required: pip install liboqs-python (and a liboqs build)"
        ) from exc
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError as exc:  # pragma: no cover - host dependent
        raise SystemExit("the cryptography package is required") from exc
    return {
        "oqs": oqs,
        "X25519PrivateKey": X25519PrivateKey,
        "X25519PublicKey": X25519PublicKey,
        "HKDF": HKDF,
        "hashes": hashes,
        "Encoding": Encoding,
        "PublicFormat": PublicFormat,
    }


def combine(ecdhe_ss: bytes, mlkem_ss: bytes, HKDF, hashes) -> bytes:
    """IETF-style combiner over the concatenated shared secrets."""

    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=HYBRID_SALT, info=HYBRID_INFO
    ).derive(ecdhe_ss + mlkem_ss)


def time_repeated(fn: Callable[[], Any], repeats: int) -> List[float]:
    """Per-operation milliseconds; each iteration performs one complete operation."""

    samples: List[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return samples


def summarise(samples: Sequence[float]) -> Dict[str, float]:
    s = sorted(samples)
    n = len(s)
    return {
        "median_ms": statistics.median(s),
        "mean_ms": statistics.fmean(s),
        "p25_ms": s[max(0, int(0.25 * (n - 1)))],
        "p75_ms": s[min(n - 1, int(0.75 * (n - 1)))],
        "min_ms": s[0],
        "max_ms": s[-1],
        "n": n,
    }


def encapsulate_to(oqs, receiver_pk: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate to ``receiver_pk`` and return (ciphertext, sender secret).

    A dedicated sender object is created because the decapsulating object holds
    the receiver's secret key; keeping them separate makes the roles explicit.
    """

    sender = oqs.KeyEncapsulation(MECHANISM)
    ct, ss = sender.encap_secret(receiver_pk)
    if not ct or not ss:
        raise RuntimeError("encapsulation produced empty output")
    return ct, ss


def pure_mlkem(backend, repeats: int) -> Dict[str, Any]:
    oqs = backend["oqs"]
    receiver = oqs.KeyEncapsulation(MECHANISM)
    receiver_pk = receiver.generate_keypair()

    keygen = time_repeated(lambda: oqs.KeyEncapsulation(MECHANISM).generate_keypair(),
                           repeats)

    # Correctness gate: encapsulate to receiver_pk, decapsulate with the matching sk.
    ct_check, sender_ss = encapsulate_to(oqs, receiver_pk)
    receiver_ss = receiver.decap_secret(ct_check)
    if sender_ss != receiver_ss:
        raise RuntimeError("pure ML-KEM shared secrets disagree; refusing to report")

    def one_encap() -> None:
        encapsulate_to(oqs, receiver_pk)

    def one_decap() -> None:
        # Fresh ciphertext for THIS receiver, decapsulated with ITS secret key.
        # The earlier prototype decapsulated with an unrelated key pair here.
        ct, _ = encapsulate_to(oqs, receiver_pk)
        if receiver.decap_secret(ct) is None:
            raise RuntimeError("decapsulation returned nothing")

    encap = time_repeated(one_encap, repeats)
    decap = time_repeated(one_decap, repeats)

    return {
        "mechanism": MECHANISM,
        "keygen": summarise(keygen),
        "encapsulate": summarise(encap),
        "decapsulate": summarise(decap),
        "shared_secret_agreement": True,
        "ciphertext_bytes": len(ct_check),
        "public_key_bytes": len(receiver_pk),
    }


def hybrid_x25519_mlkem(backend, repeats: int) -> Dict[str, Any]:
    oqs = backend["oqs"]
    X25519PrivateKey = backend["X25519PrivateKey"]
    X25519PublicKey = backend["X25519PublicKey"]
    HKDF = backend["HKDF"]
    hashes = backend["hashes"]
    Encoding = backend["Encoding"]
    PublicFormat = backend["PublicFormat"]

    # Long-lived material, generated once and outside every timing loop.
    alice_ecdh = X25519PrivateKey.generate()
    alice_ecdh_pub = alice_ecdh.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    alice_mlkem = oqs.KeyEncapsulation(MECHANISM)
    alice_mlkem_pk = alice_mlkem.generate_keypair()

    bob_ecdh = X25519PrivateKey.generate()
    bob_ecdh_pub = bob_ecdh.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def alice_ecdh_ss() -> bytes:
        return alice_ecdh.exchange(X25519PublicKey.from_public_bytes(bob_ecdh_pub))

    def bob_ecdh_ss() -> bytes:
        return bob_ecdh.exchange(X25519PublicKey.from_public_bytes(alice_ecdh_pub))

    # --- correctness gate: one full exchange, both sides compared ---------
    ct_gate, bob_mlkem_ss = encapsulate_to(oqs, alice_mlkem_pk)
    alice_mlkem_ss = alice_mlkem.decap_secret(ct_gate)
    if alice_ecdh_ss() != bob_ecdh_ss():
        raise RuntimeError("X25519 shared secrets disagree; refusing to report")
    if alice_mlkem_ss != bob_mlkem_ss:
        raise RuntimeError("ML-KEM shared secrets disagree; refusing to report")
    alice_key = combine(alice_ecdh_ss(), alice_mlkem_ss, HKDF, hashes)
    bob_key = combine(bob_ecdh_ss(), bob_mlkem_ss, HKDF, hashes)
    if alice_key != bob_key:
        raise RuntimeError("hybrid combiner output disagrees; refusing to report")

    # Material used for the timing loops; the same valid structure as the gate.
    ct_timed, _ = encapsulate_to(oqs, alice_mlkem_pk)

    def one_responder_side() -> None:
        """Bob: X25519 with Alice's public key, then encapsulate to Alice."""

        ecdhe_ss = bob_ecdh_ss()
        _ct, mlkem_ss = encapsulate_to(oqs, alice_mlkem_pk)
        combine(ecdhe_ss, mlkem_ss, HKDF, hashes)

    def one_initiator_side() -> None:
        """Alice: X25519 with Bob's public key, then decapsulate Bob's ciphertext."""

        ecdhe_ss = alice_ecdh_ss()
        mlkem_ss = alice_mlkem.decap_secret(ct_timed)
        combine(ecdhe_ss, mlkem_ss, HKDF, hashes)

    responder = time_repeated(one_responder_side, repeats)
    initiator = time_repeated(one_initiator_side, repeats)

    return {
        "mechanism": "X25519+ML-KEM-768",
        "responder_side": summarise(responder),
        "initiator_side": summarise(initiator),
        "x25519_shared_secret_agreement": True,
        "mlkem_shared_secret_agreement": True,
        "combiner_agreement": True,
        "combiner": (
            "HKDF-SHA256(salt=pq-hybrid-v1, info=X25519MLKEM768) "
            "over ecdhe_ss||mlkem_ss"
        ),
        "mlkem_ciphertext_bytes": len(ct_timed),
        "scope": "primitive-level key establishment; not a TLS handshake",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=200)
    ap.add_argument("--json-out", type=str, default=None)
    args = ap.parse_args()

    backend = _load_backends()
    oqs = backend["oqs"]
    print(f"repeats={args.repeats}")
    detected = sorted(
        m for m in oqs.get_enabled_kem_mechanisms() if "ML-KEM" in m or "Kyber" in m
    )
    print(f"  enabled KEM mechanisms matching ML-KEM/Kyber: {detected}")

    pure = pure_mlkem(backend, args.repeats)
    hyb = hybrid_x25519_mlkem(backend, args.repeats)

    pure_rt = pure["encapsulate"]["median_ms"] + pure["decapsulate"]["median_ms"]
    hyb_rt = hyb["responder_side"]["median_ms"] + hyb["initiator_side"]["median_ms"]
    results = {
        "repeats": args.repeats,
        "pure_mlkem768": pure,
        "hybrid_x25519_mlkem768": hyb,
        "all_agreement_checks_passed": True,
        "hybrid_overhead": {
            "pure_round_trip_median_ms": pure_rt,
            "hybrid_round_trip_median_ms": hyb_rt,
            "absolute_delta_ms": hyb_rt - pure_rt,
            "relative_pct": (hyb_rt - pure_rt) / pure_rt * 100.0,
        },
    }

    print(json.dumps(results, indent=2, sort_keys=True))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, sort_keys=True)
        print(f"\nwritten to {args.json_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
