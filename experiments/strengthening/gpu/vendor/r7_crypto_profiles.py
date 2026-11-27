#!/usr/bin/env python3
"""Cryptographic profiles for the R11 CBAS protocol harness.

The harness models a persistent session, not a fresh session per request.
Every protected record derives independent AES-GCM material from
``(sid, direction, sequence)``. The post-quantum profile combines ephemeral
X25519 and ML-KEM-768; it is not a replacement for TLS 1.3.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

try:
    import oqs
except ModuleNotFoundError:  # Allows classical contract tests on hosts without liboqs.
    oqs = None
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_LABEL = b"PQGUARD-R11-HYBRID-SESSION-V1\0"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hkdf(shared: bytes, context: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=context).derive(shared)


@dataclass(frozen=True)
class SessionResult:
    key: bytes
    sid: str
    setup_ns: int
    wire_bytes: int
    bundle_verified: bool
    policy_verified: bool
    hybrid: bool


class ProfileBase:
    """Shared authenticated-policy and per-record protection interface."""

    name: str
    kem_algorithm: str
    identity_algorithm: str
    audit_algorithm: str

    def __init__(self, policy_digest: str) -> None:
        self.policy_digest = policy_digest
        now = int(time.time())
        self.policy_descriptor = {
            "version": 1,
            "policy_digest": policy_digest,
            "valid_from": now - 60,
            "valid_until": now + 24 * 60 * 60,
        }

    def _record_context(self, sid: str, direction: str, sequence: int, purpose: str) -> bytes:
        if direction not in {"request", "response"}:
            raise ValueError("invalid record direction")
        if sequence < 0:
            raise ValueError("sequence must be non-negative")
        return PROTOCOL_LABEL + canonical(
            {"direction": direction, "purpose": purpose, "sequence": sequence, "sid": sid}
        )

    def record_material(self, session: SessionResult, direction: str, sequence: int) -> tuple[bytes, bytes]:
        """Return a distinct AES-GCM key and nonce for every protocol record."""
        key = hkdf(session.key, self._record_context(session.sid, direction, sequence, "record-key"), 32)
        nonce = hkdf(session.key, self._record_context(session.sid, direction, sequence, "record-nonce"), 12)
        return key, nonce

    def associated_data(self, session: SessionResult, direction: str, sequence: int) -> bytes:
        return canonical(
            {
                "direction": direction,
                "policy_digest": self.policy_digest,
                "sequence": sequence,
                "sid": session.sid,
            }
        )

    def _validate_policy(self, descriptor: dict[str, Any], signature: bytes, now: int) -> bool:
        if not self.verify_policy(canonical(descriptor), signature):
            return False
        if descriptor.get("policy_digest") != self.policy_digest:
            return False
        return int(descriptor["valid_from"]) <= now <= int(descriptor["valid_until"])

    def export_public(self) -> dict[str, Any]:
        """Export only public verification material and the signed-policy descriptor."""
        return {
            "profile": self.name,
            "kem": self.kem_algorithm,
            "identity": self.identity_algorithm,
            "audit": self.audit_algorithm,
            "identity_public_key": self.identity_public.hex(),
            "policy_public_key": self.policy_public.hex(),
            "audit_public_key": self.audit_public.hex(),
            "policy_descriptor": self.policy_descriptor,
        }


class ClassicalProfile(ProfileBase):
    name = "classical"
    kem_algorithm = "X25519"
    identity_algorithm = "Ed25519"
    audit_algorithm = "Ed25519"

    def __init__(self, policy_digest: str) -> None:
        super().__init__(policy_digest)
        self._identity_sk = Ed25519PrivateKey.generate()
        self.identity_public = self._identity_sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._policy_sk = Ed25519PrivateKey.generate()
        self.policy_public = self._policy_sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._audit_sk = Ed25519PrivateKey.generate()
        self.audit_public = self._audit_sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign_identity(self, message: bytes) -> bytes:
        return self._identity_sk.sign(message)

    def verify_identity(self, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.identity_public).verify(signature, message)
            return True
        except Exception:
            return False

    def sign_policy(self, message: bytes) -> bytes:
        return self._policy_sk.sign(message)

    def verify_policy(self, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.policy_public).verify(signature, message)
            return True
        except Exception:
            return False

    def sign_audit(self, message: bytes) -> bytes:
        return self._audit_sk.sign(message)

    def verify_audit(self, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.audit_public).verify(signature, message)
            return True
        except Exception:
            return False

    def establish_session(self, context: bytes) -> SessionResult:
        start = time.perf_counter_ns()
        client_sk = X25519PrivateKey.generate()
        server_sk = X25519PrivateKey.generate()
        client_pk = client_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        server_pk = server_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        policy_signature = self.sign_policy(canonical(self.policy_descriptor))
        bundle = {
            "client_x25519": client_pk.hex(),
            "policy": self.policy_descriptor,
            "policy_signature": policy_signature.hex(),
            "server_x25519": server_pk.hex(),
            "transcript_context": sha256(context),
            "version": "R11-CBAS-v1",
        }
        bundle_bytes = canonical(bundle)
        bundle_signature = self.sign_identity(bundle_bytes)
        if not self.verify_identity(bundle_bytes, bundle_signature):
            raise RuntimeError("identity bundle verification failed")
        if not self._validate_policy(bundle["policy"], policy_signature, int(time.time())):
            raise RuntimeError("policy certificate verification failed")
        client_shared = client_sk.exchange(X25519PublicKey.from_public_bytes(server_pk))
        server_shared = server_sk.exchange(X25519PublicKey.from_public_bytes(client_pk))
        if client_shared != server_shared:
            raise RuntimeError("X25519 shared-secret mismatch")
        transcript = sha256(bundle_bytes + bundle_signature + context)
        client_session_key = hkdf(client_shared, PROTOCOL_LABEL + b"classical\0" + transcript.encode())
        server_session_key = hkdf(server_shared, PROTOCOL_LABEL + b"classical\0" + transcript.encode())
        confirmation_context = PROTOCOL_LABEL + b"confirmation\0" + transcript.encode()
        server_confirmation = hmac.digest(server_session_key, confirmation_context, "sha256")
        expected_confirmation = hmac.digest(client_session_key, confirmation_context, "sha256")
        if not hmac.compare_digest(server_confirmation, expected_confirmation):
            raise RuntimeError("key confirmation failed")
        sid = sha256(PROTOCOL_LABEL + b"sid\0" + transcript.encode())
        return SessionResult(
            client_session_key,
            sid,
            time.perf_counter_ns() - start,
            len(client_pk) + len(server_pk) + len(bundle_bytes) + len(bundle_signature),
            True,
            True,
            False,
        )


class PostQuantumProfile(ProfileBase):
    name = "post_quantum"
    kem_algorithm = "ML-KEM-768"
    identity_algorithm = "ML-DSA-44"
    audit_algorithm = "SLH_DSA_PURE_SHA2_128F"

    def __init__(self, policy_digest: str) -> None:
        super().__init__(policy_digest)
        if oqs is None:
            raise RuntimeError("Post-quantum profile requires liboqs-python with ML-KEM/ML-DSA/SLH-DSA support")
        with oqs.Signature(self.identity_algorithm) as signer:
            self.identity_public = signer.generate_keypair()
            self._identity_sk = signer.export_secret_key()
        with oqs.Signature(self.identity_algorithm) as signer:
            self.policy_public = signer.generate_keypair()
            self._policy_sk = signer.export_secret_key()
        with oqs.Signature(self.audit_algorithm) as signer:
            self.audit_public = signer.generate_keypair()
            self._audit_sk = signer.export_secret_key()

    def _sign(self, algorithm: str, secret_key: bytes, message: bytes) -> bytes:
        with oqs.Signature(algorithm, secret_key) as signer:
            return signer.sign(message)

    def _verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(algorithm) as verifier:
            return bool(verifier.verify(message, signature, public_key))

    def sign_identity(self, message: bytes) -> bytes:
        return self._sign(self.identity_algorithm, self._identity_sk, message)

    def verify_identity(self, message: bytes, signature: bytes) -> bool:
        return self._verify(self.identity_algorithm, self.identity_public, message, signature)

    def sign_policy(self, message: bytes) -> bytes:
        return self._sign(self.identity_algorithm, self._policy_sk, message)

    def verify_policy(self, message: bytes, signature: bytes) -> bool:
        return self._verify(self.identity_algorithm, self.policy_public, message, signature)

    def sign_audit(self, message: bytes) -> bytes:
        return self._sign(self.audit_algorithm, self._audit_sk, message)

    def verify_audit(self, message: bytes, signature: bytes) -> bool:
        return self._verify(self.audit_algorithm, self.audit_public, message, signature)

    def establish_session(self, context: bytes) -> SessionResult:
        start = time.perf_counter_ns()
        client_x_sk = X25519PrivateKey.generate()
        server_x_sk = X25519PrivateKey.generate()
        client_x_pk = client_x_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        server_x_pk = server_x_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        with oqs.KeyEncapsulation(self.kem_algorithm) as client_kem:
            client_kem_pk = client_kem.generate_keypair()
            client_kem_sk = client_kem.export_secret_key()
        with oqs.KeyEncapsulation(self.kem_algorithm) as server_kem:
            ciphertext, server_kem_secret = server_kem.encap_secret(client_kem_pk)
        with oqs.KeyEncapsulation(self.kem_algorithm, client_kem_sk) as client_kem:
            client_kem_secret = client_kem.decap_secret(ciphertext)
        if client_kem_secret != server_kem_secret:
            raise RuntimeError("ML-KEM shared-secret mismatch")
        client_x_secret = client_x_sk.exchange(X25519PublicKey.from_public_bytes(server_x_pk))
        server_x_secret = server_x_sk.exchange(X25519PublicKey.from_public_bytes(client_x_pk))
        if client_x_secret != server_x_secret:
            raise RuntimeError("X25519 shared-secret mismatch")
        policy_signature = self.sign_policy(canonical(self.policy_descriptor))
        bundle = {
            "client_mlkem": client_kem_pk.hex(),
            "client_x25519": client_x_pk.hex(),
            "kem_ciphertext": ciphertext.hex(),
            "policy": self.policy_descriptor,
            "policy_signature": policy_signature.hex(),
            "server_x25519": server_x_pk.hex(),
            "transcript_context": sha256(context),
            "version": "R11-CBAS-v1",
        }
        bundle_bytes = canonical(bundle)
        bundle_signature = self.sign_identity(bundle_bytes)
        if not self.verify_identity(bundle_bytes, bundle_signature):
            raise RuntimeError("identity bundle verification failed")
        if not self._validate_policy(bundle["policy"], policy_signature, int(time.time())):
            raise RuntimeError("policy certificate verification failed")
        transcript = sha256(bundle_bytes + bundle_signature + context)
        client_session_key = hkdf(
            client_kem_secret + client_x_secret,
            PROTOCOL_LABEL + b"hybrid\0" + transcript.encode(),
        )
        server_session_key = hkdf(
            server_kem_secret + server_x_secret,
            PROTOCOL_LABEL + b"hybrid\0" + transcript.encode(),
        )
        confirmation_context = PROTOCOL_LABEL + b"confirmation\0" + transcript.encode()
        server_confirmation = hmac.digest(server_session_key, confirmation_context, "sha256")
        expected_confirmation = hmac.digest(client_session_key, confirmation_context, "sha256")
        if not hmac.compare_digest(server_confirmation, expected_confirmation):
            raise RuntimeError("key confirmation failed")
        sid = sha256(PROTOCOL_LABEL + b"sid\0" + transcript.encode())
        return SessionResult(
            client_session_key,
            sid,
            time.perf_counter_ns() - start,
            len(client_kem_pk) + len(ciphertext) + len(client_x_pk) + len(server_x_pk) + len(bundle_bytes) + len(bundle_signature),
            True,
            True,
            True,
        )


def build_profile(name: str, policy_digest: str) -> ClassicalProfile | PostQuantumProfile:
    if name == "classical":
        return ClassicalProfile(policy_digest)
    if name == "post_quantum":
        return PostQuantumProfile(policy_digest)
    raise ValueError(f"unknown profile: {name}")
