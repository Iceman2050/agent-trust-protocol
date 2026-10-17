"""
agent-trust-protocol — capability attestation (Phase 1 of 4).

An attestation is a signed statement by an identity holder that an agent
possesses a set of capabilities and is permitted a set of permissions.

SECURITY NOTE (demo vs production):
    This reference implementation signs attestations with HMAC-SHA256 under a
    shared secret key. That is fine for a local demo and for environments where
    both parties share a key out-of-band. In production, use a real asymmetric
    scheme (Ed25519) so a verifier can authenticate the issuer without holding
    its signing key — e.g. `cryptography.hazmat.primitives.asymmetric.ed25519`.
    The message format (Attestation v0.1, see SPEC.md) is signature-scheme
    agnostic: `sig` becomes the Ed25519 signature and `sig_alg` becomes
    "ed25519". Everything else stays identical.
"""

import hashlib
import hmac
import json
import time
import uuid

SIG_ALG = "hmac-sha256-demo"
DEFAULT_TTL_SECONDS = 300


def canonical(obj: dict) -> str:
    """Deterministic JSON encoding for signing (JCS-lite)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def generate(
    agent_id: str,
    capabilities: list,
    permissions: list,
    secret_key: bytes,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> dict:
    """Create a signed capability attestation for an agent."""
    ts = now if now is not None else time.time()
    payload = {
        "v": "0.1",
        "agent_id": agent_id,
        "capabilities": sorted(capabilities),
        "permissions": sorted(permissions),
        "issued_at": int(ts),
        "expires_at": int(ts) + ttl_seconds,
        "nonce": uuid.uuid4().hex,
    }
    mac = hmac.new(secret_key, canonical(payload).encode("utf-8"), hashlib.sha256).hexdigest()
    return {**payload, "sig_alg": SIG_ALG, "sig": mac}


def verify(attestation: dict, secret_key: bytes, now: float | None = None) -> tuple[bool, str]:
    """
    Verify an attestation. Returns (True, "ok") or (False, <reason>).
    Rejects: malformed, unknown sig alg, bad signature, expired, not-yet-valid.
    """
    required = {"v", "agent_id", "capabilities", "permissions",
                "issued_at", "expires_at", "nonce", "sig_alg", "sig"}
    if not isinstance(attestation, dict) or not required.issubset(attestation.keys()):
        return False, "malformed: missing fields"
    if attestation["sig_alg"] != SIG_ALG:
        return False, f"unsupported sig_alg: {attestation['sig_alg']}"

    payload = {k: attestation[k] for k in required - {"sig_alg", "sig"}}
    expected = hmac.new(secret_key, canonical(payload).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, attestation["sig"]):
        return False, "signature mismatch (tampered attestation)"

    ts = now if now is not None else time.time()
    if attestation["expires_at"] <= ts:
        return False, "attestation expired"
    if attestation["issued_at"] > ts + 60:
        return False, "attestation issued in the future (clock skew)"

    return True, "ok"
