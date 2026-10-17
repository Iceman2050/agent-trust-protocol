"""
agent-trust-protocol — permission handshake (Phase 2 of 4).

A two-party negotiation: each agent presents a capability attestation (Phase 1),
each requests a set of permissions from the other, and each grants only the
intersection of what was requested and what is actually attested. If any
requested permission is not attested, the handshake is REFUSED — no partial
grants, no silent downgrades.
"""

import uuid
from attest import verify as verify_attestation

PROTOCOL = "agent-trust/0.1"


class HandshakeRefused(Exception):
    """Raised when the handshake cannot complete safely."""


def negotiate(party_a: dict, party_b: dict, secret_key: bytes,
              now: float | None = None) -> dict:
    """
    Run a two-party handshake.

    party_a / party_b: {
        "agent_id": str,
        "attestation": dict,        # Phase 1 output
        "requests": [permissions wanted from the OTHER party],
    }
    now: optional fixed timestamp (used by tests/demos with fixed clocks).
    Returns a handshake result binding both attestations to granted permissions.
    Raises HandshakeRefused on attestation failure or incompatible permissions.
    """
    for party in (party_a, party_b):
        ok, reason = verify_attestation(party["attestation"], secret_key, now=now)
        if not ok:
            raise HandshakeRefused(
                f"attestation rejected for {party['agent_id']}: {reason}"
            )

    # Each party grants the intersection of the other's requests and its own
    # attested permissions. Anything requested-but-not-attested is a refusal.
    req_a = set(party_a["requests"])  # what A wants FROM B
    req_b = set(party_b["requests"])  # what B wants FROM A
    offered_a = set(party_a["attestation"]["permissions"])
    offered_b = set(party_b["attestation"]["permissions"])

    denied = (req_a - offered_b) | (req_b - offered_a)
    if denied:
        raise HandshakeRefused(
            f"incompatible permissions: requested but not attested: {sorted(denied)}"
        )

    handshake_id = uuid.uuid4().hex
    return {
        "v": "0.1",
        "protocol": PROTOCOL,
        "handshake_id": handshake_id,
        "parties": [party_a["agent_id"], party_b["agent_id"]],
        "granted": {
            party_a["agent_id"]: sorted(req_a),
            party_b["agent_id"]: sorted(req_b),
        },
        "attestation_ids": [
            party_a["attestation"]["nonce"],
            party_b["attestation"]["nonce"],
        ],
    }
