#!/usr/bin/env python3
"""
agent-trust-protocol — one-command A2A handshake demo.

Two agents (a calendar agent and a research agent) attest their capabilities,
negotiate a permission handshake, bind a session, exchange a message, and
verify the audit trail — in under a second, with zero dependencies.

    python3 demo.py

DEMO MODE: uses a fixed shared key and fixed timestamps so the output is
byte-identical on every run. Production deployments must use fresh keys,
real clocks, and Ed25519 attestations (see SPEC.md).
"""

from attest import generate, verify
from handshake import negotiate, HandshakeRefused
from session import Session

# Deterministic demo: seed the UUID generator so the transcript is
# byte-identical on every run (byte-match gate for the README example).
import random as _random
import uuid as _uuid
_rng = _random.Random(42)
_uuid.uuid4 = lambda: _uuid.UUID(int=_rng.getrandbits(128))  # noqa: E731

DEMO_KEY = b"agent-trust-demo-shared-key-32B!!!"  # 32 bytes, DEMO ONLY
DEMO_NOW = 1_790_000_000  # fixed demo timestamp


def p(*args):
    print(*args, flush=True)


def main() -> None:
    p("== agent-trust-protocol v0.1 — A2A handshake demo ==")
    p("parties: calendar-agent <-> research-agent")
    p()

    # Phase 1 — capability attestation
    p("[phase 1] capability attestation")
    cal_att = generate(
        "calendar-agent",
        capabilities=["calendar.read", "calendar.write"],
        permissions=["calendar.read"],
        secret_key=DEMO_KEY,
        now=DEMO_NOW,
    )
    res_att = generate(
        "research-agent",
        capabilities=["web.fetch", "web.search"],
        permissions=["web.fetch"],
        secret_key=DEMO_KEY,
        now=DEMO_NOW,
    )
    ok, _ = verify(cal_att, DEMO_KEY, now=DEMO_NOW)
    p(f"  calendar-agent attested {cal_att['capabilities']} -> verified: {ok}")
    ok, _ = verify(res_att, DEMO_KEY, now=DEMO_NOW)
    p(f"  research-agent attested {res_att['capabilities']} -> verified: {ok}")
    p()

    # Phase 2 — permission handshake
    p("[phase 2] permission handshake")
    try:
        hs = negotiate(
            {"agent_id": "calendar-agent", "attestation": cal_att,
             "requests": ["web.fetch"]},                 # calendar wants web.fetch from research
            {"agent_id": "research-agent", "attestation": res_att,
             "requests": ["calendar.read"]},             # research wants calendar.read from calendar
            DEMO_KEY,
            now=DEMO_NOW,
        )
    except HandshakeRefused as e:  # pragma: no cover - demo uses compatible perms
        p(f"  REFUSED: {e}")
        raise SystemExit(1)
    p(f"  handshake {hs['handshake_id'][:12]}... complete")
    for agent, perms in hs["granted"].items():
        p(f"    granted to {agent}: {perms}")
    p()

    # Phase 3 — session binding
    p("[phase 3] session binding")
    sess = Session(hs, now=DEMO_NOW)
    p(f"  session {sess.session_id[:12]}... bound to handshake {hs['handshake_id'][:12]}...")
    p()

    # Phase 4 — audit trail + a live message
    p("[phase 4] audit trail")
    msg = sess.send("research-agent", {"task": "fetch-availability",
                                       "for": "2026-10-19"})
    payload = sess.receive(msg)
    sess.audit("task.assigned", "calendar-agent",
               {"task": payload["task"], "to": "research-agent"})
    p(f"  message seq=0 delivered: {payload['task']}")
    p(f"  audit entries: {len(sess._log)}")
    ok, reason = sess.verify_chain()
    p(f"  audit chain verified: {ok} ({reason})")
    p()
    p("handshake complete — both agents verified, permissions granted, session bound.")
    p("try: requests=['file.delete'] in a copy of this demo and watch the refusal.")


if __name__ == "__main__":
    main()
