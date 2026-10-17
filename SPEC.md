# Agent Trust Protocol — Specification v0.1

**Status:** draft · **Version:** 0.1 · **Date:** 2026-10-17

An open protocol for agent-to-agent (A2A) verification: before two AI agents
collaborate, they prove who they are, what they can do, and what they are
allowed to do — and they keep a tamper-evident record of everything after.

## Why

Agents increasingly call other agents: a planner delegates to a coder, a
researcher queries a data agent, a support bot hands off to a billing agent.
Today those calls happen with **zero verification** — any agent can claim any
capability, request any permission, and there is no record of what was agreed.
That is the next supply-chain hole: one compromised or impersonated agent can
escalate privileges across a whole fleet, invisibly.

This protocol fixes that with four phases, each cheap enough to run per task.

## The 4-phase flow

```
 ┌──────────┐  attestation   ┌──────────┐
 │ Agent A  │ ─────────────▶ │ Agent B  │   Phase 1: ATTTESTATION
 │          │ ◀───────────── │          │   each side presents signed
 └──────────┘  attestation   └──────────┘   capability claims
        │                            │
        │   ┌──────────────────┐      │
        └──▶│    HANDSHAKE     │◀─────┘   Phase 2: HANDSHAKE
            │  offer/counter-  │          negotiate; grant only the
            │  offer on perms  │          intersection; refuse on mismatch
            └────────┬─────────┘
                     │ handshake_id
            ┌────────▼─────────┐
            │ SESSION BINDING  │              Phase 3: SESSION BINDING
            │  session_id bound│              every message carries
            │  to handshake_id │              session_id + seq; replay-
            └────────┬─────────┘              protected delivery
                     │
            ┌────────▼─────────┐
            │   AUDIT TRAIL    │              Phase 4: AUDIT TRAIL
            │ hash-chained log │              append-only; tampering
            │ of every event   │              breaks the chain
            └──────────────────┘
```

**Phase 1 — Attestation.** Each agent presents a signed `Attestation`
listing its `capabilities` (what it can do) and `permissions` (what it is
allowed to do). Verifiers reject malformed, badly signed, expired, or
future-dated attestations.

**Phase 2 — Handshake.** Each side requests permissions from the other. The
handshake grants only the intersection of *requested* and *attested*
permissions. If any requested permission is not attested, the handshake is
**refused outright** — no partial grants, no silent downgrades. The result is
bound to a `handshake_id`.

**Phase 3 — Session binding.** A `session_id` is minted and bound to the
`handshake_id`. Every message carries `session_id` + a sequence number;
receivers accept only the next expected seq, which rejects replays, gaps,
and reordered messages.

**Phase 4 — Audit trail.** An append-only log records session establishment,
messages, and task events. Each entry embeds the hash of the previous entry
(hash chain), so tampering with any entry is detectable via `verify_chain`.

## Message formats (JSON)

### Attestation (v0.1)

```json
{
  "v": "0.1",
  "agent_id": "research-agent",
  "capabilities": ["web.fetch", "web.search"],
  "permissions": ["web.fetch"],
  "issued_at": 1790000000,
  "expires_at": 1790000300,
  "nonce": "9f2c…",
  "sig_alg": "hmac-sha256-demo",
  "sig": "a3f1…"
}
```

Signature is computed over the canonical JSON of all fields except
`sig_alg`/`sig` (keys sorted, no whitespace). `sig_alg` identifies the
scheme: `hmac-sha256-demo` in this reference implementation, `ed25519` in
production deployments (see Security considerations).

### Handshake result (v0.1)

```json
{
  "v": "0.1",
  "protocol": "agent-trust/0.1",
  "handshake_id": "b71e…",
  "parties": ["calendar-agent", "research-agent"],
  "granted": {
    "calendar-agent": ["web.fetch"],
    "research-agent": ["calendar.read"]
  },
  "attestation_ids": ["9f2c…", "41ab…"]
}
```

### Session message (v0.1)

```json
{
  "session_id": "c0de…",
  "seq": 0,
  "sender": "research-agent",
  "payload": {"task": "fetch-availability"},
  "hash": "77aa…"
}
```

### Audit entry (v0.1)

```json
{
  "seq": 2,
  "session_id": "c0de…",
  "timestamp": 1790000000,
  "event_type": "message.sent",
  "actor": "research-agent",
  "detail": {"seq": 0},
  "prev_hash": "e5f2…",
  "hash": "11bb…"
}
```

## Threat model

**In scope (mitigated):**

| Threat | Mitigation |
|---|---|
| Agent claims capabilities it doesn't have | Signed attestation; tampering breaks signature |
| Permission escalation mid-session | Handshake grants only attested perms; refusal on mismatch |
| Replay of a captured message | Receiver-side expected-seq; replays rejected |
| Silent alteration of history | Hash-chained audit log; `verify_chain` detects edits |
| Stale credentials reused forever | Attestation expiry (`expires_at`, default 5 min) |
| Clock-skew abuse | Future-dated attestations (>60s) rejected |

**Out of scope:** key distribution and rotation (assumed out-of-band);
identity proofing of the attestation issuer (assumed — see Security
considerations); network-level attacks (TLS assumed); compromise of an
agent's own signing key (out of scope for v0.1).

## Security considerations

- The reference implementation uses **HMAC-SHA256 with a shared secret**.
  This authenticates the message but not the issuer's identity, and both
  parties hold the signing key. **Production deployments MUST use Ed25519**
  (or equivalent asymmetric signatures) with a PKI or trusted issuer
  registry, so verifiers authenticate the issuer without holding its key.
  The message format is scheme-agnostic: set `sig_alg` to `ed25519` and
  `sig` to the signature bytes (hex). Nothing else changes.
- Never reuse a demo key in production. Rotate keys; keep TTLs short.
- The audit log detects tampering; it does not prevent deletion of the log
  itself. Ship logs to append-only storage for real deployments.

## Non-goals (explicit)

- Not an agent discovery protocol (no registry, no DNS-like lookup).
- Not a payment/settlement layer for agent work.
- Not a replacement for TLS or transport security.
- Not a policy language — permissions are simple string scopes in v0.1.
- No central authority, no blockchain, no token.

## Versioning

`v` field on every message. Minor versions add optional fields; major
versions may change required fields. Implementations MUST reject messages
with an unknown major version.
