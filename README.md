# agent-trust-protocol

**Agents are starting to call other agents — with zero verification.**

A planner delegates to a coder. A researcher queries a data agent. A support
bot hands off to a billing agent. Today any agent can *claim* any capability,
*request* any permission, and there's no record of what was agreed. One
compromised or impersonated agent can escalate privileges across a whole
fleet — invisibly. That's the next supply-chain hole, and it's already open.

**agent-trust-protocol** is an open spec + working reference implementation
for agent-to-agent verification: capability attestation, a permission
handshake, session binding, and a tamper-evident audit trail. Four phases,
stdlib-only Python, no dependencies.

## The 30-second win

```bash
git clone https://github.com/Iceman2050/agent-trust-protocol.git
cd agent-trust-protocol
python3 demo.py
```

That's it. Two agents attest their capabilities, negotiate permissions,
bind a session, exchange a message, and verify the audit chain — in under
a second. Real captured output (byte-identical on every run):

```
== agent-trust-protocol v0.1 — A2A handshake demo ==
parties: calendar-agent <-> research-agent

[phase 1] capability attestation
  calendar-agent attested ['calendar.read', 'calendar.write'] -> verified: True
  research-agent attested ['web.fetch', 'web.search'] -> verified: True

[phase 2] permission handshake
  handshake bd9c66b3ad3c... complete
    granted to calendar-agent: ['web.fetch']
    granted to research-agent: ['calendar.read']

[phase 3] session binding
  session 972a84691641... bound to handshake bd9c66b3ad3c...

[phase 4] audit trail
  message seq=0 delivered: fetch-availability
  audit entries: 4
  audit chain verified: True (ok)

handshake complete — both agents verified, permissions granted, session bound.
try: requests=['file.delete'] in a copy of this demo and watch the refusal.
```

## How it works

| Phase | Module | What it does |
|---|---|---|
| 1. Attestation | `attest.py` | Signed capability claims; rejects tampered/expired/future-dated |
| 2. Handshake | `handshake.py` | Grants only the intersection of requested ∩ attested; **refuses** on mismatch |
| 3. Session binding | `session.py` | `session_id` bound to `handshake_id`; seq-numbered, replay-protected messages |
| 4. Audit trail | `session.py` | Append-only hash-chained log; `verify_chain()` detects any tampering |

Full spec with message formats (JSON schemas), threat model, and explicit
non-goals: [SPEC.md](SPEC.md).

## Quickstart

```python
from attest import generate, verify
from handshake import negotiate
from session import Session

KEY = b"your-32-byte-shared-secret-here!!"  # demo only — see note below

# Phase 1: attest
a_att = generate("agent-a", ["cal.read"], ["cal.read"], KEY)
b_att = generate("agent-b", ["web.fetch"], ["web.fetch"], KEY)

# Phase 2: handshake (refuses if any requested perm isn't attested)
hs = negotiate(
    {"agent_id": "agent-a", "attestation": a_att, "requests": ["web.fetch"]},
    {"agent_id": "agent-b", "attestation": b_att, "requests": ["cal.read"]},
    KEY,
)

# Phases 3+4: bind a session, exchange messages, audit everything
sess = Session(hs)
msg = sess.send("agent-b", {"task": "fetch-availability"})
payload = sess.receive(msg)          # raises ReplayRejected on replay/tamper
sess.audit("task.done", "agent-b", {"result": "ok"})
assert sess.verify_chain() == (True, "ok")
```

Run the test suite:

```bash
python3 -m unittest discover -s tests -v
```

## What it does NOT do

- **Not production cryptography.** The reference implementation signs with
  HMAC-SHA256 under a shared secret. That authenticates the message, not the
  issuer's identity. Production deployments MUST use Ed25519 with a real PKI
  or issuer registry — the message format already supports it
  (`sig_alg: "ed25519"`). See SPEC.md § Security considerations.
- Not key distribution — keys are assumed exchanged out-of-band.
- Not agent discovery, not payments, not a policy language (permissions are
  simple string scopes in v0.1), not a TLS replacement.
- The audit log detects tampering; it can't stop someone deleting the log
  file itself. Ship logs to append-only storage for real deployments.

## Ethical use

This protocol is defensive infrastructure: it exists to make agent
collaboration *verifiable* and *auditable*. Don't use it to create a false
sense of security — an attestation is only as trustworthy as its issuer and
its signing key. If you deploy this, deploy the Ed25519 upgrade, short TTLs,
and append-only log storage with it.

## License

MIT — see [LICENSE](LICENSE).

## Built by Ingenious AI
- DisclosureGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DisclosureGuard.
- ModelMinder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ModelMinder.
- TermsWatch — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20TermsWatch.
- Vibe-Code Audit — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.
- Rogue-Agent Defense — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.
- BreachHunter — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20BreachHunter.
- ChatBreaker — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ChatBreaker.
- Agent Flight Recorder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.
- Agent Auth Gateway — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.
- DomainGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DomainGuard.
- ContentCraft AI — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ContentCraft%20AI.
Built with Muse — try it free: invite code 2HCQH1
