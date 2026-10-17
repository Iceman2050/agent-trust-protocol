"""
agent-trust-protocol — session binding + audit trail (Phases 3 and 4).

A session binds a completed handshake (Phase 2) to a session_id and keeps an
append-only, hash-chained audit log. Every entry links to the previous one,
so tampering with any entry breaks the chain (detectable with verify_chain).

Replay protection: receivers accept only the next expected sequence number;
any replayed or out-of-order message is rejected with ReplayRejected.
"""

import hashlib
import json
import time
import uuid

from attest import canonical


class ReplayRejected(Exception):
    """Raised when a received message fails replay protection."""


class IntegrityError(Exception):
    """Raised when the audit chain fails verification."""


def _entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


class Session:
    def __init__(self, handshake: dict, now: float | None = None):
        self.session_id = uuid.uuid4().hex
        self.handshake_id = handshake["handshake_id"]
        self.parties = list(handshake["parties"])
        self.granted = handshake["granted"]
        self._log: list[dict] = []
        self._now = now
        self._recv_expected = 0  # next inbound seq number this receiver accepts
        self.audit("session.established", "system",
                   {"handshake_id": self.handshake_id, "granted": self.granted})

    def _ts(self) -> float:
        return self._now if self._now is not None else time.time()

    # --- Phase 4: audit trail ---------------------------------------------
    def audit(self, event_type: str, actor: str, detail: dict | None = None) -> dict:
        prev_hash = self._log[-1]["hash"] if self._log else "0" * 64
        entry = {
            "seq": len(self._log),
            "session_id": self.session_id,
            "timestamp": self._ts(),
            "event_type": event_type,
            "actor": actor,
            "detail": detail or {},
            "prev_hash": prev_hash,
        }
        entry["hash"] = _entry_hash(entry)
        self._log.append(entry)
        return entry

    def verify_chain(self) -> tuple[bool, str]:
        """Re-verify the full hash chain. Returns (True, 'ok') or (False, reason)."""
        expected_prev = "0" * 64
        for i, entry in enumerate(self._log):
            if entry["seq"] != i:
                return False, f"entry {i}: bad sequence number"
            if entry["prev_hash"] != expected_prev:
                return False, f"entry {i}: broken chain link"
            if _entry_hash(entry) != entry["hash"]:
                return False, f"entry {i}: hash mismatch (tampered)"
            expected_prev = entry["hash"]
        return True, "ok"

    # --- Phase 3: session binding / replay-protected messaging --------------
    def send(self, sender: str, payload: dict) -> dict:
        """Build the next outbound message (seq = len of sent messages)."""
        msg = {
            "session_id": self.session_id,
            "seq": self._sent_count(),
            "sender": sender,
            "payload": payload,
        }
        msg["hash"] = _entry_hash(msg)
        self.audit("message.sent", sender, {"seq": msg["seq"]})
        return msg

    def _sent_count(self) -> int:
        return sum(1 for e in self._log if e["event_type"] == "message.sent")

    def receive(self, msg: dict) -> dict:
        """
        Accept an inbound message only if it is the exact next expected one:
        same session, next sequence number, intact hash. The receiver advances
        its expected-seq counter on every accepted message, so a replayed copy
        (stale seq) or a skipped-ahead message is always rejected.
        """
        if msg.get("session_id") != self.session_id:
            raise ReplayRejected("message is for a different session")
        if msg.get("seq") != self._recv_expected:
            raise ReplayRejected(
                f"expected seq {self._recv_expected}, got {msg.get('seq')} — "
                "replayed/out-of-order message rejected"
            )
        body = {k: v for k, v in msg.items() if k != "hash"}
        if _entry_hash(body) != msg.get("hash"):
            raise ReplayRejected("message hash mismatch — tampered message rejected")
        self._recv_expected += 1
        self.audit("message.received", msg.get("sender", "?"), {"seq": msg["seq"]})
        return msg["payload"]
