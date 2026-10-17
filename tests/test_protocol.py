"""Tests for agent-trust-protocol reference implementation (stdlib only).

Note: this file deliberately uses lists (never single-element tuples) for
capability/permission collections.
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attest import generate, verify
from handshake import negotiate, HandshakeRefused
from session import Session, ReplayRejected

KEY = b"test-shared-key-32-bytes-long!!!!!"  # 32 bytes
NOW = 1_790_000_000


def make_att(agent_id="agent-a", caps=None, perms=None):
    caps = ["x.read"] if caps is None else list(caps)
    perms = ["x.read"] if perms is None else list(perms)
    return generate(agent_id, caps, perms, KEY, now=NOW)


class TestAttestation(unittest.TestCase):
    def test_attestation_sign_verify_round_trip(self):
        att = make_att()
        ok, reason = verify(att, KEY, now=NOW)
        self.assertTrue(ok, reason)

    def test_tampered_attestation_rejected(self):
        att = make_att()
        evil = copy.deepcopy(att)
        evil["permissions"].append("file.delete")  # escalate after signing
        ok, reason = verify(evil, KEY, now=NOW)
        self.assertFalse(ok)
        self.assertIn("mismatch", reason)

    def test_expired_attestation_rejected(self):
        att = generate("agent-a", ["x.read"], ["x.read"], KEY, ttl_seconds=-1, now=NOW)
        ok, _ = verify(att, KEY, now=NOW)
        self.assertFalse(ok)

    def test_wrong_key_rejected(self):
        att = make_att()
        ok, _ = verify(att, b"wrong-key-32-bytes-long?????????", now=NOW)
        self.assertFalse(ok)


class TestHandshake(unittest.TestCase):
    def _parties(self, a_reqs, b_reqs, a_perms=None, b_perms=None):
        a_perms = ["cal.read"] if a_perms is None else list(a_perms)
        b_perms = ["web.fetch"] if b_perms is None else list(b_perms)
        return (
            {"agent_id": "agent-a", "attestation": make_att("agent-a", a_perms, a_perms),
             "requests": list(a_reqs)},
            {"agent_id": "agent-b", "attestation": make_att("agent-b", b_perms, b_perms),
             "requests": list(b_reqs)},
        )

    def test_handshake_success_grants_intersection(self):
        a, b = self._parties(["web.fetch"], ["cal.read"])
        hs = negotiate(a, b, KEY, now=NOW)
        self.assertEqual(hs["granted"]["agent-a"], ["web.fetch"])
        self.assertEqual(hs["granted"]["agent-b"], ["cal.read"])
        self.assertEqual(hs["parties"], ["agent-a", "agent-b"])

    def test_handshake_refuses_incompatible_permissions(self):
        # agent-a asks for file.delete, which agent-b never attested -> REFUSAL
        a, b = self._parties(["file.delete"], ["cal.read"])
        with self.assertRaises(HandshakeRefused) as ctx:
            negotiate(a, b, KEY, now=NOW)
        self.assertIn("file.delete", str(ctx.exception))

    def test_handshake_refuses_bad_attestation(self):
        a, b = self._parties(["web.fetch"], ["cal.read"])
        bad = copy.deepcopy(b)
        bad["attestation"]["permissions"].append("admin.all")
        with self.assertRaises(HandshakeRefused):
            negotiate(a, bad, KEY, now=NOW)


class TestSession(unittest.TestCase):
    def _session(self):
        a = {"agent_id": "agent-a",
             "attestation": make_att("agent-a", ["cal.read"], ["cal.read"]),
             "requests": ["web.fetch"]}
        b = {"agent_id": "agent-b",
             "attestation": make_att("agent-b", ["web.fetch"], ["web.fetch"]),
             "requests": ["cal.read"]}
        hs = negotiate(a, b, KEY, now=NOW)
        return Session(hs, now=NOW)

    def test_session_binds_handshake(self):
        sess = self._session()
        self.assertEqual(sess.parties, ["agent-a", "agent-b"])
        self.assertTrue(sess.session_id)

    def test_session_replay_rejected(self):
        sess = self._session()
        msg = sess.send("agent-a", {"ping": 1})
        # correct first delivery
        self.assertEqual(sess.receive(msg), {"ping": 1})
        # replay of the SAME message must be rejected (stale seq)
        with self.assertRaises(ReplayRejected):
            sess.receive(msg)

    def test_session_out_of_order_rejected(self):
        sess = self._session()
        sess.send("agent-a", {"ping": 1})       # seq 0
        msg2 = sess.send("agent-a", {"ping": 2})  # seq 1
        # skipping seq 0 is rejected
        with self.assertRaises(ReplayRejected):
            sess.receive(msg2)

    def test_tampered_message_rejected(self):
        sess = self._session()
        msg = sess.send("agent-a", {"ping": 1})
        evil = dict(msg)
        evil["payload"] = {"ping": 999}
        with self.assertRaises(ReplayRejected):
            sess.receive(evil)

    def test_audit_log_integrity(self):
        sess = self._session()
        sess.send("agent-a", {"ping": 1})
        sess.audit("task.done", "agent-b", {"result": "ok"})
        ok, reason = sess.verify_chain()
        self.assertTrue(ok, reason)
        # tamper with history -> chain breaks
        sess._log[1]["detail"] = {"ping": 9999}
        ok, reason = sess.verify_chain()
        self.assertFalse(ok)
        self.assertIn("mismatch", reason)

    def test_audit_entries_are_hash_chained(self):
        sess = self._session()
        sess.audit("custom.event", "agent-a", {})
        self.assertEqual(sess._log[1]["prev_hash"], sess._log[0]["hash"])


if __name__ == "__main__":
    unittest.main()
