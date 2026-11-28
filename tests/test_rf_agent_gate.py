"""Gate tests: cryptographic fail-closed checks and real SQLite atomic ledger path."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from core import rf_agent_gate as g

ROOT = Path(__file__).resolve().parents[1]


class AgentGateTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519PrivateKey.generate()
        self.public = self.signer.public_key()
        self.policy = {"version": 1, "rules": [{"agent": "agent1", "action": "read", "resource": "invoice/42"}]}
        self.event = {"request": "review invoice", "amount": 42}
        self.token = g.issue(self.signer, self.policy, "agent1", "read", "invoice/42", self.event)

    def checked(self, token=None, policy=None, event=None, agent="agent1", action="read", resource="invoice/42"):
        return g.verify(token or self.token, self.public, policy if policy is not None else self.policy,
                        event if event is not None else self.event, agent, action, resource)

    def test_positive(self):
        self.assertEqual(self.checked()["schema"], g.SCHEMA)

    def test_tampering(self):
        token = copy.deepcopy(self.token)
        token["grant"]["resource"] = "invoice/43"
        with self.assertRaises(g.GateDenied):
            self.checked(token=token, resource="invoice/43")

    def test_wrong_operation(self):
        with self.assertRaises(g.GateDenied):
            self.checked(action="delete")

    def test_event_substitution(self):
        with self.assertRaises(g.GateDenied):
            self.checked(event={"request": "remove evidence"})

    def test_policy_change(self):
        with self.assertRaises(g.GateDenied):
            self.checked(policy={"version": 1, "rules": []})

    def test_expiry(self):
        body = self.token["grant"]
        with self.assertRaises(g.GateDenied):
            g.verify(self.token, self.public, self.policy, self.event, "agent1", "read", "invoice/42", now=body["expires"] + 1)

    def test_overlong_ttl(self):
        with self.assertRaises(ValueError):
            g.issue(self.signer, self.policy, "agent1", "read", "invoice/42", self.event, ttl=301)

    def test_invalid_policy(self):
        with self.assertRaises(g.GateDenied):
            g.issue(self.signer, {"version": 1, "rules": []}, "agent1", "read", "invoice/42", self.event)

    def test_real_ledger_atomicity_and_revocation(self):
        code = '''
from core import rf_agent_gate as g,rf_core
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
s=Ed25519PrivateKey.generate(); p={"version":1,"rules":[{"agent":"a","action":"read","resource":"one"}]}; e={"hello":"world"}
t=g.issue(s,p,"a","read","one",e)
a=g.authorize_and_record(t,s.public_key(),p,e,"a","read","one")
assert a["ledger_entry_id"]==1
try: g.authorize_and_record(t,s.public_key(),p,e,"a","read","one")
except g.GateDenied: pass
else: raise AssertionError("replay accepted")
t2=g.issue(s,p,"a","read","one",e)
g.revoke_nonce(t2["grant"]["nonce"],"test revocation")
try: g.authorize_and_record(t2,s.public_key(),p,e,"a","read","one")
except g.GateDenied: pass
else: raise AssertionError("revoked grant accepted")
ok,reason=rf_core.verify_chain(); assert ok,reason
assert rf_core._connect().execute("SELECT count(*) FROM ledger_entries").fetchone()[0]==2
print("ATOMIC_LEDGER=PASS; REPLAY=DENIED; REVOCATION=DENIED")
'''
        with tempfile.TemporaryDirectory() as work:
            env = dict(os.environ, RF_DATA_DIR=work, PYTHONPATH=str(ROOT), RF_PQ_SIGNING="auto")
            proc = subprocess.run([sys.executable, "-c", code], env=env, cwd=ROOT,
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            self.assertIn("ATOMIC_LEDGER=PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
