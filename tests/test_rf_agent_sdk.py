"""The integration SDK cannot run an action before authorization."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from core import rf_agent_gate as gate

ROOT = Path(__file__).resolve().parents[1]

class SDKTests(unittest.TestCase):
    def test_prevent_replay_and_record_completion(self):
        code='''
from core import rf_agent_gate as g,rf_agent_sdk as sdk,rf_core
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
s=Ed25519PrivateKey.generate(); p={"version":1,"rules":[{"agent":"a","action":"inspect","resource":"report/1"}]};e={"invoice":1}
t=g.issue(s,p,"a","inspect","report/1",e); called=[]
def work(): called.append(1); return {"ok":True}
result,att=sdk.run_guarded(grant=t,approver_public=s.public_key(),policy=p,agent="a",action="inspect",resource="report/1",intent=e,callback=work,result_summary=lambda x:x)
assert result=={"ok":True} and len(called)==1 and att["observed_result_entry_id"]==2
try:
    sdk.run_guarded(grant=t,approver_public=s.public_key(),policy=p,agent="a",action="inspect",resource="report/1",intent=e,callback=work,result_summary=lambda x:x)
except g.GateDenied: pass
else: raise AssertionError("replayed callback")
assert len(called)==1
try:
    sdk.run_guarded(grant=g.issue(s,p,"a","inspect","report/1",e),approver_public=s.public_key(),policy=p,agent="a",action="inspect",resource="report/1",intent={"forged":1},callback=work,result_summary=lambda x:x)
except g.GateDenied: pass
else: raise AssertionError("wrong intent allowed")
assert len(called)==1
assert rf_core.verify_chain()[0]
print("SDK_EXECUTE=PASS; REPLAY_EXECUTION=DENIED; REAL_LEDGER=PASS")
'''
        with tempfile.TemporaryDirectory() as data:
            env=dict(os.environ, RF_DATA_DIR=data, PYTHONPATH=str(ROOT), RF_PQ_SIGNING="auto")
            p=subprocess.run([sys.executable,"-c",code],env=env,cwd=ROOT,text=True,capture_output=True,timeout=90)
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            self.assertIn("SDK_EXECUTE=PASS",p.stdout)

    def test_reject_noncallable(self):
        from core import rf_agent_sdk as sdk
        with self.assertRaises(TypeError):
            sdk.run_guarded(grant={}, approver_public=None, policy={}, agent="a",action="x",
                            resource="r",intent={},callback=None,result_summary=lambda _: {})
