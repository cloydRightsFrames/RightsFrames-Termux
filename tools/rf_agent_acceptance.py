#!/usr/bin/env python3
"""RightsFrames agent product end-to-end acceptance via real loopback HTTP.

Isolates all key material and SQLite data in tempfile, never touches production.
Refuses to count ML-DSA/receipts as passed when unavailable.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import importlib.metadata
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "127.0.0.1"


def _serve_http(env: dict[str, str], port: int) -> None:
    """Run only the isolated loopback acceptance API in a managed child process."""
    os.environ.clear()
    os.environ.update(env)
    os.chdir(ROOT)
    import uvicorn
    uvicorn.run("core.rf_agent_service:app", host=DOMAIN, port=port,
                log_level="error", access_log=False)


def api(url, method="GET", body=None, token=None, timeout=60):
    data = None if body is None else json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    # Do not let ambient proxy configuration redirect loopback product tests.
    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with direct.open(request, timeout=timeout) as response:
            return response.status, response.read(8*1024*1024)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(8192)


def json_call(url, method="GET", body=None, token=None):
    code, raw = api(url, method, body, token, timeout=150)
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        payload = {"raw": raw[:400].decode("utf-8", "replace")}
    return code, payload


def expect(condition, reason):
    if not condition:
        raise AssertionError(reason)


def test(argv=None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    report = {"schema": "rf.agent.product.acceptance.v1", "status": "FAIL",
              "tests": {}, "limitations": ["Self-tested, not an independent security audit",
                "Operator/agent integration must use this gate; it cannot prevent bypass by other code",
                "Anchors must be pinned externally to detect a history rewrite",
                "No real external witnesses or tool execution attestation"]}
    source = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True)
    report["source_commit"] = source.stdout.strip() if source.returncode == 0 else "UNKNOWN"
    report["pydantic"] = importlib.metadata.version("pydantic")
    report["pydantic_core"] = importlib.metadata.version("pydantic-core")
    report["fastapi"] = importlib.metadata.version("fastapi")
    report["python"] = sys.version.split()[0]
    results = report["tests"]
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="rf-real-http-") as folder:
            base = Path(folder)
            data = base / "ledger"
            data.mkdir(mode=0o700)
            policy = {"version": 1, "rules": [{"agent": "review-bot", "action": "read", "resource": "invoice/42"}]}
            policy_path = base / "policy.json"
            policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
            approver = Ed25519PrivateKey.generate()
            pub_path = base / "issuer.pem"
            pub_path.write_bytes(approver.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            for p in (policy_path, pub_path):
                p.chmod(0o600)
            # Allowlist inherited runtime variables: never propagate Redis, GitHub,
            # API credentials, or other ambient production secrets into tests.
            safe_names = {"PATH", "PREFIX", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ",
                          "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONNOUSERSITE",
                          "VIRTUAL_ENV", "SSL_CERT_FILE", "SSL_CERT_DIR"}
            env = {key: value for key, value in os.environ.items() if key in safe_names}
            env.update(RF_DATA_DIR=str(data), RF_AGENT_POLICY_FILE=str(policy_path),
                       RF_AGENT_APPROVER_PUBKEY=str(pub_path), RF_PQ_SIGNING="auto",
                       RF_API_KEY="disabled-during-pilot", RF_ALLOWED_HOSTS="127.0.0.1,localhost",
                       RF_KEY_PASSPHRASE_FILE="", RF_REQUIRE_SEALED_KEYS="0")
            # Run principal initialization in a fresh interpreter so RF_DATA_DIR
            # cannot already have been captured at module import time.
            init_code = '''from core import rf_auth
import json
print(json.dumps({"writer":rf_auth.create_principal("pilot-writer", ["entries:write","ledger:read","anchor:create","evidence:export"],actor="acceptance"), "admin":rf_auth.create_principal("pilot-admin", ["admin:principals"],actor="acceptance")},sort_keys=True))'''
            initialized = subprocess.run([sys.executable, "-c", init_code], cwd=ROOT,
                                         capture_output=True, text=True, env=env, timeout=120)
            expect(initialized.returncode == 0,
                   "principal initialization failed: " + initialized.stderr[-350:])
            credentials = json.loads(initialized.stdout.strip())
            with socket.socket() as sock:
                sock.bind((DOMAIN, 0))
                port = sock.getsockname()[1]
            url = f"http://{DOMAIN}:{port}"
            # Spawn a bounded, locally managed worker rather than an arbitrary
            # shell process; the acceptance suite controls its lifecycle.
            process = multiprocessing.get_context("spawn").Process(
                target=_serve_http, args=(env, port), daemon=True)
            process.start()
            for _ in range(90):
                if not process.is_alive():
                    raise AssertionError(f"API startup exited early (exit={process.exitcode})")
                try:
                    status, _ = api(url+"/health", timeout=2)
                    if status == 200:
                        break
                except (urllib.error.URLError, TimeoutError, OSError):
                    pass
                time.sleep(.25)
            else:
                raise AssertionError("API failed loopback readiness")
            results["http_startup"] = "PASS"
            from core import rf_agent_gate as gate
            event = {"invoice_id": 42, "purpose": "evidence verification"}
            grant = gate.issue(approver, policy, "review-bot", "read", "invoice/42", event)
            body = {"token": grant, "agent": "review-bot", "action": "read", "resource": "invoice/42", "event": event}
            expect(json_call(url+"/v1/agent/record", "POST", body)[0] == 401, "unauthenticated write allowed")
            results["unauthenticated_write"] = "DENIED"
            accepted, receipt = json_call(url+"/v1/agent/record", "POST", body, credentials["writer"])
            expect(accepted == 201 and receipt.get("status") == "authorized_recorded",
                   f"authorization denied: HTTP {accepted} {str(receipt)[:300]}")
            evidence_id = receipt["ledger_entry_id"]
            results["authorized_atomic_ledger_write"] = "PASS"
            expect(json_call(url+"/v1/agent/record", "POST", body, credentials["writer"])[0] == 403,
                   "nonce replay allowed")
            results["nonce_replay"] = "DENIED"
            wrong = dict(body, event={"invoice_id": 99})
            expect(json_call(url+"/v1/agent/record", "POST", wrong, credentials["writer"])[0] == 403,
                   "event substituted")
            results["event_substitution"] = "DENIED"
            second_grant = gate.issue(approver, policy, "review-bot", "read", "invoice/42", event)
            nonce = second_grant["grant"]["nonce"]
            revoke_code, _ = json_call(url+"/v1/agent/revoke", "POST", {"nonce": nonce, "reason": "pilot"}, credentials["admin"])
            expect(revoke_code == 201, f"revocation endpoint returned {revoke_code}")
            expect(json_call(url+"/v1/agent/record", "POST", dict(body, token=second_grant), credentials["writer"])[0] == 403,
                   "revoked grant accepted")
            results["administrative_revocation"] = "ENFORCED"
            # The critical concurrency invariant: exactly one HTTP request can
            # successfully consume a one-time grant across competing workers.
            race = gate.issue(approver, policy, "review-bot", "read", "invoice/42", event)
            same = dict(body, token=race)
            def submit(_):
                return json_call(url+"/v1/agent/record", "POST", same, credentials["writer"])[0]
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
                statuses = list(ex.map(submit, range(6)))
            expect(statuses.count(201)==1 and statuses.count(403)==5,
                   f"grant race produced unexpected statuses {statuses}")
            results["multi_request_single_use"] = "PASS"
            oldpolicy = policy_path.read_bytes()
            policy_path.write_text('{"version":1,"rules":[]}', encoding="utf-8")
            altered = gate.issue(approver, policy, "review-bot", "read", "invoice/42", event)
            try:
                expect(json_call(url+"/v1/agent/record", "POST", dict(body, token=altered), credentials["writer"])[0]==403,
                       "tampered policy accepted")
            finally:
                policy_path.write_bytes(oldpolicy)
            results["policy_change"] = "DENIED"
            status, chain = json_call(url+"/v1/ledger/verify", token=credentials["writer"])
            expect(status == 200 and chain.get("ok") is True, "ledger invalid")
            results["real_ledger_integrity"] = "PASS"
            status, anchor = json_call(url+"/v1/anchors", "POST", token=credentials["writer"])
            expect(status == 201 and "anchor_hash" in anchor and "seq" in anchor,
                   "failed to anchor evidence: " + str(anchor)[:260])
            results["signed_anchor"] = anchor.get("schema", "UNKNOWN")
            status, proof = json_call(url+f"/v1/entries/{evidence_id}/receipt", token=credentials["writer"])
            if status == 200:
                proof_file = base / "receipt.json"
                proof_file.write_text(json.dumps(proof,sort_keys=True),encoding="utf-8")
                pin = f'{anchor["seq"]}:{anchor["anchor_hash"]}'
                verifier = ROOT / "verifier" / "rf_verify.py"
                cmd = [sys.executable,"-I",str(verifier),str(proof_file),"--receipt","--pin-anchor",pin]
                checked = subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
                expect(checked.returncode==0, "independent verifier rejected receipt: "+checked.stderr[-350:]+checked.stdout[-350:])
                results["independent_receipt_verification"] = "PASS"
                tampered = json.loads(proof_file.read_text())
                tampered["entry"]["entry_type"] = "forged.agent.authorization"
                forged_file=base/"tampered.json"
                forged_file.write_text(json.dumps(tampered,sort_keys=True),encoding="utf-8")
                forged = subprocess.run([sys.executable,"-I",str(verifier),str(forged_file),"--receipt","--pin-anchor",pin],
                                        cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
                expect(forged.returncode != 0, "independent verifier accepted forged receipt")
                results["tampered_receipt"]="DENIED"
            elif status == 409 and anchor.get("schema") != "rf.anchor.v4":
                results["independent_receipt_verification"] = "UNAVAILABLE_MLDSA_RUNTIME"
                report["limitations"].append("Current phone cryptography runtime lacks ML-DSA-65; no v4 receipts")
            else:
                raise AssertionError(f"receipt failed unexpectedly: HTTP {status}: {str(proof)[:250]}")
            report["status"] = "FULL_HTTP_PASS" if status == 200 else "PARTIAL_NO_PQ_RECEIPT"
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {str(exc)[:450]}"
        print("ACCEPTANCE_ERROR="+report["error"],file=sys.stderr)
    finally:
        if process is not None:
            if process.is_alive():
                process.terminate()
                process.join(timeout=10)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
        output_dir = Path.home() / "rf-pilot-evidence"
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / ("rf-agent-product-"+time.strftime("%Y%m%dT%H%M%SZ",time.gmtime())+".json")
        with output.open("x",encoding="utf-8") as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
        output.chmod(0o600)
        print("=== RIGHTSFRAMES PRODUCT ACCEPTANCE ===")
        for k, v in results.items(): print(f"{k.upper()}={v}")
        print("STATUS="+report["status"])
        print("REPORT="+str(output))
        print("REPORT_SHA256="+hashlib.sha256(output.read_bytes()).hexdigest())
        print("PRODUCTION_LEDGER=UNCHANGED")
    return 0 if report["status"] == "FULL_HTTP_PASS" else 4


if __name__ == "__main__":
    raise SystemExit(test())
