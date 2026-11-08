#!/usr/bin/env python3
"""RightsFrames one-command evaluation demo.

Builds a fresh ledger in a temporary directory, exports a signed evidence
bundle, verifies it with the independent verifier (verifier/rf_verify.py, run
as a separate isolated process), then mounts tampering attacks in which the
attacker recomputes everything that does not need the operator's private key
(entry hashes, hash links, manifest digests and summaries). Every attack must
be rejected; an unpinned forgery must be reported as internal_only, never as
anchor_pinned.

When the installed cryptography supports ML-DSA-65, anchors are hybrid
(Ed25519 + ML-DSA-65, rf.anchor.v4 with an RFC 9162 Merkle root) and two
post-quantum attacks are added: a "quantum forger" who holds the operator's
Ed25519 private key (as if recovered by a quantum computer) but not the
ML-DSA-65 key, and a downgrade that strips the post-quantum signatures. Both
must be rejected without any anchor pin.

Hybrid ledgers also get four single-entry inclusion receipt checks
(rf.receipt.v1, selective disclosure of one entry): an honest pinned receipt
verifies; a receipt whose entry is edited and re-hashed, a receipt re-signed by
the quantum forger, and an attacker ledger's receipt checked against the
operator's pin are all rejected.

Usage:
    python tools/rf_demo.py [--entries N] [--keep DIR] [--json]

Exit status: 0 when every expectation holds, 1 otherwise.
Requires: Python 3.10+ and the `cryptography` package (core/requirements.txt).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / 'verifier' / 'rf_verify.py'
EXPORTER = ROOT / 'tools' / 'rf_export_evidence.py'
RECEIPT_EXPORTER = ROOT / 'tools' / 'rf_export_receipt.py'
ZERO_HASH = '0' * 64
ANCHOR_V3 = 'rf.anchor.v3'
ANCHOR_V4 = 'rf.anchor.v4'
HYBRID = (ANCHOR_V3, ANCHOR_V4)
ANCHOR_CORE_V2 = ('schema', 'seq', 'created_at', 'ledger_count', 'ledger_head',
                  'prev_anchor_hash', 'key_id')
ANCHOR_CORE_V3 = ANCHOR_CORE_V2 + ('pq_key_id',)
ANCHOR_CORE_V4 = ANCHOR_CORE_V3 + ('merkle_root',)
CORE_FIELDS = {'rf.anchor.v2': ANCHOR_CORE_V2, ANCHOR_V3: ANCHOR_CORE_V3, ANCHOR_V4: ANCHOR_CORE_V4}

_LEDGER_SCRIPT = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
from core import rf_core
count = int(sys.argv[2])
tag = sys.argv[3]
for index in range(count):
    rf_core.append_entry('demo.event', {'actor': tag, 'n': index})
anchor = rf_core.create_anchor()
ok_chain, _ = rf_core.verify_chain()
ok_anchors, _ = rf_core.verify_anchors()
print(json.dumps({'anchor': anchor, 'chain_ok': ok_chain, 'anchors_ok': ok_anchors}))
'''


class DemoError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(entry_hashes: Sequence[str]) -> str:
    """RFC 9162 root over raw entry hashes: anything an attacker can recompute without a key."""
    def leaf(h: str) -> bytes:
        return hashlib.sha256(b'\x00' + bytes.fromhex(h)).digest()

    def tree(lo: int, hi: int) -> bytes:
        if hi - lo == 1:
            return leaf(entry_hashes[lo])
        split = lo + (1 << ((hi - lo - 1).bit_length() - 1))
        return hashlib.sha256(b'\x01' + tree(lo, split) + tree(split, hi)).digest()

    return tree(0, len(entry_hashes)).hex() if entry_hashes else hashlib.sha256(b'').hexdigest()


def build_ledger(data_dir: Path, entries: int, tag: str) -> dict[str, Any]:
    """Create a ledger in its own process so RF_DATA_DIR is honoured at import."""
    data_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env['RF_DATA_DIR'] = str(data_dir)
    proc = subprocess.run(
        [sys.executable, '-c', _LEDGER_SCRIPT, str(ROOT), str(entries), tag],
        cwd=str(ROOT), env=env, text=True, capture_output=True, timeout=120,
    )
    if proc.returncode != 0:
        raise DemoError(f'ledger build failed ({tag}): {proc.stderr.strip()[-800:]}')
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    if not (result['chain_ok'] and result['anchors_ok']):
        raise DemoError(f'freshly built ledger failed self-verification ({tag})')
    return result['anchor']


def export_bundle(data_dir: Path, out: Path) -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location('rf_export_evidence_demo', EXPORTER)
    if spec is None or spec.loader is None:
        raise DemoError(f'cannot load exporter: {EXPORTER}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_bundle(data_dir, out)


def export_receipt(data_dir: Path, entry_id: int, out: Path) -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location('rf_export_receipt_demo', RECEIPT_EXPORTER)
    if spec is None or spec.loader is None:
        raise DemoError(f'cannot load receipt exporter: {RECEIPT_EXPORTER}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_receipt(data_dir, entry_id, out)


def verify(bundle: Path, pins: Sequence[str] = (), receipt: bool = False) -> tuple[int, dict[str, Any]]:
    cmd = [sys.executable, '-I', str(VERIFIER), str(bundle), '--json', *pins]
    if receipt:
        cmd.append('--receipt')
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
    lines = proc.stdout.strip().splitlines()
    if not lines:
        raise DemoError(f'verifier produced no output: {proc.stderr.strip()[-800:]}')
    return proc.returncode, json.loads(lines[-1])


def read_bundle(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def write_bundle(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, blob in members.items():
            archive.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), blob)


def split_jsonl(blob: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in blob.decode('utf-8').splitlines() if line.strip()]


def join_jsonl(rows: list[dict[str, Any]]) -> bytes:
    return b''.join((canonical_json(row) + '\n').encode('utf-8') for row in rows)


def rechain(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Recompute every hash link exactly as an attacker without the key could."""
    previous = ZERO_HASH
    out = []
    for index, row in enumerate(rows, 1):
        row = dict(row, id=index, prev_hash=previous)
        material = f"{index}|{previous}|{row['ts']}|{row['entry_type']}|{row['payload']}"
        row['entry_hash'] = sha256_hex(material.encode('utf-8'))
        previous = row['entry_hash']
        out.append(row)
    return out


def reseal_manifest(members: dict[str, bytes]) -> dict[str, bytes]:
    """Make the unsigned manifest consistent with forged members."""
    manifest = json.loads(members['manifest.json'])
    ledger = split_jsonl(members['ledger.jsonl'])
    anchors = split_jsonl(members['anchors.jsonl'])
    for name in list(manifest['files']):
        manifest['files'][name] = {'sha256': sha256_hex(members[name]), 'bytes': len(members[name])}
    manifest['ledger_count'] = len(ledger)
    manifest['ledger_head'] = ledger[-1]['entry_hash'] if ledger else ZERO_HASH
    manifest['anchor_count'] = len(anchors)
    members = dict(members)
    members['manifest.json'] = canonical_json(manifest).encode('utf-8')
    return members


def attack_edit_keep_hashes(members: dict[str, bytes]) -> dict[str, bytes]:
    """Content edit with every stored hash and link left intact (pointer-only checks miss this)."""
    rows = split_jsonl(members['ledger.jsonl'])
    payload = json.loads(rows[1]['payload'])
    payload['n'] = 999_999
    rows[1]['payload'] = canonical_json(payload)
    members = dict(members, **{'ledger.jsonl': join_jsonl(rows)})
    return reseal_manifest(members)


def attack_edit_and_rechain(members: dict[str, bytes]) -> dict[str, bytes]:
    rows = split_jsonl(members['ledger.jsonl'])
    target = rows[1]
    payload = json.loads(target['payload'])
    payload['n'] = 999_999
    target['payload'] = canonical_json(payload)
    members = dict(members, **{'ledger.jsonl': join_jsonl(rechain(rows))})
    return reseal_manifest(members)


def attack_truncate(members: dict[str, bytes]) -> dict[str, bytes]:
    rows = split_jsonl(members['ledger.jsonl'])[:-1]
    members = dict(members, **{'ledger.jsonl': join_jsonl(rows)})
    return reseal_manifest(members)


def attack_strip_anchors(members: dict[str, bytes]) -> dict[str, bytes]:
    members = dict(members, **{'anchors.jsonl': b''})
    return reseal_manifest(members)


def resign_with_ed25519(members: dict[str, bytes], ed25519_key: Path,
                        downgrade: bool) -> dict[str, bytes]:
    """Rewrite entry 2, re-chain, and re-sign every anchor with the stolen Ed25519 key.

    The ML-DSA-65 key is NOT available to this attacker: either the old
    post-quantum signatures are kept (they no longer match), or, with
    downgrade=True, they are stripped and anchors are relabelled rf.anchor.v2.
    """
    from cryptography.hazmat.primitives import serialization
    private = serialization.load_pem_private_key(ed25519_key.read_bytes(), password=None)
    rows = split_jsonl(members['ledger.jsonl'])
    payload = json.loads(rows[1]['payload'])
    payload['n'] = 999_999
    rows[1]['payload'] = canonical_json(payload)
    rows = rechain(rows)
    heads = [ZERO_HASH] + [row['entry_hash'] for row in rows]
    previous = ZERO_HASH
    anchors = []
    for anchor in split_jsonl(members['anchors.jsonl']):
        anchor = dict(anchor, ledger_head=heads[anchor['ledger_count']], prev_anchor_hash=previous)
        if downgrade and anchor.get('schema') in HYBRID:
            anchor['schema'] = 'rf.anchor.v2'
            anchor.pop('pq_key_id', None)
            anchor.pop('pq_signature', None)
            anchor.pop('merkle_root', None)
        if anchor.get('schema') == ANCHOR_V4:
            anchor['merkle_root'] = merkle_root(heads[1:anchor['ledger_count'] + 1])
        fields = CORE_FIELDS[anchor['schema']]
        anchor['anchor_hash'] = sha256_hex(canonical_json({k: anchor[k] for k in fields}).encode('utf-8'))
        signature = private.sign(anchor['anchor_hash'].encode('ascii'))
        anchor['signature'] = base64.b64encode(signature).decode('ascii')
        previous = anchor['anchor_hash']
        anchors.append(anchor)
    members = dict(members, **{'ledger.jsonl': join_jsonl(rows), 'anchors.jsonl': join_jsonl(anchors)})
    return reseal_manifest(members)


def _write_json(path: Path, value: dict[str, Any]) -> Path:
    path.write_text(canonical_json(value) + '\n', encoding='utf-8')
    return path


def receipt_edit_entry(receipt: dict[str, Any]) -> dict[str, Any]:
    """Edit the disclosed entry and recompute its hash; the signed Merkle root is untouched."""
    forged = json.loads(json.dumps(receipt))
    entry = forged['entry']
    payload = json.loads(entry['payload'])
    payload['n'] = 999_999
    entry['payload'] = canonical_json(payload)
    material = f"{entry['id']}|{entry['prev_hash']}|{entry['ts']}|{entry['entry_type']}|{entry['payload']}"
    entry['entry_hash'] = sha256_hex(material.encode('utf-8'))
    return forged


def receipt_quantum_forger(receipt: dict[str, Any], ed25519_key: Path) -> dict[str, Any]:
    """Edit the entry, re-root the tree from the proof, re-sign the anchor with the stolen Ed25519 key."""
    from cryptography.hazmat.primitives import serialization
    private = serialization.load_pem_private_key(ed25519_key.read_bytes(), password=None)
    forged = receipt_edit_entry(receipt)
    index, size = forged['leaf_index'], forged['tree_size']
    digest = hashlib.sha256(b'\x00' + bytes.fromhex(forged['entry']['entry_hash'])).digest()
    fn, sn = index, size - 1
    for item in forged['inclusion_path']:
        sibling = bytes.fromhex(item)
        if fn & 1 or fn == sn:
            digest = hashlib.sha256(b'\x01' + sibling + digest).digest()
            while not fn & 1 and fn:
                fn >>= 1
                sn >>= 1
        else:
            digest = hashlib.sha256(b'\x01' + digest + sibling).digest()
        fn >>= 1
        sn >>= 1
    anchor = forged['anchor']
    anchor['merkle_root'] = digest.hex()
    if forged['entry']['id'] == size:
        anchor['ledger_head'] = forged['entry']['entry_hash']
    anchor['anchor_hash'] = sha256_hex(
        canonical_json({k: anchor[k] for k in ANCHOR_CORE_V4}).encode('utf-8'))
    anchor['signature'] = base64.b64encode(
        private.sign(anchor['anchor_hash'].encode('ascii'))).decode('ascii')
    return forged


def run_demo(workdir: Path, entries: int) -> dict[str, Any]:
    if entries < 3:
        raise DemoError('--entries must be at least 3')
    operator_anchor = build_ledger(workdir / 'operator', entries, 'operator')
    bundle = workdir / 'evidence.zip'
    manifest = export_bundle(workdir / 'operator', bundle)

    key_id = manifest['key_id']
    pq_key_id = manifest.get('pq_key_id')
    key_pins = ['--pin-key-id', key_id]
    if pq_key_id:
        key_pins += ['--pin-pq-key-id', pq_key_id, '--require-pq']
    pin_args = key_pins + ['--pin-anchor',
                           f"{operator_anchor['seq']}:{operator_anchor['anchor_hash']}"]
    original = read_bundle(bundle)
    results: list[dict[str, Any]] = []

    def check(name: str, path: Path, pins: Sequence[str], expect_code: int,
              expect_trust: str | None = None, receipt: bool = False) -> None:
        code, report = verify(path, pins, receipt)
        held = code == expect_code and (expect_trust is None or report.get('trust_level') == expect_trust)
        outcome = (f"VERIFIED ({report.get('trust_level')})" if report.get('status') == 'VERIFIED'
                   else f"REJECTED: {report.get('error')}")
        results.append({'check': name, 'expected_exit': expect_code, 'exit': code,
                        'outcome': outcome, 'held': held})

    check('honest bundle, operator pins held externally', bundle, pin_args, 0, 'anchor_pinned')
    check('honest bundle, no pins (self-consistency only)', bundle, [], 10, 'internal_only')

    attacks: list[tuple[str, Callable[[dict[str, bytes]], dict[str, bytes]]]] = [
        ('edit past entry, keep stored hashes + reseal manifest', attack_edit_keep_hashes),
        ('edit past entry + recompute every hash + reseal manifest', attack_edit_and_rechain),
        ('delete an anchored entry + reseal manifest', attack_truncate),
        ('strip all signed anchors + reseal manifest', attack_strip_anchors),
    ]
    for index, (name, mutate) in enumerate(attacks, 1):
        forged = workdir / f'attack-{index}.zip'
        write_bundle(forged, mutate(original))
        check(name, forged, pin_args, 1)

    forged_dir = workdir / 'attacker'
    build_ledger(forged_dir, entries, 'attacker')
    forged_bundle = workdir / 'attack-forged-history.zip'
    export_bundle(forged_dir, forged_bundle)
    check('rewrite entire history with attacker key, no pins', forged_bundle, [], 10, 'internal_only')
    check('rewrite entire history with attacker key, operator pins', forged_bundle, pin_args, 1)

    if pq_key_id:
        stolen_ed25519 = workdir / 'operator' / 'signing_key.pem'
        quantum = workdir / 'attack-quantum-forger.zip'
        write_bundle(quantum, resign_with_ed25519(original, stolen_ed25519, downgrade=False))
        check('quantum forger: stolen Ed25519 key, re-sign anchors, key pins only',
              quantum, key_pins, 1)
        stripped = workdir / 'attack-pq-downgrade.zip'
        write_bundle(stripped, resign_with_ed25519(original, stolen_ed25519, downgrade=True))
        check('downgrade: strip ML-DSA-65 signatures, re-sign Ed25519, key pins only',
              stripped, key_pins, 1)

        honest_receipt = workdir / 'receipt-entry-2.json'
        receipt = export_receipt(workdir / 'operator', 2, honest_receipt)
        receipt_pins = ['--pin-key-id', key_id, '--pin-pq-key-id', pq_key_id, '--pin-anchor',
                        f"{receipt['anchor']['seq']}:{receipt['anchor']['anchor_hash']}"]
        check('receipt: disclose one entry only, operator pin held externally',
              honest_receipt, receipt_pins, 0, 'anchor_pinned', receipt=True)
        check('receipt: edit disclosed entry + recompute its hash',
              _write_json(workdir / 'attack-receipt-edit.json', receipt_edit_entry(receipt)),
              receipt_pins, 1, receipt=True)
        check('receipt: quantum forger re-roots Merkle tree, re-signs Ed25519, key pins only',
              _write_json(workdir / 'attack-receipt-quantum.json',
                          receipt_quantum_forger(receipt, stolen_ed25519)),
              key_pins[:4], 1, receipt=True)
        attacker_receipt = workdir / 'attack-receipt-attacker-ledger.json'
        export_receipt(forged_dir, 2, attacker_receipt)
        check('receipt: attacker ledger receipt, operator pins', attacker_receipt,
              receipt_pins, 1, receipt=True)
    return {'results': results, 'post_quantum': 'hybrid ML-DSA-65' if pq_key_id else 'unavailable',
            'pq_key_id': pq_key_id}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='RightsFrames tamper-evidence demo.')
    parser.add_argument('--entries', type=int, default=5)
    parser.add_argument('--keep', metavar='DIR', help='keep bundles in DIR (must not exist)')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    try:
        if args.keep:
            workdir = Path(args.keep)
            workdir.mkdir(parents=True, exist_ok=False)
            outcome = run_demo(workdir, args.entries)
        else:
            with tempfile.TemporaryDirectory(prefix='rf-demo-', ignore_cleanup_errors=True) as tmp:
                outcome = run_demo(Path(tmp), args.entries)
    except (DemoError, OSError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
        print(f'rf-demo: error: {exc}', file=sys.stderr)
        return 1

    results = outcome['results']
    passed = all(item['held'] for item in results)
    if args.json:
        print(json.dumps({'passed': passed, 'post_quantum': outcome['post_quantum'],
                          'results': results}, sort_keys=True))
    else:
        print(f"post-quantum anchor signatures: {outcome['post_quantum']}"
              + ('' if outcome['pq_key_id'] else
                 ' (ML-DSA-65 missing from this cryptography build, or RF_PQ_SIGNING=off;'
                 ' post-quantum attacks skipped)') + '\n')
        width = max(len(item['check']) for item in results)
        for item in results:
            mark = 'PASS' if item['held'] else 'FAIL'
            print(f"[{mark}] {item['check']:<{width}}  exit={item['exit']}  {item['outcome']}")
        print(f"\n{sum(i['held'] for i in results)}/{len(results)} expectations held"
              + ('' if passed else ' -- DEMO FAILED'))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
