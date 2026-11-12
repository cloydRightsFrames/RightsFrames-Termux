#!/usr/bin/env python3
"""Export an rf.consistency.v1 append-only proof between two anchors (discloses no entry).

The proof shows that the ledger signed by a later rf.anchor.v4 anchor is the ledger
signed by an earlier one with entries appended. It carries both hybrid-signed
(Ed25519 + ML-DSA-65) anchors, an RFC 9162 Merkle consistency path and both public
keys, and no ledger entry. Someone who pinned the earlier anchor at the last review can
check everything written since and move their pin forward:

    python tools/rf_export_consistency.py --data-dir /data --from-seq 3 --out since-3.json
    python verifier/rf_verify.py since-3.json --consistency --pin-anchor 3:HASH

--to-seq defaults to the newest anchor. Read-only: never reads a private key, refuses
to overwrite an existing file, and refuses to emit a proof whose Merkle roots, path or
key identities do not match the anchors.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_consistency_module():
    """Import core/rf_consistency.py the same way the API does (core/ on sys.path)."""
    core = str(ROOT / 'core')
    if core not in sys.path:
        sys.path.insert(0, core)
    import rf_consistency
    return rf_consistency


def export_consistency(data_dir: str | os.PathLike[str], from_seq: int,
                       out: str | os.PathLike[str], to_seq: int | None = None) -> dict:
    module = _load_consistency_module()
    proof = module.build_consistency_proof(data_dir, from_seq, to_seq)
    blob = module.canonical_proof(proof)
    out_path = Path(out)
    try:
        with open(out_path, 'xb') as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise
    except Exception:
        try:
            out_path.unlink()
        except OSError as cleanup_err:
            print(f'warning: failed to remove incomplete output {out_path}: {cleanup_err}',
                  file=sys.stderr)
        raise
    return proof


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Export an append-only consistency proof between two anchors.')
    parser.add_argument('--data-dir', default=os.environ.get('RF_DATA_DIR'))
    parser.add_argument('--from-seq', type=int, required=True,
                        help='earlier rf.anchor.v4 anchor (the one already pinned)')
    parser.add_argument('--to-seq', type=int, help='later rf.anchor.v4 anchor (default: newest)')
    parser.add_argument('--out', required=True, help='output file (must not exist)')
    args = parser.parse_args(argv)
    if not args.data_dir:
        parser.error('--data-dir or RF_DATA_DIR is required')
    try:
        proof = export_consistency(args.data_dir, args.from_seq, args.out, args.to_seq)
    except FileExistsError:
        print(f'rf-export-consistency: refusing to overwrite {args.out}', file=sys.stderr)
        return 1
    except (LookupError, ValueError, TypeError, OSError) as exc:
        print(f'rf-export-consistency: {exc}', file=sys.stderr)
        return 1
    first, second = proof['first_anchor'], proof['second_anchor']
    print(f"consistency proof from anchor {first['seq']} ({first['ledger_count']} entries) to "
          f"anchor {second['seq']} ({second['ledger_count']} entries), "
          f"{len(proof['consistency_path'])} path hashes")
    print(f"verify with: --pin-anchor {first['seq']}:{first['anchor_hash']}")
    print(f"next pin:    --pin-anchor {second['seq']}:{second['anchor_hash']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
