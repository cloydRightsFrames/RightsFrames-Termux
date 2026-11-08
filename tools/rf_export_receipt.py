#!/usr/bin/env python3
"""Export an rf.receipt.v1 single-entry inclusion receipt (selective disclosure).

The receipt proves that ONE ledger entry is in the hybrid-signed (Ed25519 + ML-DSA-65)
ledger without revealing any other entry: the entry, an RFC 9162 Merkle inclusion path,
the rf.anchor.v4 anchor that signs the Merkle root, and both public keys.

    python tools/rf_export_receipt.py --data-dir /data --entry-id 42 --out receipt-42.json
    python verifier/rf_verify.py receipt-42.json --receipt --pin-anchor SEQ:HASH

By default the newest v4 anchor covering the entry is used; pass --anchor-seq to prove
against an anchor whose hash you have already pinned off-box. Read-only: never reads a
private key, refuses to overwrite an existing file, and refuses to emit a receipt whose
Merkle root or key identities do not match the anchor.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_receipt_module():
    """Import core/rf_receipt.py the same way the API does (core/ on sys.path)."""
    core = str(ROOT / 'core')
    if core not in sys.path:
        sys.path.insert(0, core)
    import rf_receipt
    return rf_receipt


def export_receipt(data_dir: str | os.PathLike[str], entry_id: int, out: str | os.PathLike[str],
                   anchor_seq: int | None = None) -> dict:
    module = _load_receipt_module()
    receipt = module.build_receipt(data_dir, entry_id, anchor_seq)
    blob = module.canonical_receipt(receipt)
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
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Export a single-entry inclusion receipt.')
    parser.add_argument('--data-dir', default=os.environ.get('RF_DATA_DIR'))
    parser.add_argument('--entry-id', type=int, required=True)
    parser.add_argument('--anchor-seq', type=int, help='prove against this rf.anchor.v4 anchor')
    parser.add_argument('--out', required=True, help='output file (must not exist)')
    args = parser.parse_args(argv)
    if not args.data_dir:
        parser.error('--data-dir or RF_DATA_DIR is required')
    try:
        receipt = export_receipt(args.data_dir, args.entry_id, args.out, args.anchor_seq)
    except FileExistsError:
        print(f'rf-export-receipt: refusing to overwrite {args.out}', file=sys.stderr)
        return 1
    except (LookupError, ValueError, TypeError, OSError) as exc:
        print(f'rf-export-receipt: {exc}', file=sys.stderr)
        return 1
    anchor = receipt['anchor']
    print(f"receipt for entry {receipt['entry']['id']} against anchor {anchor['seq']} "
          f"(tree size {receipt['tree_size']}, {len(receipt['inclusion_path'])} path hashes)")
    print(f"pin: --pin-anchor {anchor['seq']}:{anchor['anchor_hash']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
