#!/usr/bin/env python3
"""Recover the anchor log after an interrupted write (crash or power loss during an anchor).

An anchor append that is cut short leaves anchors.jsonl ending without a newline; from
then on the core refuses to verify or extend the log. This tool, under the anchor lock:

  * copies the trailing fragment to anchors.torn.<UTC timestamp>.bin (mode 0600),
  * rewrites the log atomically: terminated when the fragment is a complete anchor that
    only lost its newline (its signatures are still verified afterwards), otherwise
    truncated to the last complete anchor,
  * records the repair in the ledger as `maintenance.anchor_log.repaired` with the
    fragment's SHA-256,
  * re-runs chain and anchor verification and exits non-zero unless both pass.

    python tools/rf_repair_anchor_log.py --data-dir /data            # repair if torn
    python tools/rf_repair_anchor_log.py --data-dir /data --check    # report only

A log that is not torn is never modified.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Repair an anchor log torn by an interrupted write.')
    parser.add_argument('--data-dir', default=os.environ.get('RF_DATA_DIR'))
    parser.add_argument('--check', action='store_true', help='report only; change nothing')
    args = parser.parse_args(argv)
    if not args.data_dir:
        parser.error('--data-dir or RF_DATA_DIR is required')
    data_dir = Path(args.data_dir).resolve()
    if not (data_dir / 'ledger.db').is_file():
        print(f'rf-repair-anchor-log: no ledger.db in {data_dir}', file=sys.stderr)
        return 1
    # rf_core resolves its data directory at import time.
    os.environ['RF_DATA_DIR'] = str(data_dir)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from core import rf_core

    if args.check:
        torn = rf_core.ANCHOR_PATH.exists() and rf_core._anchor_log_is_torn()
        print(json.dumps({'torn': torn}, sort_keys=True))
        return 2 if torn else 0
    try:
        result = rf_core.repair_anchor_log()
    except (OSError, ValueError) as exc:
        print(f'rf-repair-anchor-log: {exc}', file=sys.stderr)
        return 1
    chain_ok, chain_reason = rf_core.verify_chain()
    anchors_ok, anchors_reason = rf_core.verify_anchors()
    result['chain'] = chain_reason
    result['anchors'] = anchors_reason
    print(json.dumps(result, sort_keys=True))
    return 0 if chain_ok and anchors_ok else 1


if __name__ == '__main__':
    sys.exit(main())
