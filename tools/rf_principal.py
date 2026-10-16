#!/usr/bin/env python3
"""Local principal administration (requires filesystem access to RF_DATA_DIR)."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Manage RightsFrames API principals.')
    sub = parser.add_subparsers(dest='cmd', required=True)
    create = sub.add_parser('create')
    create.add_argument('--id', required=True)
    create.add_argument('--scopes', required=True, help='comma separated')
    create.add_argument('--label', default='')
    create.add_argument('--if-absent', action='store_true')
    sub.add_parser('list')
    revoke = sub.add_parser('revoke')
    revoke.add_argument('--id', required=True)
    args = parser.parse_args(argv)

    if not os.environ.get('RF_DATA_DIR'):
        print('RF_DATA_DIR must be set', file=sys.stderr)
        return 2
    sys.path.insert(0, str(ROOT / 'core'))
    import rf_auth  # noqa: E402

    actor = f'local-cli:{getpass.getuser()}'
    try:
        if args.cmd == 'create':
            if args.if_absent and rf_auth.get_principal(args.id) is not None:
                print(f'EXISTS={args.id}')
                return 0
            scopes = [s.strip() for s in args.scopes.split(',') if s.strip()]
            token = rf_auth.create_principal(args.id, scopes, args.label, actor)
            print(f'PRINCIPAL={args.id}')
            print('SCOPES=' + ','.join(sorted(set(scopes))))
            print(f'TOKEN={token}')
        elif args.cmd == 'list':
            print(json.dumps(rf_auth.list_principals(), indent=2))
        else:
            rf_auth.revoke_principal(args.id, actor)
            print(f'REVOKED={args.id}')
    except (ValueError, LookupError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())