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
    delivery = create.add_mutually_exclusive_group(required=True)
    delivery.add_argument('--token-file', help='write the token here (new file, mode 0600)')
    delivery.add_argument('--print-token', action='store_true',
                          help='print the token to stdout (it lands in terminal scrollback)')
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
            token_path = Path(args.token_file).expanduser() if args.token_file else None
            if token_path is not None and (token_path.exists() or token_path.is_symlink()):
                print(f'ERROR: token file already exists: {token_path}', file=sys.stderr)
                return 1
            # The token is shown exactly once; only its PBKDF2 hash is stored.
            token = rf_auth.create_principal(args.id, scopes, args.label, actor)
            if token_path is not None:
                token_path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                    handle.write(token + '\n')
                    handle.flush()
                    os.fsync(handle.fileno())
            print(f'PRINCIPAL={args.id}')
            print('SCOPES=' + ','.join(sorted(set(scopes))))
            if token_path is not None:
                print(f'TOKEN_FILE={token_path}')
            else:
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