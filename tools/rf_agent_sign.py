#!/usr/bin/env python3
"""Offline scoped-approval signer. Run on an APPROVER device, never on the agent host.

Accepts only an encrypted Ed25519 PKCS#8 private key; never emits secrets.
An interactive passphrase is mandatory to prevent an unattended signing oracle.
"""
from __future__ import annotations
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def private_file(path: str) -> bytes:
    target = Path(path)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(target, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 10000:
            raise PermissionError('approver private key must be an owner-only regular file (0600)')
        blob = os.read(fd, 10001)
    finally: os.close(fd)
    if not blob.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
        raise ValueError('unencrypted or unsupported signing key refused')
    return blob


def main():
    parser = argparse.ArgumentParser(description='Offline, interactive, scope-bound RightsFrames grant signer')
    parser.add_argument('--encrypted-key', required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--request', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--ttl', type=int, default=60)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path: sys.path.insert(0, str(root))
    from core import rf_agent_gate as gate
    if not 1 <= args.ttl <= gate.MAX_TTL: raise ValueError('invalid TTL')
    policy_path = Path(args.policy)
    request_path = Path(args.request)
    if policy_path.stat().st_size > 131072 or request_path.stat().st_size > 262144:
        raise ValueError('policy/request size limit exceeded')
    policy = json.loads(policy_path.read_text('utf-8'))
    request = json.loads(request_path.read_text('utf-8'))
    if not isinstance(request,dict) or set(request) != {'agent','action','resource','event'}:
        raise ValueError('request must contain exactly agent,action,resource,event')
    print('APPROVAL_REQUEST_SHA256='+hashlib.sha256(request_path.read_bytes()).hexdigest())
    print('Verify requested agent/action/resource and the intended event before unlocking.')
    print('AGENT='+str(request['agent']))
    print('ACTION='+str(request['action']))
    print('RESOURCE='+str(request['resource']))
    password = getpass.getpass('Offline approver key passphrase: ')
    if not password: raise ValueError('passphrase required')
    key = serialization.load_pem_private_key(private_file(args.encrypted_key), password=password.encode())
    if not isinstance(key, Ed25519PrivateKey): raise ValueError('Ed25519 key required')
    token = gate.issue(key, policy, request['agent'], request['action'], request['resource'], request['event'], ttl=args.ttl)
    blob = (json.dumps(token, sort_keys=True, separators=(',',':'), allow_nan=False)+'\n').encode()
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(blob);f.flush();os.fsync(f.fileno())
    except Exception:
        Path(args.out).unlink(missing_ok=True)
        raise
    print('SIGNED_GRANT=CREATED')
    print('GRANT_SHA256='+hashlib.sha256(blob).hexdigest())
    print('VALID_FOR_SECONDS='+str(args.ttl))
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except Exception as exc:
        print('APPROVAL_DENIED='+type(exc).__name__+': '+str(exc),file=sys.stderr)
        sys.exit(1)
