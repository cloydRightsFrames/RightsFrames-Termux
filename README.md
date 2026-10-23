# RightsFrames

A tamper-evident governance ledger. Every event is cryptographically
hash-chained, independently anchored against truncation, and Ed25519-signed
against forgery — verifiable by any third party using nothing but Python's
standard library. No trust in the operator required.

## AI-Assisted Development — Disclosure

This project was built through extensive AI-assisted development. Every
security claim below was independently adversarially tested — not just
described — with the test scripts included in this repo.

## How It Works

| Layer | Protects Against | Verified By |
|---|---|---|
| Content-hash chain | Editing a past entry | verify_chain() |
| Anchor chain | Truncating/deleting recent history | verify_anchors() |
| Ed25519 signatures | Forgery, even with full database access | Signature check against a public key only |

## Quick Start

cd core && docker-compose up

## What's Intentionally Not Here

The full production deployment (IDS, threat-intel feeds, automated backup
verification, self-healing process supervision) runs as a personal
Android/Termux stack and is not included here.

## Termux Node: Self-Healing Installer

`termux/rf-pinnacle.sh` hardens the Android/Termux node in one idempotent run:
waits out PostgreSQL crash recovery (and clears a provably stale
`postmaster.pid`), installs the `rf-watchdog` and `rf-wifi-watch` runit
services, supervises Threat Intel / Aletheia with crash-loop backoff, and
diagnoses whole-stack restarts (Android phantom-process killer, memory
pressure). Every change is backed up; `--dry-run` shows them first.

    cd ~/RightsFrames-Termux && git pull
    bash termux/rf-pinnacle.sh --dry-run   # preview
    bash termux/rf-pinnacle.sh             # apply
    bash termux/rf-pinnacle.sh status      # live watchdog view

## Honest Limitations

This proves the ledger's integrity, not the security of whatever system
writes to it. Local anchoring resists a database-only attacker.

## License

MIT — see LICENSE.

## Contact

Charlie Loyd — CharlieLoyd@RightsFrames.onmicrosoft.com
