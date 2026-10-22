from __future__ import annotations

import hashlib
import json
import sqlite3
import time


DOMAIN = b"RightsFrames-Audit-v1\x00"


class AuditLog:

    def __init__(self, db_path):
        self.conn = sqlite3.connect(
            db_path,
            isolation_level="IMMEDIATE",
        )

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY,
                ts_ns INTEGER NOT NULL,
                event TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL UNIQUE
            )
            """
        )

        self.conn.commit()

    @staticmethod
    def canonical(
        seq,
        ts_ns,
        event,
        prev_hash,
    ):
        return json.dumps(
            {
                "seq": seq,
                "ts_ns": ts_ns,
                "event": event,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def append(self, event):
        row = self.conn.execute(
            """
            SELECT seq, hash
            FROM audit
            ORDER BY seq DESC
            LIMIT 1
            """
        ).fetchone()

        seq = row[0] + 1 if row else 1
        previous = row[1] if row else "0" * 64
        timestamp = time.time_ns()

        event_json = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        digest = hashlib.sha256(
            DOMAIN
            + self.canonical(
                seq,
                timestamp,
                event_json,
                previous,
            )
        ).hexdigest()

        self.conn.execute(
            """
            INSERT INTO audit
            (seq, ts_ns, event, prev_hash, hash)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                seq,
                timestamp,
                event_json,
                previous,
                digest,
            ),
        )

        self.conn.commit()
        return digest

    def verify(self):
        previous = "0" * 64
        expected = 1

        rows = self.conn.execute(
            """
            SELECT seq, ts_ns, event, prev_hash, hash
            FROM audit
            ORDER BY seq
            """
        )

        for (
            seq,
            timestamp,
            event,
            previous_hash,
            current_hash,
        ) in rows:
            if seq != expected:
                return False

            if previous_hash != previous:
                return False

            expected_hash = hashlib.sha256(
                DOMAIN
                + self.canonical(
                    seq,
                    timestamp,
                    event,
                    previous_hash,
                )
            ).hexdigest()

            if expected_hash != current_hash:
                return False

            previous = current_hash
            expected += 1

        return True

    def head(self):
        row = self.conn.execute(
            """
            SELECT hash
            FROM audit
            ORDER BY seq DESC
            LIMIT 1
            """
        ).fetchone()

        return row[0] if row else "0" * 64

    def close(self):
        """Close the SQLite connection used by this audit log."""
        conn = getattr(self, 'conn', None)
        if conn is not None:
            conn.close()
            self.conn = None

