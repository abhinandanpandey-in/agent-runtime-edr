import sqlite3
from pathlib import Path
from typing import List
from app.models import SyscallAuditRecord

DB_PATH = Path(__file__).parent.parent / "edr_telemetry.db"


class TelemetryStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS syscall_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    worker_pid INTEGER NOT NULL,
                    event_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    canonical_target TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
                """
            )

    def insert_records(self, records: List[SyscallAuditRecord]):
        if not records:
            return
        with self._conn() as conn:
            conn.executemany(
                """
                INSERT INTO syscall_audit
                (timestamp, session_id, agent_name, worker_pid, event_name, target, canonical_target, verdict, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        r.timestamp,
                        r.session_id,
                        r.agent_name,
                        r.worker_pid,
                        r.event_name,
                        r.target,
                        r.canonical_target,
                        r.verdict,
                        r.reason,
                    )
                    for r in records
                ],
            )

    def recent_records(self, limit: int = 100) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM syscall_audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def metrics(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM syscall_audit").fetchone()[0]
            blocked = conn.execute(
                "SELECT COUNT(*) FROM syscall_audit WHERE verdict = 'BLOCK_EPERM'"
            ).fetchone()[0]
            allowed = total - blocked
            return {"total_events": total, "blocked_eperm": blocked, "allowed_events": allowed}

    def clear(self):
        with self._conn() as conn:
            conn.execute("DELETE FROM syscall_audit")
