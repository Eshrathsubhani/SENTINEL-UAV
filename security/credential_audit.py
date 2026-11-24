"""Record changes to credentials loaded by a gateway instance."""

from contextlib import closing
import logging
import sqlite3
from uuid import uuid4

from database.telemetry_repository import timestamp_us

LOGGER = logging.getLogger(__name__)


def audit_credentials(path, role, credentials, *, on_event=None):
    """Persist changes atomically and log the kind of change without credential IDs."""
    events = []
    with closing(sqlite3.connect(path)) as database, database:
        database.execute("BEGIN IMMEDIATE")
        database.execute("""
            CREATE TABLE IF NOT EXISTS active_credentials (
                role TEXT, kind TEXT, identifier TEXT NOT NULL,
                PRIMARY KEY (role, kind))
        """)
        database.execute("""
            CREATE TABLE IF NOT EXISTS credential_events (
                event_id INTEGER PRIMARY KEY, timestamp_utc TEXT DEFAULT CURRENT_TIMESTAMP,
                role TEXT, kind TEXT, event TEXT)
        """)
        database.execute("CREATE TABLE IF NOT EXISTS credential_audit_metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        database.execute("INSERT OR IGNORE INTO credential_audit_metadata VALUES ('instance_id',?)", (uuid4().hex,))
        instance_id = database.execute("SELECT value FROM credential_audit_metadata WHERE name='instance_id'").fetchone()[0]
        previous = dict(database.execute(
            "SELECT kind, identifier FROM active_credentials WHERE role = ?", (role,)
        ))
        for kind in sorted(previous.keys() | credentials.keys()):
            before = previous.get(kind)
            after = credentials.get(kind)
            if before == after:
                continue
            if before is not None:
                events.append((role, kind, "retired"))
            if after is not None:
                events.append((role, kind, "rotated" if before is not None else "activated"))

        database.execute("DELETE FROM active_credentials WHERE role = ?", (role,))
        database.executemany(
            "INSERT INTO active_credentials VALUES (?, ?, ?)",
            ((role, kind, identifier) for kind, identifier in credentials.items()),
        )
        database.executemany(
            "INSERT INTO credential_events (role, kind, event) VALUES (?, ?, ?)", events
        )

        replay = database.execute(
            "SELECT event_id,timestamp_utc,role,kind,event FROM credential_events WHERE role=? ORDER BY event_id", (role,)
        ).fetchall() if on_event is not None else []

    # Replay the durable source on startup; stable event IDs make retries idempotent.
    # No identifier, certificate PEM or private credential contents leave this database.
    for event_id, stamp, event_role, kind, event in replay:
        on_event("credential", "credential_" + event, outcome="success",
                 producer_event_id=instance_id + ":" + str(event_id),
                 occurred_at_us=timestamp_us(stamp.replace(" ", "T") + "+00:00"),
                 details={"role": event_role, "kind": kind})

    for event_role, kind, event in events:
        LOGGER.info("credential_%s role=%s kind=%s", event, event_role, kind)
