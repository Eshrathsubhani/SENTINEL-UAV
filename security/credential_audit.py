"""Record changes to credentials loaded by a gateway instance."""

from contextlib import closing
import logging
import sqlite3

LOGGER = logging.getLogger(__name__)


def audit_credentials(path, role, credentials):
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

    for event_role, kind, event in events:
        LOGGER.info("credential_%s role=%s kind=%s", event, event_role, kind)
