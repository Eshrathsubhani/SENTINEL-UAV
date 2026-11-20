"""Shared SQLite connections and explicit transaction ownership.

Services must authorize access; this module grants no application permissions.
"""

from contextlib import closing, contextmanager
import sqlite3


def connect_database(path, *, timeout=10):
    """Return a caller-owned connection with foreign keys always enforced."""
    connection = sqlite3.connect(path, timeout=timeout)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise RuntimeError("SQLite foreign-key enforcement is unavailable")
        return connection
    except BaseException:
        connection.close()
        raise


@contextmanager
def database_transaction(path, *, write=True, timeout=10):
    """Commit on success, roll back on failure, and always close.

    Write transactions reserve the writer before reading mutable policy state.
    Read transactions provide a consistent snapshot. SQLite lock/errors propagate
    to the caller; this helper never retries a business operation implicitly.
    """
    with closing(connect_database(path, timeout=timeout)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
