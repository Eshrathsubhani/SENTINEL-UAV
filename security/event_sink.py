"""Trusted local gateway event producer; never expose this as an unauthenticated API."""

from pathlib import Path

from database.connection import database_transaction
from database.identity_database import initialize_database
from database.security_event_repository import append_event


class SecurityEventSink:
    def __init__(self, database, producer):
        self.database = Path(database)
        if not self.database.is_file():
            raise ValueError("The event database must already exist")
        initialize_database(self.database)
        self.producer = producer

    def __call__(self, category, event, **metadata):
        with database_transaction(self.database) as db:
            return append_event(db, self.producer, category, event, **metadata)
