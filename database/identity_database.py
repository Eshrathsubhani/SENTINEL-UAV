"""Initialize the persistent identity schema using ordered atomic migrations."""

import argparse
from pathlib import Path

from database.connection import connect_database, database_transaction
from database.migrations import SCHEMA_VERSION, apply_migrations
from database.schema_v1 import PERMISSIONS, SCHEMA


def initialize_database(path):
    """Initialize or upgrade atomically while preserving existing records."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with database_transaction(path) as connection:
        apply_migrations(connection)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    initialize_database(args.database)
    print(f"Identity database ready at {args.database} (schema {SCHEMA_VERSION})")


if __name__ == "__main__":
    main()
