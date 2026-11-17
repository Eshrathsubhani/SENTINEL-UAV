"""Persistent local authentication and session services for Phase 4."""

import argparse
from contextlib import closing, contextmanager
from getpass import getpass
from hashlib import sha256
from pathlib import Path
import re
import secrets
import time
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from database.identity_database import connect_database, initialize_database

HASHER = PasswordHasher()
DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))
SESSION_SECONDS = 3600
LOGIN_WINDOW_SECONDS = 60
MAX_FAILURES = 5


class AuthenticationError(ValueError):
    """Authentication or administrator authorization failed."""


def _username(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", value) is None:
        raise ValueError("Username must have 3 to 64 ASCII letters, digits, dots, dashes or underscores")
    return value.lower()


def _password_hash(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValueError("Password must contain 12 to 1024 characters")
    return HASHER.hash(password)


def _token_hash(token):
    if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
        raise AuthenticationError("Invalid or expired session")
    return sha256(token.encode("ascii")).hexdigest()


def _event(db, actor, target, event, reason):
    db.execute(
        "INSERT INTO identity_events (actor_id, target_id, event, reason) VALUES (?, ?, ?, ?)",
        (actor, target, event, reason),
    )


def _principal(db, token_hash, now):
    row = db.execute("""
        SELECT u.user_id, u.username, u.role_name, u.status
        FROM sessions s JOIN users u ON u.user_id = s.user_id
        WHERE s.token_hash = ? AND s.revoked_at_epoch IS NULL
          AND s.expires_at_epoch > ? AND u.status = 'active'
    """, (token_hash, now)).fetchone()
    if row is None:
        raise AuthenticationError("Invalid or expired session")
    return dict(row)


class AuthService:
    """Read current identity state on each call using a fresh database connection."""

    def __init__(self, database, *, clock=time.time):
        self.database = Path(database)
        self.clock = clock
        initialize_database(self.database)

    @contextmanager
    def _transaction(self):
        with closing(connect_database(self.database)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            yield db

    def bootstrap_admin(self, username, password):
        username = _username(username)
        password_hash = _password_hash(password)
        user_id = uuid4().hex
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise AuthenticationError("Administrator initialization requires an empty user table")
            db.execute("""
                INSERT INTO users (user_id, username, password_hash, role_name)
                VALUES (?, ?, ?, 'Administrator')
            """, (user_id, username, password_hash))
            _event(db, user_id, user_id, "administrator_initialized", "local_bootstrap")
        return user_id

    def login(self, username, password):
        username = _username(username)
        now = int(self.clock())
        token = None
        with self._transaction() as db:
            attempt = db.execute(
                "SELECT * FROM login_attempts WHERE username = ?", (username,)
            ).fetchone()
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            actor = user["user_id"] if user is not None else None
            if attempt is not None and attempt["blocked_until_epoch"] > now:
                _event(db, actor, actor, "login_failed", "throttled")
            else:
                verified = False
                if isinstance(password, str) and len(password) <= 1024:
                    try:
                        verified = HASHER.verify(
                            user["password_hash"] if user is not None else DUMMY_HASH, password
                        )
                    except (VerificationError, InvalidHashError):
                        pass
                if verified and user is not None and user["status"] == "active":
                    if HASHER.check_needs_rehash(user["password_hash"]):
                        db.execute("UPDATE users SET password_hash = ? WHERE user_id = ?",
                                   (HASHER.hash(password), actor))
                    token = secrets.token_urlsafe(32)
                    db.execute("""
                        INSERT INTO sessions
                        (token_hash, user_id, created_at_epoch, expires_at_epoch)
                        VALUES (?, ?, ?, ?)
                    """, (_token_hash(token), actor, now, now + SESSION_SECONDS))
                    db.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
                    _event(db, actor, actor, "login_succeeded", "credentials_verified")
                else:
                    failures = 1
                    start = now
                    if attempt is not None and now - attempt["window_start_epoch"] < LOGIN_WINDOW_SECONDS:
                        failures += attempt["failures"]
                        start = attempt["window_start_epoch"]
                    blocked = now + LOGIN_WINDOW_SECONDS if failures >= MAX_FAILURES else 0
                    db.execute("""
                        INSERT INTO login_attempts VALUES (?, ?, ?, ?)
                        ON CONFLICT(username) DO UPDATE SET failures=excluded.failures,
                        window_start_epoch=excluded.window_start_epoch,
                        blocked_until_epoch=excluded.blocked_until_epoch
                    """, (username, failures, start, blocked))
                    _event(db, actor, actor, "login_failed", "invalid_credentials_or_account")
        if token is None:
            raise AuthenticationError("Login failed")
        return token

    def authenticate(self, token):
        token_hash = _token_hash(token)
        with closing(connect_database(self.database)) as db:
            return _principal(db, token_hash, int(self.clock()))

    def logout(self, token):
        token_hash = _token_hash(token)
        now = int(self.clock())
        with self._transaction() as db:
            row = db.execute(
                "SELECT user_id FROM sessions WHERE token_hash = ? AND revoked_at_epoch IS NULL",
                (token_hash,),
            ).fetchone()
            if row is not None:
                db.execute("UPDATE sessions SET revoked_at_epoch = ? WHERE token_hash = ?",
                           (now, token_hash))
                _event(db, row["user_id"], row["user_id"], "logout", "session_revoked")

    def create_user(self, administrator_token, username, password, role):
        username = _username(username)
        password_hash = _password_hash(password)
        if role not in ("Administrator", "Operator", "Viewer"):
            raise ValueError("Unknown role")
        token_hash = _token_hash(administrator_token)
        user_id = uuid4().hex
        with self._transaction() as db:
            administrator = _principal(db, token_hash, int(self.clock()))
            if administrator["role_name"] != "Administrator":
                raise AuthenticationError("Administrator permission required")
            db.execute("""
                INSERT INTO users (user_id, username, password_hash, role_name)
                VALUES (?, ?, ?, ?)
            """, (user_id, username, password_hash, role))
            _event(db, administrator["user_id"], user_id, "user_created", role)
        return user_id

    def set_user_status(self, administrator_token, user_id, status):
        if status not in ("active", "suspended", "revoked"):
            raise ValueError("Unknown account status")
        token_hash = _token_hash(administrator_token)
        now = int(self.clock())
        with self._transaction() as db:
            administrator = _principal(db, token_hash, now)
            if administrator["role_name"] != "Administrator":
                raise AuthenticationError("Administrator permission required")
            target = db.execute("SELECT status FROM users WHERE user_id = ?", (user_id,)).fetchone()
            if target is None:
                raise ValueError("Unknown user")
            if target["status"] == "revoked" and status != "revoked":
                raise ValueError("A revoked account cannot be reactivated")
            db.execute("UPDATE users SET status = ? WHERE user_id = ?", (status, user_id))
            if status != "active":
                db.execute(
                    "UPDATE sessions SET revoked_at_epoch = ? WHERE user_id = ? AND revoked_at_epoch IS NULL",
                    (now, user_id),
                )
            _event(db, administrator["user_id"], user_id, "user_status_changed", status)


def main():
    parser = argparse.ArgumentParser(description="Initialize the first local administrator")
    parser.add_argument("command", choices=("bootstrap-admin",))
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--username", required=True)
    args = parser.parse_args()
    password = getpass("New administrator password (12 or more characters): ")
    if password != getpass("Confirm password: "):
        parser.error("Passwords do not match")
    try:
        user_id = AuthService(args.database).bootstrap_admin(args.username, password)
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + "\n")
    print(f"Administrator created with user ID {user_id}")


if __name__ == "__main__":
    main()
