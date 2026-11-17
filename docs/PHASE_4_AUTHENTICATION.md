# Phase 4 user authentication

This milestone provides a local backend authentication service. Initialize the
first Administrator through the CLI. Administrator sessions can create users and
change their account status. RBAC for UAV operations and gateway integration
follow in later milestones.

From Windows Command Prompt at the repository root, run:

    python -m database.identity_database --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3"
    python -m security.authentication.auth_service bootstrap-admin --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3" --username admin

Enter the password at the hidden prompts. The password must contain 12 to 1024
characters. Usernames contain 3 to 64 ASCII letters, digits, dots, underscores,
or dashes and are stored lowercase. These are initial prototype parameters.

The command creates the first administrator only when the user table is empty.
Running it again returns an error and preserves the existing account.

The database upgrades version one to version two in one transaction, adding
persistent login attempt counters. Existing users, sessions, assignments,
and events are retained.

The AuthService Python interface provides login, authenticate, logout,
create_user, and set_user_status. The CLI exposes administrator bootstrap.
The UI and HTTP integration are pending.

Passwords use Argon2id through PasswordHasher. Successful login rehashes a
password when its stored parameters require an update. Each successful login
creates a new random bearer token. The database stores its SHA-256 hash with a
one-hour expiration. Keep bearer tokens out of logs and Git.

After five failed logins for a username within sixty seconds, further login
attempts for that username are blocked for sixty seconds. Attempts and login
events persist across process restarts. Error responses for unknown accounts,
wrong passwords, and inactive accounts use the same login-failed message.
Malformed usernames return an input validation error.

Logout invalidates the selected session. Account suspension and revocation
invalidate all current sessions atomically with the status change. Reactivating
a suspended account requires a new login. Revocation is terminal in this service.
Authenticated requests reload the current role and account status from SQLite.

Authentication decisions and account changes are recorded in identity_events.
Future authorization milestones add denied-operation auditing and resource
permissions. Database access remains restricted to the local application account.

For consistency during concurrent requests, authentication changes take a
SQLite write lock. Password verification holds that lock in this initial local
prototype. Multi-user throughput needs separate evaluation before scaling.

Run the full Windows test suite after applying the patch. The authentication
suite covers credential storage, all three roles, administrator restrictions,
session expiry, logout, throttling, account revocation, migration, and input
validation.
