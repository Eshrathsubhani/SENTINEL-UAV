"""Administrative operations and permission-scoped audit access."""

from security.authentication.auth_service import AuthService, AuthenticationError, _event, _principal, _token_hash


class AccessAdministration:
    def __init__(self, database):
        self.auth = AuthService(database)

    def list_users(self, token):
        with self.auth.administrator_transaction(token, "users.list") as (db, _):
            return [dict(row) for row in db.execute("""
                SELECT user_id, username, role_name, status, created_at FROM users ORDER BY username
            """)]

    def list_assignments(self, token):
        with self.auth.administrator_transaction(token, "assignments.list") as (db, _):
            return [dict(row) for row in db.execute("""
                SELECT a.user_id, a.uav_id, u.username, v.name AS uav_name
                FROM uav_assignments a JOIN users u ON u.user_id=a.user_id
                JOIN uavs v ON v.uav_id=a.uav_id ORDER BY u.username, v.name
            """)]

    def set_role(self, token, user_id, role):
        if role not in ("Administrator", "Operator", "Viewer"):
            raise ValueError("Unknown role")
        with self.auth.administrator_transaction(token, "user.set_role", user_id) as (db, actor):
            current = db.execute("SELECT role_name FROM users WHERE user_id=?", (user_id,)).fetchone()
            if current is None:
                raise ValueError("Unknown user")
            if current["role_name"] == role:
                return
            db.execute("UPDATE users SET role_name=? WHERE user_id=?", (role, user_id))
            db.execute("""
                UPDATE sessions SET revoked_at_epoch=?
                WHERE user_id=? AND revoked_at_epoch IS NULL
            """, (int(self.auth.clock()), user_id))
            _event(db, actor["user_id"], user_id, "role_changed", role)

    def assigned_uavs(self, token):
        with self.auth._transaction() as db:
            actor = _principal(db, _token_hash(token), int(self.auth.clock()))
            permitted = db.execute("""
                SELECT 1 FROM role_permissions WHERE role_name=? AND permission_name='telemetry.read'
            """, (actor["role_name"],)).fetchone()
            if permitted is None:
                raise PermissionError("role_denied")
            return [dict(row) for row in db.execute("""
                SELECT v.uav_id, v.name, v.system_id FROM uavs v
                JOIN uav_assignments a ON a.uav_id=v.uav_id
                WHERE a.user_id=? AND v.status='active' ORDER BY v.name, v.uav_id
            """, (actor["user_id"],))]

    def audit_events(self, token):
        reason = "allowed"
        result = None
        with self.auth._transaction() as db:
            actor = _principal(db, _token_hash(token), int(self.auth.clock()))
            permissions = {row[0] for row in db.execute(
                "SELECT permission_name FROM role_permissions WHERE role_name=?", (actor["role_name"],)
            )}
            if "audit.read" in permissions:
                condition, parameters = "", ()
            elif "audit.read_own" in permissions:
                condition, parameters = "WHERE actor_id=?", (actor["user_id"],)
            else:
                reason = "role_denied"
                condition, parameters = "", ()
            db.execute("""
                INSERT INTO authorization_events (actor_id, action, decision, reason)
                VALUES (?, 'audit.read', ?, ?)
            """, (actor["user_id"], "allow" if reason == "allowed" else "deny", reason))
            if reason == "allowed":
                # Table names and condition are fixed internal choices.
                result = {
                    table: [dict(row) for row in db.execute(
                        f"SELECT * FROM {table} {condition} ORDER BY event_id DESC LIMIT 100", parameters
                    )]
                    for table in ("identity_events", "authorization_events")
                }
        if reason != "allowed":
            raise PermissionError(reason)
        return result
