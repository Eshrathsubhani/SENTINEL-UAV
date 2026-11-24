"""Frozen schema-10 security incident records, evidence links and append histories."""


def install_schema(db):
    db.execute("""
        CREATE TABLE incidents (
            incident_id TEXT PRIMARY KEY NOT NULL,
            uav_id TEXT REFERENCES uavs(uav_id),
            title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 128),
            description TEXT NOT NULL CHECK(length(description)<=4096),
            attack_type TEXT NOT NULL CHECK(attack_type IN
                ('signature_failure','replay','freshness','tls_authentication','unauthorized_access',
                 'authentication','telemetry_validation','availability','credential','storage','other')),
            severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
            status TEXT NOT NULL CHECK(status IN ('open','investigating','resolved')),
            created_by TEXT NOT NULL REFERENCES users(user_id),
            created_at_us INTEGER NOT NULL CHECK(created_at_us>=0),
            updated_at_us INTEGER NOT NULL CHECK(updated_at_us>=created_at_us),
            resolved_at_us INTEGER,
            resolution TEXT NOT NULL DEFAULT '' CHECK(length(resolution)<=4096),
            CHECK((status='resolved' AND resolved_at_us IS NOT NULL
                       AND resolved_at_us>=created_at_us AND length(trim(resolution))>0)
                OR (status IN ('open','investigating') AND resolved_at_us IS NULL AND resolution='')))
    """)
    db.execute("CREATE INDEX incidents_time ON incidents(created_at_us,incident_id)")
    db.execute(
        "CREATE INDEX incidents_status ON incidents(status,created_at_us,incident_id)"
    )
    db.execute(
        "CREATE INDEX incidents_uav ON incidents(uav_id,created_at_us,incident_id)"
    )
    db.execute("""
        CREATE TABLE incident_event_links (
            link_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
            security_event_id INTEGER NOT NULL REFERENCES security_events(event_id),
            actor_id TEXT NOT NULL REFERENCES users(user_id),
            linked_at_us INTEGER NOT NULL CHECK(linked_at_us>=0),
            UNIQUE(incident_id,security_event_id))
    """)
    db.execute("""
        CREATE TABLE incident_notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
            actor_id TEXT NOT NULL REFERENCES users(user_id),
            occurred_at_us INTEGER NOT NULL CHECK(occurred_at_us>=0),
            body TEXT NOT NULL CHECK(length(trim(body)) BETWEEN 1 AND 4096))
    """)
    db.execute(
        "CREATE INDEX incident_notes_incident ON incident_notes(incident_id,note_id)"
    )
    db.execute("""
        CREATE TABLE incident_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
            actor_id TEXT NOT NULL REFERENCES users(user_id),
            occurred_at_us INTEGER NOT NULL CHECK(occurred_at_us>=0),
            action TEXT NOT NULL CHECK(action IN
                ('created','event_linked','note_added','status_changed','classification_changed')),
            details_json TEXT NOT NULL CHECK(json_valid(details_json)))
    """)
    db.execute(
        "CREATE INDEX incident_history_incident ON incident_history(incident_id,history_id)"
    )
    db.execute("""
        CREATE TRIGGER incident_event_scope BEFORE INSERT ON incident_event_links BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM incidents i JOIN security_events e ON e.event_id=NEW.security_event_id
                WHERE i.incident_id=NEW.incident_id AND i.status<>'resolved'
                  AND (i.uav_id IS NULL OR e.uav_id IS NULL OR e.uav_id=i.uav_id))
                THEN RAISE(ABORT,'Invalid incident evidence scope') END;
        END
    """)
    db.execute("""
        CREATE TRIGGER incident_links_immutable BEFORE UPDATE ON incident_event_links BEGIN
            SELECT RAISE(ABORT,'Incident evidence links cannot be reassigned');
        END
    """)
