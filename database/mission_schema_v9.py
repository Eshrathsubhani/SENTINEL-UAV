"""Frozen schema-9 mission records and same-transaction telemetry associations."""


def install_schema(db):
    db.execute("""
        CREATE TABLE missions (
            mission_id TEXT PRIMARY KEY NOT NULL,
            uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
            name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),
            description TEXT NOT NULL CHECK(length(description)<=2048),
            details_json TEXT NOT NULL CHECK(json_valid(details_json)),
            status TEXT NOT NULL CHECK(status IN ('planned','active','completed','aborted','cancelled')),
            created_at_us INTEGER NOT NULL CHECK(created_at_us>=0),
            created_by TEXT NOT NULL REFERENCES users(user_id),
            started_at_us INTEGER,
            ended_at_us INTEGER,
            UNIQUE(mission_id,uav_id),
            CHECK(started_at_us IS NULL OR started_at_us>=created_at_us),
            CHECK(ended_at_us IS NULL OR ended_at_us>=COALESCE(started_at_us,created_at_us)),
            CHECK((status='planned' AND started_at_us IS NULL AND ended_at_us IS NULL)
               OR (status='active' AND started_at_us IS NOT NULL AND ended_at_us IS NULL)
               OR (status IN ('completed','aborted') AND started_at_us IS NOT NULL AND ended_at_us IS NOT NULL)
               OR (status='cancelled' AND started_at_us IS NULL AND ended_at_us IS NOT NULL)))
    """)
    db.execute(
        "CREATE UNIQUE INDEX missions_one_active_uav ON missions(uav_id) WHERE status='active'"
    )
    db.execute(
        "CREATE INDEX missions_uav_time ON missions(uav_id,created_at_us,mission_id)"
    )
    db.execute("""
        CREATE TABLE mission_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            mission_id TEXT NOT NULL REFERENCES missions(mission_id),
            actor_id TEXT NOT NULL REFERENCES users(user_id),
            occurred_at_us INTEGER NOT NULL CHECK(occurred_at_us>=0),
            event TEXT NOT NULL CHECK(event IN ('created','started','completed','aborted','cancelled')))
    """)
    db.execute(
        "CREATE INDEX mission_events_mission ON mission_events(mission_id,event_id)"
    )
    db.execute(
        "CREATE UNIQUE INDEX telemetry_record_uav ON telemetry_records(record_id,uav_id)"
    )
    db.execute("""
        CREATE TABLE mission_telemetry (
            record_id TEXT PRIMARY KEY NOT NULL,
            uav_id TEXT NOT NULL,
            mission_id TEXT NOT NULL,
            linked_at_us INTEGER NOT NULL CHECK(linked_at_us>=0),
            FOREIGN KEY(record_id,uav_id) REFERENCES telemetry_records(record_id,uav_id) ON DELETE CASCADE,
            FOREIGN KEY(mission_id,uav_id) REFERENCES missions(mission_id,uav_id))
    """)
    db.execute(
        "CREATE INDEX mission_telemetry_mission ON mission_telemetry(mission_id,record_id)"
    )
    db.execute("""
        CREATE TRIGGER mission_link_validate BEFORE INSERT ON mission_telemetry BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM missions m JOIN telemetry_records t ON t.uav_id=m.uav_id
                WHERE m.mission_id=NEW.mission_id AND m.uav_id=NEW.uav_id AND t.record_id=NEW.record_id
                  AND m.status='active' AND t.captured_at_us>=m.started_at_us
                  AND t.received_at_us>=m.started_at_us AND t.captured_at_us<=t.received_at_us
                  AND NEW.linked_at_us=t.received_at_us)
                THEN RAISE(ABORT,'Invalid mission telemetry association') END;
        END
    """)
    db.execute("""
        CREATE TRIGGER mission_link_immutable BEFORE UPDATE ON mission_telemetry BEGIN
            SELECT RAISE(ABORT,'Mission telemetry associations cannot be reassigned');
        END
    """)
    db.execute("""
        CREATE TRIGGER mission_link_accepted_telemetry AFTER INSERT ON telemetry_records BEGIN
            INSERT INTO mission_telemetry(record_id,uav_id,mission_id,linked_at_us)
            SELECT NEW.record_id,NEW.uav_id,m.mission_id,NEW.received_at_us
            FROM missions m WHERE m.uav_id=NEW.uav_id AND m.status='active'
              AND NEW.captured_at_us>=m.started_at_us AND NEW.received_at_us>=m.started_at_us
              AND NEW.captured_at_us<=NEW.received_at_us;
        END
    """)
