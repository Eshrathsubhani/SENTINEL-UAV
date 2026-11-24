"""Frozen schema-8 centralized security/audit projection."""

COLUMNS = "producer,producer_event_id,occurred_at_us,category,event,severity,outcome,actor_id,uav_id,target_id,details_json"


def install_schema(connection):
    connection.execute("""
        CREATE TABLE security_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            producer TEXT NOT NULL,
            producer_event_id TEXT NOT NULL,
            occurred_at_us INTEGER NOT NULL,
            ingested_at_us INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)*1000000),
            category TEXT NOT NULL CHECK(category IN
                ('authentication','authorization','identity','administration','communication',
                 'mavlink_signing','replay','freshness','tls','credential','storage','mission','incident')),
            event TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
            outcome TEXT NOT NULL CHECK(outcome IN ('info','success','failure','allow','deny')),
            actor_id TEXT,
            uav_id TEXT REFERENCES uavs(uav_id),
            target_id TEXT,
            details_json TEXT NOT NULL CHECK(json_valid(details_json)),
            UNIQUE(producer,producer_event_id))
    """)
    for label, columns in (
        ("time", "occurred_at_us,event_id"),
        ("category", "category,occurred_at_us,event_id"),
        ("actor", "actor_id,occurred_at_us,event_id"),
        ("uav", "uav_id,occurred_at_us,event_id"),
    ):
        connection.execute(
            f"CREATE INDEX security_events_{label} ON security_events({columns})"
        )

    projections = (
        (
            "identity_events",
            """
            'identity_events',CAST(event_id AS TEXT),
            CAST(strftime('%s',occurred_at) AS INTEGER)*1000000,
            CASE WHEN event IN ('login_succeeded','login_failed','logout') THEN 'authentication'
                 WHEN event='administrative_action_failed' THEN 'administration' ELSE 'identity' END,
            event,CASE WHEN event LIKE '%failed' THEN 'medium' ELSE 'info' END,
            CASE WHEN event LIKE '%failed' THEN 'failure' ELSE 'success' END,
            actor_id,(SELECT uav_id FROM uavs WHERE uav_id=target_id),target_id,
            json_object('reason',reason)
        """,
        ),
        (
            "authorization_events",
            """
            'authorization_events',CAST(event_id AS TEXT),
            CAST(strftime('%s',occurred_at) AS INTEGER)*1000000,'authorization',action,
            CASE WHEN decision='deny' THEN 'medium' ELSE 'info' END,decision,
            actor_id,(SELECT uav_id FROM uavs WHERE uav_id=target_id),target_id,
            json_object('reason',reason)
        """,
        ),
        (
            "communication_events",
            """
            'communication_events',CAST(event_id AS TEXT),occurred_at_us,'communication',event,
            CASE WHEN event='heartbeat_lost' THEN 'medium' ELSE 'info' END,'info',
            NULL,uav_id,uav_id,json_object('reason',reason)
        """,
        ),
    )
    # Identical projections backfill each legacy row once, then run atomically
    # with future source inserts. No untrusted identifier is interpolated.
    for table, expression in projections:
        connection.execute(
            f"INSERT INTO security_events ({COLUMNS}) SELECT {expression} FROM {table}"
        )
        # A one-row subquery gives source-column names the same binding as backfill.
        connection.execute(f"""
            CREATE TRIGGER security_project_{table} AFTER INSERT ON {table} BEGIN
                INSERT INTO security_events ({COLUMNS})
                SELECT {expression} FROM {table} WHERE event_id=NEW.event_id;
            END
        """)

    command_values = """
        'command_requests',request_id || ':snapshot',created_at_epoch*1000000,
        'administration','command.' || status,
        CASE WHEN status IN ('failed','denied') THEN 'medium' ELSE 'info' END,
        CASE WHEN status='sent' THEN 'success' WHEN status='failed' THEN 'failure'
             WHEN status='denied' THEN 'deny' ELSE 'info' END,
        (SELECT user_id FROM sessions WHERE token_hash=command_requests.token_hash),
        uav_id,request_id,json_object('reason',reason)
    """
    connection.execute(
        f"INSERT INTO security_events ({COLUMNS}) SELECT {command_values} FROM command_requests"
    )
    connection.execute(f"""
        CREATE TRIGGER security_project_command_insert AFTER INSERT ON command_requests BEGIN
            INSERT INTO security_events ({COLUMNS}) SELECT {command_values}
            FROM command_requests WHERE request_id=NEW.request_id;
        END
    """)
    connection.execute(f"""
        CREATE TRIGGER security_project_command_update AFTER UPDATE OF status,reason ON command_requests
        WHEN NEW.status<>OLD.status OR NEW.reason<>OLD.reason BEGIN
            INSERT INTO security_events ({COLUMNS}) VALUES (
                'command_requests',NEW.request_id || ':change:' || lower(hex(randomblob(16))),
                CAST(strftime('%s','now') AS INTEGER)*1000000,'administration','command.' || NEW.status,
                CASE WHEN NEW.status IN ('failed','denied') THEN 'medium' ELSE 'info' END,
                CASE WHEN NEW.status='sent' THEN 'success' WHEN NEW.status='failed' THEN 'failure'
                     WHEN NEW.status='denied' THEN 'deny' ELSE 'info' END,
                (SELECT user_id FROM sessions WHERE token_hash=NEW.token_hash),
                NEW.uav_id,NEW.request_id,json_object('reason',NEW.reason));
        END
    """)
    for operation, event in (
        ("INSERT", "policy.created"),
        ("UPDATE", "policy.updated"),
    ):
        connection.execute(f"""
            CREATE TRIGGER security_project_policy_{operation.lower()} AFTER {operation} ON policies BEGIN
                INSERT INTO security_events ({COLUMNS}) VALUES (
                    'policies',NEW.name || ':' || lower(hex(randomblob(16))),
                    CAST(strftime('%s','now') AS INTEGER)*1000000,'administration','{event}',
                    'info','success',NULL,NULL,NEW.name,json_object('version',NEW.version));
            END
        """)
