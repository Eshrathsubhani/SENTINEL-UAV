"""Internal GCS heartbeat-path observations inside caller-owned transactions."""

from time import time_ns


def utc_us():
    return time_ns() // 1000


def append_event(db, uav_id, now, event, reason, record_id=None):
    db.execute("INSERT INTO communication_events "
               "(uav_id,occurred_at_us,event,source,reason,record_id) VALUES (?, ?, ?, ?, ?, ?)",
               (uav_id, now, event, "gcs_accepted_heartbeat", reason, record_id))


def expire_heartbeats(db, now, uav_id=None):
    sql = "SELECT * FROM communication_state WHERE state='connected' AND ? >= last_received_at_us + timeout_us"
    parameters = [now]
    if uav_id is not None:
        sql += " AND uav_id=?"
        parameters.append(uav_id)
    for row in db.execute(sql, parameters).fetchall():
        db.execute("UPDATE communication_state SET state='lost' WHERE uav_id=?", (row["uav_id"],))
        append_event(db, row["uav_id"], now, "heartbeat_lost", "accepted_heartbeat_timeout")


def observe_heartbeat(db, uav, record, received_us, captured_us, timeout_us):
    # Only fresh advancing source observations may refresh the path status.
    # Accepted history remains available even if this status evidence is stale.
    if not 0 <= received_us - captured_us < timeout_us:
        return
    previous = db.execute("SELECT * FROM communication_state WHERE uav_id=?", (uav["uav_id"],)).fetchone()
    if previous and (captured_us <= previous["last_captured_at_us"]
                     or received_us < previous["last_received_at_us"]):
        return
    expire_heartbeats(db, received_us, uav["uav_id"])
    state = db.execute("SELECT state FROM communication_state WHERE uav_id=?", (uav["uav_id"],)).fetchone()
    event = "heartbeat_received" if state is None else "heartbeat_recovered" if state["state"] == "lost" else None
    if event:
        append_event(db, uav["uav_id"], received_us, event, "fresh_accepted_heartbeat", record["record_id"])
    db.execute("""
        INSERT INTO communication_state VALUES (?, 'connected', ?, ?, ?, ?, ?)
        ON CONFLICT(uav_id) DO UPDATE SET state='connected',
            last_captured_at_us=excluded.last_captured_at_us,
            last_received_at_us=excluded.last_received_at_us, timeout_us=excluded.timeout_us,
            signing_key_id=excluded.signing_key_id, certificate_identity=excluded.certificate_identity
    """, (uav["uav_id"], captured_us, received_us, timeout_us, uav["signing_key_id"],
          uav["certificate_identity"]))


def read_communication(db, uav_id, now, limit, before=None):
    expire_heartbeats(db, now, uav_id)
    row = db.execute("SELECT * FROM communication_state WHERE uav_id=?", (uav_id,)).fetchone()
    uav = db.execute("SELECT * FROM uavs WHERE uav_id=?", (uav_id,)).fetchone()
    state, reason = "unknown", "no_fresh_heartbeat_observed"
    age = None
    if row:
        age = (now - row["last_received_at_us"]) / 1000000
        if age < 0:
            reason = "clock_moved_backwards"
        elif row["signing_key_id"] != uav["signing_key_id"] or row["certificate_identity"] != uav["certificate_identity"]:
            reason = "registry_credentials_changed"
        else:
            state, reason = row["state"], "fresh_accepted_heartbeat" if row["state"] == "connected" else "accepted_heartbeat_timeout"
    sql = "SELECT * FROM communication_events WHERE uav_id=?"
    parameters = [uav_id]
    if before:
        sql += " AND (occurred_at_us,event_id) < (?,?)"
        parameters.extend(before)
    sql += " ORDER BY occurred_at_us DESC,event_id DESC LIMIT ?"
    parameters.append(limit + 1)
    events = db.execute(sql, parameters).fetchall()
    page = events[:limit]
    # Cursor is a timestamp + event ID. It is a position, not an authorization token.
    next_before = [page[-1]["occurred_at_us"], page[-1]["event_id"]] if len(events) > limit else None
    return {"state": state, "reason": reason, "source": "gcs_accepted_heartbeat",
            "last_heartbeat_received_at_us": row["last_received_at_us"] if row else None,
            "heartbeat_age_s": age, "timeout_s": row["timeout_us"] / 1000000 if row else None,
            "events": [dict(event) for event in page], "next_before": next_before}
