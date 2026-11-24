"""Internal history queries. Call only within an authorized service transaction."""

import base64
from datetime import datetime, timezone
import json

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_US = 253402300799999999


def timestamp_us(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ValueError("Timestamp must be an ISO 8601 string with timezone")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    try:
        delta = parsed.astimezone(timezone.utc) - EPOCH
    except OverflowError as error:
        raise ValueError("Timestamp is outside supported UTC range") from error
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def history_filter(start, end, limit, cursor):
    start, end = timestamp_us(start), timestamp_us(end)
    if not 0 <= start < end <= MAX_US:
        raise ValueError("History range must be after 1970 with start before end")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("Page size must be 1 to 1000")
    after = None
    if cursor is not None:
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 512:
            raise ValueError("Invalid history cursor")
        try:
            raw = base64.b64decode(cursor.encode("ascii"), altchars=b"-_", validate=True)
            after = json.loads(raw)
            if (type(after) is not list or len(after) != 2 or type(after[0]) is not int
                    or not start <= after[0] < end or not isinstance(after[1], str)
                    or not 1 <= len(after[1]) <= 128):
                raise ValueError("Invalid history cursor")
        except (ValueError, UnicodeError) as error:
            raise ValueError("Invalid history cursor") from error
    return start, end, limit, after


def insert_record(db, uav_id, record, received_at_us):
    """Return inserted/duplicate/conflict. Do not commit here."""
    payload = json.dumps(record, allow_nan=False, sort_keys=True, separators=(",", ":"))
    previous = db.execute("SELECT uav_id,payload_json FROM telemetry_records WHERE record_id=?",
                          (record["record_id"],)).fetchone()
    if previous:
        return "duplicate" if previous["uav_id"] == uav_id and previous["payload_json"] == payload else "conflict"
    db.execute("""
        INSERT INTO telemetry_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (record["record_id"], uav_id, timestamp_us(record["captured_at"]), received_at_us,
          record["message_type"], record["system_id"], record["component_id"],
          "authenticated_uav_gateway", "gateway_attested", payload))
    return "inserted"


def query_history(db, uav_id, filters, *, mission_id=None):
    start, end, limit, after = filters
    sql = "SELECT * FROM telemetry_records WHERE uav_id=? AND captured_at_us>=? AND captured_at_us<?"
    parameters = [uav_id, start, end]
    if mission_id is not None:
        sql += " AND EXISTS (SELECT 1 FROM mission_telemetry mt WHERE mt.record_id=telemetry_records.record_id AND mt.mission_id=?)"
        parameters.append(mission_id)
    if after:
        sql += " AND (captured_at_us,record_id) > (?,?)"
        parameters.extend(after)
    sql += " ORDER BY captured_at_us,record_id LIMIT ?"
    parameters.append(limit + 1)
    rows = db.execute(sql, parameters).fetchall()
    page = rows[:limit]
    cursor = None
    if len(rows) > limit:
        last = page[-1]
        cursor = base64.urlsafe_b64encode(json.dumps(
            [last["captured_at_us"], last["record_id"]], separators=(",", ":")
        ).encode()).decode("ascii")
    return {"telemetry": [
        {"record": json.loads(row["payload_json"]), "received_at_us": row["received_at_us"],
         "source": row["source"], "validation_status": row["validation_status"]}
        for row in page
    ], "next_cursor": cursor}
