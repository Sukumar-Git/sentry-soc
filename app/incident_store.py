import json
import sqlite3
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "sentry_incidents.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def create_fingerprint(incident):
    """Create a stable identity for the same incident occurrence."""
    timeline = sorted(incident.get("timeline", []))
    first_seen = timeline[0] if timeline else ""

    identity = [
        incident.get("type", "unknown"),
        incident.get("source_ip") or "",
        incident.get("username") or "",
        first_seen,
    ]

    return json.dumps(identity, separators=(",", ":"))


def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                incident_type TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (
                        status IN ('open', 'investigating', 'resolved')
                    ),
                analyst_notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                fingerprint TEXT,
                related_events INTEGER NOT NULL DEFAULT 0,
                timeline_json TEXT NOT NULL DEFAULT '[]',
                evidence_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )

        # Migrate databases created by the earlier version.
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(incidents)"
            ).fetchall()
        }

        migrations = {
            "fingerprint": "ALTER TABLE incidents ADD COLUMN fingerprint TEXT",
            "related_events": (
                "ALTER TABLE incidents ADD COLUMN related_events "
                "INTEGER NOT NULL DEFAULT 0"
            ),
            "timeline_json": (
                "ALTER TABLE incidents ADD COLUMN timeline_json "
                "TEXT NOT NULL DEFAULT '[]'"
            ),
            "evidence_json": (
                "ALTER TABLE incidents ADD COLUMN evidence_json "
                "TEXT NOT NULL DEFAULT '{}'"
            ),
        }

        for column, statement in migrations.items():
            if column not in columns:
                connection.execute(statement)


def sync_incidents(incidents):
    """
    Save new incidents and update existing detections.

    Existing incident IDs, statuses, analyst notes, and creation times
    are preserved. Incidents absent from the latest scan are not deleted.
    """
    initialize_database()

    with get_connection() as connection:
        for incident in incidents:
            fingerprint = create_fingerprint(incident)

            existing = connection.execute(
                """
                SELECT incident_id
                FROM incidents
                WHERE fingerprint = ?
                LIMIT 1
                """,
                (fingerprint,),
            ).fetchone()

            # Migrate a matching record from the previous database schema.
            if existing is None:
                existing = connection.execute(
                    """
                    SELECT incident_id
                    FROM incidents
                    WHERE fingerprint IS NULL
                      AND incident_type = ?
                      AND COALESCE(source_ip, '') = ?
                      AND COALESCE(username, '') = ?
                    ORDER BY created_at ASC
                    LIMIT 1
                    """,
                    (
                        incident.get("type", "unknown"),
                        incident.get("source_ip") or "",
                        incident.get("username") or "",
                    ),
                ).fetchone()

            if existing:
                incident_id = existing["incident_id"]

                connection.execute(
                    """
                    UPDATE incidents
                    SET incident_type = ?,
                        source_ip = ?,
                        username = ?,
                        risk_score = ?,
                        risk_level = ?,
                        fingerprint = ?,
                        related_events = ?,
                        timeline_json = ?,
                        evidence_json = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE incident_id = ?
                    """,
                    (
                        incident.get("type", "unknown"),
                        incident.get("source_ip"),
                        incident.get("username"),
                        incident["risk_score"],
                        incident["risk_level"],
                        fingerprint,
                        incident.get("related_events", 0),
                        json.dumps(incident.get("timeline", [])),
                        json.dumps(incident.get("evidence", {})),
                        incident_id,
                    ),
                )

            else:
                incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

                connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_id,
                        incident_type,
                        source_ip,
                        username,
                        risk_score,
                        risk_level,
                        fingerprint,
                        related_events,
                        timeline_json,
                        evidence_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        incident.get("type", "unknown"),
                        incident.get("source_ip"),
                        incident.get("username"),
                        incident["risk_score"],
                        incident["risk_level"],
                        fingerprint,
                        incident.get("related_events", 0),
                        json.dumps(incident.get("timeline", [])),
                        json.dumps(incident.get("evidence", {})),
                    ),
                )

            # Keep the dashboard's incident references consistent with SQLite.
            incident["incident_id"] = incident_id

    # Return every stored incident, including historical incidents.
    return get_all_incidents()


def get_all_incidents():
    initialize_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY created_at DESC, incident_id DESC
            """
        ).fetchall()

    incidents = []

    for row in rows:
        incident = dict(row)

        incident["timeline"] = json.loads(
            incident.pop("timeline_json", "[]")
        )
        incident["evidence"] = json.loads(
            incident.pop("evidence_json", "{}")
        )

        incidents.append(incident)

    return incidents


def update_incident_status(incident_id, status):
    allowed_statuses = {"open", "investigating", "resolved"}

    if status not in allowed_statuses:
        raise ValueError(
            f"Invalid status: {status}. "
            f"Allowed statuses: {sorted(allowed_statuses)}"
        )

    initialize_database()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE incidents
            SET status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
            """,
            (status, incident_id),
        )

        return cursor.rowcount == 1


def update_analyst_notes(incident_id, notes):
    initialize_database()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE incidents
            SET analyst_notes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
            """,
            (notes, incident_id),
        )

        return cursor.rowcount == 1
