import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(__file__).resolve().parent / "flights.db"
DEFAULT_EXPORT_DIR = ROOT_DIR / "Star Alliance Virtual Data - 2025-10-15-14-19-28"
METERS_TO_FEET = 3.280839895
MPS_TO_KNOTS = 1.94384449


def parse_args():
    parser = argparse.ArgumentParser(
        description="Import Star Alliance Virtual flight-report exports into the HeatTracker database."
    )
    parser.add_argument(
        "--export-dir",
        default=str(DEFAULT_EXPORT_DIR),
        help="Path to the Star Alliance export directory.",
    )
    parser.add_argument(
        "--vatsim-id",
        default=os.environ.get("IMPORT_VATSIM_ID", "").strip(),
        help="VATSIM CID to associate the imported flights with.",
    )
    parser.add_argument(
        "--sample-seconds",
        type=int,
        default=20,
        help="Minimum number of seconds between stored points from each flight report.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=0,
        help="Optional limit for the number of report files to import.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse everything and print what would be imported without writing to the database.",
    )
    return parser.parse_args()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_tables(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS imported_flight_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            report_id TEXT NOT NULL,
            vatsim_id TEXT NOT NULL,
            imported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(source, report_id, vatsim_id)
        )
        """
    )


def resolve_vatsim_id(conn, requested_vatsim_id: str) -> str:
    if requested_vatsim_id:
        return requested_vatsim_id

    rows = conn.execute(
        """
        SELECT DISTINCT vatsim_id
        FROM users
        WHERE vatsim_id IS NOT NULL AND TRIM(vatsim_id) != ''
        ORDER BY vatsim_id
        """
    ).fetchall()

    if len(rows) == 1:
        return str(rows[0]["vatsim_id"])

    if not rows:
        raise SystemExit(
            "No linked VATSIM CID was found in backend/flights.db. "
            "Run with --vatsim-id YOURCID."
        )

    raise SystemExit(
        "Multiple linked VATSIM CIDs were found in backend/flights.db. "
        "Run with --vatsim-id YOURCID."
    )


def load_submitted_flights(export_dir: Path):
    submitted_path = export_dir / "submitted_flights.json"
    if not submitted_path.exists():
        return {}

    with submitted_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    metadata_by_id = {}
    for item in payload:
        report_id = str(item.get("id") or "").strip()
        if report_id:
            metadata_by_id[report_id] = item
    return metadata_by_id


def parse_iso8601(value: str):
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def to_sqlite_timestamp(dt: datetime | None):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def coerce_float(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def extract_position(payload: dict):
    if payload.get("latitude") is not None and payload.get("longitude") is not None:
        return coerce_float(payload.get("latitude")), coerce_float(payload.get("longitude"))

    position = payload.get("position") or {}
    return coerce_float(position.get("latitude")), coerce_float(position.get("longitude"))


def extract_recorded_time(payload: dict):
    for key in ("realTime", "correctedTime", "systemTime"):
        value = payload.get(key)
        if value:
            parsed = parse_iso8601(str(value))
            if parsed is not None:
                return parsed
    return None


def extract_altitude_feet(payload: dict):
    if payload.get("altitude") is not None:
        return int(float(payload.get("altitude")))

    altitude_meters = coerce_float(payload.get("altitudeMeters"))
    if altitude_meters is None:
        return 0
    return int(round(altitude_meters * METERS_TO_FEET))


def extract_groundspeed_knots(payload: dict):
    if payload.get("groundSpeed") is not None:
        return int(float(payload.get("groundSpeed")))

    groundspeed_mps = coerce_float(payload.get("groundSpeedMetersPerSecond"))
    if groundspeed_mps is None:
        return 0
    return int(round(groundspeed_mps * MPS_TO_KNOTS))


def build_callsign(metadata: dict, report_id: str) -> str:
    airline = str(metadata.get("airlineIcao") or "").strip()
    flight_number = str(metadata.get("flightNumber") or "").strip()
    if airline and flight_number:
        return f"{airline}{flight_number}"
    if airline:
        return airline
    return report_id[:8].upper()


def build_aircraft(metadata: dict) -> str:
    return (
        str(metadata.get("aircraftTypeICAO") or "").strip()
        or str(metadata.get("aircraftModelName") or "").strip()
        or str((metadata.get("flight") or {}).get("aircraftType") or "").strip()
    )


def is_already_imported(conn, vatsim_id: str, report_id: str) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM imported_flight_reports
        WHERE source = 'star-alliance-export'
          AND report_id = ?
          AND vatsim_id = ?
        """,
        (report_id, vatsim_id),
    ).fetchone()
    return row is not None


def insert_flight(conn, vatsim_id: str, report_id: str, metadata: dict, started_at: str, ended_at: str):
    callsign = build_callsign(metadata, report_id)
    dep = str(metadata.get("departureIcao") or "").strip()
    arr = str(metadata.get("arrivalIcao") or "").strip()
    aircraft = build_aircraft(metadata)

    cursor = conn.execute(
        """
        INSERT INTO flights (vatsim_id, callsign, dep, arr, aircraft, started_at, ended_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (vatsim_id, callsign, dep, arr, aircraft, started_at, ended_at),
    )
    return cursor.lastrowid, callsign


def insert_points(conn, vatsim_id: str, callsign: str, sampled_points):
    conn.executemany(
        """
        INSERT INTO flight_points (vatsim_id, callsign, lat, lng, altitude, groundspeed, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                vatsim_id,
                callsign,
                point["lat"],
                point["lng"],
                point["altitude"],
                point["groundspeed"],
                point["recorded_at"],
            )
            for point in sampled_points
        ],
    )


def mark_imported(conn, vatsim_id: str, report_id: str):
    conn.execute(
        """
        INSERT INTO imported_flight_reports (source, report_id, vatsim_id)
        VALUES ('star-alliance-export', ?, ?)
        """,
        (report_id, vatsim_id),
    )


def sample_report_points(report_path: Path, sample_seconds: int):
    sampled_points = []
    started_at = None
    ended_at = None
    last_kept_time = None

    with report_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            lat, lng = extract_position(payload)
            recorded_dt = extract_recorded_time(payload)
            if lat is None or lng is None or recorded_dt is None:
                continue

            if started_at is None:
                started_at = recorded_dt
            ended_at = recorded_dt

            if last_kept_time is not None:
                delta_seconds = (recorded_dt - last_kept_time).total_seconds()
                if delta_seconds < sample_seconds:
                    continue

            sampled_points.append(
                {
                    "lat": float(lat),
                    "lng": float(lng),
                    "altitude": extract_altitude_feet(payload),
                    "groundspeed": extract_groundspeed_knots(payload),
                    "recorded_at": to_sqlite_timestamp(recorded_dt),
                }
            )
            last_kept_time = recorded_dt

    return sampled_points, to_sqlite_timestamp(started_at), to_sqlite_timestamp(ended_at)


def main():
    args = parse_args()
    export_dir = Path(args.export_dir).resolve()
    reports_dir = export_dir / "flight-reports"
    if not reports_dir.exists():
        raise SystemExit(f"flight-reports directory not found: {reports_dir}")

    with get_db() as conn:
        ensure_tables(conn)
        vatsim_id = resolve_vatsim_id(conn, args.vatsim_id)
        metadata_by_id = load_submitted_flights(export_dir)
        report_paths = sorted(reports_dir.glob("*.json"))
        if args.max_files > 0:
            report_paths = report_paths[:args.max_files]

        imported_files = 0
        skipped_files = 0
        imported_points = 0

        for report_path in report_paths:
            report_id = report_path.stem
            if is_already_imported(conn, vatsim_id, report_id):
                skipped_files += 1
                continue

            sampled_points, started_at, ended_at = sample_report_points(report_path, args.sample_seconds)
            if not sampled_points or not started_at or not ended_at:
                skipped_files += 1
                continue

            metadata = metadata_by_id.get(report_id, {})
            callsign = build_callsign(metadata, report_id)

            if args.dry_run:
                imported_files += 1
                imported_points += len(sampled_points)
                print(
                    f"[dry-run] {report_id} -> {callsign} "
                    f"{metadata.get('departureIcao', '???')}->{metadata.get('arrivalIcao', '???')} "
                    f"points={len(sampled_points)}"
                )
                continue

            insert_flight(conn, vatsim_id, report_id, metadata, started_at, ended_at)
            insert_points(conn, vatsim_id, callsign, sampled_points)
            mark_imported(conn, vatsim_id, report_id)
            imported_files += 1
            imported_points += len(sampled_points)

        if args.dry_run:
            conn.rollback()
        else:
            conn.commit()

    print(
        f"Processed {len(report_paths)} reports for VATSIM CID {vatsim_id}. "
        f"Imported {imported_files} reports / {imported_points} points. "
        f"Skipped {skipped_files} reports."
    )


if __name__ == "__main__":
    main()
