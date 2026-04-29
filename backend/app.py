# Copyright (c) 2026 Alex Nord.
# Licensed under the PolyForm Noncommercial License 1.0.0.
# Commercial use is prohibited without written permission.
#
# This project is source-available for noncommercial use only.
import base64
import hashlib
import importlib
import json
import math
import os
import secrets
import sqlite3
import threading
import time
from functools import wraps
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request, send_from_directory, session
from flask_cors import CORS

SimConnect = None
AircraftRequests = None

base64url_to_bytes: Any = None
generate_authentication_options: Any = None
generate_registration_options: Any = None
options_to_json: Any = None
verify_authentication_response: Any = None
verify_registration_response: Any = None
AuthenticatorSelectionCriteria: Any = None
PublicKeyCredentialDescriptor: Any = None
ResidentKeyRequirement: Any = None
UserVerificationRequirement: Any = None

try:
    webauthn_module = importlib.import_module("webauthn")
    webauthn_structs = importlib.import_module("webauthn.helpers.structs")

    base64url_to_bytes = webauthn_module.base64url_to_bytes
    generate_authentication_options = webauthn_module.generate_authentication_options
    generate_registration_options = webauthn_module.generate_registration_options
    options_to_json = webauthn_module.options_to_json
    verify_authentication_response = webauthn_module.verify_authentication_response
    verify_registration_response = webauthn_module.verify_registration_response
    AuthenticatorSelectionCriteria = webauthn_structs.AuthenticatorSelectionCriteria
    PublicKeyCredentialDescriptor = webauthn_structs.PublicKeyCredentialDescriptor
    ResidentKeyRequirement = webauthn_structs.ResidentKeyRequirement
    UserVerificationRequirement = webauthn_structs.UserVerificationRequirement
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False

try:
    simconnect_module = importlib.import_module("SimConnect")
    SimConnect = simconnect_module.SimConnect
    AircraftRequests = simconnect_module.AircraftRequests
    SIMCONNECT_AVAILABLE = True
except ImportError:
    SIMCONNECT_AVAILABLE = False

load_dotenv()

app = Flask(__name__, static_folder="../frontend/static", template_folder="../frontend/templates")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
CORS(app, supports_credentials=True)


@app.after_request
def apply_security_headers(response):
    path = request.path or ""
    if (
        path == "/mcp"
        or path.startswith("/.well-known/oauth-")
        or path in {"/oauth/register", "/oauth/token"}
    ):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
    return response

# Discord OAuth config
DISCORD_AUTH_URL = "https://discord.com/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_USER_URL = "https://discord.com/api/users/@me"
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI")

# Allowlist: only these Discord user IDs may log in
ALLOWED_DISCORD_IDS = {
    discord_id.strip()
    for discord_id in (os.environ.get("ALLOWED_DISCORD_IDS") or "").split(",")
    if discord_id.strip()
}

# Tracker config
TRACKER_POLL_SECONDS = max(10, int(os.environ.get("TRACKER_POLL_SECONDS", "20")))
TRACKER_MIN_INSERT_SECONDS = max(5, int(os.environ.get("TRACKER_MIN_INSERT_SECONDS", "10")))

SIMCONNECT_CALLSIGN = (os.environ.get("SIMCONNECT_CALLSIGN") or "SIMCONNECT").strip() or "SIMCONNECT"
SIMCONNECT_DEP = (os.environ.get("SIMCONNECT_DEP") or "").strip().upper()
SIMCONNECT_ARR = (os.environ.get("SIMCONNECT_ARR") or "").strip().upper()
SIMCONNECT_AIRCRAFT = (os.environ.get("SIMCONNECT_AIRCRAFT") or "").strip()

SIMCONNECT_STATE_PATH = os.environ.get(
    "SIMCONNECT_STATE_PATH",
    os.path.join(os.path.dirname(__file__), "simconnect-state.json"),
)

SIMCONNECT_STALE_SECONDS = max(5, int(os.environ.get("SIMCONNECT_STALE_SECONDS", "30")))
SIMCONNECT_TELEMETRY_TOKEN = (os.environ.get("SIMCONNECT_TELEMETRY_TOKEN") or "").strip()

LOCAL_TRACKER_PREFIX = "LOCAL-"

SIMBRIEF_API_URL = "https://www.simbrief.com/api/xml.fetcher.php"
SIMBRIEF_USERID = (os.environ.get("SIMBRIEF_USERID") or "").strip()
SIMBRIEF_USERNAME = (os.environ.get("SIMBRIEF_USERNAME") or "").strip()
SIMBRIEF_CACHE_TTL_SECONDS = max(30, int(os.environ.get("SIMBRIEF_CACHE_TTL_SECONDS", "300")))
_simbrief_cache: dict[str, Any] = {"data": None, "fetched_at": 0, "identity": None}

MAX_SEGMENT_GAP_SECONDS = 60 * 60 * 4
MAX_SEGMENT_DISTANCE_KM = 900

PASSKEY_RP_NAME = os.environ.get("PASSKEY_RP_NAME", "VATSIM HeatTracker")
MCP_SERVER_NAME = os.environ.get("MCP_SERVER_NAME", "SimpleSim MCP")
MCP_SERVER_VERSION = os.environ.get("MCP_SERVER_VERSION", "1.0.0")
MCP_PROTOCOL_VERSION = os.environ.get("MCP_PROTOCOL_VERSION", "2025-03-26")
MCP_READ_SCOPE = os.environ.get("MCP_READ_SCOPE", "mcp:read")

_tracker_thread = None
_tracker_lock = threading.Lock()


def utc_now_iso8601() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, (int, float)):
        return bool(value)

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "online", "connected"}:
            return True
        if normalized in {"0", "false", "no", "n", "offline", "disconnected"}:
            return False

    return default


def parse_finite_float(value: Any, field_name: str) -> float:
    if value is None or value == "":
        raise ValueError(f"missing_{field_name}")

    if isinstance(value, bool):
        raise ValueError(f"invalid_{field_name}")

    if not isinstance(value, (int, float, str)):
        raise ValueError(f"invalid_{field_name}")

    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid_{field_name}")

    if not math.isfinite(number):
        raise ValueError(f"invalid_{field_name}")

    return number


def safe_float(
    payload: dict[str, Any],
    key: str,
    *,
    required: bool = False,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float | None:
    value: Any = payload.get(key)

    if value is None or value == "":
        if required:
            raise ValueError(f"missing_{key}")
        return None

    number = parse_finite_float(value, key)

    if minimum is not None and number < minimum:
        raise ValueError(f"{key}_below_minimum")

    if maximum is not None and number > maximum:
        raise ValueError(f"{key}_above_maximum")

    return number


def safe_text(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback

    text = str(value).strip()
    return text if text else fallback


def nested_get(payload: dict[str, Any], *path: str) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def first_present(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def now_unix() -> int:
    return int(time.time())


def normalize_origin_url(value: str) -> str:
    parsed = urlparse(value)
    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    return urlunparse((scheme, netloc, path, "", "", ""))


def get_public_base_url() -> str:
    configured = (os.environ.get("PUBLIC_BASE_URL") or "").strip()
    if configured:
        return normalize_origin_url(configured)

    redirect_uri = (DISCORD_REDIRECT_URI or "").strip()
    if redirect_uri:
        parsed = urlparse(redirect_uri)
        if parsed.scheme and parsed.netloc:
            return normalize_origin_url(f"{parsed.scheme}://{parsed.netloc}")

    return normalize_origin_url(request.url_root)


def get_mcp_server_url() -> str:
    return f"{get_public_base_url()}/mcp"


def get_oauth_issuer() -> str:
    configured = (os.environ.get("MCP_OAUTH_ISSUER") or "").strip()
    if configured:
        return normalize_origin_url(configured)
    return get_public_base_url()


def build_mcp_resource_metadata_url() -> str:
    return f"{get_public_base_url()}/.well-known/oauth-protected-resource"


def build_oauth_metadata_url() -> str:
    return f"{get_public_base_url()}/.well-known/oauth-authorization-server"


def normalize_resource_uri(resource: str | None) -> str:
    if resource:
        return normalize_origin_url(resource)
    return get_mcp_server_url()


def encode_json_text_content(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, separators=(",", ":"), ensure_ascii=True),
            }
        ]
    }


def sha256_base64url(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def is_valid_redirect_uri(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme == "https":
        return bool(parsed.netloc)
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        return True
    return False


def parse_json_field(value: Any, default: Any):
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return default
        return decoded
    return value if value is not None else default


def clean_scope(value: Any) -> str:
    scopes = sorted({scope for scope in safe_text(value).split(" ") if scope})
    if MCP_READ_SCOPE not in scopes:
        scopes.append(MCP_READ_SCOPE)
    return " ".join(scopes)


def normalize_telemetry_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("invalid_json_body")

    online = safe_bool(first_present(
        payload.get("online"),
        payload.get("Connected to Simulator"),
    ), default=True)
    connected = safe_bool(first_present(
        payload.get("connected"),
        payload.get("Connected to Backend"),
    ), default=online)

    latitude_source = first_present(payload.get("latitude"), nested_get(payload, "position", "latitude"))
    longitude_source = first_present(payload.get("longitude"), nested_get(payload, "position", "longitude"))
    altitude_source = first_present(payload.get("altitude"), payload.get("altitudeMeters"))
    groundspeed_source = first_present(payload.get("groundspeed"), payload.get("groundSpeedMetersPerSecond"))
    heading_source = first_present(payload.get("heading"), payload.get("headingTrueDegrees"))

    latitude = None
    longitude = None
    altitude = None
    groundspeed = None
    heading = None

    if latitude_source is not None or online:
        latitude = parse_finite_float(latitude_source, "latitude")
        if latitude < -90.0 or latitude > 90.0:
            raise ValueError("latitude_out_of_range")

    if longitude_source is not None or online:
        longitude = parse_finite_float(longitude_source, "longitude")
        if longitude < -180.0 or longitude > 180.0:
            raise ValueError("longitude_out_of_range")

    if altitude_source not in (None, ""):
        altitude = parse_finite_float(altitude_source, "altitude")

    if groundspeed_source not in (None, ""):
        groundspeed = parse_finite_float(groundspeed_source, "groundspeed")

    if heading_source not in (None, ""):
        heading = parse_finite_float(heading_source, "heading")

    if heading is not None:
        heading = heading % 360.0

    flight_plan_raw: Any = payload.get("flight_plan")
    flight_plan: dict[str, Any] = flight_plan_raw if isinstance(flight_plan_raw, dict) else {}

    departure = safe_text(flight_plan.get("departure"), SIMCONNECT_DEP).upper()
    arrival = safe_text(flight_plan.get("arrival"), SIMCONNECT_ARR).upper()
    aircraft_short = safe_text(
        flight_plan.get("aircraft_short") or flight_plan.get("aircraft"),
        SIMCONNECT_AIRCRAFT,
    ).upper()

    callsign = safe_text(payload.get("callsign"), SIMCONNECT_CALLSIGN)
    source = safe_text(payload.get("source"), "simconnect-bridge")
    last_error = payload.get("last_error")
    current_unix = now_unix()

    return {
        "online": online,
        "connected": connected,
        "latitude": latitude,
        "longitude": longitude,
        "altitude": int(round(altitude)) if altitude is not None else None,
        "groundspeed": int(round(groundspeed)) if groundspeed is not None else None,
        "heading": heading,
        "callsign": callsign,
        "flight_plan": {
            "departure": departure,
            "arrival": arrival,
            "aircraft_short": aircraft_short,
        },
        "source": source,
        "last_error": last_error,
        "raw": payload,
        "received_at": utc_now_iso8601(),
        "received_at_unix": current_unix,
        "updated_at": current_unix,
    }


def is_telemetry_request_authorized() -> bool:
    if SIMCONNECT_TELEMETRY_TOKEN:
        auth_header = request.headers.get("Authorization", "")
        bearer_token = ""

        if auth_header.lower().startswith("bearer "):
            bearer_token = auth_header.split(" ", 1)[1].strip()

        provided_token = (
            request.headers.get("X-Telemetry-Token")
            or bearer_token
            or ""
        ).strip()

        return secrets.compare_digest(provided_token, SIMCONNECT_TELEMETRY_TOKEN)

    remote_addr = request.remote_addr or ""

    return (
        remote_addr == "127.0.0.1"
        or remote_addr == "::1"
        or remote_addr.startswith("127.")
    )


class SimConnectTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def _read_state_locked(self) -> dict[str, Any] | None:
        if not os.path.exists(SIMCONNECT_STATE_PATH):
            return None

        try:
            with open(SIMCONNECT_STATE_PATH, "r", encoding="utf-8") as handle:
                state: Any = json.load(handle)

            if not isinstance(state, dict):
                return {
                    "online": False,
                    "connected": False,
                    "status": "state_invalid",
                    "last_error": "State file does not contain a JSON object.",
                }

            return state

        except Exception as exc:
            return {
                "online": False,
                "connected": False,
                "status": "state_read_failed",
                "last_error": str(exc),
            }

    def _write_state_locked(self, state: dict[str, Any]) -> None:
        state_dir = os.path.dirname(SIMCONNECT_STATE_PATH)

        if state_dir:
            os.makedirs(state_dir, exist_ok=True)

        temp_path = f"{SIMCONNECT_STATE_PATH}.tmp"

        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")

        os.replace(temp_path, SIMCONNECT_STATE_PATH)

    def update_from_telemetry(self, payload: dict[str, Any]) -> dict[str, Any]:
        state = normalize_telemetry_payload(payload)

        with self._lock:
            self._write_state_locked(state)

        return state

    def _state_age_seconds(self, state: dict[str, Any]) -> float | None:
        updated_at_raw: Any = state.get("updated_at")

        if updated_at_raw is None:
            updated_at_raw = state.get("received_at_unix")

        if updated_at_raw is None or updated_at_raw == "":
            return None

        try:
            updated_at = parse_finite_float(updated_at_raw, "updated_at")
        except ValueError:
            return None

        return max(0.0, time.time() - updated_at)

    def _is_stale(self, state: dict[str, Any]) -> bool:
        age = self._state_age_seconds(state)

        if age is None:
            return False

        return age > SIMCONNECT_STALE_SECONDS

    def snapshot(self) -> dict[str, Any] | None:
        with self._lock:
            state = self._read_state_locked()

            if not state or not state.get("online"):
                return None

            if self._is_stale(state):
                return None

            return {
                "latitude": state.get("latitude"),
                "longitude": state.get("longitude"),
                "altitude": state.get("altitude"),
                "groundspeed": state.get("groundspeed"),
                "heading": state.get("heading"),
                "callsign": state.get("callsign") or SIMCONNECT_CALLSIGN,
                "flight_plan": state.get("flight_plan") or {
                    "departure": SIMCONNECT_DEP,
                    "arrival": SIMCONNECT_ARR,
                    "aircraft_short": SIMCONNECT_AIRCRAFT,
                },
                "source": state.get("source") or "simconnect-bridge",
                "raw": state.get("raw") if isinstance(state.get("raw"), dict) else None,
            }

    def status(self) -> dict[str, Any]:
        with self._lock:
            state = self._read_state_locked()

            if not state:
                return {
                    "available": True,
                    "simconnect_python_package_available": SIMCONNECT_AVAILABLE,
                    "connected": False,
                    "online": False,
                    "stale": False,
                    "state_path": SIMCONNECT_STATE_PATH,
                    "last_error": f"State file not found at {SIMCONNECT_STATE_PATH}",
                }

            age_seconds = self._state_age_seconds(state)
            stale = self._is_stale(state)

            return {
                "available": True,
                "simconnect_python_package_available": SIMCONNECT_AVAILABLE,
                "connected": bool(state.get("connected", state.get("online"))) and not stale,
                "online": bool(state.get("online")) and not stale,
                "stale": stale,
                "age_seconds": round(age_seconds, 1) if age_seconds is not None else None,
                "stale_after_seconds": SIMCONNECT_STALE_SECONDS,
                "state_path": SIMCONNECT_STATE_PATH,
                "last_error": state.get("last_error"),
                "received_at": state.get("received_at"),
                "source": state.get("source"),
                "callsign": state.get("callsign"),
            }


simconnect_tracker = SimConnectTracker()


def bytes_to_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def parse_json_options(options: Any) -> dict[str, Any]:
    return json.loads(options_to_json(options))


def json_error(message: str, status_code: int = 400):
    return jsonify({"error": message}), status_code


def get_passkey_rp_id() -> str:
    configured = os.environ.get("PASSKEY_RP_ID")
    if configured:
        return configured

    redirect_uri = os.environ.get("DISCORD_REDIRECT_URI")
    if redirect_uri:
        parsed = urlparse(redirect_uri)
        if parsed.hostname:
            return parsed.hostname

    return request.host.split(":", 1)[0]


def get_passkey_origin() -> str:
    configured = os.environ.get("PASSKEY_ORIGIN")
    if configured:
        return configured

    redirect_uri = os.environ.get("DISCORD_REDIRECT_URI")
    if redirect_uri:
        parsed = urlparse(redirect_uri)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"

    return f"{request.scheme}://{request.host}"


def ensure_webauthn():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({
            "error": "Passkeys are not available until the `webauthn` package is installed."
        }), 503
    return None


def is_discord_configured() -> bool:
    return bool(DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET and DISCORD_REDIRECT_URI)


def build_local_tracker_id(user_id: int) -> str:
    return f"{LOCAL_TRACKER_PREFIX}{user_id}"


def ensure_tracking_profile(user_id: int) -> str:
    with get_db() as conn:
        row = conn.execute(
            "SELECT vatsim_id FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        tracker_id = str((row["vatsim_id"] if row else "") or "").strip()
        if tracker_id:
            return tracker_id

        tracker_id = build_local_tracker_id(user_id)
        conn.execute(
            "UPDATE users SET vatsim_id = ? WHERE id = ?",
            (tracker_id, user_id),
        )
        return tracker_id


def ensure_session_tracking_profile() -> str | None:
    user_id = session.get("user_id")
    if not user_id:
        return None

    tracker_id = ensure_tracking_profile(int(user_id))
    session["vatsim_id"] = tracker_id
    return tracker_id


def coerce_text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, dict):
        for key in ("#text", "text", "value"):
            nested = value.get(key)
            if nested not in (None, ""):
                return str(nested).strip()
        return ""

    return str(value).strip()


def coerce_float(value: Any) -> float | None:
    text = coerce_text(value)
    if not text:
        return None

    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def coerce_int(value: Any) -> int | None:
    text = coerce_text(value)
    if not text:
        return None

    try:
        return int(float(text))
    except (TypeError, ValueError):
        return None


def unix_to_iso8601(value: Any) -> str | None:
    unix_value = coerce_int(value)
    if unix_value is None:
        return None

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(unix_value))


def get_simbrief_identity() -> tuple[str, str] | None:
    if SIMBRIEF_USERID:
        return ("userid", SIMBRIEF_USERID)

    if SIMBRIEF_USERNAME:
        return ("username", SIMBRIEF_USERNAME)

    return None


def extract_simbrief_route_points(payload: dict[str, Any]) -> list[dict[str, Any]]:
    origin = payload.get("origin") or {}
    destination = payload.get("destination") or {}
    navlog = payload.get("navlog") or {}

    fixes: Any = navlog.get("fix") if isinstance(navlog, dict) else []
    if isinstance(fixes, dict):
        fixes = [fixes]

    route_points: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None

    def append_point(point: dict[str, Any]) -> None:
        nonlocal previous

        if point["lat"] is None or point["lng"] is None:
            return

        if (
            previous
            and abs(previous["lat"] - point["lat"]) < 1e-6
            and abs(previous["lng"] - point["lng"]) < 1e-6
        ):
            return

        route_points.append(point)
        previous = point

    append_point({
        "ident": coerce_text(origin.get("icao_code")) or coerce_text(origin.get("iata_code")) or "DEP",
        "name": coerce_text(origin.get("name")),
        "lat": coerce_float(origin.get("pos_lat")),
        "lng": coerce_float(origin.get("pos_long")),
        "stage": "DEP",
        "airway": "",
    })

    for fix in fixes or []:
        if not isinstance(fix, dict):
            continue

        lat = coerce_float(fix.get("pos_lat"))
        lng = coerce_float(fix.get("pos_long"))

        if lat is None or lng is None:
            continue

        point = {
            "ident": coerce_text(fix.get("ident")) or coerce_text(fix.get("name")),
            "name": coerce_text(fix.get("name")),
            "lat": lat,
            "lng": lng,
            "stage": coerce_text(fix.get("stage")),
            "airway": coerce_text(fix.get("via_airway")),
        }
        append_point(point)

    append_point({
        "ident": coerce_text(destination.get("icao_code")) or coerce_text(destination.get("iata_code")) or "ARR",
        "name": coerce_text(destination.get("name")),
        "lat": coerce_float(destination.get("pos_lat")),
        "lng": coerce_float(destination.get("pos_long")),
        "stage": "ARR",
        "airway": "",
    })

    return route_points


def build_simbrief_summary(payload: dict[str, Any]) -> dict[str, Any]:
    params = payload.get("params") or {}
    general = payload.get("general") or {}
    origin = payload.get("origin") or {}
    destination = payload.get("destination") or {}
    aircraft = payload.get("aircraft") or {}
    route_points = extract_simbrief_route_points(payload)
    identity = get_simbrief_identity()

    departure = coerce_text(origin.get("icao_code")) or coerce_text(origin.get("iata_code"))
    arrival = coerce_text(destination.get("icao_code")) or coerce_text(destination.get("iata_code"))
    airline = coerce_text(general.get("icao_airline"))
    flight_number = coerce_text(general.get("flight_number"))
    callsign = coerce_text(general.get("callsign")) or f"{airline}{flight_number}".strip()

    if not callsign:
        callsign = coerce_text(general.get("flightid"))

    bounds = None
    if route_points:
        latitudes = [point["lat"] for point in route_points]
        longitudes = [point["lng"] for point in route_points]
        bounds = {
            "southWest": [min(latitudes), min(longitudes)],
            "northEast": [max(latitudes), max(longitudes)],
        }

    return {
        "configured": True,
        "available": bool(route_points or departure or arrival),
        "identity_mode": identity[0] if identity else None,
        "callsign": callsign,
        "flight_number": flight_number,
        "airline": airline,
        "departure": departure,
        "arrival": arrival,
        "departure_name": coerce_text(origin.get("name")),
        "arrival_name": coerce_text(destination.get("name")),
        "aircraft": (
            coerce_text(aircraft.get("icaocode"))
            or coerce_text(aircraft.get("icao_code"))
            or coerce_text(general.get("icao_aircraft"))
            or coerce_text(general.get("aircraft"))
        ),
        "route": coerce_text(general.get("route")),
        "route_points": route_points,
        "generated_at": unix_to_iso8601(params.get("time_generated")),
        "request_id": coerce_text(params.get("request_id")),
        "distance_nm": coerce_int(general.get("route_distance")),
        "bounds": bounds,
    }


def get_simbrief_data() -> dict[str, Any]:
    identity = get_simbrief_identity()
    if not identity:
        return {
            "configured": False,
            "available": False,
            "identity_mode": None,
            "callsign": "",
            "flight_number": "",
            "airline": "",
            "departure": "",
            "arrival": "",
            "departure_name": "",
            "arrival_name": "",
            "aircraft": "",
            "route": "",
            "route_points": [],
            "generated_at": None,
            "request_id": "",
            "distance_nm": None,
            "bounds": None,
            "error": "missing_simbrief_identity",
        }

    now = time.time()
    if (
        _simbrief_cache["data"] is not None
        and _simbrief_cache["identity"] == identity
        and now - float(_simbrief_cache["fetched_at"]) < SIMBRIEF_CACHE_TTL_SECONDS
    ):
        return _simbrief_cache["data"]

    params = {identity[0]: identity[1], "json": 1}

    try:
        response = requests.get(SIMBRIEF_API_URL, params=params, timeout=12)
        response.raise_for_status()
        data = build_simbrief_summary(response.json())
    except Exception as exc:
        print(f"SimBrief data fetch error: {exc}")
        if _simbrief_cache["data"] is not None:
            return _simbrief_cache["data"]

        return {
            "configured": True,
            "available": False,
            "identity_mode": identity[0],
            "callsign": "",
            "flight_number": "",
            "airline": "",
            "departure": "",
            "arrival": "",
            "departure_name": "",
            "arrival_name": "",
            "aircraft": "",
            "route": "",
            "route_points": [],
            "generated_at": None,
            "request_id": "",
            "distance_nm": None,
            "bounds": None,
            "error": "simbrief_fetch_failed",
        }

    _simbrief_cache["data"] = data
    _simbrief_cache["fetched_at"] = now
    _simbrief_cache["identity"] = identity
    return data


def get_simconnect_snapshot() -> dict[str, Any] | None:
    return simconnect_tracker.snapshot()


def enrich_snapshot_with_simbrief(snapshot: dict[str, Any] | None) -> dict[str, Any] | None:
    if not snapshot:
        return None

    simbrief = get_simbrief_data()
    flight_plan = dict(snapshot.get("flight_plan") or {})

    if simbrief.get("available"):
        callsign = safe_text(simbrief.get("callsign"), snapshot.get("callsign") or SIMCONNECT_CALLSIGN)
        departure = safe_text(simbrief.get("departure"), "")
        arrival = safe_text(simbrief.get("arrival"), "")
    else:
        callsign = safe_text(snapshot.get("callsign"), SIMCONNECT_CALLSIGN)
        departure = safe_text(flight_plan.get("departure"), "")
        arrival = safe_text(flight_plan.get("arrival"), "")

    flight_plan["departure"] = departure
    flight_plan["arrival"] = arrival

    enriched = dict(snapshot)
    enriched["callsign"] = callsign
    enriched["flight_plan"] = flight_plan
    enriched["simbrief"] = simbrief
    return enriched


def get_live_snapshot() -> dict[str, Any] | None:
    return enrich_snapshot_with_simbrief(get_simconnect_snapshot())


def close_active_flight(conn: sqlite3.Connection, vatsim_id: str) -> None:
    conn.execute(
        """
        UPDATE flights
        SET ended_at = CURRENT_TIMESTAMP
        WHERE vatsim_id = ? AND ended_at IS NULL
        """,
        (vatsim_id,),
    )


def record_tracker_snapshot(conn: sqlite3.Connection, vatsim_id: str, snapshot: dict[str, Any] | None) -> None:
    if not snapshot:
        return

    latest = conn.execute(
        """
        SELECT
            callsign,
            lat,
            lng,
            altitude,
            groundspeed,
            CAST(strftime('%s', recorded_at) AS INTEGER) AS recorded_unix
        FROM flight_points
        WHERE vatsim_id = ?
        ORDER BY recorded_at DESC, id DESC
        LIMIT 1
        """,
        (vatsim_id,),
    ).fetchone()

    current_unix = now_unix()
    lat = snapshot.get("latitude")
    lng = snapshot.get("longitude")
    altitude = snapshot.get("altitude")
    groundspeed = snapshot.get("groundspeed")
    callsign = snapshot.get("callsign")
    raw_json = json.dumps(snapshot.get("raw"), separators=(",", ":"), ensure_ascii=True) if isinstance(snapshot.get("raw"), dict) else None

    if latest:
        same_position = (
            latest["callsign"] == callsign
            and latest["lat"] == lat
            and latest["lng"] == lng
            and latest["altitude"] == altitude
            and latest["groundspeed"] == groundspeed
        )
        latest_unix = latest["recorded_unix"] or 0
        if same_position and current_unix - latest_unix < TRACKER_MIN_INSERT_SECONDS:
            return

    conn.execute(
        """
        INSERT INTO flight_points (vatsim_id, callsign, lat, lng, altitude, groundspeed, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (vatsim_id, callsign, lat, lng, altitude, groundspeed, raw_json),
    )

    fp = snapshot.get("flight_plan") or {}
    conn.execute(
        """
        INSERT INTO flights (vatsim_id, callsign, dep, arr, aircraft)
        SELECT ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM flights WHERE vatsim_id = ? AND ended_at IS NULL
        )
        """,
        (
            vatsim_id,
            callsign,
            fp.get("departure", ""),
            fp.get("arrival", ""),
            fp.get("aircraft_short", ""),
            vatsim_id,
        ),
    )


def great_circle_distance_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    radius_km = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lng2 - lng1)

    a = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    return 2 * radius_km * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def should_split_segment(previous: dict[str, Any] | None, current: dict[str, Any]) -> bool:
    if previous is None:
        return True

    prev_ts = previous["recorded_unix"] or 0
    curr_ts = current["recorded_unix"] or 0
    if curr_ts - prev_ts > MAX_SEGMENT_GAP_SECONDS:
        return True

    distance_km = great_circle_distance_km(
        float(previous["lat"]),
        float(previous["lng"]),
        float(current["lat"]),
        float(current["lng"]),
    )
    return distance_km > MAX_SEGMENT_DISTANCE_KM


def build_track_segments(rows: list[sqlite3.Row]) -> tuple[list[dict[str, Any]], list[list[list[float]]]]:
    segments: list[list[list[float]]] = []
    points: list[dict[str, Any]] = []
    current_segment: list[list[float]] = []
    previous: dict[str, Any] | None = None

    for row in rows:
        point = {
            "lat": row["lat"],
            "lng": row["lng"],
            "callsign": row["callsign"],
            "altitude": row["altitude"],
            "groundspeed": row["groundspeed"],
            "recorded_at": row["recorded_at"],
            "recorded_unix": row["recorded_unix"],
        }
        points.append(point)

        if should_split_segment(previous, point):
            if len(current_segment) > 1:
                segments.append(current_segment)
            current_segment = [[point["lat"], point["lng"]]]
        else:
            current_segment.append([point["lat"], point["lng"]])

        previous = point

    if len(current_segment) > 1:
        segments.append(current_segment)

    return points, segments


def poll_linked_tracker_users() -> None:
    snapshot = get_live_snapshot()

    with get_db() as conn:
        linked_users = conn.execute(
            "SELECT vatsim_id FROM users WHERE vatsim_id IS NOT NULL"
        ).fetchall()

        for row in linked_users:
            vatsim_id = str(row["vatsim_id"])
            if snapshot:
                record_tracker_snapshot(conn, vatsim_id, snapshot)
            else:
                close_active_flight(conn, vatsim_id)


def tracker_loop() -> None:
    while True:
        try:
            poll_linked_tracker_users()
        except Exception as exc:
            print(f"Background tracker error: {exc}")

        time.sleep(TRACKER_POLL_SECONDS)


def start_background_tracker() -> None:
    global _tracker_thread

    with _tracker_lock:
        if _tracker_thread and _tracker_thread.is_alive():
            return

        _tracker_thread = threading.Thread(
            target=tracker_loop,
            name="simconnect-background-tracker",
            daemon=True,
        )
        _tracker_thread.start()


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    with get_db() as conn:
        return conn.execute(
            """
            SELECT
                users.id,
                users.discord_id,
                users.discord_name,
                users.vatsim_id,
                EXISTS(
                    SELECT 1 FROM passkeys WHERE passkeys.user_id = users.id
                ) AS has_passkey
            FROM users
            WHERE users.id = ?
            """,
            (user_id,),
        ).fetchone()


# Database
DB_PATH = os.path.join(os.path.dirname(__file__), "flights.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_column(conn: sqlite3.Connection, table_name: str, column_name: str, column_sql: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing = {row["name"] for row in rows}
    if column_name in existing:
        return
    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                discord_id   TEXT UNIQUE NOT NULL,
                discord_name TEXT,
                vatsim_id    TEXT UNIQUE,
                created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS flight_points (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                vatsim_id   TEXT NOT NULL,
                callsign    TEXT,
                lat         REAL NOT NULL,
                lng         REAL NOT NULL,
                altitude    INTEGER,
                groundspeed INTEGER,
                raw_json    TEXT,
                recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS flights (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                vatsim_id   TEXT NOT NULL,
                callsign    TEXT,
                dep         TEXT,
                arr         TEXT,
                aircraft    TEXT,
                started_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                ended_at    DATETIME
            );

            CREATE TABLE IF NOT EXISTS passkeys (
                id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id                INTEGER NOT NULL,
                credential_id          TEXT UNIQUE NOT NULL,
                public_key             TEXT NOT NULL,
                sign_count             INTEGER NOT NULL DEFAULT 0,
                transports             TEXT,
                credential_device_type TEXT,
                backed_up              INTEGER NOT NULL DEFAULT 0,
                created_at             DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at           DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id                   TEXT PRIMARY KEY,
                client_name                 TEXT,
                redirect_uris               TEXT NOT NULL,
                grant_types                 TEXT NOT NULL,
                response_types              TEXT NOT NULL,
                scope                       TEXT NOT NULL,
                token_endpoint_auth_method  TEXT NOT NULL DEFAULT 'none',
                created_at                  DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
                code                  TEXT PRIMARY KEY,
                client_id             TEXT NOT NULL,
                user_id               INTEGER NOT NULL,
                redirect_uri          TEXT NOT NULL,
                scope                 TEXT NOT NULL,
                resource              TEXT NOT NULL,
                code_challenge        TEXT NOT NULL,
                code_challenge_method TEXT NOT NULL,
                expires_at            INTEGER NOT NULL,
                consumed_at           INTEGER,
                created_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS oauth_access_tokens (
                access_token  TEXT PRIMARY KEY,
                refresh_token TEXT UNIQUE,
                client_id     TEXT NOT NULL,
                user_id       INTEGER NOT NULL,
                scope         TEXT NOT NULL,
                resource      TEXT NOT NULL,
                expires_at    INTEGER NOT NULL,
                revoked_at    INTEGER,
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_points_vatsim  ON flight_points(vatsim_id);
            CREATE INDEX IF NOT EXISTS idx_flights_vatsim ON flights(vatsim_id);
            CREATE INDEX IF NOT EXISTS idx_passkeys_user  ON passkeys(user_id);
            CREATE INDEX IF NOT EXISTS idx_oauth_codes_client ON oauth_authorization_codes(client_id);
            CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh ON oauth_access_tokens(refresh_token);
        """)
        ensure_column(conn, "flight_points", "raw_json", "TEXT")


init_db()
start_background_tracker()


# Auth decorators
def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "unauthorized"}), 401

        return fn(*args, **kwargs)

    return wrapper


def require_linked(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "unauthorized"}), 401

        tracker_id = session.get("vatsim_id") or ensure_session_tracking_profile()
        if not tracker_id:
            return jsonify({"error": "no_vatsim_linked"}), 403

        return fn(*args, **kwargs)

    return wrapper


def load_oauth_client(client_id: str) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT
                client_id,
                client_name,
                redirect_uris,
                grant_types,
                response_types,
                scope,
                token_endpoint_auth_method
            FROM oauth_clients
            WHERE client_id = ?
            """,
            (client_id,),
        ).fetchone()

    if not row:
        return None

    return {
        "client_id": row["client_id"],
        "client_name": row["client_name"] or "",
        "redirect_uris": parse_json_field(row["redirect_uris"], []),
        "grant_types": parse_json_field(row["grant_types"], ["authorization_code", "refresh_token"]),
        "response_types": parse_json_field(row["response_types"], ["code"]),
        "scope": row["scope"] or MCP_READ_SCOPE,
        "token_endpoint_auth_method": row["token_endpoint_auth_method"] or "none",
    }


def make_oauth_error_redirect(redirect_uri: str, error: str, state: str | None = None, description: str | None = None):
    params = {"error": error}
    if state:
        params["state"] = state
    if description:
        params["error_description"] = description
    separator = "&" if "?" in redirect_uri else "?"
    return redirect(f"{redirect_uri}{separator}{urlencode(params)}")


def issue_oauth_tokens(
    *,
    client_id: str,
    user_id: int,
    scope: str,
    resource: str,
) -> dict[str, Any]:
    access_token = secrets.token_urlsafe(48)
    refresh_token = secrets.token_urlsafe(48)
    expires_in = 3600
    expires_at = now_unix() + expires_in

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO oauth_access_tokens (
                access_token, refresh_token, client_id, user_id, scope, resource, expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (access_token, refresh_token, client_id, user_id, scope, resource, expires_at),
        )

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": refresh_token,
        "scope": scope,
    }


def verify_mcp_bearer_token() -> dict[str, Any] | None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None

    access_token = auth_header.split(" ", 1)[1].strip()
    if not access_token:
        return None

    with get_db() as conn:
        row = conn.execute(
            """
            SELECT
                oauth_access_tokens.access_token,
                oauth_access_tokens.client_id,
                oauth_access_tokens.user_id,
                oauth_access_tokens.scope,
                oauth_access_tokens.resource,
                oauth_access_tokens.expires_at,
                oauth_access_tokens.revoked_at,
                users.discord_id,
                users.discord_name,
                users.vatsim_id
            FROM oauth_access_tokens
            JOIN users ON users.id = oauth_access_tokens.user_id
            WHERE oauth_access_tokens.access_token = ?
            """,
            (access_token,),
        ).fetchone()

    if not row or row["revoked_at"] is not None:
        return None

    if int(row["expires_at"]) <= now_unix():
        return None

    if normalize_resource_uri(row["resource"]) != normalize_resource_uri(get_mcp_server_url()):
        return None

    return dict(row)


def mcp_unauthorized_response():
    response = jsonify({"error": "unauthorized"})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = (
        f'Bearer resource_metadata="{build_mcp_resource_metadata_url()}"'
    )
    return response


def jsonrpc_error_response(request_id: Any, code: int, message: str, status_code: int = 200):
    response = jsonify({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    })
    response.status_code = status_code
    return response


def jsonrpc_result_response(request_id: Any, result: dict[str, Any], status_code: int = 200):
    response = jsonify({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    })
    response.status_code = status_code
    return response


def get_mcp_tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "search",
            "description": "Search the current simulator telemetry, SimBrief flight plan, and recent tracked flights.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Natural language search query.",
                    }
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
        {
            "name": "fetch",
            "description": "Fetch a full telemetry or flight document by id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Document id returned by search.",
                    }
                },
                "required": ["id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "get_live_telemetry",
            "description": "Return the latest live aircraft telemetry enriched with SimBrief callsign, departure, and arrival.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    ]


def build_mcp_documents_for_user(vatsim_id: str | None) -> list[dict[str, Any]]:
    live_snapshot = get_live_snapshot()
    simbrief = get_simbrief_data()
    documents: list[dict[str, Any]] = []

    if live_snapshot:
        fp = live_snapshot.get("flight_plan") or {}
        documents.append({
            "id": "live-telemetry",
            "title": f"Live telemetry for {safe_text(live_snapshot.get('callsign'), 'active flight')}",
            "text": json.dumps({
                "online": True,
                "callsign": live_snapshot.get("callsign"),
                "departure": fp.get("departure", ""),
                "arrival": fp.get("arrival", ""),
                "latitude": live_snapshot.get("latitude"),
                "longitude": live_snapshot.get("longitude"),
                "altitude": live_snapshot.get("altitude"),
                "groundspeed": live_snapshot.get("groundspeed"),
                "heading": live_snapshot.get("heading"),
                "aircraft": fp.get("aircraft_short", ""),
                "source": live_snapshot.get("source", "simconnect"),
            }, indent=2),
            "url": f"{get_public_base_url()}/api/live",
            "metadata": {
                "type": "telemetry",
                "online": True,
            },
        })

    if simbrief.get("configured"):
        documents.append({
            "id": "simbrief-flight-plan",
            "title": f"Latest SimBrief OFP for {safe_text(simbrief.get('callsign'), 'configured account')}",
            "text": json.dumps(simbrief, indent=2),
            "url": f"{get_public_base_url()}/api/simbrief",
            "metadata": {
                "type": "simbrief",
                "available": bool(simbrief.get("available")),
            },
        })

    with get_db() as conn:
        recent_flights = conn.execute(
            """
            SELECT callsign, dep, arr, aircraft, started_at, ended_at
            FROM flights
            WHERE vatsim_id = ?
            ORDER BY COALESCE(ended_at, started_at) DESC, id DESC
            LIMIT 10
            """,
            (vatsim_id or "",),
        ).fetchall()

    if recent_flights:
        flights_payload = [dict(row) for row in recent_flights]
        documents.append({
            "id": "recent-flights",
            "title": "Recent tracked flights",
            "text": json.dumps({"flights": flights_payload}, indent=2),
            "url": f"{get_public_base_url()}/api/flights",
            "metadata": {
                "type": "history",
                "count": len(flights_payload),
            },
        })

    return documents


def perform_mcp_search(query: str, vatsim_id: str | None) -> dict[str, Any]:
    words = {part for part in safe_text(query).lower().split() if part}
    results: list[dict[str, Any]] = []

    for document in build_mcp_documents_for_user(vatsim_id):
        haystack = f"{document['title']} {document['text']} {json.dumps(document.get('metadata', {}))}".lower()
        if not words or any(word in haystack for word in words):
            results.append({
                "id": document["id"],
                "title": document["title"],
                "text": document["text"][:400],
                "url": document["url"],
                "metadata": document.get("metadata", {}),
            })

    return {"results": results}


def perform_mcp_fetch(document_id: str, vatsim_id: str | None) -> dict[str, Any]:
    for document in build_mcp_documents_for_user(vatsim_id):
        if document["id"] == document_id:
            return {
                "id": document["id"],
                "title": document["title"],
                "text": document["text"],
                "url": document["url"],
                "metadata": document.get("metadata", {}),
            }

    raise ValueError("unknown_document_id")


# Discord OAuth
@app.route("/auth/login")
def login():
    if not is_discord_configured():
        return redirect("/?error=discord_not_configured")

    next_url = request.args.get("next")
    if next_url:
        session["post_auth_redirect"] = next_url

    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state,
    }
    return redirect(f"{DISCORD_AUTH_URL}?{urlencode(params)}")


@app.route("/auth/callback")
def callback():
    if not is_discord_configured():
        return redirect("/?error=discord_not_configured")

    if request.args.get("error"):
        return redirect(f"/?error={request.args.get('error')}")

    code = request.args.get("code")
    state = request.args.get("state")
    if state != session.pop("oauth_state", None):
        return redirect("/?error=state_mismatch")

    try:
        token_resp = requests.post(
            DISCORD_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "redirect_uri": DISCORD_REDIRECT_URI,
                "code": code,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()
    except Exception as exc:
        print(f"Discord token error: {exc}")
        return redirect("/?error=token_exchange_failed")

    try:
        user_resp = requests.get(
            DISCORD_USER_URL,
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            timeout=10,
        )
        user_resp.raise_for_status()
        discord_user = user_resp.json()
    except Exception:
        return redirect("/?error=user_fetch_failed")

    discord_id = str(discord_user.get("id", ""))
    discriminator = discord_user.get("discriminator", "0")
    discord_name = discord_user.get("username", "")

    if discriminator and discriminator != "0":
        discord_name = f"{discord_name}#{discriminator}"

    if discord_id not in ALLOWED_DISCORD_IDS:
        return redirect("/?error=access_denied")

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO users (discord_id, discord_name)
            VALUES (?, ?)
            ON CONFLICT(discord_id) DO UPDATE SET discord_name = excluded.discord_name
            """,
            (discord_id, discord_name),
        )
        row = conn.execute(
            "SELECT id, vatsim_id FROM users WHERE discord_id = ?",
            (discord_id,),
        ).fetchone()
        user_id = row["id"] if row else None
        vatsim_id = ensure_tracking_profile(user_id) if user_id else None

    session["user_id"] = user_id
    session["discord_id"] = discord_id
    session["discord_name"] = discord_name
    session["vatsim_id"] = vatsim_id
    session["auth_method"] = "discord"

    redirect_target = session.pop("post_auth_redirect", None) or "/dashboard"
    return redirect(redirect_target)


@app.route("/auth/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/.well-known/oauth-protected-resource")
def oauth_protected_resource_metadata():
    return jsonify({
        "resource": get_mcp_server_url(),
        "authorization_servers": [get_oauth_issuer()],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [MCP_READ_SCOPE],
    })


@app.route("/.well-known/oauth-authorization-server")
def oauth_authorization_server_metadata():
    base_url = get_public_base_url()
    return jsonify({
        "issuer": get_oauth_issuer(),
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [MCP_READ_SCOPE],
        "response_modes_supported": ["query"],
        "resource_parameter_supported": True,
    })


@app.route("/oauth/register", methods=["POST"])
def oauth_register_client():
    payload = request.get_json(silent=True) or {}
    redirect_uris = payload.get("redirect_uris")

    if not isinstance(redirect_uris, list) or not redirect_uris:
        return jsonify({"error": "invalid_redirect_uris"}), 400

    normalized_redirect_uris: list[str] = []
    for redirect_uri in redirect_uris:
        if not isinstance(redirect_uri, str) or not is_valid_redirect_uri(redirect_uri):
            return jsonify({"error": "invalid_redirect_uri"}), 400
        normalized_redirect_uris.append(redirect_uri)

    token_endpoint_auth_method = safe_text(payload.get("token_endpoint_auth_method"), "none")
    if token_endpoint_auth_method != "none":
        return jsonify({"error": "unsupported_token_endpoint_auth_method"}), 400

    grant_types = payload.get("grant_types")
    if not isinstance(grant_types, list) or not grant_types:
        grant_types = ["authorization_code", "refresh_token"]

    if "authorization_code" not in grant_types:
        return jsonify({"error": "authorization_code_required"}), 400

    response_types = payload.get("response_types")
    if not isinstance(response_types, list) or not response_types:
        response_types = ["code"]

    client_id = f"mcp-client-{secrets.token_urlsafe(18)}"
    client_name = safe_text(payload.get("client_name"), "ChatGPT MCP Client")
    scope = clean_scope(payload.get("scope"))

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO oauth_clients (
                client_id, client_name, redirect_uris, grant_types, response_types, scope,
                token_endpoint_auth_method
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                client_name,
                json.dumps(normalized_redirect_uris),
                json.dumps(grant_types),
                json.dumps(response_types),
                scope,
                token_endpoint_auth_method,
            ),
        )

    return jsonify({
        "client_id": client_id,
        "client_id_issued_at": now_unix(),
        "client_name": client_name,
        "redirect_uris": normalized_redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "scope": scope,
        "token_endpoint_auth_method": token_endpoint_auth_method,
    }), 201


@app.route("/oauth/authorize")
def oauth_authorize():
    client_id = safe_text(request.args.get("client_id"))
    redirect_uri = safe_text(request.args.get("redirect_uri"))
    response_type = safe_text(request.args.get("response_type"))
    state = safe_text(request.args.get("state"))
    scope = clean_scope(request.args.get("scope"))
    code_challenge = safe_text(request.args.get("code_challenge"))
    code_challenge_method = safe_text(request.args.get("code_challenge_method"), "S256")
    resource = normalize_resource_uri(request.args.get("resource"))

    client = load_oauth_client(client_id)
    if not client:
        return jsonify({"error": "invalid_client"}), 400

    if redirect_uri not in client["redirect_uris"]:
        return jsonify({"error": "invalid_redirect_uri"}), 400

    if response_type != "code":
        return make_oauth_error_redirect(redirect_uri, "unsupported_response_type", state)

    if code_challenge_method != "S256" or not code_challenge:
        return make_oauth_error_redirect(redirect_uri, "invalid_request", state, "PKCE S256 is required")

    if resource != normalize_resource_uri(get_mcp_server_url()):
        return make_oauth_error_redirect(redirect_uri, "invalid_target", state)

    if not session.get("user_id"):
        session["post_auth_redirect"] = request.url
        return redirect("/auth/login")

    user_id = int(session["user_id"])
    code = secrets.token_urlsafe(32)

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO oauth_authorization_codes (
                code, client_id, user_id, redirect_uri, scope, resource,
                code_challenge, code_challenge_method, expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                code,
                client_id,
                user_id,
                redirect_uri,
                scope,
                resource,
                code_challenge,
                code_challenge_method,
                now_unix() + 600,
            ),
        )

    params = {"code": code}
    if state:
        params["state"] = state
    return redirect(f"{redirect_uri}{'&' if '?' in redirect_uri else '?'}{urlencode(params)}")


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    grant_type = safe_text(request.form.get("grant_type"))
    client_id = safe_text(request.form.get("client_id"))
    client = load_oauth_client(client_id)

    if not client:
        return jsonify({"error": "invalid_client"}), 401

    if client["token_endpoint_auth_method"] != "none":
        return jsonify({"error": "unauthorized_client"}), 401

    if grant_type == "authorization_code":
        code = safe_text(request.form.get("code"))
        redirect_uri = safe_text(request.form.get("redirect_uri"))
        code_verifier = safe_text(request.form.get("code_verifier"))
        resource = normalize_resource_uri(request.form.get("resource"))

        with get_db() as conn:
            code_row = conn.execute(
                """
                SELECT *
                FROM oauth_authorization_codes
                WHERE code = ? AND client_id = ?
                """,
                (code, client_id),
            ).fetchone()

            if not code_row:
                return jsonify({"error": "invalid_grant"}), 400

            if code_row["consumed_at"] is not None or int(code_row["expires_at"]) <= now_unix():
                return jsonify({"error": "invalid_grant"}), 400

            if redirect_uri != code_row["redirect_uri"]:
                return jsonify({"error": "invalid_grant"}), 400

            if resource != normalize_resource_uri(code_row["resource"]):
                return jsonify({"error": "invalid_target"}), 400

            if not code_verifier or sha256_base64url(code_verifier) != code_row["code_challenge"]:
                return jsonify({"error": "invalid_grant"}), 400

            conn.execute(
                "UPDATE oauth_authorization_codes SET consumed_at = ? WHERE code = ?",
                (now_unix(), code),
            )

        return jsonify(issue_oauth_tokens(
            client_id=client_id,
            user_id=int(code_row["user_id"]),
            scope=code_row["scope"],
            resource=normalize_resource_uri(code_row["resource"]),
        ))

    if grant_type == "refresh_token":
        refresh_token = safe_text(request.form.get("refresh_token"))

        with get_db() as conn:
            token_row = conn.execute(
                """
                SELECT *
                FROM oauth_access_tokens
                WHERE refresh_token = ? AND client_id = ?
                """,
                (refresh_token, client_id),
            ).fetchone()

            if not token_row or token_row["revoked_at"] is not None:
                return jsonify({"error": "invalid_grant"}), 400

            if int(token_row["expires_at"]) <= now_unix():
                return jsonify({"error": "invalid_grant"}), 400

            conn.execute(
                "UPDATE oauth_access_tokens SET revoked_at = ? WHERE refresh_token = ?",
                (now_unix(), refresh_token),
            )

        return jsonify(issue_oauth_tokens(
            client_id=client_id,
            user_id=int(token_row["user_id"]),
            scope=token_row["scope"],
            resource=normalize_resource_uri(token_row["resource"]),
        ))

    return jsonify({"error": "unsupported_grant_type"}), 400


# VATSIM linking
@app.route("/api/link-vatsim", methods=["POST"])
@require_auth
def link_vatsim():
    tracker_id = ensure_session_tracking_profile()
    return jsonify({"ok": True, "vatsim_id": tracker_id, "tracker_id": tracker_id})


@app.route("/api/unlink-vatsim", methods=["POST"])
@require_auth
def unlink_vatsim():
    tracker_id = ensure_session_tracking_profile()
    return jsonify({"ok": True, "tracker_id": tracker_id})


# User info
@app.route("/api/me")
def me():
    user = get_current_user()

    if not user:
        return jsonify({"authenticated": False}), 401

    tracker_id = user["vatsim_id"] or ensure_tracking_profile(user["id"])
    session["vatsim_id"] = tracker_id

    return jsonify({
        "authenticated": True,
        "user_id": user["id"],
        "discord_id": user["discord_id"],
        "discord_name": user["discord_name"] or "",
        "vatsim_id": tracker_id,
        "tracker_id": tracker_id,
        "auth_method": session.get("auth_method", "discord"),
        "has_passkey": bool(user["has_passkey"]),
    })


@app.route("/api/passkey/register/options", methods=["POST"])
@require_auth
def passkey_register_options():
    unavailable = ensure_webauthn()
    if unavailable:
        return unavailable

    user = get_current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    with get_db() as conn:
        credentials = conn.execute(
            "SELECT credential_id FROM passkeys WHERE user_id = ?",
            (user["id"],),
        ).fetchall()

    user_label = user["discord_name"] or user["discord_id"] or f"user-{user['id']}"

    try:
        options = generate_registration_options(
            rp_id=get_passkey_rp_id(),
            rp_name=PASSKEY_RP_NAME,
            user_id=str(user["id"]).encode("utf-8"),
            user_name=user_label,
            user_display_name=user_label,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred["credential_id"]))
                for cred in credentials
            ],
        )
        options_json = parse_json_options(options)
    except Exception as exc:
        return json_error(f"passkey_registration_options_failed: {exc}", 500)

    session["passkey_registration_challenge"] = options_json["challenge"]
    return jsonify(options_json)


@app.route("/api/passkey/register/verify", methods=["POST"])
@require_auth
def passkey_register_verify():
    unavailable = ensure_webauthn()
    if unavailable:
        return unavailable

    challenge = session.pop("passkey_registration_challenge", None)
    if not challenge:
        return jsonify({"error": "registration_expired"}), 400

    user = get_current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    credential = request.get_json() or {}

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=get_passkey_rp_id(),
            expected_origin=get_passkey_origin(),
            require_user_verification=True,
        )
    except Exception as exc:
        return json_error(f"registration_failed: {exc}", 400)

    transports = credential.get("response", {}).get("transports", [])

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO passkeys (
                user_id, credential_id, public_key, sign_count,
                transports, credential_device_type, backed_up, last_used_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(credential_id) DO UPDATE SET
                public_key = excluded.public_key,
                sign_count = excluded.sign_count,
                transports = excluded.transports,
                credential_device_type = excluded.credential_device_type,
                backed_up = excluded.backed_up,
                last_used_at = CURRENT_TIMESTAMP
            """,
            (
                user["id"],
                bytes_to_base64url(verification.credential_id),
                bytes_to_base64url(verification.credential_public_key),
                verification.sign_count,
                json.dumps(transports),
                verification.credential_device_type,
                int(bool(verification.credential_backed_up)),
            ),
        )

    return jsonify({"ok": True})


@app.route("/api/passkey/auth/options", methods=["POST"])
def passkey_auth_options():
    unavailable = ensure_webauthn()
    if unavailable:
        return unavailable

    try:
        options = generate_authentication_options(
            rp_id=get_passkey_rp_id(),
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        options_json = parse_json_options(options)
    except Exception as exc:
        return json_error(f"passkey_authentication_options_failed: {exc}", 500)

    session["passkey_authentication_challenge"] = options_json["challenge"]
    return jsonify(options_json)


@app.route("/api/passkey/auth/verify", methods=["POST"])
def passkey_auth_verify():
    unavailable = ensure_webauthn()
    if unavailable:
        return unavailable

    challenge = session.pop("passkey_authentication_challenge", None)
    if not challenge:
        return jsonify({"error": "authentication_expired"}), 400

    credential = request.get_json() or {}
    credential_id = credential.get("id")

    if not credential_id:
        return jsonify({"error": "missing_credential_id"}), 400

    with get_db() as conn:
        passkey = conn.execute(
            """
            SELECT
                passkeys.id,
                passkeys.user_id,
                passkeys.credential_id,
                passkeys.public_key,
                passkeys.sign_count,
                users.discord_id,
                users.discord_name,
                users.vatsim_id
            FROM passkeys
            JOIN users ON users.id = passkeys.user_id
            WHERE passkeys.credential_id = ?
            """,
            (credential_id,),
        ).fetchone()

        if not passkey:
            return json_error("unknown_passkey", 404)

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=get_passkey_rp_id(),
                expected_origin=get_passkey_origin(),
                credential_public_key=base64url_to_bytes(passkey["public_key"]),
                credential_current_sign_count=passkey["sign_count"],
                require_user_verification=True,
            )
        except Exception as exc:
            return json_error(f"authentication_failed: {exc}", 400)

        conn.execute(
            """
            UPDATE passkeys
            SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP,
                credential_device_type = ?, backed_up = ?
            WHERE id = ?
            """,
            (
                verification.new_sign_count,
                verification.credential_device_type,
                int(bool(verification.credential_backed_up)),
                passkey["id"],
            ),
        )

    tracker_id = passkey["vatsim_id"] or ensure_tracking_profile(passkey["user_id"])

    session.clear()
    session["user_id"] = passkey["user_id"]
    session["discord_id"] = passkey["discord_id"]
    session["discord_name"] = passkey["discord_name"]
    session["vatsim_id"] = tracker_id
    session["auth_method"] = "passkey"

    return jsonify({"ok": True, "vatsim_id": tracker_id, "tracker_id": tracker_id})


# SimConnect telemetry intake
@app.route("/api/telemetry", methods=["POST"])
def telemetry():
    if not is_telemetry_request_authorized():
        return jsonify({"error": "telemetry_unauthorized"}), 401

    payload_raw: Any = request.get_json(silent=True)

    if payload_raw is None:
        return jsonify({"error": "invalid_json_body"}), 400

    if not isinstance(payload_raw, dict):
        return jsonify({"error": "invalid_json_body"}), 400

    try:
        state = simconnect_tracker.update_from_telemetry(payload_raw)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        print(f"Telemetry write error: {exc}")
        return jsonify({"error": "telemetry_write_failed"}), 500

    return jsonify({
        "ok": True,
        "online": state.get("online"),
        "connected": state.get("connected"),
        "callsign": state.get("callsign"),
        "received_at": state.get("received_at"),
        "status": simconnect_tracker.status(),
    })


@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    token_record = verify_mcp_bearer_token()
    if not token_record:
        return mcp_unauthorized_response()

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonrpc_error_response(None, -32700, "Parse error", 400)

    request_id = payload.get("id")
    method = safe_text(payload.get("method"))
    params = payload.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return jsonrpc_error_response(request_id, -32602, "Invalid params", 400)

    if method == "initialize":
        protocol_version = safe_text(params.get("protocolVersion"), MCP_PROTOCOL_VERSION) or MCP_PROTOCOL_VERSION
        return jsonrpc_result_response(request_id, {
            "protocolVersion": protocol_version,
            "capabilities": {
                "tools": {
                    "listChanged": False,
                }
            },
            "serverInfo": {
                "name": MCP_SERVER_NAME,
                "version": MCP_SERVER_VERSION,
            },
            "instructions": (
                "This MCP server exposes live simulator telemetry from SimConnect and "
                "flight identity from SimBrief. Use get_live_telemetry for the latest status, "
                "or search/fetch for ChatGPT-compatible read access."
            ),
        })

    if method == "notifications/initialized":
        return ("", 204)

    if method == "ping":
        return jsonrpc_result_response(request_id, {})

    if method == "tools/list":
        return jsonrpc_result_response(request_id, {"tools": get_mcp_tools()})

    if method == "tools/call":
        tool_name = safe_text(params.get("name"))
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return jsonrpc_error_response(request_id, -32602, "Invalid tool arguments", 400)

        vatsim_id = safe_text(token_record.get("vatsim_id"))

        try:
            if tool_name == "search":
                result = encode_json_text_content(
                    perform_mcp_search(safe_text(arguments.get("query")), vatsim_id)
                )
            elif tool_name == "fetch":
                result = encode_json_text_content(
                    perform_mcp_fetch(safe_text(arguments.get("id")), vatsim_id)
                )
            elif tool_name == "get_live_telemetry":
                snapshot = get_live_snapshot()
                if not snapshot:
                    result = encode_json_text_content({
                        "online": False,
                        "status": simconnect_tracker.status(),
                    })
                else:
                    fp = snapshot.get("flight_plan") or {}
                    result = encode_json_text_content({
                        "online": True,
                        "callsign": snapshot.get("callsign"),
                        "departure": fp.get("departure", ""),
                        "arrival": fp.get("arrival", ""),
                        "aircraft": fp.get("aircraft_short", ""),
                        "latitude": snapshot.get("latitude"),
                        "longitude": snapshot.get("longitude"),
                        "altitude": snapshot.get("altitude"),
                        "groundspeed": snapshot.get("groundspeed"),
                        "heading": snapshot.get("heading"),
                        "raw": snapshot.get("raw"),
                        "source": snapshot.get("source", "simconnect"),
                        "simbrief": snapshot.get("simbrief", {}),
                        "status": simconnect_tracker.status(),
                    })
            else:
                return jsonrpc_error_response(request_id, -32601, "Tool not found", 404)
        except ValueError as exc:
            return jsonrpc_error_response(request_id, -32000, str(exc), 400)

        return jsonrpc_result_response(request_id, result)

    if method == "resources/list":
        return jsonrpc_result_response(request_id, {"resources": []})

    if method == "prompts/list":
        return jsonrpc_result_response(request_id, {"prompts": []})

    return jsonrpc_error_response(request_id, -32601, "Method not found", 404)


@app.route("/api/simconnect/status")
@require_auth
def simconnect_status():
    return jsonify(simconnect_tracker.status())


# Flight data
@app.route("/api/live")
@require_linked
def live_flight():
    vatsim_id = session["vatsim_id"]
    snapshot = get_live_snapshot()

    if not snapshot:
        with get_db() as conn:
            close_active_flight(conn, vatsim_id)

        return jsonify({
            "online": False,
            "source": "simconnect",
            "tracker_id": vatsim_id,
            "status": simconnect_tracker.status(),
        })

    with get_db() as conn:
        record_tracker_snapshot(conn, vatsim_id, snapshot)

    return jsonify({
        "online": True,
        "callsign": snapshot.get("callsign"),
        "lat": snapshot.get("latitude"),
        "lng": snapshot.get("longitude"),
        "altitude": snapshot.get("altitude"),
        "groundspeed": snapshot.get("groundspeed"),
        "heading": snapshot.get("heading"),
        "dep": (snapshot.get("flight_plan") or {}).get("departure", ""),
        "arr": (snapshot.get("flight_plan") or {}).get("arrival", ""),
        "aircraft": (snapshot.get("flight_plan") or {}).get("aircraft_short", ""),
        "raw": snapshot.get("raw"),
        "source": "simconnect",
        "tracker_id": vatsim_id,
        "status": simconnect_tracker.status(),
    })


@app.route("/api/heatmap")
@require_linked
def heatmap():
    vatsim_id = session["vatsim_id"]

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT lat, lng, COUNT(*) as weight
            FROM flight_points WHERE vatsim_id = ?
            GROUP BY ROUND(lat,2), ROUND(lng,2)
            """,
            (vatsim_id,),
        ).fetchall()

        track_rows = conn.execute(
            """
            SELECT
                callsign,
                lat,
                lng,
                altitude,
                groundspeed,
                recorded_at,
                CAST(strftime('%s', recorded_at) AS INTEGER) AS recorded_unix
            FROM flight_points
            WHERE vatsim_id = ?
            ORDER BY recorded_at ASC, id ASC
            """,
            (vatsim_id,),
        ).fetchall()

    ordered_points, segments = build_track_segments(track_rows)
    recent_track = [
        {"lat": point["lat"], "lng": point["lng"], "recorded_at": point["recorded_at"]}
        for point in ordered_points[-120:]
    ]

    bounds = None
    if ordered_points:
        latitudes = [point["lat"] for point in ordered_points]
        longitudes = [point["lng"] for point in ordered_points]
        bounds = {
            "southWest": [min(latitudes), min(longitudes)],
            "northEast": [max(latitudes), max(longitudes)],
        }

    return jsonify({
        "points": [{"lat": row["lat"], "lng": row["lng"], "weight": row["weight"]} for row in rows],
        "segments": segments,
        "recent_track": recent_track,
        "bounds": bounds,
        "totals": {
            "track_points": len(ordered_points),
            "segments": len(segments),
        },
    })


@app.route("/api/flights")
@require_linked
def flights():
    vatsim_id = session["vatsim_id"]

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT callsign, dep, arr, aircraft, started_at, ended_at
            FROM flights WHERE vatsim_id = ?
            ORDER BY started_at DESC LIMIT 20
            """,
            (vatsim_id,),
        ).fetchall()

    return jsonify({"flights": [dict(row) for row in rows]})


@app.route("/api/stats")
@require_linked
def stats():
    vatsim_id = session["vatsim_id"]

    with get_db() as conn:
        total_points = conn.execute(
            "SELECT COUNT(*) as c FROM flight_points WHERE vatsim_id=?",
            (vatsim_id,),
        ).fetchone()["c"]

        total_flights = conn.execute(
            "SELECT COUNT(*) as c FROM flights WHERE vatsim_id=?",
            (vatsim_id,),
        ).fetchone()["c"]

        top_routes = conn.execute(
            """
            SELECT dep, arr, COUNT(*) as times
            FROM flights WHERE vatsim_id=? AND dep!='' AND arr!=''
            GROUP BY dep, arr ORDER BY times DESC LIMIT 5
            """,
            (vatsim_id,),
        ).fetchall()

    return jsonify({
        "total_points": total_points,
        "total_flights": total_flights,
        "top_routes": [dict(row) for row in top_routes],
    })


@app.route("/api/simbrief")
@require_auth
def simbrief():
    return jsonify(get_simbrief_data())


# Serve frontend
@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/dashboard")
def dashboard():
    return send_from_directory("../frontend", "dashboard.html")


@app.route("/link-vatsim")
def link_vatsim_page():
    return redirect("/dashboard")


@app.route("/roadmap")
def roadmap_page():
    return send_from_directory("../frontend", "roadmap.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("../frontend", path)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
