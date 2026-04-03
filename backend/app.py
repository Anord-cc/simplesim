import base64
import importlib
import json
import math
import os
import secrets
import sqlite3
import time
from functools import wraps
from typing import Any
from urllib.parse import urlencode, urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request, send_from_directory, session
from flask_cors import CORS

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

load_dotenv()

app = Flask(__name__, static_folder="../frontend/static", template_folder="../frontend/templates")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
CORS(app, supports_credentials=True)

# ── Discord OAuth Config ──────────────────────────────────────────────────────
DISCORD_AUTH_URL      = "https://discord.com/oauth2/authorize"
DISCORD_TOKEN_URL     = "https://discord.com/api/oauth2/token"
DISCORD_USER_URL      = "https://discord.com/api/users/@me"
DISCORD_CLIENT_ID     = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI  = os.environ.get("DISCORD_REDIRECT_URI")

# ── Allowlist — only these Discord user IDs may log in ───────────────────────
ALLOWED_DISCORD_IDS = {
    discord_id.strip()
    for discord_id in (os.environ.get("ALLOWED_DISCORD_IDS") or "").split(",")
    if discord_id.strip()
}

# ── VATSIM public data feed ───────────────────────────────────────────────────
VATSIM_DATA_URL = "https://data.vatsim.net/v3/vatsim-data.json"
_vatsim_cache   = {"data": None, "fetched_at": 0}
VATSIM_CACHE_TTL_SECONDS = max(5, int(os.environ.get("VATSIM_CACHE_TTL_SECONDS", "15")))
MAX_SEGMENT_GAP_SECONDS = 60 * 60 * 4
MAX_SEGMENT_DISTANCE_KM = 900
PASSKEY_RP_NAME = os.environ.get("PASSKEY_RP_NAME", "VATSIM HeatTracker")


def bytes_to_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def parse_json_options(options) -> dict:
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

def get_vatsim_data():
    now = time.time()
    if now - _vatsim_cache["fetched_at"] < VATSIM_CACHE_TTL_SECONDS:
        return _vatsim_cache["data"]
    try:
        r = requests.get(VATSIM_DATA_URL, timeout=10)
        r.raise_for_status()
        _vatsim_cache["data"] = r.json()
        _vatsim_cache["fetched_at"] = now
    except Exception as e:
        print(f"VATSIM data fetch error: {e}")
    return _vatsim_cache["data"]

def find_pilot(vatsim_id: str):
    data = get_vatsim_data()
    if not data:
        return None
    for pilot in data.get("pilots", []):
        if str(pilot.get("cid")) == str(vatsim_id):
            return pilot
    return None


def close_active_flight(conn, vatsim_id: str):
    conn.execute(
        """
        UPDATE flights
        SET ended_at = CURRENT_TIMESTAMP
        WHERE vatsim_id = ? AND ended_at IS NULL
        """,
        (vatsim_id,),
    )


def great_circle_distance_km(lat1, lng1, lat2, lng2):
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


def should_split_segment(previous, current):
    if previous is None:
        return True

    prev_ts = previous["recorded_unix"] or 0
    curr_ts = current["recorded_unix"] or 0
    if curr_ts - prev_ts > MAX_SEGMENT_GAP_SECONDS:
        return True

    distance_km = great_circle_distance_km(
        previous["lat"], previous["lng"], current["lat"], current["lng"]
    )
    return distance_km > MAX_SEGMENT_DISTANCE_KM


def build_track_segments(rows):
    segments = []
    points = []
    current_segment = []
    previous = None

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

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "flights.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
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

            CREATE INDEX IF NOT EXISTS idx_points_vatsim  ON flight_points(vatsim_id);
            CREATE INDEX IF NOT EXISTS idx_flights_vatsim ON flights(vatsim_id);
            CREATE INDEX IF NOT EXISTS idx_passkeys_user  ON passkeys(user_id);
        """)

init_db()

# ── Auth decorators ───────────────────────────────────────────────────────────
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
        if not session.get("vatsim_id"):
            return jsonify({"error": "no_vatsim_linked"}), 403
        return fn(*args, **kwargs)
    return wrapper

# ── Discord OAuth ─────────────────────────────────────────────────────────────
@app.route("/auth/login")
def login():
    if not is_discord_configured():
        return redirect("/?error=discord_not_configured")

    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    params = {
        "client_id":     DISCORD_CLIENT_ID,
        "redirect_uri":  DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope":         "identify",
        "state":         state,
    }
    return redirect(f"{DISCORD_AUTH_URL}?{urlencode(params)}")

@app.route("/auth/callback")
def callback():
    if not is_discord_configured():
        return redirect("/?error=discord_not_configured")

    if request.args.get("error"):
        return redirect(f"/?error={request.args.get('error')}")

    code  = request.args.get("code")
    state = request.args.get("state")
    if state != session.pop("oauth_state", None):
        return redirect("/?error=state_mismatch")

    # Exchange code for token
    try:
        token_resp = requests.post(DISCORD_TOKEN_URL, data={
            "grant_type":    "authorization_code",
            "client_id":     DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "redirect_uri":  DISCORD_REDIRECT_URI,
            "code":          code,
        }, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=10)
        token_resp.raise_for_status()
        tokens = token_resp.json()
    except Exception as e:
        print(f"Discord token error: {e}")
        return redirect("/?error=token_exchange_failed")

    # Fetch Discord user info
    try:
        user_resp = requests.get(DISCORD_USER_URL, headers={
            "Authorization": f"Bearer {tokens['access_token']}"
        }, timeout=10)
        user_resp.raise_for_status()
        discord_user = user_resp.json()
    except Exception:
        return redirect("/?error=user_fetch_failed")

    discord_id   = str(discord_user.get("id", ""))
    discriminator = discord_user.get("discriminator", "0")
    discord_name  = discord_user.get("username", "")
    if discriminator and discriminator != "0":
        discord_name = f"{discord_name}#{discriminator}"

    # ── Allowlist gate ────────────────────────────────────────────────────────
    if discord_id not in ALLOWED_DISCORD_IDS:
        return redirect("/?error=access_denied")

    # Upsert user
    with get_db() as conn:
        conn.execute("""
            INSERT INTO users (discord_id, discord_name)
            VALUES (?, ?)
            ON CONFLICT(discord_id) DO UPDATE SET discord_name = excluded.discord_name
        """, (discord_id, discord_name))
        row = conn.execute(
            "SELECT id, vatsim_id FROM users WHERE discord_id = ?", (discord_id,)
        ).fetchone()
        user_id = row["id"] if row else None
        vatsim_id = row["vatsim_id"] if row else None

    session["user_id"]      = user_id
    session["discord_id"]   = discord_id
    session["discord_name"] = discord_name
    session["vatsim_id"]    = vatsim_id
    session["auth_method"]  = "discord"

    return redirect("/link-vatsim" if not vatsim_id else "/dashboard")

@app.route("/auth/logout")
def logout():
    session.clear()
    return redirect("/")

# ── VATSIM Linking ────────────────────────────────────────────────────────────
@app.route("/api/link-vatsim", methods=["POST"])
@require_auth
def link_vatsim():
    user_id     = session["user_id"]
    data       = request.get_json() or {}
    vatsim_id  = str(data.get("vatsim_id", "")).strip()

    if not vatsim_id.isdigit() or len(vatsim_id) < 4:
        return jsonify({"error": "Invalid VATSIM CID — must be a number (e.g. 1234567)"}), 400

    try:
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET vatsim_id = ? WHERE id = ?",
                (vatsim_id, user_id)
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "That VATSIM CID is already linked to another account"}), 409

    session["vatsim_id"] = vatsim_id
    return jsonify({"ok": True, "vatsim_id": vatsim_id})

@app.route("/api/unlink-vatsim", methods=["POST"])
@require_auth
def unlink_vatsim():
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET vatsim_id = NULL WHERE id = ?",
            (session["user_id"],)
        )
    session["vatsim_id"] = None
    return jsonify({"ok": True})

# ── User info ─────────────────────────────────────────────────────────────────
@app.route("/api/me")
def me():
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "user_id":       user["id"],
        "discord_id":    user["discord_id"],
        "discord_name":  user["discord_name"] or "",
        "vatsim_id":     user["vatsim_id"],
        "auth_method":   session.get("auth_method", "discord"),
        "has_passkey":   bool(user["has_passkey"]),
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

    session.clear()
    session["user_id"] = passkey["user_id"]
    session["discord_id"] = passkey["discord_id"]
    session["discord_name"] = passkey["discord_name"]
    session["vatsim_id"] = passkey["vatsim_id"]
    session["auth_method"] = "passkey"

    return jsonify({"ok": True, "vatsim_id": passkey["vatsim_id"]})

# ── Flight data ───────────────────────────────────────────────────────────────
@app.route("/api/live")
@require_linked
def live_flight():
    vatsim_id = session["vatsim_id"]
    pilot = find_pilot(vatsim_id)

    if not pilot:
        with get_db() as conn:
            close_active_flight(conn, vatsim_id)
        return jsonify({"online": False})

    with get_db() as conn:
        conn.execute("""
            INSERT INTO flight_points (vatsim_id, callsign, lat, lng, altitude, groundspeed)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            vatsim_id, pilot.get("callsign"),
            pilot.get("latitude"), pilot.get("longitude"),
            pilot.get("altitude"), pilot.get("groundspeed"),
        ))
        fp = pilot.get("flight_plan") or {}
        conn.execute("""
            INSERT INTO flights (vatsim_id, callsign, dep, arr, aircraft)
            SELECT ?, ?, ?, ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM flights WHERE vatsim_id = ? AND ended_at IS NULL
            )
        """, (
            vatsim_id, pilot.get("callsign"),
            fp.get("departure",""), fp.get("arrival",""), fp.get("aircraft_short",""),
            vatsim_id,
        ))

    return jsonify({
        "online":      True,
        "callsign":    pilot.get("callsign"),
        "lat":         pilot.get("latitude"),
        "lng":         pilot.get("longitude"),
        "altitude":    pilot.get("altitude"),
        "groundspeed": pilot.get("groundspeed"),
        "heading":     pilot.get("heading"),
        "dep":         (pilot.get("flight_plan") or {}).get("departure",""),
        "arr":         (pilot.get("flight_plan") or {}).get("arrival",""),
        "aircraft":    (pilot.get("flight_plan") or {}).get("aircraft_short",""),
    })

@app.route("/api/heatmap")
@require_linked
def heatmap():
    vatsim_id = session["vatsim_id"]
    with get_db() as conn:
        rows = conn.execute("""
            SELECT lat, lng, COUNT(*) as weight
            FROM flight_points WHERE vatsim_id = ?
            GROUP BY ROUND(lat,2), ROUND(lng,2)
        """, (vatsim_id,)).fetchall()
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
        "points": [{"lat": r["lat"], "lng": r["lng"], "weight": r["weight"]} for r in rows],
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
        rows = conn.execute("""
            SELECT callsign, dep, arr, aircraft, started_at, ended_at
            FROM flights WHERE vatsim_id = ?
            ORDER BY started_at DESC LIMIT 20
        """, (vatsim_id,)).fetchall()
    return jsonify({"flights": [dict(r) for r in rows]})

@app.route("/api/stats")
@require_linked
def stats():
    vatsim_id = session["vatsim_id"]
    with get_db() as conn:
        total_points  = conn.execute(
            "SELECT COUNT(*) as c FROM flight_points WHERE vatsim_id=?", (vatsim_id,)
        ).fetchone()["c"]
        total_flights = conn.execute(
            "SELECT COUNT(*) as c FROM flights WHERE vatsim_id=?", (vatsim_id,)
        ).fetchone()["c"]
        top_routes = conn.execute("""
            SELECT dep, arr, COUNT(*) as times
            FROM flights WHERE vatsim_id=? AND dep!='' AND arr!=''
            GROUP BY dep, arr ORDER BY times DESC LIMIT 5
        """, (vatsim_id,)).fetchall()
    return jsonify({
        "total_points":  total_points,
        "total_flights": total_flights,
        "top_routes":    [dict(r) for r in top_routes],
    })

# ── Serve frontend ────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")

@app.route("/dashboard")
def dashboard():
    return send_from_directory("../frontend", "dashboard.html")

@app.route("/link-vatsim")
def link_vatsim_page():
    return send_from_directory("../frontend", "link-vatsim.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("../frontend", path)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
