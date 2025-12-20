import os
import secrets
import bcrypt
import redis
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify
)
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_cors import CORS

from sqlalchemy import func, and_
from models import User, SessionLocal


# -----------------------------
# App setup
# -----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# IMPORTANT:
# If your frontend is on a different origin (different port/domain),
# you MUST allow credentials and also send credentials from fetch().
CORS(app, supports_credentials=True)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    serve_client=True  # ✅ add this
)

# -----------------------------
# Redis connection
# -----------------------------
# ✅ Best practice: store these in env vars (do NOT hardcode secrets in code)
REDIS_HOST = os.environ.get("REDIS_HOST", "redis-13709.c10.us-east-1-2.ec2.cloud.redislabs.com")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "13709"))
REDIS_USERNAME = os.environ.get("REDIS_USERNAME", "default")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "rI14amESBaN6Rnwt1Fjh2fCcIor5Bz43")
REDIS_DB = int(os.environ.get("REDIS_DB", "0"))

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    username=REDIS_USERNAME,
    password=REDIS_PASSWORD,
    db=REDIS_DB,
    decode_responses=True
)

# -----------------------------
# Config
# -----------------------------
SESSION_EXPIRY_SECONDS = 86400  # 24 hours
ONLINE_STATUS_TTL = 60          # user considered offline if no ping in this ttl


# -----------------------------
# Helpers
# -----------------------------
def get_db():
    return SessionLocal()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def parse_expiration_time(expiration_str: str) -> int:
    """Parse expiration time string (e.g., '10s', '1m', '1h', '1d') to seconds."""
    expiration_str = (expiration_str or "").strip().lower()
    if not expiration_str:
        return 3600

    if expiration_str.endswith("s"):
        return int(expiration_str[:-1])
    if expiration_str.endswith("m"):
        return int(expiration_str[:-1]) * 60
    if expiration_str.endswith("h"):
        return int(expiration_str[:-1]) * 3600
    if expiration_str.endswith("d"):
        return int(expiration_str[:-1]) * 86400

    # Default: treat as seconds
    return int(expiration_str)


def require_session(f):
    """Decorator to require valid Redis session.

    ✅ Handles OPTIONS without auth (preflight).
    ✅ Returns JSON 401 for API routes / JSON requests.
    ✅ Redirects for browser page routes.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Allow CORS preflight to pass
        if request.method == "OPTIONS":
            return ("", 204)

        print(f"[DEBUG] require_session called for {request.path}")
        print(f"[DEBUG] Request method: {request.method}")
        print(f"[DEBUG] Request is_json: {request.is_json}")

        session_id = session.get("session_id")
        print(f"[DEBUG] Session ID from session: {session_id}")

        is_api = request.path.startswith("/api/") or request.is_json

        if not session_id:
            print("[DEBUG] No session ID found")
            if is_api:
                return jsonify({"error": "Not authenticated"}), 401
            flash("Please login to access this page", "error")
            return redirect(url_for("login"))

        username = redis_client.get(f"session:{session_id}")
        print(f"[DEBUG] Username from Redis: {username}")

        if not username:
            print("[DEBUG] Username not found in Redis, clearing session")
            session.clear()
            if is_api:
                return jsonify({"error": "Session expired"}), 401
            flash("Session expired. Please login again", "error")
            return redirect(url_for("login"))

        # Refresh session TTL
        redis_client.expire(f"session:{session_id}", SESSION_EXPIRY_SECONDS)
        print(f"[DEBUG] Session validated for user: {username}")

        return f(*args, **kwargs)

    return decorated_function


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("register.html")

        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters", "error")
            return render_template("register.html")

        if not username.replace("_", "").isalnum():
            flash("Username can only contain letters, numbers, and underscores", "error")
            return render_template("register.html")

        db = get_db()
        try:
            existing_user = db.query(User).filter_by(username=username).first()
            if existing_user:
                flash("Username already taken", "error")
                return render_template("register.html")

            new_user = User(username=username, password_hash=hash_password(password))
            db.add(new_user)
            db.commit()

            flash("Registration successful! Please login", "success")
            return redirect(url_for("login"))
        except Exception as e:
            print(f"[ERROR] register failed: {e}")
            db.rollback()
            flash("Registration failed. Please try again", "error")
            return render_template("register.html")
        finally:
            db.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("login.html")

        db = get_db()
        try:
            user = db.query(User).filter_by(username=username).first()
            print(user)

            if not user or not verify_password(password, user.password_hash):
                flash("Invalid username or password", "error")
                return render_template("login.html")

            # Create session
            session_id = secrets.token_urlsafe(32)
            redis_client.setex(f"session:{session_id}", SESSION_EXPIRY_SECONDS, username)

            session["session_id"] = session_id
            session["username"] = username

            flash("Login successful!", "success")
            return redirect(url_for("chat"))
        except Exception as e:
            print(f"[ERROR] login failed: {e}")
            flash("Login failed. Please try again", "error")
            return render_template("login.html")
        finally:
            db.close()

    return render_template("login.html")


@app.route("/chat")
@require_session
def chat():
    username = session.get("username")
    print(f"[DEBUG] Rendering chat template for user: {username}")
    return render_template("chat.html", username=username)


@app.route("/api/search-users", methods=["POST", "OPTIONS"])
@require_session
def search_users():
    """Search for users by username."""
    print("[DEBUG] search_users endpoint called")

    current_username = session.get("username")
    print(f"[DEBUG] Current username from session: {current_username}")

    if not current_username:
        return jsonify({"error": "Not authenticated", "users": []}), 401

    # Prefer JSON; fallback to form
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or request.form.get("query") or "").strip()
    print(f"[DEBUG] Search query: '{query}'")

    if not query or len(query) < 2:
        return jsonify({"users": []})

    db = get_db()
    try:
        users = (
            db.query(User)
            .filter(
                and_(
                    func.lower(User.username).like(f"%{query.lower()}%"),
                    User.username != current_username
                )
            )
            .limit(10)
            .all()
        )

        user_list = []
        for user in users:
            is_online = redis_client.exists(f"online:{user.username}")
            user_list.append({"username": user.username, "online": bool(is_online)})

        return jsonify({"users": user_list})
    except Exception as e:
        print(f"[ERROR] Database error in search_users: {e}")
        return jsonify({"error": "Database error", "users": []}), 500
    finally:
        db.close()


@app.route("/api/recent-users", methods=["GET", "OPTIONS"])
@require_session
def recent_users():
    """Get all users (excluding current user)."""
    print("[DEBUG] recent_users endpoint called")

    current_username = session.get("username")
    print(f"[DEBUG] Current username from session: {current_username}")

    if not current_username:
        return jsonify({"error": "Not authenticated", "users": []}), 401

    db = get_db()
    try:
        users = (
            db.query(User)
            .filter(User.username != current_username)
            .order_by(User.created_at.desc())
            .all()
        )

        user_list = []
        for user in users:
            is_online = redis_client.exists(f"online:{user.username}")
            user_list.append({
                "username": user.username,
                "online": bool(is_online),
                "created_at": user.created_at.isoformat() if user.created_at else None
            })

        print(f"[DEBUG] Returning {len(user_list)} users")
        return jsonify({"users": user_list})
    except Exception as e:
        print(f"[ERROR] Database error in recent_users: {e}")
        return jsonify({"error": "Database error", "users": []}), 500
    finally:
        db.close()


@app.route("/profile")
@require_session
def profile():
    username = session.get("username")

    db = get_db()
    try:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            flash("User not found", "error")
            return redirect(url_for("chat"))

        is_online = redis_client.exists(f"online:{username}")

        account_age_days = None
        if user.created_at:
            account_age_days = (datetime.utcnow() - user.created_at).days

        user_stats = {
            "username": user.username,
            "created_at": user.created_at,
            "is_online": bool(is_online),
            "account_age_days": account_age_days
        }

        return render_template("profile.html", user=user, stats=user_stats)
    finally:
        db.close()


@app.route("/logout")
def logout():
    username = session.get("username")
    session_id = session.get("session_id")

    if session_id:
        redis_client.delete(f"session:{session_id}")
    if username:
        redis_client.delete(f"online:{username}")

    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for("login"))


# -----------------------------
# WebSocket events
# -----------------------------
@socketio.on("connect")
def handle_connect():
    session_id = session.get("session_id")
    username = session.get("username")

    if not session_id or not username:
        disconnect()
        return False

    stored_username = redis_client.get(f"session:{session_id}")
    if not stored_username or stored_username != username:
        disconnect()
        return False

    redis_client.setex(f"online:{username}", ONLINE_STATUS_TTL, "1")
    join_room(username)

    emit("connected", {"username": username, "status": "online"})
    socketio.emit("user_status", {"username": username, "status": "online"}, include_self=False)


@socketio.on("disconnect")
def handle_disconnect():
    username = session.get("username")
    if username:
        redis_client.delete(f"online:{username}")
        socketio.emit("user_status", {"username": username, "status": "offline"})


@socketio.on("ping")
def handle_ping():
    username = session.get("username")
    if username:
        redis_client.setex(f"online:{username}", ONLINE_STATUS_TTL, "1")
        emit("pong")


@socketio.on("start_chat")
def handle_start_chat(data):
    username = session.get("username")
    other_username = (data or {}).get("username")

    if not username or not other_username:
        emit("error", {"message": "Invalid request"})
        return

    db = get_db()
    try:
        other_user = db.query(User).filter_by(username=other_username).first()
        if not other_user:
            emit("error", {"message": "User not found"})
            return

        room = ":".join(sorted([username, other_username]))
        join_room(room)

        messages = get_chat_messages(room)

        emit("chat_started", {
            "room": room,
            "other_user": other_username,
            "messages": messages
        })
    finally:
        db.close()


@socketio.on("send_message")
def handle_send_message(data):
    username = session.get("username")
    room = (data or {}).get("room")
    message_text = ((data or {}).get("message") or "").strip()
    expiration_str = (data or {}).get("expiration", "1h")

    if not username or not room or not message_text:
        emit("error", {"message": "Invalid message data"})
        return

    usernames = room.split(":")
    if username not in usernames:
        emit("error", {"message": "Unauthorized"})
        return

    try:
        expiration_seconds = parse_expiration_time(expiration_str)
    except Exception:
        expiration_seconds = 3600

    message_id = secrets.token_urlsafe(16)
    now = datetime.utcnow()
    message_data = {
        "id": message_id,
        "room": room,
        "from": username,
        "message": message_text,
        "timestamp": now.isoformat(),
        "expiration": expiration_seconds,
        "expires_at": (now + timedelta(seconds=expiration_seconds)).isoformat()
    }

    redis_key = f"message:{room}:{message_id}"
    redis_client.setex(redis_key, expiration_seconds, json.dumps(message_data))

    chat_key = f"chat:{room}:messages"
    redis_client.lpush(chat_key, message_id)
    redis_client.expire(chat_key, expiration_seconds)

    socketio.emit("new_message", message_data, room=room)

    emit("message_sent", {"message_id": message_id, "time_remaining": expiration_seconds})


@socketio.on("leave_chat")
def handle_leave_chat(data):
    room = (data or {}).get("room")
    if room:
        leave_room(room)


def get_chat_messages(room: str):
    chat_key = f"chat:{room}:messages"
    message_ids = redis_client.lrange(chat_key, 0, -1)

    messages = []
    for msg_id in message_ids:
        msg_key = f"message:{room}:{msg_id}"
        msg_data = redis_client.get(msg_key)
        if not msg_data:
            continue

        try:
            msg = json.loads(msg_data)
            expires_at = datetime.fromisoformat(msg["expires_at"])
            remaining = int((expires_at - datetime.utcnow()).total_seconds())
            if remaining > 0:
                msg["time_remaining"] = remaining
                messages.append(msg)
        except Exception:
            continue

    messages.sort(key=lambda x: x["timestamp"])
    return messages


# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    try:
        redis_client.ping()
        print("✓ Redis connection successful")
    except redis.ConnectionError:
        print("✗ Redis connection failed. Please check Redis configuration.")
        raise SystemExit(1)

    print("🚀 Starting Flask-SocketIO server...")
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
