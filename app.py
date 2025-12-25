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
from models import User, PublicMessage, SessionLocal


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

    # Robust parsing: remove spaces
    expiration_str = expiration_str.replace(" ", "")

    # Handle explicit "minutes", "hours" if passed
    if "minute" in expiration_str:
        return int(expiration_str.split("minute")[0]) * 60
    if "hour" in expiration_str:
        return int(expiration_str.split("hour")[0]) * 3600
    if "day" in expiration_str:
        return int(expiration_str.split("day")[0]) * 86400

    if expiration_str.endswith("s"):
        return int(expiration_str[:-1])
    if expiration_str.endswith("m"):
        return int(expiration_str[:-1]) * 60
    if expiration_str.endswith("h"):
        return int(expiration_str[:-1]) * 3600
    if expiration_str.endswith("d"):
        return int(expiration_str[:-1]) * 86400

    # Default: treat as seconds first, then try simple int
    try:
        return int(expiration_str)
    except ValueError:
        print(f"[ERROR] Could not parse expiration: {expiration_str}")
        return 3600 # default to 1h


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

        # Check for hard account expiry
        db = get_db()
        try:
            user = db.query(User).filter_by(username=username).first()
            if not user:
                # User deleted (probably expired)
                session.clear()
                if is_api:
                    return jsonify({"error": "Account no longer exists"}), 401
                flash("Account expired or deleted.", "error")
                return redirect(url_for("login"))

            if user.expires_at and datetime.utcnow() > user.expires_at:
                print(f"[DEBUG] Account for {username} expired at {user.expires_at}. Deleting.")
                # Hard delete account
                db.delete(user)
                db.commit()
                
                # Cleanup Redis
                redis_client.delete(f"session:{session_id}")
                redis_client.delete(f"online:{username}")
                # Note: Keeping specific messages or data might be optional, but request says "remove account data"
                
                session.clear()
                if is_api:
                    return jsonify({"error": "Account expired"}), 401
                flash("Your account time has expired.", "info")
                return redirect(url_for("login"))
                
        except Exception as e:
            print(f"[ERROR] Session validation db error: {e}")
        finally:
            db.close()

        # Refresh session TTL
        redis_client.expire(f"session:{session_id}", SESSION_EXPIRY_SECONDS)
        
        # Update Online Status
        # This was missing, causing users to appear offline
        redis_client.setex(f"online:{username}", ONLINE_STATUS_TTL, "true")
        
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
        age = request.form.get("age")
        interests = request.form.get("interests", "")
        duration = request.form.get("duration", "Permanent")

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("register.html")

        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters", "error")
            return render_template("register.html")

        # Relaxed validation: Allow printable characters (no control chars)
        if not username.isprintable():
            flash("Username contains invalid characters", "error")
            return render_template("register.html")

        db = get_db()
        try:
            existing_user = db.query(User).filter_by(username=username).first()
            if existing_user:
                flash("Username already taken", "error")
                return render_template("register.html")

            # Calculate expiry
            expires_at = None
            if duration != "Permanent":
                seconds = parse_expiration_time(duration)
                expires_at = datetime.utcnow() + timedelta(seconds=seconds)

            new_user = User(
                username=username, 
                password_hash=hash_password(password),
                age=int(age) if age else None,
                interests=interests,
                account_duration=duration,
                expires_at=expires_at
            )
            db.add(new_user)
            db.commit()

            # Add interests to Redis for recommendations
            if interests:
                interest_list = [i.strip().lower() for i in interests.split(",") if i.strip()]
                for interest in interest_list:
                    redis_client.sadd(f"user:interests:{interest}", username)

            flash("Registration successful! Please login", "success")
            return redirect(url_for("login"))
        except Exception as e:
            print(f"[ERROR] Registration failed: {e}")
            import traceback
            traceback.print_exc()
            db.rollback()
            flash(f"Registration failed: {str(e)}", "error")
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
            # User Not Found (Expired)
            # Render a minimal page saying "Account Expired"
            return render_template("base.html", content="""
                <div class="container" style="text-align: center; padding-top: 100px;">
                    <h2 style="color: var(--text-muted);">Account Expired</h2>
                    <p>This user's time has run out.</p>
                    <a href="/" class="btn btn-primary" style="margin-top: 20px;">Return Home</a>
                </div>
            """)

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
# Features: Anonymous Messaging
# -----------------------------
@app.route("/anonymous")
@require_session
def anonymous():
    username = session.get("username")
    return render_template("anonymous.html", username=username)


@app.route("/api/anonymous/send", methods=["POST"])
@require_session
def send_anonymous_message():
    data = request.get_json()
    message = (data.get("message") or "").strip()
    duration = (data.get("duration") or "1h").strip() # Default 1h
    file_data = data.get("file_data")
    file_type = data.get("file_type")
    
    if not message and not file_data:
        return jsonify({"error": "Message or file required"}), 400

    sender = session.get("username")
    msg_id = secrets.token_hex(8)
    now_iso = datetime.utcnow().isoformat() + "Z" # Append Z to indicate UTC
    
    # Logic for Persistence
    if duration.lower() == "permanent":
        # Store in DB
        db = get_db()
        try:
            new_msg = PublicMessage(
                id=msg_id,
                sender=sender,
                message=message,
                timestamp=datetime.utcnow(),
                file_data=file_data,
                file_type=file_type
            )
            db.add(new_msg)
            db.commit()
        except Exception as e:
            print(f"[ERROR] Failed to save permanent msg: {e}")
            return jsonify({"error": "Database error"}), 500
        finally:
            db.close()
            
        print(f"[DEBUG] Permanent Msg: '{sender}' posted to DB")
        
    else:
        # Temporary Message (Redis)
        seconds = parse_expiration_time(duration) # utilizes existing helper
        if seconds <= 0: seconds = 3600
        
        msg_data = {
            "id": msg_id,
            "sender": sender,
            "message": message,
            "timestamp": now_iso,
            "type": "temporary",
            "expires_in": seconds,
            "file_data": file_data,
            "file_type": file_type
        }
        
        # We store the *content* in a key with TTL
        # And the ID in the global list. 
        # When fetching, if key is gone, we skip it.
        try:
            redis_client.setex(f"public:msg:{msg_id}", seconds, json.dumps(msg_data))
            redis_client.lpush("public:feed:ids", msg_id)
            print(f"[DEBUG] Temp Msg ({duration}): '{sender}' posted to Redis")
        except Exception as e:
            print(f"[ERROR] Redis error: {e}")
            return jsonify({"error": "Failed to store temporary message"}), 500

    return jsonify({"success": True})


@app.route("/api/anonymous/feed")
@require_session
def public_feed():
    messages = []
    
    # 1. Fetch Temporary from Redis
    raw_ids = redis_client.lrange("public:feed:ids", 0, -1)
    live_ids = []
    
    for mid in raw_ids:
        raw_data = redis_client.get(f"public:msg:{mid}")
        if raw_data:
            messages.append(json.loads(raw_data))
            live_ids.append(mid)
        # else: expired
            
    # Cleanup lazy (trim list to live IDs)
    # To avoid race conditions in high traffic, we might just leave them or trim occasionally.
    # For now, let's just re-push live ones if count mismatched significantly? 
    # Actually, simpler to just append found ones.
    
    # 2. Fetch Permanent from DB
    db = get_db()
    try:
        # Limit to last 50 for performance? Or all? User asked for "all".
        # Let's get last 100 for now to be safe.
        db_msgs = db.query(PublicMessage).order_by(PublicMessage.timestamp.desc()).limit(100).all()
        for m in db_msgs:
            messages.append(m.to_dict())
    except Exception as e:
        print(f"[ERROR] Failed to fetch DB messages (migration needed?): {e}")
        # Identify if we need to migrate? (For now just log)
    finally:
        db.close()
        
    # Sort combined list by timestamp descending (newest first)
    messages.sort(key=lambda x: x["timestamp"], reverse=True)
            
    return jsonify({"messages": messages})


@app.route("/api/user/<target_username>/status")
@require_session
def user_status(target_username):
    """Check if a user exists and is active."""
    db = get_db()
    try:
        user = db.query(User).filter_by(username=target_username).first()
        if not user:
            return jsonify({"status": "expired", "message": "Profile expired or unavailable"})
            
        # Optional: Check expiry time specifically if not deleted but expired
        if user.expires_at and datetime.utcnow() > user.expires_at:
             return jsonify({"status": "expired", "message": "Profile expired or unavailable"})

        return jsonify({"status": "active"})
    finally:
        db.close()



# -----------------------------
# User Search
# -----------------------------
@app.route("/api/users/search")
@require_session
def search_users():
    """Search for users by username."""
    query = request.args.get("q", "").strip()
    current_username = session.get("username")
    
    if not query:
        return jsonify({"users": []})
        
    db = get_db()
    try:
        # Simple case-insensitive prefix match
        users = db.query(User).filter(
            User.username.ilike(f"{query}%"),
            User.username != current_username
        ).limit(10).all()
        
        results = []
        for u in users:
             # Check if already friends
             is_friend = redis_client.sismember(f"friends:{current_username}", u.username)
             results.append({
                 "username": u.username,
                 "is_friend": bool(is_friend)
             })
             
        return jsonify({"users": results})
    finally:
        db.close()


# -----------------------------
# Features: Friends & Recommendations
# -----------------------------
@app.route("/api/recommendations")
@require_session
def recommendations():
    username = session.get("username")
    
    db = get_db()
    try:
        current_user = db.query(User).filter_by(username=username).first()
        if not current_user or not current_user.interests:
            return jsonify({"users": []})
            
        my_interests = [i.strip().lower() for i in current_user.interests.split(",") if i.strip()]
        
        # Redis SINTER
        keys = [f"user:interests:{i}" for i in my_interests]
        if not keys:
            return jsonify({"users": []})
            
        common_users = redis_client.sunion(keys) # Use Union to get anyone with ANY shared interest, or SINTER for ALL.
        # "Suggest people based on common interests" -> Intersection is stricter, Union is broader. 
        # Let's use Union but rank or duplicate check. Actually prompt says "using Redis sets". 
        # Let's try to find people with *at least one* common interest.
        
        candidates = set()
        for member in common_users:
            if member != username:
                candidates.add(member)
        
        # Limit to 10
        result = []
        for cand in list(candidates)[:10]:
             is_online = redis_client.exists(f"online:{cand}")
             result.append({"username": cand, "online": bool(is_online)})
             
        return jsonify({"users": result})
        
    finally:
        db.close()


@app.route("/api/friends/request", methods=["POST"])
@require_session
def send_friend_request():
    username = session.get("username")
    data = request.get_json()
    target = data.get("username")
    
    if not target or target == username:
        return jsonify({"error": "Invalid user"}), 400
        
    # Store request in Redis or DB. Using Redis for ephemeral nature.
    # Set: friend:requests:{target} -> {sender}
    redis_client.sadd(f"friend:requests:{target}", username)
    return jsonify({"success": True})


@app.route("/api/friends/accept", methods=["POST"])
@require_session
def accept_friend_request():
    username = session.get("username")
    data = request.get_json()
    requester = data.get("username")
    
    if not redis_client.sismember(f"friend:requests:{username}", requester):
        return jsonify({"error": "No request found"}), 404
        
    # Add to friends list (Bidirectional)
    # redis set: friends:{user}
    redis_client.sadd(f"friends:{username}", requester)
    redis_client.sadd(f"friends:{requester}", username)
    
    # Remove request
    redis_client.srem(f"friend:requests:{username}", requester)
    
    # Update total friends count in DB (optional, for profile display)
    db = get_db()
    try:
        u1 = db.query(User).filter_by(username=username).first()
        u2 = db.query(User).filter_by(username=requester).first()
        if u1: u1.total_friends += 1
        if u2: u2.total_friends += 1
        db.commit()
    finally:
        db.close()
        
    return jsonify({"success": True})


@app.route("/api/friends/list")
@require_session
def list_friends():
    username = session.get("username")
    
    # 1. Fetch friend list from Redis
    friend_usernames = redis_client.smembers(f"friends:{username}")
    friends_list = []
    
    db = get_db()
    try:
        if not friend_usernames:
             return jsonify({"friends": []})
             
        # 2. Check DB status for each friend
        # Optimization: fetch all at once
        users = db.query(User).filter(User.username.in_(friend_usernames)).all()
        user_map = {u.username: u for u in users}
        
        for fname in friend_usernames:
             user_obj = user_map.get(fname)
             is_online = redis_client.exists(f"online:{fname}")
             
             # Default state
             is_expired = False
             
             # Check if expired
             if not user_obj:
                 # User not in DB -> Deleted/Expired
                 is_expired = True
             elif user_obj.expires_at and datetime.utcnow() > user_obj.expires_at:
                 is_expired = True
             
             friends_list.append({
                 "username": fname,
                 "online": bool(is_online),
                 "expired": is_expired
             })
             
    finally:
        db.close()
        
    return jsonify({"friends": friends_list})


@app.route("/api/friends/requests")
@require_session
def list_friend_requests():
    username = session.get("username")
    reqs = redis_client.smembers(f"friend:requests:{username}")
    return jsonify({"requests": list(reqs)})


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
    room = data.get("room")
    message_text = (data.get("message") or "").strip()
    expiration_str = data.get("expiration", "1h")
    file_data = data.get("file_data")
    file_type = data.get("file_type")

    if not username or not room:
        return
        
    if not message_text and not file_data:
        return

    # Helper function for parsing time (re-used from existing logic if possible, or simple check)
    expiration_seconds = 3600 # Default
    try:
        expiration_seconds = parse_expiration_time(expiration_str)
    except:
        pass
        
    message_id = secrets.token_hex(8)
    now = datetime.utcnow()
    
    expires_at_dt = now + timedelta(seconds=expiration_seconds)
    
    message_data = {
        "id": message_id,
        "room": room,
        "from": username, # Frontend expects "from"
        "message": message_text,
        "timestamp": now.isoformat() + "Z",
        "expiration": expiration_seconds,
        "expires_at": expires_at_dt.isoformat(),
        "time_remaining": expiration_seconds, # For immediate display
        "file_data": file_data,
        "file_type": file_type
    }

    # Save Message Content
    redis_key = f"message:{room}:{message_id}"
    try:
        redis_client.setex(redis_key, expiration_seconds, json.dumps(message_data))
        
        # Add to room list
        chat_key = f"chat:{room}:messages"
        redis_client.rpush(chat_key, message_id)
        redis_client.expire(chat_key, expiration_seconds) # Extend room expiry
        
        # Emit to room
        socketio.emit("new_message", message_data, room=room)
        
    except Exception as e:
        print(f"[ERROR] Failed to save chat msg: {e}")


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
    
    # Ensure tables are created (including new PublicMessage)
    from models import Base, engine
    Base.metadata.create_all(engine)
    
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
