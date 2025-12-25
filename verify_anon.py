import sys
import os
import json
import secrets
from datetime import datetime
import redis

# Redis connection (matching app.py defaults)
REDIS_HOST = os.environ.get("REDIS_HOST", "redis-13709.c10.us-east-1-2.ec2.cloud.redislabs.com")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "13709"))
REDIS_USERNAME = os.environ.get("REDIS_USERNAME", "default")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "rI14amESBaN6Rnwt1Fjh2fCcIor5Bz43")
REDIS_DB = int(os.environ.get("REDIS_DB", "0"))

try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        username=REDIS_USERNAME,
        password=REDIS_PASSWORD,
        db=REDIS_DB,
        decode_responses=True
    )
    redis_client.ping()
    print("Redis connected successfully.")
except Exception as e:
    print(f"Redis connection failed: {e}")
    sys.exit(1)

def test_anon_flow():
    sender = "tester_sender"
    recipient = "tester_recv"
    
    print(f"Testing Anon Flow: {sender} -> {recipient}")
    
    # 1. Simulate Send
    msg_id = secrets.token_hex(8)
    msg_data = {
        "id": msg_id,
        "message": "Hello Secret World",
        "timestamp": datetime.utcnow().isoformat(),
        "expires_in": 3600
    }
    
    print(f"Sending message {msg_id}...")
    # Logic from send_anonymous_message
    redis_client.setex(f"anon:msg:{msg_id}", 3600, json.dumps(msg_data))
    redis_client.lpush(f"anon:ids:{recipient}", msg_id)
    
    # Verify Redis state directly
    print("Verifying Redis State...")
    stored_ids = redis_client.lrange(f"anon:ids:{recipient}", 0, -1)
    print(f"IDs in redis for {recipient}: {stored_ids}")
    
    if msg_id not in stored_ids:
        print("FAIL: Message ID not found in recipient list")
        return
        
    stored_msg = redis_client.get(f"anon:msg:{msg_id}")
    if not stored_msg:
        print("FAIL: Message content not found in Redis")
        return
    print(f"Message content found: {stored_msg}")
    
    # 2. Simulate Inbox Retrieve
    print("Simulating Inbox Retrieval...")
    # Logic from anonymous_inbox
    username = recipient
    
    msg_ids = redis_client.lrange(f"anon:ids:{username}", 0, -1)
    messages = []
    
    for mid in msg_ids:
        raw = redis_client.get(f"anon:msg:{mid}")
        if raw:
            messages.append(json.loads(raw))
        else:
             print(f"Warn: msg {mid} expired or missing")
            
    print(f"Retrieved {len(messages)} messages.")
    if len(messages) > 0:
        print("SUCCESS: Flow verified.")
        # print("Inbox content:", messages)
    else:
        print("FAIL: No messages retrieved.")

if __name__ == "__main__":
    try:
        test_anon_flow()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
