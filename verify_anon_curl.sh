#!/bin/bash

# Base URL
BASE_URL="http://127.0.0.1:5000"
COOKIE_JAR="cookies.txt"
USER="anon_tester_$(date +%s)"
PASS="password123"

echo "Testing with user: $USER"

# 1. Register
echo "Registering..."
curl -s -X POST "$BASE_URL/register" \
    -d "username=$USER" \
    -d "password=$PASS" \
    -d "duration=permanent" \
    -d "interests=cURLing" \
    -c $COOKIE_JAR > /dev/null

# 2. Login
echo "Logging in..."
curl -s -X POST "$BASE_URL/login" \
    -d "username=$USER" \
    -d "password=$PASS" \
    -c $COOKIE_JAR \
    -b $COOKIE_JAR > /dev/null

# 3. Send Anon Message to Self
echo "Sending anonymous message to self..."
curl -s -X POST "$BASE_URL/api/anonymous/send" \
    -H "Content-Type: application/json" \
    -d "{\"recipient\": \"$USER\", \"message\": \"Hello from cURL\"}" \
    -c $COOKIE_JAR \
    -b $COOKIE_JAR

echo -e "\n"

# 4. Check Inbox
echo "Checking inbox..."
RESPONSE=$(curl -s "$BASE_URL/api/anonymous/inbox" \
    -c $COOKIE_JAR \
    -b $COOKIE_JAR)

echo "Inbox Response: $RESPONSE"

# Check if message exists
if [[ "$RESPONSE" == *"Hello from cURL"* ]]; then
    echo "SUCCESS: Message found in inbox!"
else
    echo "FAIL: Message not found."
fi

rm $COOKIE_JAR
