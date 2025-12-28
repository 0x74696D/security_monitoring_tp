#!/bin/bash
# Brute Force Test Script - Simulates multiple failed login attempts followed by success
# This script is for security testing and demonstration purposes
# Usage: ./bruteforce-test.sh <API_KEY> <API_URL> <TARGET_EMAIL> <CORRECT_PASSWORD>

set -e

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <IDENTITY_PLATFORM_API_KEY> <API_GATEWAY_URL> <TARGET_EMAIL> <CORRECT_PASSWORD>"
    echo ""
    echo "Example:"
    echo "  ./bruteforce-test.sh AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXX https://gateway-xxxxx-uc.a.run.app victim@example.com Password123"
    exit 1
fi

API_KEY="$1"
API_URL="$2"
TARGET_EMAIL="$3"
CORRECT_PASSWORD="$4"

# Remove trailing slash from URL
API_URL="${API_URL%/}"

echo "================================================"
echo "Brute Force Attack Simulation"
echo "================================================"
echo ""
echo "Configuration:"
echo "  API URL: $API_URL"
echo "  Target Email: $TARGET_EMAIL"
echo "  Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""
echo "⚠️  WARNING: This is a security test simulation"
echo ""

# Common weak passwords for testing
WEAK_PASSWORDS=(
    "123456"
    "password"
    "12345678"
    "qwerty"
    "123456789"
    "12345"
    "1234"
    "111111"
    "1234567"
    "dragon"
    "123123"
    "baseball"
    "iloveyou"
    "trustno1"
    "1234567890"
    "superman"
    "qazwsx"
    "michael"
    "Football"
    "password123"
)

# Step 1: Create target user account (if it doesn't exist)
echo "Step 1: Creating target user account..."
echo "---------------------------------------"
SIGNUP_RESPONSE=$(curl -s -X POST \
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TARGET_EMAIL\",\"password\":\"$CORRECT_PASSWORD\",\"returnSecureToken\":true}")

USER_ID=$(echo "$SIGNUP_RESPONSE" | jq -r '.localId')

if [ "$USER_ID" = "null" ] || [ -z "$USER_ID" ]; then
    # User might already exist, try to get user info
    echo "⚠️  User may already exist (or sign up failed)"
    echo "$SIGNUP_RESPONSE" | jq '.'
else
    echo "✅ Target user created: $TARGET_EMAIL"
    echo "   User ID: $USER_ID"
fi
echo ""

# Step 2: Simulate failed login attempts
echo "Step 2: Simulating Brute Force Attack (Failed Attempts)"
echo "--------------------------------------------------------"
echo "Attempting login with common weak passwords..."
echo ""

FAILED_COUNT=0
ATTEMPT_NUM=0

for password in "${WEAK_PASSWORDS[@]}"; do
    ATTEMPT_NUM=$((ATTEMPT_NUM + 1))
    
    echo "[Attempt $ATTEMPT_NUM] Trying password: '$password'"
    
    # Attempt login with incorrect password
    LOGIN_RESPONSE=$(curl -s -X POST \
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=$API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$TARGET_EMAIL\",\"password\":\"$password\",\"returnSecureToken\":true}")
    
    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.idToken')
    ERROR_CODE=$(echo "$LOGIN_RESPONSE" | jq -r '.error.code // empty')
    ERROR_MESSAGE=$(echo "$LOGIN_RESPONSE" | jq -r '.error.message // empty')
    
    if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
        # Failed attempt - log it via the API
        echo "  ❌ Failed: $ERROR_MESSAGE"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        
        # Log the failed attempt to the audit endpoint
        curl -s -X POST \
            "$API_URL/auth/audit" \
            -H "Content-Type: application/json" \
            -d "{\"action\":\"login\",\"outcome\":\"failure\",\"email\":\"$TARGET_EMAIL\",\"reason\":\"invalid_password\",\"attempted_password\":\"$password\"}" > /dev/null
        
        # Small delay between attempts to simulate realistic timing
        sleep 0.5
    else
        echo "  ✅ Unexpected success with weak password!"
        break
    fi
done

echo ""
echo "Summary of failed attempts: $FAILED_COUNT failures"
echo ""

# Step 3: Successful login with correct password
echo "Step 3: Successful Login (Correct Password)"
echo "--------------------------------------------"
echo "Attempting login with correct password..."

SUCCESS_RESPONSE=$(curl -s -X POST \
    "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=$API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TARGET_EMAIL\",\"password\":\"$CORRECT_PASSWORD\",\"returnSecureToken\":true}")

SUCCESS_TOKEN=$(echo "$SUCCESS_RESPONSE" | jq -r '.idToken')
SUCCESS_USER_ID=$(echo "$SUCCESS_RESPONSE" | jq -r '.localId')

if [ "$SUCCESS_TOKEN" = "null" ] || [ -z "$SUCCESS_TOKEN" ]; then
    echo "❌ Login failed even with correct password"
    echo "$SUCCESS_RESPONSE" | jq '.'
    exit 1
fi

echo "✅ Successfully logged in!"
echo "   User ID: $SUCCESS_USER_ID"
echo ""

# Log the successful login attempt
echo "Logging successful authentication..."
AUDIT_RESPONSE=$(curl -s -X POST \
    "$API_URL/auth/audit" \
    -H "Authorization: Bearer $SUCCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"action":"login","outcome":"success"}')

echo "$AUDIT_RESPONSE" | jq '.'
echo ""

# Step 4: Test authenticated endpoint access
echo "Step 4: Testing Authenticated Access"
echo "-------------------------------------"
PROFILE_RESPONSE=$(curl -s -H "Authorization: Bearer $SUCCESS_TOKEN" "$API_URL/profile")
echo "$PROFILE_RESPONSE" | jq '.'
echo ""

# Step 5: Summary and investigation instructions
echo "================================================"
echo "Brute Force Attack Simulation Complete"
echo "================================================"
echo ""
echo "Attack Summary:"
echo "  Target Email: $TARGET_EMAIL"
echo "  Failed Attempts: $FAILED_COUNT"
echo "  Final Result: SUCCESS"
echo "  User ID: $SUCCESS_USER_ID"
echo ""
echo "🔍 Detection and Investigation:"
echo "--------------------------------"
echo ""
echo "View authentication audit logs:"
echo "  gcloud logging read 'resource.type=cloud_function AND jsonPayload.event_type=\"auth_audit\" AND jsonPayload.email=\"$TARGET_EMAIL\"' --limit 50 --format json"
echo ""
echo "View failed login attempts:"
echo "  gcloud logging read 'resource.type=cloud_function AND jsonPayload.event_type=\"auth_audit\" AND jsonPayload.result=\"failure\" AND jsonPayload.email=\"$TARGET_EMAIL\"' --limit 50 --format json"
echo ""
echo "Count failed attempts in last hour:"
echo "  gcloud logging read 'resource.type=cloud_function AND jsonPayload.event_type=\"auth_audit\" AND jsonPayload.result=\"failure\" AND jsonPayload.email=\"$TARGET_EMAIL\" AND timestamp>=\"$(date -u -v-1H '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%SZ')\"' --format json | grep -c '\"result\": \"failure\"'"
echo ""
echo "View all access attempts from source IP:"
echo "  gcloud logging read 'resource.type=cloud_function AND jsonPayload.source_ip=\"<IP_ADDRESS>\"' --limit 50 --format json"
echo ""
echo "BigQuery investigation (if logs exported):"
echo "  SELECT"
echo "    timestamp,"
echo "    jsonPayload.email,"
echo "    jsonPayload.result,"
echo "    jsonPayload.source_ip,"
echo "    jsonPayload.action"
echo "  FROM \`<project>.<dataset>.cloudaudit_googleapis_com_data_access\`"
echo "  WHERE jsonPayload.email = '$TARGET_EMAIL'"
echo "    AND jsonPayload.event_type = 'auth_audit'"
echo "  ORDER BY timestamp DESC"
echo "  LIMIT 100;"
echo ""
echo "⚠️  Security Best Practices:"
echo "  - Implement rate limiting after N failed attempts"
echo "  - Add CAPTCHA after multiple failures"
echo "  - Alert on brute force patterns"
echo "  - Consider account lockout policies"
echo "  - Monitor for distributed attacks from multiple IPs"
echo ""

