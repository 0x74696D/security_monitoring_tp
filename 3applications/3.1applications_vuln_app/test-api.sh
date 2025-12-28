#!/bin/bash
# Test script for Security Lab API
# Usage: ./test-api.sh <API_KEY> <API_URL>

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <IDENTITY_PLATFORM_API_KEY> <API_GATEWAY_URL>"
    echo ""
    echo "Example:"
    echo "  ./test-api.sh AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXX https://gateway-xxxxx-uc.a.run.app"
    exit 1
fi

API_KEY="$1"
API_URL="$2"

# Remove trailing slash from URL
API_URL="${API_URL%/}"

echo "================================================"
echo "GCP Security Lab API Test Suite"
echo "================================================"
echo ""

# Generate random test user
RANDOM_SUFFIX=$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 8)
TEST_EMAIL="testuser-${RANDOM_SUFFIX}@example.com"
TEST_PASSWORD="TestPass123!@#"

echo "Test Configuration:"
echo "  API URL: $API_URL"
echo "  Test Email: $TEST_EMAIL"
echo ""

# Test 1: Health Check
echo "Test 1: Health Check (No Auth)"
echo "------------------------------"
HEALTH_RESPONSE=$(curl -s "$API_URL/health")
echo "$HEALTH_RESPONSE" | jq '.'
if echo "$HEALTH_RESPONSE" | jq -e '.status == "healthy"' > /dev/null; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi
echo ""

# Test 2: Sign Up
echo "Test 2: User Sign Up"
echo "--------------------"
SIGNUP_RESPONSE=$(curl -s -X POST \
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"returnSecureToken\":true}")

TOKEN=$(echo "$SIGNUP_RESPONSE" | jq -r '.idToken')
USER_ID=$(echo "$SIGNUP_RESPONSE" | jq -r '.localId')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    echo "❌ Sign up failed"
    echo "$SIGNUP_RESPONSE" | jq '.'
    exit 1
fi

echo "✅ User created successfully"
echo "   User ID: $USER_ID"
echo ""

# Test 3: Get Profile
echo "Test 3: Get Profile (Authenticated)"
echo "------------------------------------"
PROFILE_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$API_URL/profile")
echo "$PROFILE_RESPONSE" | jq '.'
if echo "$PROFILE_RESPONSE" | jq -e '.user_id' > /dev/null; then
    echo "✅ Profile retrieved successfully"
else
    echo "❌ Profile retrieval failed"
    exit 1
fi
echo ""

# Test 4: Upload Image
echo "Test 4: Upload Image"
echo "--------------------"
# Create a minimal PNG file (1x1 pixel)
printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0a\x49\x44\x41\x54\x78\x9c\x63\x00\x01\x00\x00\x05\x00\x01\x0d\x0a\x2d\xb4\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82' > /tmp/test-lab-image.png
UPLOAD_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -F "image=@/tmp/test-lab-image.png" \
    "$API_URL/images/upload")

IMAGE_ID=$(echo "$UPLOAD_RESPONSE" | jq -r '.image_id')
echo "$UPLOAD_RESPONSE" | jq '.'

if [ "$IMAGE_ID" = "null" ] || [ -z "$IMAGE_ID" ]; then
    echo "❌ Image upload failed"
    exit 1
fi

echo "✅ Image uploaded successfully"
echo "   Image ID: $IMAGE_ID"
echo ""

# Test 5: Get Image (Authorized)
echo "Test 5: Get Image (Owner)"
echo "-------------------------"
GET_IMAGE_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$API_URL/images/$IMAGE_ID")
echo "$GET_IMAGE_RESPONSE" | jq '.'
if echo "$GET_IMAGE_RESPONSE" | jq -e '.signed_url' > /dev/null; then
    echo "✅ Image retrieved successfully"
else
    echo "❌ Image retrieval failed"
fi
echo ""

# Test 6: Export User Data
echo "Test 6: Export User Data"
echo "------------------------"
EXPORT_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$API_URL/export")
echo "$EXPORT_RESPONSE" | jq '.'
if echo "$EXPORT_RESPONSE" | jq -e '.images' > /dev/null; then
    IMAGE_COUNT=$(echo "$EXPORT_RESPONSE" | jq '.images | length')
    echo "✅ Export successful - $IMAGE_COUNT image(s) found"
else
    echo "❌ Export failed"
fi
echo ""

# Test 7: Admin Access (Should Fail)
echo "Test 7: Admin Access (Should be Denied)"
echo "----------------------------------------"
ADMIN_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -H "Authorization: Bearer $TOKEN" "$API_URL/admin")
HTTP_STATUS=$(echo "$ADMIN_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
ADMIN_BODY=$(echo "$ADMIN_RESPONSE" | sed '/HTTP_STATUS:/d')

echo "$ADMIN_BODY" | jq '.'
if [ "$HTTP_STATUS" = "403" ]; then
    echo "✅ Admin access correctly denied (403 Forbidden)"
else
    echo "⚠️  Unexpected status: $HTTP_STATUS (expected 403)"
fi
echo ""

# Test 8: Auth Audit Log
echo "Test 8: Log Authentication Event"
echo "---------------------------------"
AUDIT_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"action":"login","outcome":"success"}' \
    "$API_URL/auth/audit")
echo "$AUDIT_RESPONSE" | jq '.'
echo "✅ Auth audit logged"
echo ""

# Test 9: Unauthorized Access (No Token)
echo "Test 9: Unauthorized Access (No Token)"
echo "---------------------------------------"
UNAUTH_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$API_URL/profile")
HTTP_STATUS=$(echo "$UNAUTH_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
UNAUTH_BODY=$(echo "$UNAUTH_RESPONSE" | sed '/HTTP_STATUS:/d')

echo "$UNAUTH_BODY" | jq '.'
if [ "$HTTP_STATUS" = "401" ]; then
    echo "✅ Unauthorized access correctly blocked (401)"
else
    echo "⚠️  Unexpected status: $HTTP_STATUS (expected 401)"
fi
echo ""

# Test 10: Delete Image
echo "Test 10: Delete Image"
echo "---------------------"
DELETE_RESPONSE=$(curl -s -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    "$API_URL/images/$IMAGE_ID")
echo "$DELETE_RESPONSE" | jq '.'
if echo "$DELETE_RESPONSE" | jq -e '.message' > /dev/null; then
    echo "✅ Image deleted successfully"
else
    echo "❌ Image deletion failed"
fi
echo ""

# Test 11: Access Deleted Image (Should Fail)
echo "Test 11: Access Deleted Image (Should 404)"
echo "-------------------------------------------"
DELETED_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "$API_URL/images/$IMAGE_ID")
HTTP_STATUS=$(echo "$DELETED_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
DELETED_BODY=$(echo "$DELETED_RESPONSE" | sed '/HTTP_STATUS:/d')

echo "$DELETED_BODY" | jq '.'
if [ "$HTTP_STATUS" = "404" ]; then
    echo "✅ Deleted image correctly returns 404"
else
    echo "⚠️  Unexpected status: $HTTP_STATUS (expected 404)"
fi
echo ""

# Cleanup
rm -f /tmp/test-lab-image.txt

echo "================================================"
echo "✅ Test Suite Complete!"
echo "================================================"
echo ""
echo "Test Summary:"
echo "  Test User: $TEST_EMAIL"
echo "  User ID: $USER_ID"
echo "  Image ID: $IMAGE_ID (deleted)"
echo ""
echo "View logs with:"
echo "  gcloud logging read 'resource.type=cloud_function AND jsonPayload.user_id=\"$USER_ID\"' --limit 20 --format json"
echo ""

