#!/bin/bash
# Create a Keycloak realm via Admin REST API

BASE_URL="${1:-http://localhost:8080}"
REALM_NAME="${2:-aauth-test}"
ADMIN_USER="${3:-admin}"
ADMIN_PASSWORD="${4:-admin}"

echo "Creating realm '$REALM_NAME' in Keycloak at $BASE_URL..."

# Get admin token
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASSWORD" \
  -d "grant_type=password" \
  -d "client_id=admin-cli")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
  echo ""
  echo "❌ ERROR: Failed to get admin token."
  echo ""
  echo "Possible causes:"
  echo "  1. Admin user doesn't exist yet (first-time setup)"
  echo "  2. Wrong credentials"
  echo "  3. Keycloak not fully started"
  echo ""
  echo "Solutions:"
  echo "  Option 1: Create admin user via web UI (first time only):"
  echo "    1. Open http://localhost:8080 in your browser"
  echo "    2. Fill in the form to create the admin user"
  echo "    3. Then run this script again"
  echo ""
  echo "  Option 2: Start Keycloak with bootstrap admin (recommended):"
  echo "    java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \\"
  echo "      --bootstrap-admin-username=admin \\"
  echo "      --bootstrap-admin-password=admin"
  echo ""
  echo "  Option 3: Use admin client credentials (if configured):"
  echo "    ./scripts/create_realm.sh $BASE_URL $REALM_NAME <client-id> <client-secret>"
  echo ""
  echo "Token response: $TOKEN_RESPONSE"
  exit 1
fi

# Create realm
REALM_JSON="{\"realm\":\"$REALM_NAME\",\"enabled\":true}"

CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/admin/realms" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$REALM_JSON")

HTTP_CODE=$(echo "$CREATE_RESPONSE" | tail -n1)
BODY=$(echo "$CREATE_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ]; then
  echo "✅ Realm '$REALM_NAME' created successfully!"
elif [ "$HTTP_CODE" = "409" ]; then
  echo "ℹ️  Realm '$REALM_NAME' already exists."
else
  echo "ERROR: Failed to create realm. HTTP $HTTP_CODE"
  echo "Response: $BODY"
  exit 1
fi

