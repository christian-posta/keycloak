#!/bin/bash
# Set AAuth consent-required scopes and scope prefixes via Admin REST API

BASE_URL="${1:-http://localhost:8080}"
REALM_NAME="${2:-aauth-test}"
ADMIN_USER="${3:-admin}"
ADMIN_PASSWORD="${4:-admin}"

# Default consent-required scopes (matches current hardcoded behavior)
DEFAULT_CONSENT_SCOPES='["openid","profile","email"]'
DEFAULT_CONSENT_PREFIXES='["user.","profile.","email."]'

# Allow override via environment variables
CONSENT_SCOPES="${AAUTH_CONSENT_SCOPES:-$DEFAULT_CONSENT_SCOPES}"
CONSENT_PREFIXES="${AAUTH_CONSENT_PREFIXES:-$DEFAULT_CONSENT_PREFIXES}"

echo "Setting AAuth consent attributes for realm '$REALM_NAME' in Keycloak at $BASE_URL..."
echo "  Consent-required scopes: $CONSENT_SCOPES"
echo "  Consent-required prefixes: $CONSENT_PREFIXES"
echo ""

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
  echo "    1. Open $BASE_URL in your browser"
  echo "    2. Fill in the form to create the admin user"
  echo "    3. Then run this script again"
  echo ""
  echo "  Option 2: Start Keycloak with bootstrap admin (recommended):"
  echo "    java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \\"
  echo "      --bootstrap-admin-username=$ADMIN_USER \\"
  echo "      --bootstrap-admin-password=$ADMIN_PASSWORD"
  echo ""
  echo "Token response: $TOKEN_RESPONSE"
  exit 1
fi

# Get current realm
REALM_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/admin/realms/$REALM_NAME" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json")

HTTP_CODE=$(echo "$REALM_RESPONSE" | tail -n1)
REALM_JSON=$(echo "$REALM_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
  echo "❌ ERROR: Failed to get realm '$REALM_NAME'. HTTP $HTTP_CODE"
  echo "Response: $REALM_JSON"
  echo ""
  echo "Make sure the realm exists. You can create it with:"
  echo "  ./scripts/create_realm.sh $BASE_URL $REALM_NAME"
  exit 1
fi

# Check if jq is available for JSON manipulation
if command -v jq >/dev/null 2>&1; then
  # Use jq to merge attributes
  UPDATED_REALM_JSON=$(echo "$REALM_JSON" | jq --arg scopes "$CONSENT_SCOPES" --arg prefixes "$CONSENT_PREFIXES" '
    .attributes = (.attributes // {}) |
    .attributes["aauth.consent.required.scopes"] = $scopes |
    .attributes["aauth.consent.required.scope.prefixes"] = $prefixes
  ')
  
  if [ $? -ne 0 ]; then
    echo "❌ ERROR: Failed to update realm JSON with jq"
    exit 1
  fi
else
  # Fallback: Use sed/awk to merge attributes (simpler but less robust)
  echo "⚠️  Warning: jq not found. Using basic JSON manipulation (may fail with complex realm configs)."
  echo "   Install jq for better reliability: brew install jq (macOS) or apt-get install jq (Linux)"
  echo ""
  
  # Create a temporary file for the realm JSON
  TEMP_REALM=$(mktemp)
  echo "$REALM_JSON" > "$TEMP_REALM"
  
  # Try to merge attributes using sed
  # This is a simplified approach - it may not work with all JSON structures
  # Escape the JSON strings for sed
  ESCAPED_SCOPES=$(echo "$CONSENT_SCOPES" | sed 's/[[\]/\\&/g')
  ESCAPED_PREFIXES=$(echo "$CONSENT_PREFIXES" | sed 's/[[\]/\\&/g')
  
  # Check if attributes section exists
  if grep -q '"attributes"' "$TEMP_REALM"; then
    # Attributes exist - update them
    sed -i.bak "s/\"attributes\":{[^}]*}/\"attributes\":{\"aauth.consent.required.scopes\":$ESCAPED_SCOPES,\"aauth.consent.required.scope.prefixes\":$ESCAPED_PREFIXES}/" "$TEMP_REALM" 2>/dev/null
    if [ $? -ne 0 ]; then
      echo "❌ ERROR: Failed to update attributes with sed. Please install jq for better JSON support."
      rm -f "$TEMP_REALM" "$TEMP_REALM.bak"
      exit 1
    fi
  else
    # Attributes don't exist - add them before the closing brace
    sed -i.bak "s/}$/,\"attributes\":{\"aauth.consent.required.scopes\":$ESCAPED_SCOPES,\"aauth.consent.required.scope.prefixes\":$ESCAPED_PREFIXES}}/" "$TEMP_REALM" 2>/dev/null
    if [ $? -ne 0 ]; then
      echo "❌ ERROR: Failed to add attributes with sed. Please install jq for better JSON support."
      rm -f "$TEMP_REALM" "$TEMP_REALM.bak"
      exit 1
    fi
  fi
  
  UPDATED_REALM_JSON=$(cat "$TEMP_REALM")
  rm -f "$TEMP_REALM" "$TEMP_REALM.bak"
fi

# Update realm
UPDATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$BASE_URL/admin/realms/$REALM_NAME" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$UPDATED_REALM_JSON")

HTTP_CODE=$(echo "$UPDATE_RESPONSE" | tail -n1)
BODY=$(echo "$UPDATE_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "200" ]; then
  echo "✅ Successfully set AAuth consent attributes for realm '$REALM_NAME'!"
  echo ""
  echo "Configured values:"
  echo "  aauth.consent.required.scopes: $CONSENT_SCOPES"
  echo "  aauth.consent.required.scope.prefixes: $CONSENT_PREFIXES"
  echo ""
  echo "To customize these values, set environment variables:"
  echo "  export AAUTH_CONSENT_SCOPES='[\"custom.scope\"]'"
  echo "  export AAUTH_CONSENT_PREFIXES='[\"custom.\"]'"
  echo "  ./scripts/set_aauth_consent_attributes.sh $BASE_URL $REALM_NAME"
else
  echo "❌ ERROR: Failed to update realm. HTTP $HTTP_CODE"
  echo "Response: $BODY"
  exit 1
fi
