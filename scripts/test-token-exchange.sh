#!/bin/bash
#
# AAuth Token Exchange End-to-End Test Script (Section 9.10 of SPEC.md)
#
# This script automates the FULL token exchange flow per AAuth spec:
#
# Phase 1: Obtain Upstream Auth Token (Sections 9.3-9.6)
#   1. Request a request_token (triggers user consent flow)
#   2. Open browser for user authentication
#   3. Wait for user to paste callback URL with auth code
#   4. Exchange auth code for auth_token (this becomes UPSTREAM token)
#
# Phase 2: Token Exchange (Section 9.10)
#   5. Create mock resource token (simulating downstream resource challenge)
#   6. Perform token exchange: upstream auth_token + resource_token → NEW auth_token
#      - Uses scheme=jwt with upstream auth_token in Signature-Key header
#      - Returns new auth_token with `act` claim showing delegation chain
#
# Usage: ./scripts/test-token-exchange.sh [options]
#
# Options:
#   --base-url URL       Keycloak base URL (default: http://localhost:8080)
#   --realm REALM        Realm name (default: aauth-test)
#   --agent-id ID        Agent ID URL (default: https://agent1.example.com)
#   --scope SCOPE        Scopes for initial auth (default: "profile email data.read data.write")
#   --resource-id ID     Downstream resource ID for exchange (default: http://localhost:9001)
#   --resource-port PORT Port for mock resource server (default: 9001)
#   --exchange-scope SC  Scope for exchange request (default: data.read)
#   --skip-auth          Skip Phase 1, use provided upstream token
#   --upstream-token TK  Upstream token to use (with --skip-auth)
#   -v, --verbose        Enable verbose output
#   -h, --help           Show this help message
#
# Prerequisites:
#   - Keycloak running at BASE_URL with AAuth support built in
#   - aauth-test realm created with a test user
#   - Python 3 with 'cryptography' and 'requests' packages installed
#

set -e

# Default values
BASE_URL="http://localhost:8080"
REALM="aauth-test"
AGENT_ID="http://localhost:9002"  # Agent URL for identified agent (mock agent server)
AGENT_PORT="9002"
SCOPE="profile email data.read data.write"
RESOURCE_ID="http://localhost:9001"  # Mock resource server
RESOURCE_PORT="9001"
EXCHANGE_SCOPE="data.read"
REDIRECT_URI="http://localhost:9000/callback"
VERBOSE=""
SKIP_AUTH=""
UPSTREAM_TOKEN=""
KEY_FILE=".aauth_test_key.pem"
RESOURCE_KEY_FILE=".mock_resource_key.pem"
MOCK_RESOURCE_PID=""
MOCK_AGENT_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --base-url)
            BASE_URL="$2"
            shift 2
            ;;
        --realm)
            REALM="$2"
            shift 2
            ;;
        --agent-id)
            AGENT_ID="$2"
            shift 2
            ;;
        --scope)
            SCOPE="$2"
            shift 2
            ;;
        --resource-id)
            RESOURCE_ID="$2"
            shift 2
            ;;
        --resource-port)
            RESOURCE_PORT="$2"
            shift 2
            ;;
        --exchange-scope)
            EXCHANGE_SCOPE="$2"
            shift 2
            ;;
        --skip-auth)
            SKIP_AUTH="true"
            shift
            ;;
        --upstream-token)
            UPSTREAM_TOKEN="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="--verbose"
            shift
            ;;
        -h|--help)
            head -30 "$0" | tail -25
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

AUTH_SERVER_ID="${BASE_URL}/realms/${REALM}"

# Ensure RESOURCE_ID matches RESOURCE_PORT if using defaults
if [[ "$RESOURCE_ID" == "http://localhost:9001" && "$RESOURCE_PORT" != "9001" ]]; then
    RESOURCE_ID="http://localhost:${RESOURCE_PORT}"
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  AAuth Token Exchange Test Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Base URL:       ${GREEN}${BASE_URL}${NC}"
echo -e "Realm:          ${GREEN}${REALM}${NC}"
echo -e "Agent ID:       ${GREEN}${AGENT_ID}${NC} (identified agent, scheme=jwks)"
echo -e "Agent Port:     ${GREEN}${AGENT_PORT}${NC} (mock agent server)"
echo -e "Auth Server:    ${GREEN}${AUTH_SERVER_ID}${NC}"
echo -e "Resource ID:    ${GREEN}${RESOURCE_ID}${NC} (mock resource server)"
echo -e "Resource Port:  ${GREEN}${RESOURCE_PORT}${NC}"
echo -e "Scope:          ${GREEN}${SCOPE}${NC}"
echo -e "Exchange Scope: ${GREEN}${EXCHANGE_SCOPE}${NC}"
echo ""

# Check if Python scripts exist
if [[ ! -f "scripts/aauth_test_client.py" ]]; then
    echo -e "${RED}Error: scripts/aauth_test_client.py not found${NC}"
    echo "Please run this script from the Keycloak root directory"
    exit 1
fi

if [[ ! -f "scripts/mock_resource_server.py" ]]; then
    echo -e "${RED}Error: scripts/mock_resource_server.py not found${NC}"
    echo "Please run this script from the Keycloak root directory"
    exit 1
fi

if [[ ! -f "scripts/generate_resource_token.py" ]]; then
    echo -e "${RED}Error: scripts/generate_resource_token.py not found${NC}"
    echo "Please run this script from the Keycloak root directory"
    exit 1
fi

# Cleanup function to stop mock servers and remove temp files
cleanup() {
    if [[ -n "$MOCK_RESOURCE_PID" ]] && kill -0 "$MOCK_RESOURCE_PID" 2>/dev/null; then
        echo -e "\n${YELLOW}Stopping mock resource server (PID: $MOCK_RESOURCE_PID)...${NC}"
        kill "$MOCK_RESOURCE_PID" 2>/dev/null || true
        wait "$MOCK_RESOURCE_PID" 2>/dev/null || true
    fi
    if [[ -n "$MOCK_AGENT_PID" ]] && kill -0 "$MOCK_AGENT_PID" 2>/dev/null; then
        echo -e "${YELLOW}Stopping mock agent server (PID: $MOCK_AGENT_PID)...${NC}"
        kill "$MOCK_AGENT_PID" 2>/dev/null || true
        wait "$MOCK_AGENT_PID" 2>/dev/null || true
    fi
    # Clean up temp files
    rm -f .agent_public_key.pem 2>/dev/null || true
}
trap cleanup EXIT

# ============================================
# Start Mock Agent Server (for scheme=jwks)
# ============================================
echo -e "${YELLOW}Starting mock agent server at ${AGENT_ID}...${NC}"

# Check if port is already in use
if lsof -i ":$AGENT_PORT" >/dev/null 2>&1; then
    echo -e "${YELLOW}Port $AGENT_PORT already in use. Assuming mock agent server is already running.${NC}"
else
    python3 scripts/mock_agent_server.py \
        --port "$AGENT_PORT" \
        --agent-url "$AGENT_ID" \
        --key-file "$KEY_FILE" \
        >/dev/null 2>&1 &
    MOCK_AGENT_PID=$!
    
    # Wait for server to start
    sleep 2
    
    if ! kill -0 "$MOCK_AGENT_PID" 2>/dev/null; then
        echo -e "${RED}Failed to start mock agent server${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Mock agent server started (PID: $MOCK_AGENT_PID)${NC}"
fi

# ============================================
# Start Mock Resource Server
# ============================================
echo -e "${YELLOW}Starting mock resource server at ${RESOURCE_ID}...${NC}"

# Check if port is already in use
if lsof -i ":$RESOURCE_PORT" >/dev/null 2>&1; then
    echo -e "${YELLOW}Port $RESOURCE_PORT already in use. Assuming mock resource server is already running.${NC}"
else
    python3 scripts/mock_resource_server.py \
        --port "$RESOURCE_PORT" \
        --resource-url "$RESOURCE_ID" \
        --key-file "$RESOURCE_KEY_FILE" \
        >/dev/null 2>&1 &
    MOCK_RESOURCE_PID=$!
    
    # Wait for server to start
    sleep 2
    
    if ! kill -0 "$MOCK_RESOURCE_PID" 2>/dev/null; then
        echo -e "${RED}Failed to start mock resource server${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Mock resource server started (PID: $MOCK_RESOURCE_PID)${NC}"
fi
echo ""

# Function to extract value from JSON
extract_json_value() {
    local json="$1"
    local key="$2"
    echo "$json" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('$key', ''))" 2>/dev/null || echo ""
}

# Function to extract auth code from callback URL
extract_auth_code() {
    local url="$1"
    # Extract the 'code' parameter from the URL
    echo "$url" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p'
}

if [[ -z "$SKIP_AUTH" ]]; then
    # ============================================
    # PHASE 1: Obtain Upstream Auth Token
    # ============================================
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  PHASE 1: Obtain Upstream Auth Token${NC}"
    echo -e "${BLUE}  (Sections 9.3-9.6 of AAuth Spec)${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # ============================================
    # Step 1.1: Request a request_token
    # ============================================
    echo -e "${YELLOW}Step 1.1: Requesting request_token (Section 9.3-9.4)...${NC}"
    echo ""

    REQUEST_RESPONSE=$(python3 scripts/aauth_test_client.py \
        --base-url "$BASE_URL" \
        --realm "$REALM" \
        --agent-id "$AGENT_ID" \
        --agent-url "$AGENT_ID" \
        --scope "$SCOPE" \
        --redirect-uri "$REDIRECT_URI" \
        --key-file "$KEY_FILE" \
        2>&1)

    # Check if we got a request_token (user consent required)
    if echo "$REQUEST_RESPONSE" | grep -q "request_token"; then
        REQUEST_TOKEN=$(echo "$REQUEST_RESPONSE" | grep "Request Token:" | head -1 | awk '{print $NF}')
        
        if [[ -z "$REQUEST_TOKEN" ]]; then
            # Try to extract from JSON response
            JSON_PART=$(echo "$REQUEST_RESPONSE" | grep -A 20 "Response:" | tail -n +2)
            REQUEST_TOKEN=$(echo "$JSON_PART" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('request_token', ''))" 2>/dev/null || echo "")
        fi
        
        if [[ -z "$REQUEST_TOKEN" ]]; then
            echo -e "${RED}Failed to extract request_token from response${NC}"
            echo "$REQUEST_RESPONSE"
            exit 1
        fi
        
        echo -e "${GREEN}✓ Got request_token${NC}"
        echo -e "  Token: ${REQUEST_TOKEN:0:50}..."
        echo ""
        
        # ============================================
        # Step 1.2: Open browser for user authentication
        # ============================================
        echo -e "${YELLOW}Step 1.2: User Authentication Required (Section 9.5)${NC}"
        echo ""
        
        AUTH_URL="${BASE_URL}/realms/${REALM}/protocol/aauth/agent/auth?request_token=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REQUEST_TOKEN'))")&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REDIRECT_URI'))")"
        
        echo -e "Please authenticate in your browser:"
        echo -e "${BLUE}${AUTH_URL}${NC}"
        echo ""
        
        # Try to open browser automatically
        if command -v open &> /dev/null; then
            open "$AUTH_URL" 2>/dev/null || true
        elif command -v xdg-open &> /dev/null; then
            xdg-open "$AUTH_URL" 2>/dev/null || true
        fi
        
        echo -e "${YELLOW}After authenticating and granting consent, you will be redirected to:${NC}"
        echo -e "  ${REDIRECT_URI}?code=<authorization_code>"
        echo ""
        echo -e "${YELLOW}Paste the FULL callback URL here (including the ?code=... part):${NC}"
        read -r CALLBACK_URL
        
        # Extract auth code from callback URL
        AUTH_CODE=$(extract_auth_code "$CALLBACK_URL")
        
        if [[ -z "$AUTH_CODE" ]]; then
            echo -e "${RED}Failed to extract authorization code from URL${NC}"
            echo "URL provided: $CALLBACK_URL"
            exit 1
        fi
        
        echo -e "${GREEN}✓ Extracted authorization code${NC}"
        echo -e "  Code: ${AUTH_CODE:0:30}..."
        echo ""
        
    else
        # Check if we got a direct auth_token (no user consent required)
        if echo "$REQUEST_RESPONSE" | grep -q "auth_token"; then
            echo -e "${GREEN}✓ Got auth_token directly (no user consent required)${NC}"
            JSON_PART=$(echo "$REQUEST_RESPONSE" | grep -A 20 "Response:" | tail -n +2)
            UPSTREAM_TOKEN=$(echo "$JSON_PART" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('auth_token', ''))" 2>/dev/null || echo "")
            
            if [[ -z "$UPSTREAM_TOKEN" ]]; then
                echo -e "${RED}Failed to extract auth_token${NC}"
                echo "$REQUEST_RESPONSE"
                exit 1
            fi
            
            # Skip to step 4
            AUTH_CODE=""
        else
            echo -e "${RED}Unexpected response:${NC}"
            echo "$REQUEST_RESPONSE"
            exit 1
        fi
    fi

    # ============================================
    # Step 1.3: Exchange auth code for auth_token (UPSTREAM TOKEN)
    # ============================================
    if [[ -n "$AUTH_CODE" ]]; then
        echo -e "${YELLOW}Step 1.3: Exchanging authorization code for auth_token (Section 9.6)...${NC}"
        echo ""
        
        CODE_RESPONSE=$(python3 scripts/aauth_test_client.py \
            --base-url "$BASE_URL" \
            --realm "$REALM" \
            --agent-id "$AGENT_ID" \
            --agent-url "$AGENT_ID" \
            --code "$AUTH_CODE" \
            --redirect-uri "$REDIRECT_URI" \
            --key-file "$KEY_FILE" \
            $VERBOSE \
            2>&1)
        
        if echo "$CODE_RESPONSE" | grep -q '"auth_token"'; then
            # Extract auth_token from JSON response using Python for robust parsing
            UPSTREAM_TOKEN=$(echo "$CODE_RESPONSE" | python3 -c "
import sys
import json
import re

content = sys.stdin.read()
# Find JSON object in the output
match = re.search(r'\{[^{}]*\"auth_token\"[^{}]*\}', content, re.DOTALL)
if match:
    try:
        data = json.loads(match.group())
        print(data.get('auth_token', ''))
    except:
        # Try to find just the token value
        token_match = re.search(r'\"auth_token\":\s*\"([^\"]+)\"', content)
        if token_match:
            print(token_match.group(1))
" 2>/dev/null)
            
            if [[ -z "$UPSTREAM_TOKEN" ]]; then
                echo -e "${RED}Failed to extract auth_token from response${NC}"
                echo "$CODE_RESPONSE"
                exit 1
            fi
            
            echo -e "${GREEN}✓ Got UPSTREAM auth_token (will be used in token exchange)${NC}"
            echo -e "  Token: ${UPSTREAM_TOKEN:0:50}..."
            echo ""
            
            # Show upstream token claims
            echo -e "${BLUE}Upstream Token Claims:${NC}"
            # Use Python for base64url decoding (macOS base64 doesn't handle base64url)
            UPSTREAM_CLAIMS=$(python3 -c "
import base64
import json
import sys

token = '$UPSTREAM_TOKEN'
payload_b64 = token.split('.')[1]
# Add padding if needed
padding = 4 - len(payload_b64) % 4
if padding != 4:
    payload_b64 += '=' * padding
payload = base64.urlsafe_b64decode(payload_b64)
claims = json.loads(payload)
print(f\"aud: {claims.get('aud', '')}\")
print(f\"sub: {claims.get('sub', '')}\")
print(f\"scope: {claims.get('scope', '')}\")
print(f\"agent: {claims.get('agent', '')}\")
" 2>/dev/null) || UPSTREAM_CLAIMS="(failed to decode)"
            echo -e "$UPSTREAM_CLAIMS"
            echo ""
        else
            echo -e "${RED}Failed to exchange code for token:${NC}"
            echo "$CODE_RESPONSE"
            exit 1
        fi
    fi
else
    # Skip auth flow, use provided token
    if [[ -z "$UPSTREAM_TOKEN" ]]; then
        echo -e "${RED}Error: --skip-auth requires --upstream-token${NC}"
        exit 1
    fi
    echo -e "${YELLOW}Skipping Phase 1, using provided upstream token${NC}"
    echo -e "  Token: ${UPSTREAM_TOKEN:0:50}..."
    echo ""
fi

# ============================================
# PHASE 2: Token Exchange (Section 9.10)
# ============================================
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  PHASE 2: Token Exchange${NC}"
echo -e "${BLUE}  (Section 9.10 of AAuth Spec)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Upstream Auth Token obtained in Phase 1"
echo -e "  Now simulating downstream resource challenge..."
echo ""

# ============================================
# Step 2.1: Create resource token using the resource server's key
# ============================================
echo -e "${YELLOW}Step 2.1: Creating resource token (downstream resource challenge)...${NC}"
echo -e "  This simulates a downstream resource returning Agent-Auth: resource_token=..."
echo -e "  Resource ID: ${RESOURCE_ID}"
echo -e "  Agent ID: ${AGENT_ID} (identified agent, using scheme=jwks)"
echo ""

# Export the agent's public key for the resource token
AGENT_PUBLIC_KEY_FILE=".agent_public_key.pem"
python3 -c "
from cryptography.hazmat.primitives import serialization

# Load agent's private key
with open('$KEY_FILE', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Export public key
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('$AGENT_PUBLIC_KEY_FILE', 'wb') as f:
    f.write(public_pem)
print('Exported agent public key to $AGENT_PUBLIC_KEY_FILE')
"

# Generate resource token using the resource server's key
# Use explicit agent ID since we're using scheme=jwks (identified agent)
RESOURCE_TOKEN=$(python3 scripts/generate_resource_token.py \
    --resource-url "$RESOURCE_ID" \
    --agent-id "$AGENT_ID" \
    --agent-public-key-file "$AGENT_PUBLIC_KEY_FILE" \
    --auth-server-id "$AUTH_SERVER_ID" \
    --scope "$EXCHANGE_SCOPE" \
    --key-file "$RESOURCE_KEY_FILE" \
    2>&1)

if [[ $? -ne 0 ]] || [[ -z "$RESOURCE_TOKEN" ]] || [[ "$RESOURCE_TOKEN" == ERROR* ]]; then
    echo -e "${RED}Failed to create resource token:${NC}"
    echo "$RESOURCE_TOKEN"
    exit 1
fi

echo -e "${GREEN}✓ Created resource token (signed by resource server)${NC}"
echo -e "  Token: ${RESOURCE_TOKEN:0:50}..."
echo ""

# ============================================
# Step 2.2: Perform token exchange (request_type=exchange)
# ============================================
echo -e "${YELLOW}Step 2.2: Performing token exchange (request_type=exchange)...${NC}"
echo -e "  - Presenting upstream auth_token via Signature-Key: scheme=jwt"
echo -e "  - Including resource_token from downstream resource"
echo -e "  - Requesting scope: ${EXCHANGE_SCOPE}"
echo ""

EXCHANGE_RESPONSE=$(python3 scripts/aauth_test_client.py \
    --base-url "$BASE_URL" \
    --realm "$REALM" \
    --exchange \
    --upstream-token "$UPSTREAM_TOKEN" \
    --resource-token "$RESOURCE_TOKEN" \
    --scope "$EXCHANGE_SCOPE" \
    --key-file "$KEY_FILE" \
    $VERBOSE \
    2>&1)

echo "$EXCHANGE_RESPONSE"
echo ""

if echo "$EXCHANGE_RESPONSE" | grep -q '"auth_token"'; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  ✓ TOKEN EXCHANGE SUCCESSFUL!${NC}"
    echo -e "${GREEN}  (Section 9.10 of AAuth Spec)${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    # Extract the new auth_token using Python for robust parsing
    NEW_AUTH_TOKEN=$(echo "$EXCHANGE_RESPONSE" | python3 -c "
import sys
import re

content = sys.stdin.read()
# Try to find the token in JSON
match = re.search(r'\"auth_token\":\s*\"([^\"]+)\"', content)
if match:
    print(match.group(1))
" 2>/dev/null)
    
    if [[ -n "$NEW_AUTH_TOKEN" ]]; then
        echo ""
        echo -e "${BLUE}New Auth Token (decoded):${NC}"
        # Use Python for base64url decoding
        python3 -c "
import base64
import json

token = '$NEW_AUTH_TOKEN'
parts = token.split('.')

def decode_part(b64):
    padding = 4 - len(b64) % 4
    if padding != 4:
        b64 += '=' * padding
    return base64.urlsafe_b64decode(b64)

try:
    header = json.loads(decode_part(parts[0]))
    print('Header:', json.dumps(header, indent=2))
except Exception as e:
    print('Header: (decode failed)')

print()

try:
    payload = json.loads(decode_part(parts[1]))
    print('Payload:', json.dumps(payload, indent=2))
    print()
    print('Key Claims (per Section 9.10):')
    print(f\"  iss (Auth Server):      {payload.get('iss', '')}\")
    print(f\"  aud (Resource):         {payload.get('aud', '')}\")
    print(f\"  agent (Current Agent):  {payload.get('agent', '')}\")
    print(f\"  sub (User):             {payload.get('sub', '')}\")
    print(f\"  scope:                  {payload.get('scope', '')}\")
    
    act = payload.get('act')
    if act:
        print()
        print('  act (Delegation Chain - shows upstream agent):')
        for line in json.dumps(act, indent=2).split('\n'):
            print(f'    {line}')
    else:
        print()
        print('  act (Delegation Chain): Not present (may be first hop)')
except Exception as e:
    print(f'Payload: (decode failed: {e})')
" 2>/dev/null || echo "(decode failed)"
    fi
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  ✗ TOKEN EXCHANGE FAILED${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "  - Make sure Keycloak is running and rebuilt with latest changes"
    echo "  - Check that the upstream token hasn't expired (5 min default)"
    echo "  - Check that the resource token hasn't expired (5 min default)"
    echo "  - Review Keycloak logs for detailed error messages"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Token Exchange Flow Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Summary:"
echo "  1. Obtained upstream auth_token via user consent flow"
echo "  2. Created mock resource_token for downstream resource"
echo "  3. Exchanged tokens using scheme=jwt (Section 9.10)"
echo "  4. Received new auth_token bound to agent's key"
echo ""
echo -e "${GREEN}Done!${NC}"

