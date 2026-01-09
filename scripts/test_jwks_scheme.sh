#!/bin/bash
# End-to-end test script for jwks signature scheme
# This script:
# 1. Starts a mock agent server
# 2. Generates agent keys
# 3. Makes a signed request using scheme=jwks (Mode 2: id + well-known)
# 4. Requests an auth token

set -e

AGENT_PORT=${AGENT_PORT:-9001}
AGENT_URL="http://localhost:${AGENT_PORT}"
AUTH_SERVER_ID=${AUTH_SERVER_ID:-"http://localhost:8080/realms/aauth-test"}
BASE_URL=${BASE_URL:-"http://localhost:8080"}
REALM=${REALM:-"aauth-test"}

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Initialize agent server PID variable
AGENT_SERVER_PID=""

# Cleanup function
cleanup() {
    if [ -n "$AGENT_SERVER_PID" ]; then
        echo -e "\n${YELLOW}Cleaning up agent server (PID: $AGENT_SERVER_PID)...${NC}"
        kill $AGENT_SERVER_PID 2>/dev/null || true
        # Wait a moment for graceful shutdown
        sleep 1
        # Force kill if still running
        kill -9 $AGENT_SERVER_PID 2>/dev/null || true
    fi
    rm -f agent_private_key.pem agent_public_key.pem
}

# Set trap to cleanup on exit (normal exit, error, or interrupt)
trap cleanup EXIT INT TERM

echo -e "${GREEN}=== AAuth JWKS Scheme Test ===${NC}\n"

# Check if Keycloak is running
echo "Checking if Keycloak is running..."
if ! curl -s "${BASE_URL}" > /dev/null; then
    echo -e "${RED}ERROR: Keycloak is not running at ${BASE_URL}${NC}"
    echo "Start Keycloak with:"
    echo "  java -jar quarkus/server/target/lib/quarkus-run.jar start-dev --bootstrap-admin-username=admin --bootstrap-admin-password=admin"
    exit 1
fi
echo -e "${GREEN}✓ Keycloak is running${NC}\n"

# Generate agent keys
echo "Generating agent key pair..."
python3 <<EOF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

with open('agent_private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open('agent_public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Agent keys saved")
EOF

echo -e "${GREEN}✓ Agent keys generated${NC}\n"

# Start mock agent server in background
echo "Starting mock agent server on port ${AGENT_PORT}..."
python3 scripts/mock_agent_server.py \
  --port "${AGENT_PORT}" \
  --agent-url "${AGENT_URL}" \
  --key-file agent_private_key.pem \
  --kid "agent-key-1" > /tmp/agent_server.log 2>&1 &
AGENT_SERVER_PID=$!

# Wait for server to start
sleep 2

# Check if server started successfully
if ! kill -0 $AGENT_SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Failed to start agent server${NC}"
    cat /tmp/agent_server.log
    exit 1
fi

echo -e "${GREEN}✓ Agent server started (PID: $AGENT_SERVER_PID)${NC}\n"

# Verify agent metadata endpoint
echo "Verifying agent metadata endpoint..."
if ! curl -s "${AGENT_URL}/.well-known/aauth-agent" > /dev/null; then
    echo -e "${RED}ERROR: Agent metadata endpoint not accessible${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Agent metadata endpoint accessible${NC}\n"

# Verify JWKS endpoint
echo "Verifying JWKS endpoint..."
if ! curl -s "${AGENT_URL}/jwks.json" > /dev/null; then
    echo -e "${RED}ERROR: JWKS endpoint not accessible${NC}"
    exit 1
fi
echo -e "${GREEN}✓ JWKS endpoint accessible${NC}\n"

# Request auth token using jwks scheme (Mode 2: id + well-known)
echo "Requesting auth token with jwks scheme (Mode 2: id + well-known)..."
python3 <<EOF
import sys
import json
import time
import base64
import urllib.parse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import requests

# Load agent private key
with open('agent_private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

public_key = private_key.public_key()
public_bytes = public_key.public_bytes_raw()
jwk_x = base64.urlsafe_b64encode(public_bytes).decode().rstrip('=')
kid = "agent-key-1"  # Must match the kid in JWKS

# Build signature
method = "POST"
url = "${BASE_URL}/realms/${REALM}/protocol/aauth/agent/token"
parsed = urllib.parse.urlparse(url)
authority = parsed.netloc or parsed.hostname
path = parsed.path or "/"

created = int(time.time())
signature_base = f'"@method": {method.upper()}\\n'
signature_base += f'"@authority": {authority.lower()}\\n'
signature_base += f'"@path": {path}\\n'
signature_base += f'"@signature-params": (@method @authority @path);created={created}'

signature_bytes = private_key.sign(signature_base.encode('utf-8'))
signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode().rstrip('=')

# Use jwks scheme Mode 2: id + well-known
# Signature-Key: sig=jwks;id="<agent-url>";well-known="aauth-agent";kid="<kid>"
headers = {
    'Host': authority,
    'Signature-Key': f'sig=jwks;id="${AGENT_URL}";well-known="aauth-agent";kid="{kid}"',
    'Signature-Input': f'sig=("@method" "@authority" "@path");created={created}',
    'Signature': f'sig=:{signature_b64}:',
    'Content-Type': 'application/x-www-form-urlencoded'
}

data = {
    'request_type': 'auth',
    'scope': 'data.read data.write'
}

response = requests.post(url, headers=headers, data=data)
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json() if response.status_code == 200 else response.text, indent=2)}")

if response.status_code == 200:
    print("\\n✅ Success! Auth token issued with jwks scheme")
    if 'auth_token' in response.json():
        token = response.json()['auth_token']
        print(f"\\nToken (first 50 chars): {token[:50]}...")
else:
    sys.exit(1)
EOF

TEST_RESULT=$?

# Cleanup will be handled by trap, but we can exit explicitly here
if [ $TEST_RESULT -eq 0 ]; then
    echo -e "\n${GREEN}✓ Test completed successfully${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Test failed${NC}"
    exit 1
fi

