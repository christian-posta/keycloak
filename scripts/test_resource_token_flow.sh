#!/bin/bash
# End-to-end test script for resource token flow
# This script:
# 1. Starts a mock resource server
# 2. Generates agent keys
# 3. Generates a resource token
# 4. Requests an auth token using the resource token

set -e

RESOURCE_PORT=${RESOURCE_PORT:-9000}
RESOURCE_URL="http://localhost:${RESOURCE_PORT}"
AGENT_ID=${AGENT_ID:-"https://agent.example.com"}
AUTH_SERVER_ID=${AUTH_SERVER_ID:-"http://localhost:8080/realms/aauth-test"}
BASE_URL=${BASE_URL:-"http://localhost:8080"}
REALM=${REALM:-"aauth-test"}

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Initialize resource server PID variable
RESOURCE_SERVER_PID=""

# Cleanup function
cleanup() {
    if [ -n "$RESOURCE_SERVER_PID" ]; then
        echo -e "\n${YELLOW}Cleaning up resource server (PID: $RESOURCE_SERVER_PID)...${NC}"
        kill $RESOURCE_SERVER_PID 2>/dev/null || true
        # Wait a moment for graceful shutdown
        sleep 1
        # Force kill if still running
        kill -9 $RESOURCE_SERVER_PID 2>/dev/null || true
    fi
    rm -f agent_private_key.pem agent_public_key.pem resource_key.pem
}

# Set trap to cleanup on exit (normal exit, error, or interrupt)
trap cleanup EXIT INT TERM

echo -e "${GREEN}=== AAuth Resource Token Flow Test ===${NC}\n"

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

# Start mock resource server in background
echo "Starting mock resource server on port ${RESOURCE_PORT}..."
python3 scripts/mock_resource_server.py \
  --port "${RESOURCE_PORT}" \
  --resource-url "${RESOURCE_URL}" \
  --key-file resource_key.pem > /tmp/resource_server.log 2>&1 &
RESOURCE_SERVER_PID=$!

# Wait for server to start
sleep 2

# Check if server started successfully
if ! kill -0 $RESOURCE_SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Failed to start resource server${NC}"
    cat /tmp/resource_server.log
    exit 1
fi

echo -e "${GREEN}✓ Resource server started (PID: $RESOURCE_SERVER_PID)${NC}\n"

# Verify resource metadata endpoint
echo "Verifying resource metadata endpoint..."
if ! curl -s "${RESOURCE_URL}/.well-known/aauth-resource" > /dev/null; then
    echo -e "${RED}ERROR: Resource metadata endpoint not accessible${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Resource metadata endpoint accessible${NC}\n"

# Compute agent JKT (for pseudonymous agent ID with hwk scheme)
echo "Computing agent JKT..."
AGENT_JKT=$(python3 <<EOF
import base64
import hashlib
import json
from cryptography.hazmat.primitives import serialization

with open('agent_public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read())
    public_bytes = public_key.public_bytes_raw()
    
# Base64URL encode the public key
x = base64.urlsafe_b64encode(public_bytes).decode('utf-8').rstrip('=')

# Create JWK for thumbprint calculation
jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": x
}

# Sort keys and create canonical JSON
canonical = json.dumps(jwk, separators=(',', ':'), sort_keys=True)

# SHA-256 hash
thumbprint = hashlib.sha256(canonical.encode('utf-8')).digest()

# Base64URL encode
jkt = base64.urlsafe_b64encode(thumbprint).decode('utf-8').rstrip('=')
print(jkt)
EOF
)

# Use pseudonymous agent ID (matches what Keycloak derives for hwk scheme)
PSEUDONYMOUS_AGENT_ID="pseudonymous:${AGENT_JKT}"
echo -e "${GREEN}✓ Agent JKT computed: ${AGENT_JKT}${NC}"
echo -e "  Using pseudonymous agent ID: ${PSEUDONYMOUS_AGENT_ID}\n"

# Generate resource token
echo "Generating resource token..."
RESOURCE_TOKEN=$(python3 scripts/generate_resource_token.py \
  --resource-url "${RESOURCE_URL}" \
  --agent-id "${PSEUDONYMOUS_AGENT_ID}" \
  --agent-public-key-file agent_public_key.pem \
  --auth-server-id "${AUTH_SERVER_ID}" \
  --scope "data.read data.write" \
  --key-file resource_key.pem)

if [ -z "$RESOURCE_TOKEN" ]; then
    echo -e "${RED}ERROR: Failed to generate resource token${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Resource token generated${NC}"
echo "  Token (first 50 chars): ${RESOURCE_TOKEN:0:50}...\n"

# Request auth token using Python test client
# Note: We need to modify the test client to use the same agent key
# For now, we'll use a workaround: create a temporary Python script
echo "Requesting auth token with resource token..."
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
kid = base64.urlsafe_b64encode(public_bytes[:16]).decode().rstrip('=')

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

headers = {
    'Host': authority,
    'Signature-Key': f'sig=hwk;kty="OKP";crv="Ed25519";x="{jwk_x}";kid="{kid}"',
    'Signature-Input': f'sig=("@method" "@authority" "@path");created={created}',
    'Signature': f'sig=:{signature_b64}:',
    'Content-Type': 'application/x-www-form-urlencoded'
}

data = {
    'request_type': 'auth',
    'resource_token': '${RESOURCE_TOKEN}'
}

response = requests.post(url, headers=headers, data=data)
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json() if response.status_code == 200 else response.text, indent=2)}")

if response.status_code == 200:
    print("\\n✅ Success! Auth token issued with resource token")
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

