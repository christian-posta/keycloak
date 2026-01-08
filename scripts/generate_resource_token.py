#!/usr/bin/env python3
"""
Resource Token Generator for AAuth Testing

Generates a resource token (resource+jwt) signed by a resource's private key.

Usage:
    python generate_resource_token.py \\
        --resource-url https://resource.example.com \\
        --agent-id https://agent.example.com \\
        --auth-server-id http://localhost:8080/realms/aauth-test \\
        --scope "data.read data.write" \\
        --key-file resource_key.pem

The resource token can then be used with the AAuth test client:
    python scripts/aauth_test_client.py \\
        --base-url http://localhost:8080 \\
        --realm aauth-test \\
        --resource-token <token>
"""

import argparse
import base64
import json
import sys
import time
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils
except ImportError:
    print("ERROR: Required packages not installed.")
    print("Install with: pip install cryptography")
    sys.exit(1)


def compute_jwk_thumbprint(public_key_bytes: bytes) -> str:
    """
    Compute JWK thumbprint per RFC 7638.
    For Ed25519 (OKP), the required members are: kty, crv, x
    """
    import hashlib
    
    # Base64URL encode the public key
    x = base64.urlsafe_b64encode(public_key_bytes).decode('utf-8').rstrip('=')
    
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
    return base64.urlsafe_b64encode(thumbprint).decode('utf-8').rstrip('=')


def generate_resource_token(
    resource_url: str,
    agent_id: str,
    agent_public_key: bytes,  # Raw Ed25519 public key bytes
    auth_server_id: str,
    scope: Optional[str] = None,
    auth_request_url: Optional[str] = None,
    private_key: Ed25519PrivateKey = None,
    kid: str = "resource-key-1",
    expires_in: int = 3600
) -> str:
    """
    Generate a resource token (resource+jwt) per AAuth spec Section 6.5.
    
    Args:
        resource_url: Resource identifier (iss claim)
        agent_id: Agent identifier (agent claim)
        agent_public_key: Agent's public key (raw bytes) for agent_jkt
        auth_server_id: Auth server identifier (aud claim)
        scope: Optional scope string
        auth_request_url: Optional auth request URL (alternative to scope)
        private_key: Resource's private key for signing
        kid: Key ID for JWT header
        expires_in: Token expiration in seconds
    
    Returns:
        Signed JWT string
    """
    if scope is None and auth_request_url is None:
        raise ValueError("Either 'scope' or 'auth_request_url' must be provided")
    
    if private_key is None:
        raise ValueError("Private key is required")
    
    # Compute agent_jkt (JWK thumbprint of agent's public key)
    agent_jkt = compute_jwk_thumbprint(agent_public_key)
    
    # Create JWT header
    header = {
        "typ": "resource+jwt",
        "alg": "EdDSA",
        "kid": kid
    }
    
    # Create JWT payload
    now = int(time.time())
    payload = {
        "iss": resource_url,
        "aud": auth_server_id,
        "agent": agent_id,
        "agent_jkt": agent_jkt,
        "iat": now,
        "exp": now + expires_in
    }
    
    if scope:
        payload["scope"] = scope
    if auth_request_url:
        payload["auth_request_url"] = auth_request_url
    
    # Encode header and payload
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(',', ':')).encode()
    ).decode('utf-8').rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(',', ':')).encode()
    ).decode('utf-8').rstrip('=')
    
    # Create signature input
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    # Sign with Ed25519
    signature_bytes = private_key.sign(signing_input)
    signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode('utf-8').rstrip('=')
    
    # Return complete JWT
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def main():
    parser = argparse.ArgumentParser(description="Generate Resource Token for AAuth Testing")
    parser.add_argument("--resource-url", type=str, required=True,
                       help="Resource identifier (HTTPS URL)")
    parser.add_argument("--agent-id", type=str, required=True,
                       help="Agent identifier (HTTPS URL)")
    parser.add_argument("--agent-public-key-file", type=str, required=True,
                       help="Path to agent's public key file (PEM format)")
    parser.add_argument("--auth-server-id", type=str, required=True,
                       help="Auth server identifier (e.g., http://localhost:8080/realms/aauth-test)")
    parser.add_argument("--scope", type=str, help="Scope string (e.g., 'data.read data.write')")
    parser.add_argument("--auth-request-url", type=str, help="Auth request URL (alternative to scope)")
    parser.add_argument("--key-file", type=str, required=True,
                       help="Path to resource's private key file (PEM format)")
    parser.add_argument("--kid", type=str, default="resource-key-1",
                       help="Key ID for JWT header (default: resource-key-1)")
    parser.add_argument("--expires-in", type=int, default=3600,
                       help="Token expiration in seconds (default: 3600)")
    
    args = parser.parse_args()
    
    if args.scope is None and args.auth_request_url is None:
        parser.error("Either --scope or --auth-request-url must be provided")
    
    # Load resource private key
    try:
        with open(args.key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
            if not isinstance(private_key, Ed25519PrivateKey):
                print(f"ERROR: Key in {args.key_file} is not Ed25519")
                sys.exit(1)
    except FileNotFoundError:
        print(f"ERROR: Private key file not found: {args.key_file}")
        print(f"Generate one with: python scripts/mock_resource_server.py --key-file {args.key_file}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load private key: {e}")
        sys.exit(1)
    
    # Load agent public key
    try:
        with open(args.agent_public_key_file, 'rb') as f:
            agent_public_key = serialization.load_pem_public_key(f.read())
            if not isinstance(agent_public_key, Ed25519PublicKey):
                print(f"ERROR: Key in {args.agent_public_key_file} is not Ed25519")
                sys.exit(1)
            # Get raw public key bytes
            agent_public_key_bytes = agent_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
    except FileNotFoundError:
        print(f"ERROR: Agent public key file not found: {args.agent_public_key_file}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load agent public key: {e}")
        sys.exit(1)
    
    # Generate token
    try:
        token = generate_resource_token(
            resource_url=args.resource_url,
            agent_id=args.agent_id,
            agent_public_key=agent_public_key_bytes,
            auth_server_id=args.auth_server_id,
            scope=args.scope,
            auth_request_url=args.auth_request_url,
            private_key=private_key,
            kid=args.kid,
            expires_in=args.expires_in
        )
        
        print(token)
        
    except Exception as e:
        print(f"ERROR: Failed to generate token: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

