#!/usr/bin/env python3
"""
AAuth Test Client - Helper script for manual testing of AAuth endpoints

This script generates signed HTTP requests for testing AAuth Phase 2 endpoints.
Note: This is a simplified implementation for testing. For production use,
ensure full RFC 9421 compliance.

Usage:
    python aauth_test_client.py --base-url http://localhost:8080 --realm aauth-test --scope "data.read data.write"
    python aauth_test_client.py --base-url http://localhost:8080 --realm aauth-test --resource-token "eyJ..."
"""

import argparse
import base64
import json
import sys
import time
import urllib.parse
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    import requests
except ImportError:
    print("ERROR: Required packages not installed.")
    print("Install with: pip install cryptography requests")
    sys.exit(1)


class AAuthTestClient:
    """Simple AAuth client for testing purposes"""
    
    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None, agent_id: str = "https://agent.example.com"):
        """
        Initialize AAuth test client.
        
        Args:
            private_key: Ed25519 private key (generates new if None)
            agent_id: Agent identifier (HTTPS URL)
        """
        if private_key is None:
            private_key = Ed25519PrivateKey.generate()
        
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.agent_id = agent_id
        
        # Extract JWK parameters
        public_bytes = self.public_key.public_bytes_raw()
        self.jwk_x = base64.urlsafe_b64encode(public_bytes).decode().rstrip('=')
        self.kid = base64.urlsafe_b64encode(public_bytes[:16]).decode().rstrip('=')
    
    def _build_signature_base(self, method: str, authority: str, path: str, created: int) -> bytes:
        """
        Build signature base string per RFC 9421.
        
        WARNING: This is a simplified implementation. For production,
        use Keycloak's SignatureBaseBuilder class for full compliance.
        """
        # Canonical format per RFC 9421 Section 2.3
        # Note: Method must match exactly what Keycloak sees (uppercase: POST, GET, etc.)
        # Authority should be lowercase per RFC 9421
        # Path should be the absolute path without query parameters
        # Signature-params: components are NOT quoted, just space-separated in parentheses
        signature_base = f'"@method": {method.upper()}\n'
        signature_base += f'"@authority": {authority.lower()}\n'
        signature_base += f'"@path": {path}\n'
        signature_base += f'"@signature-params": (@method @authority @path);created={created}'
        return signature_base.encode('utf-8')
    
    def create_signed_headers(self, method: str, url: str, verbose: bool = False) -> dict:
        """
        Create HTTP headers with HTTP Message Signature.
        
        Args:
            method: HTTP method (e.g., "POST")
            url: Full URL
        
        Returns:
            Dictionary of headers including Signature-Key, Signature-Input, and Signature
        """
        parsed = urllib.parse.urlparse(url)
        # Authority should match Host header exactly (host:port or just host)
        authority = parsed.netloc
        if not authority:
            # Fallback if netloc is empty
            authority = parsed.hostname
            if parsed.port:
                authority += f":{parsed.port}"
        
        # Path should NOT include query string (per RFC 9421, @path is separate from @query)
        path = parsed.path
        if not path:
            path = "/"
        
        created = int(time.time())
        
        # Build signature base (authority will be lowercased in _build_signature_base)
        signature_base = self._build_signature_base(method, authority, path, created)
        
        # Debug output
        if verbose:
            print(f"\nDEBUG Signature Base:")
            print(signature_base.decode('utf-8'))
            print(f"DEBUG: Method={method.upper()}, Authority={authority.lower()}, Path={path}, Created={created}")
        
        # Sign with Ed25519
        signature_bytes = self.private_key.sign(signature_base)
        signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode().rstrip('=')
        
        # Create headers per AAuth spec
        signature_key = f'sig=hwk;kty="OKP";crv="Ed25519";x="{self.jwk_x}";kid="{self.kid}"'
        signature_input = f'sig=("@method" "@authority" "@path");created={created}'
        signature = f'sig=:{signature_b64}:'
        
        headers = {
            'Host': authority,  # Host header must match @authority component exactly
            'Signature-Key': signature_key,
            'Signature-Input': signature_input,
            'Signature': signature,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        return headers
    
    def get_metadata(self, base_url: str, realm: str) -> dict:
        """Fetch AAuth issuer metadata"""
        metadata_url = f"{base_url}/realms/{realm}/.well-known/aauth-issuer"
        response = requests.get(metadata_url, headers={'Accept': 'application/json'})
        return {
            'status_code': response.status_code,
            'body': response.json() if response.status_code == 200 else response.text
        }
    
    def request_token(self, base_url: str, realm: str, scope: Optional[str] = None, 
                     resource_token: Optional[str] = None, verbose: bool = False) -> dict:
        """
        Request an AAuth token.
        
        Args:
            base_url: Keycloak base URL (e.g., http://localhost:8080)
            realm: Realm name
            scope: Scope string (for agent-as-resource)
            resource_token: Resource token JWT (for resource authorization)
        
        Returns:
            Dictionary with status_code, headers, and body
        """
        if not scope and not resource_token:
            raise ValueError("Either 'scope' or 'resource_token' must be provided")
        
        token_url = f"{base_url}/realms/{realm}/protocol/aauth/agent/token"
        
        # Build form data
        form_data = {'request_type': 'auth'}
        if scope:
            form_data['scope'] = scope
        else:
            form_data['resource_token'] = resource_token
        
        # Create signed request
        headers = self.create_signed_headers('POST', token_url, verbose=verbose)
        
        # Make request
        response = requests.post(token_url, headers=headers, data=form_data)
        
        result = {
            'status_code': response.status_code,
            'headers': dict(response.headers)
        }
        
        # Parse response body
        content_type = response.headers.get('content-type', '')
        if 'application/json' in content_type:
            try:
                result['body'] = response.json()
            except:
                result['body'] = response.text
        else:
            result['body'] = response.text
        
        return result
    
    def print_key_info(self):
        """Print key information for reference"""
        print(f"Agent ID: {self.agent_id}")
        print(f"Public Key (JWK x): {self.jwk_x}")
        print(f"Key ID: {self.kid}")
        print()


def main():
    parser = argparse.ArgumentParser(description='AAuth Test Client')
    parser.add_argument('--base-url', required=True, help='Keycloak base URL (e.g., http://localhost:8080)')
    parser.add_argument('--realm', required=True, help='Realm name')
    parser.add_argument('--scope', help='Scope string (for agent-as-resource)')
    parser.add_argument('--resource-token', help='Resource token JWT (for resource authorization)')
    parser.add_argument('--metadata', action='store_true', help='Fetch metadata only')
    parser.add_argument('--agent-id', default='https://agent.example.com', help='Agent identifier')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    client = AAuthTestClient(agent_id=args.agent_id)
    
    if args.verbose:
        client.print_key_info()
    
    if args.metadata:
        print("Fetching AAuth issuer metadata...")
        result = client.get_metadata(args.base_url, args.realm)
        print(f"\nStatus: {result['status_code']}")
        print(f"Response:\n{json.dumps(result['body'], indent=2)}")
        return
    
    if not args.scope and not args.resource_token:
        print("ERROR: Either --scope or --resource-token must be provided")
        parser.print_help()
        sys.exit(1)
    
    print("Requesting AAuth token...")
    if args.verbose:
        print(f"  URL: {args.base_url}/realms/{args.realm}/protocol/aauth/agent/token")
        print(f"  Scope: {args.scope or 'N/A'}")
        print(f"  Resource Token: {'Present' if args.resource_token else 'N/A'}")
        print()
    
    try:
        result = client.request_token(
            args.base_url,
            args.realm,
            scope=args.scope,
            resource_token=args.resource_token,
            verbose=args.verbose
        )
        
        print(f"Status: {result['status_code']}")
        print(f"\nResponse:\n{json.dumps(result['body'], indent=2)}")
        
        if result['status_code'] == 200 and 'auth_token' in result['body']:
            print("\n✅ Token issued successfully!")
            print(f"\nToken (first 50 chars): {result['body']['auth_token'][:50]}...")
            print("\nTo decode the token, use:")
            print("  - jwt.io (paste the auth_token)")
            print("  - Or: echo $TOKEN | cut -d. -f2 | base64 -d | jq")
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

