#!/usr/bin/env python3
"""
AAuth Test Client - Helper script for manual testing of AAuth endpoints

This script generates signed HTTP requests for testing AAuth endpoints (Phase 2 & 3).
Note: This is a simplified implementation for testing. For production use,
ensure full RFC 9421 compliance.

Usage:
    # Phase 2: Direct grant
    python aauth_test_client.py --base-url http://localhost:8080 --realm aauth-test --scope "data.read data.write"
    
    # Phase 3: User consent flow
    python aauth_test_client.py --base-url http://localhost:8080 --realm aauth-test --scope "profile email" --redirect-uri "http://localhost:9000/callback"
    
    # Phase 3: Code exchange
    python aauth_test_client.py --base-url http://localhost:8080 --realm aauth-test --code <authorization_code> --redirect-uri "http://localhost:9000/callback"
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
    
    def _build_signature_base(self, method: str, authority: str, path: str, created: int, 
                              signature_key: Optional[str] = None, body: Optional[bytes] = None) -> bytes:
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
        
        components = []
        signature_params_components = []
        
        # Always include these components
        components.append(f'"@method": {method.upper()}')
        signature_params_components.append("@method")
        
        components.append(f'"@authority": {authority.lower()}')
        signature_params_components.append("@authority")
        
        components.append(f'"@path": {path}')
        signature_params_components.append("@path")
        
        # Include signature-key (required by AAuth)
        if signature_key:
            components.append(f'"signature-key": {signature_key}')
            signature_params_components.append("signature-key")
        
        # Include content-type and content-digest if body is present
        if body and len(body) > 0:
            components.append('"content-type": application/x-www-form-urlencoded')
            signature_params_components.append("content-type")
            
            # Calculate content-digest (SHA-256)
            import hashlib
            digest = hashlib.sha256(body).digest()
            digest_b64 = base64.urlsafe_b64encode(digest).decode().rstrip('=')
            components.append(f'"content-digest": sha-256=:{digest_b64}:')
            signature_params_components.append("content-digest")
        
        # Build signature-params
        signature_params = "(" + " ".join(signature_params_components) + f");created={created}"
        components.append(f'"@signature-params": {signature_params}')
        
        signature_base = "\n".join(components)
        return signature_base.encode('utf-8')
    
    def create_signed_headers(self, method: str, url: str, body: Optional[bytes] = None, verbose: bool = False) -> dict:
        """
        Create HTTP headers with HTTP Message Signature.
        
        Args:
            method: HTTP method (e.g., "POST")
            url: Full URL
            body: Request body bytes (for content-digest calculation)
        
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
        
        # Create signature-key header
        signature_key_header = f'sig=hwk;kty="OKP";crv="Ed25519";x="{self.jwk_x}";kid="{self.kid}"'
        
        # Build signature base (include signature-key and body components if present)
        signature_base = self._build_signature_base(method, authority, path, created, 
                                                    signature_key=signature_key_header, body=body)
        
        # Debug output
        if verbose:
            print(f"\nDEBUG Signature Base:")
            print(signature_base.decode('utf-8'))
            print(f"DEBUG: Method={method.upper()}, Authority={authority.lower()}, Path={path}, Created={created}")
            if body:
                print(f"DEBUG: Body length={len(body)}")
        
        # Sign with Ed25519
        signature_bytes = self.private_key.sign(signature_base)
        signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode().rstrip('=')
        
        # Build signature-input based on components
        # RFC 9421 requires components to be quoted strings
        component_list = ["@method", "@authority", "@path", "signature-key"]
        if body and len(body) > 0:
            component_list.extend(["content-type", "content-digest"])
        # Quote each component as required by RFC 9421
        quoted_components = ' '.join(f'"{comp}"' for comp in component_list)
        signature_input = f'sig=({quoted_components});created={created}'
        
        signature = f'sig=:{signature_b64}:'
        
        headers = {
            'Host': authority,  # Host header must match @authority component exactly
            'Signature-Key': signature_key_header,
            'Signature-Input': signature_input,
            'Signature': signature,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # Add Content-Digest if body is present
        if body and len(body) > 0:
            import hashlib
            digest = hashlib.sha256(body).digest()
            digest_b64 = base64.urlsafe_b64encode(digest).decode().rstrip('=')
            headers['Content-Digest'] = f'sha-256=:{digest_b64}:'
        
        return headers
    
    def get_metadata(self, base_url: str, realm: str) -> dict:
        """Fetch AAuth issuer metadata"""
        metadata_url = f"{base_url}/realms/{realm}/.well-known/aauth-issuer"
        response = requests.get(metadata_url, headers={'Accept': 'application/json'})
        return {
            'status_code': response.status_code,
            'body': response.json() if response.status_code == 200 else response.text
        }
    
    def export_public_key(self, output_file: str):
        """Export public key to PEM file for use with resource token generation"""
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(output_file, 'wb') as f:
            f.write(public_pem)
        print(f"Exported agent public key to {output_file}")
    
    def save_key_pair(self, key_file: str):
        """Save private key to file for reuse across script invocations"""
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_file, 'wb') as f:
            f.write(private_pem)
        if hasattr(self, '_verbose') and self._verbose:
            print(f"Saved key pair to {key_file}")
    
    @staticmethod
    def load_key_pair(key_file: str) -> Optional[Ed25519PrivateKey]:
        """Load private key from file"""
        try:
            with open(key_file, 'rb') as f:
                private_pem = f.read()
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None
            )
            if isinstance(private_key, Ed25519PrivateKey):
                return private_key
            else:
                print(f"ERROR: Key file {key_file} is not an Ed25519 key")
                return None
        except FileNotFoundError:
            return None
        except Exception as e:
            print(f"ERROR: Failed to load key from {key_file}: {e}")
            return None
    
    def request_token(self, base_url: str, realm: str, scope: Optional[str] = None, 
                     resource_token: Optional[str] = None, redirect_uri: Optional[str] = None,
                     verbose: bool = False) -> dict:
        """
        Request an AAuth token or request token.
        
        Args:
            base_url: Keycloak base URL (e.g., http://localhost:8080)
            realm: Realm name
            scope: Scope string (for agent-as-resource)
            resource_token: Resource token JWT (for resource authorization)
            redirect_uri: Redirect URI for user consent flow (required when user consent is needed)
        
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
        
        if redirect_uri:
            form_data['redirect_uri'] = redirect_uri
        
        # Convert form data to bytes for signature
        form_data_bytes = urllib.parse.urlencode(form_data).encode('utf-8')
        
        # Create signed request (include body for content-digest)
        headers = self.create_signed_headers('POST', token_url, body=form_data_bytes, verbose=verbose)
        
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
    
    def exchange_code(self, base_url: str, realm: str, code: str, 
                     redirect_uri: Optional[str] = None, verbose: bool = False) -> dict:
        """
        Exchange authorization code for auth token.
        
        Args:
            base_url: Keycloak base URL (e.g., http://localhost:8080)
            realm: Realm name
            code: Authorization code from consent flow
            redirect_uri: Redirect URI (must match original request)
        
        Returns:
            Dictionary with status_code, headers, and body
        """
        token_url = f"{base_url}/realms/{realm}/protocol/aauth/agent/token"
        
        # Build form data
        form_data = {
            'request_type': 'code',
            'code': code
        }
        
        if redirect_uri:
            form_data['redirect_uri'] = redirect_uri
        
        # Convert form data to bytes for signature
        form_data_bytes = urllib.parse.urlencode(form_data).encode('utf-8')
        
        # Create signed request (include body for content-digest)
        headers = self.create_signed_headers('POST', token_url, body=form_data_bytes, verbose=verbose)
        
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
    parser.add_argument('--redirect-uri', help='Redirect URI for user consent flow')
    parser.add_argument('--code', help='Authorization code for code exchange')
    parser.add_argument('--metadata', action='store_true', help='Fetch metadata only')
    parser.add_argument('--agent-id', default='https://agent.example.com', help='Agent identifier')
    parser.add_argument('--key-file', default='.aauth_test_key.pem', help='File to save/load key pair (default: .aauth_test_key.pem)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Try to load existing key pair, or generate new one
    private_key = AAuthTestClient.load_key_pair(args.key_file)
    if private_key is None:
        if args.verbose:
            print(f"Generating new key pair (key file not found: {args.key_file})")
        private_key = None  # Will be generated in AAuthTestClient.__init__
    else:
        if args.verbose:
            print(f"Loaded existing key pair from {args.key_file}")
    
    client = AAuthTestClient(private_key=private_key, agent_id=args.agent_id)
    client._verbose = args.verbose
    
    # Save key pair after first use (if it was newly generated)
    if private_key is None:
        client.save_key_pair(args.key_file)
    
    if args.verbose:
        client.print_key_info()
    
    if args.metadata:
        print("Fetching AAuth issuer metadata...")
        result = client.get_metadata(args.base_url, args.realm)
        print(f"\nStatus: {result['status_code']}")
        print(f"Response:\n{json.dumps(result['body'], indent=2)}")
        return
    
    # Code exchange flow
    if args.code:
        print("Exchanging authorization code for auth token...")
        if args.verbose:
            print(f"  URL: {args.base_url}/realms/{args.realm}/protocol/aauth/agent/token")
            print(f"  Code: {args.code[:20]}...")
            print(f"  Redirect URI: {args.redirect_uri or 'N/A'}")
            print()
        
        try:
            result = client.exchange_code(
                args.base_url,
                args.realm,
                args.code,
                redirect_uri=args.redirect_uri,
                verbose=args.verbose
            )
            
            print(f"Status: {result['status_code']}")
            print(f"\nResponse:\n{json.dumps(result['body'], indent=2)}")
            
            if result['status_code'] == 200 and 'auth_token' in result['body']:
                print("\n✅ Code exchanged successfully!")
                print(f"\nToken (first 50 chars): {result['body']['auth_token'][:50]}...")
                if 'refresh_token' in result['body']:
                    print(f"Refresh Token: {result['body']['refresh_token'][:50]}...")
            
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        return
    
    # Token request flow
    if not args.scope and not args.resource_token:
        print("ERROR: Either --scope, --resource-token, or --code must be provided")
        parser.print_help()
        sys.exit(1)
    
    print("Requesting AAuth token...")
    if args.verbose:
        print(f"  URL: {args.base_url}/realms/{args.realm}/protocol/aauth/agent/token")
        print(f"  Scope: {args.scope or 'N/A'}")
        print(f"  Resource Token: {'Present' if args.resource_token else 'N/A'}")
        print(f"  Redirect URI: {args.redirect_uri or 'N/A'}")
        print()
    
    try:
        result = client.request_token(
            args.base_url,
            args.realm,
            scope=args.scope,
            resource_token=args.resource_token,
            redirect_uri=args.redirect_uri,
            verbose=args.verbose
        )
        
        print(f"Status: {result['status_code']}")
        print(f"\nResponse:\n{json.dumps(result['body'], indent=2)}")
        
        if result['status_code'] == 200:
            if 'auth_token' in result['body']:
                print("\n✅ Token issued successfully!")
                print(f"\nToken (first 50 chars): {result['body']['auth_token'][:50]}...")
                print("\nTo decode the token, use:")
                print("  - jwt.io (paste the auth_token)")
                print("  - Or: echo $TOKEN | cut -d. -f2 | base64 -d | jq")
            elif 'request_token' in result['body']:
                print("\n✅ Request token issued (user consent required)!")
                print(f"\nRequest Token: {result['body']['request_token']}")
                print(f"\nNext steps:")
                print(f"  1. Open in browser:")
                auth_url = f"{args.base_url}/realms/{args.realm}/protocol/aauth/agent/auth"
                auth_url += f"?request_token={result['body']['request_token']}"
                if args.redirect_uri:
                    auth_url += f"&redirect_uri={urllib.parse.quote(args.redirect_uri)}"
                print(f"     {auth_url}")
                print(f"  2. Authenticate and grant consent")
                print(f"  3. Extract authorization code from redirect")
                print(f"  4. Exchange code:")
                print(f"     python {sys.argv[0]} --base-url {args.base_url} --realm {args.realm} --code <code> --redirect-uri {args.redirect_uri or '<redirect_uri>'}")
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

