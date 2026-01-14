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
        # Per RFC 9421: component names in @signature-params must be quoted strings
        
        components = []
        signature_params_components = []
        
        # Always include these components
        components.append(f'"@method": {method.upper()}')
        signature_params_components.append('"@method"')
        
        components.append(f'"@authority": {authority.lower()}')
        signature_params_components.append('"@authority"')
        
        components.append(f'"@path": {path}')
        signature_params_components.append('"@path"')
        
        # Include signature-key (required by AAuth)
        if signature_key:
            components.append(f'"signature-key": {signature_key}')
            signature_params_components.append('"signature-key"')
        
        # Include content-type and content-digest if body is present
        if body and len(body) > 0:
            components.append('"content-type": application/x-www-form-urlencoded')
            signature_params_components.append('"content-type"')
            
            # Calculate content-digest (SHA-256)
            import hashlib
            digest = hashlib.sha256(body).digest()
            digest_b64 = base64.urlsafe_b64encode(digest).decode().rstrip('=')
            components.append(f'"content-digest": sha-256=:{digest_b64}:')
            signature_params_components.append('"content-digest"')
        
        # Build signature-params with quoted component names per RFC 9421
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
    
    def create_signed_headers_jwks(self, method: str, url: str, agent_url: str, 
                                    body: Optional[bytes] = None, verbose: bool = False) -> dict:
        """
        Create HTTP headers with HTTP Message Signature using scheme=jwks.
        
        This is used for identified agents that have a metadata endpoint at
        {agent_url}/.well-known/aauth-agent exposing their JWKS.
        
        Args:
            method: HTTP method (e.g., "POST")
            url: Full URL
            agent_url: Agent's URL (e.g., "http://localhost:9002")
            body: Request body bytes (for content-digest calculation)
        
        Returns:
            Dictionary of headers including Signature-Key, Signature-Input, and Signature
        """
        parsed = urllib.parse.urlparse(url)
        authority = parsed.netloc
        if not authority:
            authority = parsed.hostname
            if parsed.port:
                authority += f":{parsed.port}"
        
        path = parsed.path
        if not path:
            path = "/"
        
        created = int(time.time())
        
        # Create signature-key header with scheme=jwks (Mode 2: identifier + metadata)
        # Format: sig=jwks;id="<agent_url>";kid="<key_id>"
        signature_key_header = f'sig=jwks;id="{agent_url}";kid="{self.kid}"'
        
        # Build signature base
        signature_base = self._build_signature_base(method, authority, path, created, 
                                                    signature_key=signature_key_header, body=body)
        
        if verbose:
            print(f"\nDEBUG Signature Base (scheme=jwks):")
            print(signature_base.decode('utf-8'))
            print(f"DEBUG: Agent URL={agent_url}, KID={self.kid}")
        
        # Sign with Ed25519
        signature_bytes = self.private_key.sign(signature_base)
        signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode().rstrip('=')
        
        # Build signature-input
        component_list = ["@method", "@authority", "@path", "signature-key"]
        if body and len(body) > 0:
            component_list.extend(["content-type", "content-digest"])
        quoted_components = ' '.join(f'"{comp}"' for comp in component_list)
        signature_input = f'sig=({quoted_components});created={created}'
        
        signature = f'sig=:{signature_b64}:'
        
        headers = {
            'Host': authority,
            'Signature-Key': signature_key_header,
            'Signature-Input': signature_input,
            'Signature': signature,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
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
                     agent_url: Optional[str] = None, verbose: bool = False) -> dict:
        """
        Request an AAuth token or request token.
        
        Args:
            base_url: Keycloak base URL (e.g., http://localhost:8080)
            realm: Realm name
            scope: Scope string (for agent-as-resource)
            resource_token: Resource token JWT (for resource authorization)
            redirect_uri: Redirect URI for user consent flow (required when user consent is needed)
            agent_url: Agent URL for scheme=jwks (if None, uses scheme=hwk for pseudonymous)
        
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
        
        # Create signed request - use scheme=jwks if agent_url provided, else scheme=hwk
        if agent_url:
            headers = self.create_signed_headers_jwks('POST', token_url, agent_url, body=form_data_bytes, verbose=verbose)
        else:
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
                     redirect_uri: Optional[str] = None, agent_url: Optional[str] = None,
                     verbose: bool = False) -> dict:
        """
        Exchange authorization code for auth token.
        
        Args:
            base_url: Keycloak base URL (e.g., http://localhost:8080)
            realm: Realm name
            code: Authorization code from consent flow
            redirect_uri: Redirect URI (must match original request)
            agent_url: Agent URL for scheme=jwks (if None, uses scheme=hwk for pseudonymous)
        
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
        
        # Create signed request - use scheme=jwks if agent_url provided, else scheme=hwk
        if agent_url:
            headers = self.create_signed_headers_jwks('POST', token_url, agent_url, body=form_data_bytes, verbose=verbose)
        else:
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
    
    def refresh_token(self, base_url: str, realm: str, refresh_token: str,
                     verbose: bool = False) -> dict:
        """
        Refresh an auth token using a refresh token.
        
        Args:
            base_url: Keycloak base URL (e.g., http://localhost:8080)
            realm: Realm name
            refresh_token: Refresh token JWT
        
        Returns:
            Dictionary with status_code, headers, and body
        """
        token_url = f"{base_url}/realms/{realm}/protocol/aauth/agent/token"
        
        # Build form data
        form_data = {
            'request_type': 'refresh',
            'refresh_token': refresh_token
        }
        
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
    
    def exchange_token(self, base_url: str, realm: str, resource_token: str, 
                      upstream_token: str, verbose: bool = False) -> dict:
        """
        Exchange an upstream auth token for a new auth token.
        
        Args:
            base_url: Keycloak base URL (e.g., http://localhost:8080)
            realm: Realm name
            resource_token: Resource token JWT
            upstream_token: Upstream auth token JWT (will be included in Signature-Key header)
        
        Returns:
            Dictionary with status_code, headers, and body
        """
        token_url = f"{base_url}/realms/{realm}/protocol/aauth/agent/token"
        
        # Build form data
        form_data = {
            'request_type': 'exchange',
            'resource_token': resource_token
        }
        
        # Convert form data to bytes for signature
        form_data_bytes = urllib.parse.urlencode(form_data).encode('utf-8')
        
        # Create signed request with scheme=jwt containing upstream token
        # The upstream token goes in the Signature-Key header's jwt parameter
        headers = self.create_signed_headers_with_jwt(
            'POST', token_url, body=form_data_bytes, upstream_token=upstream_token, verbose=verbose
        )
        
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
    
    def create_mock_resource_token(self, resource_id: str, aud_agent_id: str, auth_server_id: str,
                                   scope: str, verbose: bool = False) -> dict:
        """
        Creates a mock resource token for testing purposes.
        
        Args:
            resource_id: Resource identifier (iss claim)
            aud_agent_id: Agent ID for whom the token is intended (agent claim)
            auth_server_id: Auth server identifier (aud claim)
            scope: Scope string
            verbose: Enable verbose output
        
        Returns:
            Dictionary with status_code and body containing resource_token
        """
        import hashlib
        
        # Compute agent_jkt from the current agent's public key
        agent_public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Compute JWK thumbprint per RFC 7638
        x = base64.urlsafe_b64encode(agent_public_key_bytes).decode('utf-8').rstrip('=')
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x
        }
        canonical = json.dumps(jwk, separators=(',', ':'), sort_keys=True)
        agent_jkt = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
        
        # Create JWT header
        header = {
            "typ": "resource+jwt",
            "alg": "EdDSA",
            "kid": self.kid
        }
        
        # Create JWT payload
        now = int(time.time())
        payload = {
            "iss": resource_id,
            "aud": auth_server_id,
            "agent": aud_agent_id,
            "agent_jkt": agent_jkt,
            "iat": now,
            "exp": now + 300,  # 5 minutes
            "scope": scope
        }
        
        # Encode header and payload
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode('utf-8').rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode('utf-8').rstrip('=')
        
        # Create signature input
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        
        # Sign with agent's private key (for testing - in production, resource would use its own key)
        signature_bytes = self.private_key.sign(signing_input)
        signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode('utf-8').rstrip('=')
        
        # Return complete JWT
        resource_token = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        if verbose:
            print(f"Generated Mock Resource Token:")
            print(f"  Issuer (Resource ID): {resource_id}")
            print(f"  Audience (Auth Server ID): {auth_server_id}")
            print(f"  Agent (for whom token is intended): {aud_agent_id}")
            print(f"  Agent JKT: {agent_jkt}")
            print(f"  Scope: {scope}")
        
        return {
            'status_code': 200,
            'body': {'resource_token': resource_token}
        }
    
    def create_signed_headers_with_jwt(self, method: str, url: str, body: Optional[bytes] = None,
                                      upstream_token: Optional[str] = None, verbose: bool = False) -> dict:
        """
        Create signed headers with scheme=jwt for token exchange.
        
        Args:
            method: HTTP method
            url: Full URL
            body: Request body bytes (optional)
            upstream_token: Upstream auth token JWT to include in Signature-Key
            verbose: Enable verbose output
        
        Returns:
            Dictionary of headers
        """
        parsed_url = urllib.parse.urlparse(url)
        now = int(time.time())
        
        # Build signature base string components
        # Note: @path should NOT include query string per RFC 9421
        components = []
        components.append(('@method', method))
        components.append(('@authority', parsed_url.netloc))
        path = parsed_url.path if parsed_url.path else '/'
        components.append(('@path', path))
        
        # Add @query if present (RFC 9421: @query includes the "?" prefix)
        if parsed_url.query:
            components.append(('@query', '?' + parsed_url.query))
        
        # Add content-type if body present
        if body:
            components.append(('content-type', 'application/x-www-form-urlencoded'))
        
        # Add content-digest if body present
        if body:
            import hashlib
            digest = hashlib.sha256(body).digest()
            digest_b64 = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
            components.append(('content-digest', f'sha-256=:{digest_b64}:'))
        
        # Build signature params (without label prefix)
        # Per RFC 9421: @signature-params value does NOT include the label (sig=)
        sig_input_parts = []
        for name, value in components:
            sig_input_parts.append(f'"{name}"')
        sig_input_parts.append('"signature-key"')  # Add signature-key component
        
        # sig_params is the value for @signature-params (no label prefix)
        sig_params = f'({" ".join(sig_input_parts)});created={now}'
        # sig_input is the full Signature-Input header (with label prefix)
        sig_input = f'sig={sig_params}'
        
        # Build Signature-Key header with scheme=jwt
        # Format: sig=jwt;jwt=<upstream_token>
        # Note: The label must match the label used in Signature-Input and Signature headers
        signature_key_header = f'sig=jwt;jwt={upstream_token}' if upstream_token else f'sig=jwt'
        
        # Build signature base string (must include signature-key component and @signature-params)
        sig_base_parts = []
        for name, value in components:
            sig_base_parts.append(f'"{name}": {value}')
        sig_base_parts.append(f'"signature-key": {signature_key_header}')  # Add signature-key to base
        
        # Add @signature-params line (required by RFC 9421)
        # Format: "@signature-params": (component1 component2 ...);created=timestamp
        # Note: Does NOT include the label prefix (sig=)
        sig_base_parts.append(f'"@signature-params": {sig_params}')
        
        sig_base = '\n'.join(sig_base_parts)
        
        # Sign with agent's private key
        sig_bytes = self.private_key.sign(sig_base.encode('utf-8'))
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode('utf-8').rstrip('=')
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': parsed_url.netloc,
            'Signature-Key': signature_key_header,
            'Signature-Input': sig_input,
            'Signature': f'sig=:{sig_b64}:'
        }
        
        if body:
            headers['Content-Digest'] = f'sha-256=:{digest_b64}:'
        
        if verbose:
            print(f"Signature Base String:\n{sig_base}\n")
            print(f"Signature-Key: {signature_key_header[:100]}...")
            print(f"Signature-Input: {sig_input}")
            print(f"Signature: sig=:{sig_b64[:20]}...\n")
        
        return headers
    
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
    parser.add_argument('--refresh-token', help='Refresh token for token refresh')
    parser.add_argument('--exchange', action='store_true', help='Exchange upstream token for new token')
    parser.add_argument('--upstream-token', help='Upstream auth token JWT (for token exchange)')
    parser.add_argument('--create-mock-resource-token', action='store_true', help='Create a mock resource token')
    parser.add_argument('--resource-id', help='Resource identifier for mock resource token (iss claim)')
    parser.add_argument('--aud-agent-id', help='Agent ID for mock resource token (agent claim - agent for whom token is intended)')
    parser.add_argument('--auth-server-id', help='Auth server ID for mock resource token (aud claim)')
    parser.add_argument('--metadata', action='store_true', help='Fetch metadata only')
    parser.add_argument('--agent-id', default='https://agent.example.com', help='Agent identifier')
    parser.add_argument('--agent-url', help='Agent URL for scheme=jwks (e.g., http://localhost:9002). If provided, uses scheme=jwks instead of scheme=hwk')
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
    
    # Create mock resource token flow
    if args.create_mock_resource_token:
        print("Creating mock resource token...")
        if not args.resource_id or not args.aud_agent_id or not args.scope or not args.auth_server_id:
            print("ERROR: --resource-id, --aud-agent-id, --scope, and --auth-server-id are required for --create-mock-resource-token", file=sys.stderr)
            sys.exit(1)
        
        try:
            result = client.create_mock_resource_token(
                args.resource_id,
                args.aud_agent_id,
                args.auth_server_id,
                args.scope,
                verbose=args.verbose
            )
            print(f"Status: {result['status_code']}")
            print(f"\nResponse:\n{json.dumps(result['body'], indent=2)}")
            if result['status_code'] == 200 and 'resource_token' in result['body']:
                print("\n✅ Mock Resource Token created successfully!")
                print(f"\nResource Token: {result['body']['resource_token']}")
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
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
                agent_url=args.agent_url,
                verbose=args.verbose
            )
            
            print(f"Status: {result['status_code']}")
            print(f"\nResponse:\n{json.dumps(result['body'], indent=2)}")
            
            if result['status_code'] == 200 and 'auth_token' in result['body']:
                print("\n✅ Code exchanged successfully!")
                print(f"\nToken (first 50 chars): {result['body']['auth_token'][:50]}...")
                if 'refresh_token' in result['body']:
                    print(f"Refresh Token: {result['body']['refresh_token'][:50]}...")
                    print(f"\nTo refresh this token, use:")
                    print(f"  python {sys.argv[0]} --base-url {args.base_url} --realm {args.realm} --refresh-token {result['body']['refresh_token']}")
            
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        return
    
    # Refresh token flow
    if args.refresh_token:
        print("Refreshing auth token...")
        if args.verbose:
            print(f"  URL: {args.base_url}/realms/{args.realm}/protocol/aauth/agent/token")
            print(f"  Refresh Token: {args.refresh_token[:50]}...")
            print()
        
        try:
            result = client.refresh_token(
                args.base_url,
                args.realm,
                args.refresh_token,
                verbose=args.verbose
            )
            
            print(f"Status: {result['status_code']}")
            print(f"\nResponse:\n{json.dumps(result['body'], indent=2)}")
            
            if result['status_code'] == 200 and 'auth_token' in result['body']:
                print("\n✅ Token refreshed successfully!")
                print(f"\nNew Token (first 50 chars): {result['body']['auth_token'][:50]}...")
                print(f"Expires In: {result['body'].get('expires_in', 'N/A')} seconds")
            
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        return
    
    # Token exchange flow
    if args.exchange:
        if not args.resource_token:
            print("ERROR: --resource-token is required for token exchange", file=sys.stderr)
            sys.exit(1)
        if not args.upstream_token:
            print("ERROR: --upstream-token is required for token exchange", file=sys.stderr)
            sys.exit(1)
        
        print("Exchanging upstream token for new auth token...")
        if args.verbose:
            print(f"  URL: {args.base_url}/realms/{args.realm}/protocol/aauth/agent/token")
            print(f"  Resource Token: {args.resource_token[:50]}...")
            print(f"  Upstream Token: {args.upstream_token[:50]}...")
            print()
        
        try:
            result = client.exchange_token(
                args.base_url,
                args.realm,
                args.resource_token,
                args.upstream_token,
                verbose=args.verbose
            )
            
            print(f"Status: {result['status_code']}")
            print(f"\nResponse:\n{json.dumps(result['body'], indent=2)}")
            
            if result['status_code'] == 200 and 'auth_token' in result['body']:
                print("\n✅ Token exchanged successfully!")
                print(f"\nNew Auth Token (first 50 chars): {result['body']['auth_token'][:50]}...")
                print("\nTo inspect the actor claim in the token, decode the JWT and check the 'act' field.")
            
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        return
    
    # Token request flow
    if not args.scope and not args.resource_token and not args.code and not args.refresh_token and not args.exchange:
        print("ERROR: Either --scope, --resource-token, --code, or --refresh-token must be provided")
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
            agent_url=args.agent_url,
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

