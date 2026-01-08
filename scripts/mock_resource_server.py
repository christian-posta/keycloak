#!/usr/bin/env python3
"""
Mock Resource Server for AAuth Testing

This script runs a simple HTTP server that serves:
- /.well-known/aauth-resource (resource metadata)
- /jwks.json (JWKS endpoint)

This allows testing resource token validation without a real resource server.

Usage:
    python mock_resource_server.py --port 9000 --resource-url https://resource.example.com

Note: For HTTPS, you'll need to use a reverse proxy or modify this script to use SSL.
For testing with Keycloak, you can use http://localhost:9000 if Keycloak is configured
to allow HTTP (not recommended for production).
"""

import argparse
import base64
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR: Required packages not installed.")
    print("Install with: pip install cryptography")
    sys.exit(1)


class MockResourceHandler(BaseHTTPRequestHandler):
    """HTTP request handler for mock resource server"""
    
    def __init__(self, resource_url: str, jwks: dict, *args, **kwargs):
        self.resource_url = resource_url
        self.jwks = jwks
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == "/.well-known/aauth-resource":
            self._serve_metadata()
        elif self.path == "/jwks.json":
            self._serve_jwks()
        else:
            self.send_error(404, "Not Found")
    
    def _serve_metadata(self):
        """Serve resource metadata"""
        metadata = {
            "resource": self.resource_url,
            "jwks_uri": f"{self.resource_url}/jwks.json",
            "resource_token_endpoint": f"{self.resource_url}/token",
            "supported_scopes": ["data.read", "data.write", "admin"],
            "scope_descriptions": {
                "data.read": "Read access to data",
                "data.write": "Write access to data",
                "admin": "Administrative access"
            }
        }
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(metadata, indent=2).encode())
    
    def _serve_jwks(self):
        """Serve JWKS"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(self.jwks, indent=2).encode())
    
    def log_message(self, format, *args):
        """Override to reduce log noise"""
        pass


def create_jwks(public_key: Ed25519PublicKey, kid: str = "resource-key-1") -> dict:
    """Create JWKS from Ed25519 public key"""
    # Serialize public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Base64URL encode
    x = base64.urlsafe_b64encode(public_bytes).decode('utf-8').rstrip('=')
    
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "x": x,
                "use": "sig",
                "alg": "EdDSA"
            }
        ]
    }


def main():
    parser = argparse.ArgumentParser(description="Mock Resource Server for AAuth Testing")
    parser.add_argument("--port", type=int, default=9000, help="Port to listen on (default: 9000)")
    parser.add_argument("--resource-url", type=str, default="http://localhost:9000",
                       help="Resource URL (default: http://localhost:9000)")
    parser.add_argument("--key-file", type=str, help="Path to save/load private key (PEM format)")
    parser.add_argument("--kid", type=str, default="resource-key-1", help="Key ID for JWKS")
    
    args = parser.parse_args()
    
    # Load or generate key pair
    if args.key_file:
        try:
            with open(args.key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
                if not isinstance(private_key, Ed25519PrivateKey):
                    print(f"ERROR: Key in {args.key_file} is not Ed25519")
                    sys.exit(1)
            print(f"Loaded private key from {args.key_file}")
        except FileNotFoundError:
            # Generate new key and save it
            private_key = Ed25519PrivateKey.generate()
            with open(args.key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            print(f"Generated new private key and saved to {args.key_file}")
    else:
        private_key = Ed25519PrivateKey.generate()
        print("Generated new private key (not saved)")
    
    public_key = private_key.public_key()
    
    # Create JWKS
    jwks = create_jwks(public_key, args.kid)
    
    print(f"\nMock Resource Server")
    print(f"Resource URL: {args.resource_url}")
    print(f"Listening on: http://0.0.0.0:{args.port}")
    print(f"\nEndpoints:")
    print(f"  GET {args.resource_url}/.well-known/aauth-resource")
    print(f"  GET {args.resource_url}/jwks.json")
    print(f"\nTo generate a resource token, use:")
    print(f"  python scripts/generate_resource_token.py --resource-url {args.resource_url} --key-file {args.key_file or 'resource_key.pem'}")
    print(f"\nPress Ctrl+C to stop\n")
    
    # Create handler factory with resource URL and JWKS captured in closure
    resource_url = args.resource_url
    def handler_factory(*handler_args, **handler_kwargs):
        return MockResourceHandler(resource_url, jwks, *handler_args, **handler_kwargs)
    
    # Start server
    server = HTTPServer(("0.0.0.0", args.port), handler_factory)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()


if __name__ == "__main__":
    main()

