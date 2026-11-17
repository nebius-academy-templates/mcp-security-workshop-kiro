"""Facilitator demo for Problem 4: least privilege and step-up authorization.

Gets two real tokens from the local fake authorization server through the full
OAuth flow (client registration, PKCE authorize, token exchange):

  1. a base token with only  acme:tickets:read
  2. a step-up token with    acme:tickets:read acme:emails:write

It prints the decoded claims of both, then shows which tool each token would
be allowed to call, and the WWW-Authenticate header a server would send back
when the scope is missing.

Start the authorization server first, in another terminal:
    uv run python -m fake_authz_server

Then run:
    uv run python scripts/scope_demo.py
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import sys
from urllib.parse import parse_qs, urlparse

import httpx
import jwt

ISSUER = "http://localhost:9000"
RESOURCE = "https://acmeops.internal"
REDIRECT_URI = "http://localhost:8765/callback"  # never called, we read the redirect ourselves

# Which scope each tool needs. This is the policy the server should enforce.
TOOL_SCOPES = {
    "search_tickets": "acme:tickets:read",
    "read_customer_note": "acme:tickets:read",
    "draft_email": "acme:emails:write",
}


def get_token(client: httpx.Client, client_id: str, scope: str) -> str:
    """Run one PKCE authorization code flow and return the access token."""
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    resp = client.get(
        f"{ISSUER}/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": scope,
            "resource": RESOURCE,
            "state": "demo",
        },
    )
    match = re.search(r'name="request_id" value="([^"]+)"', resp.text)
    if resp.status_code != 200 or not match:
        sys.exit(f"authorize failed: {resp.status_code} {resp.text[:200]}")
    # Click "Allow" on the consent page.
    resp = client.post(f"{ISSUER}/authorize/decision", data={"request_id": match.group(1), "decision": "approve"})
    if resp.status_code not in (302, 303, 307):
        sys.exit(f"consent failed: {resp.status_code} {resp.text}")
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]

    resp = client.post(
        f"{ISSUER}/token",
        data={"grant_type": "authorization_code", "code": code, "code_verifier": verifier, "client_id": client_id},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def verify(token: str) -> dict:
    """Check signature, issuer and audience, like AcmeTokenVerifier does."""
    key = jwt.PyJWKClient(f"{ISSUER}/jwks.json").get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["RS256"], audience=RESOURCE, issuer=ISSUER)


def show(label: str, token: str) -> None:
    claims = verify(token)
    granted = set(claims["scope"].split())
    print(f"\n=== {label} ===")
    for k in ("iss", "aud", "sub", "scope", "exp"):
        print(f"  {k:6}: {claims[k]}")
    print("  tool access:")
    for tool, needed in TOOL_SCOPES.items():
        if needed in granted:
            print(f"    {tool:20} ALLOWED")
        else:
            print(f"    {tool:20} DENIED  -> 403  WWW-Authenticate: Bearer error=\"insufficient_scope\", scope=\"{needed}\"")


def main() -> None:
    with httpx.Client(follow_redirects=False, timeout=10) as client:
        try:
            reg = client.post(f"{ISSUER}/register", json={"client_name": "scope-demo", "redirect_uris": [REDIRECT_URI]})
        except httpx.ConnectError:
            sys.exit("Cannot reach http://localhost:9000. Start it first: uv run python -m fake_authz_server")
        reg.raise_for_status()
        client_id = reg.json()["client_id"]

        show("1. Base token (least privilege)", get_token(client, client_id, "acme:tickets:read"))
        show("2. Step-up token (after the user grants email access)",
             get_token(client, client_id, "acme:tickets:read acme:emails:write"))


if __name__ == "__main__":
    main()
