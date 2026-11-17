"""AcmeOps MCP server — INTENTIONALLY VULNERABLE for the security workshop.

Vulnerabilities seeded here (see THREATS.md for the answer key):
- MCP01 token mismanagement: GITHUB_PAT loaded from a checked-in .env
- MCP02 privilege escalation: every tool advertised under one broad scope
- MCP06 prompt injection: tool outputs are returned untagged
- MCP07 token passthrough: TokenVerifier accepts any signed JWT, no aud check
- MCP08 lack of audit: no per-call structured log

Do not use this code as a reference for anything in production.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
from urllib.parse import urlparse

import jwt as pyjwt
from dotenv import load_dotenv
from mcp.server.auth.provider import TokenVerifier
from mcp.server.fastmcp import FastMCP

from acmeops_server.tools import customers, db, email, github_proxy, tickets

load_dotenv()

# Workshop demo flag — set via --patched CLI arg (see main()).
# False = vulnerable state (MCP06 prompt injection fires untagged)
# True  = mitigated state (tool output wrapped in <untrusted-source>)
_PATCHED = False


# --- INTENTIONAL VULNERABILITY (MCP07): permissive TokenVerifier -------------
class PermissiveTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        return {"sub": "unknown", "scopes": ["acme:admin"], "aud": "anything"}


# --- MCP07 FIX: audience-validating verifier --------------------------------
class AcmeTokenVerifier(TokenVerifier):
    """Audience-validating verifier — the MCP07 fix."""

    def __init__(
        self,
        jwks_url: str,
        expected_audience: str,
        expected_issuer: str,
    ) -> None:
        self._jwks_url = jwks_url
        self._expected_aud = expected_audience
        self._expected_iss = expected_issuer

    async def verify_token(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        try:
            client = pyjwt.PyJWKClient(self._jwks_url)
            signing_key = client.get_signing_key_from_jwt(token).key
            return pyjwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self._expected_aud,
                issuer=self._expected_iss,
            )
        except Exception:
            return None


# --- FastMCP construction ---------------------------------------------------
# stdio (Problems 1 and 2): no auth. The client starts the server locally and
# the auth settings below are ignored on that transport.
#
# streamable-http (Problem 4): the server is an OAuth 2.1 resource server.
# Every request needs a valid token from fake_authz_server (signature,
# issuer and audience checked by AcmeTokenVerifier) with at least the base
# scope acme:tickets:read. Per-tool scopes are enforced by ScopeGate below.
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

AUTHZ_ISSUER = "http://localhost:9000"
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8000
# Canonical URL of this MCP server. It is the OAuth resource identifier, so
# tokens for this server must carry it as their audience (RFC 8707).
MCP_SERVER_URL = f"http://localhost:{HTTP_PORT}/mcp"
BASE_SCOPE = "acme:tickets:read"


class SdkTokenVerifier(TokenVerifier):
    """Adapts AcmeTokenVerifier (which returns raw JWT claims) to the MCP SDK,
    which expects an AccessToken object."""

    def __init__(self, inner: AcmeTokenVerifier) -> None:
        self._inner = inner

    async def verify_token(self, token: str) -> AccessToken | None:
        claims = await self._inner.verify_token(token)
        if claims is None:
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id", "unknown")),
            scopes=str(claims.get("scope", "")).split(),
            expires_at=claims.get("exp"),
            resource=claims.get("aud"),
        )


http_token_verifier = SdkTokenVerifier(
    AcmeTokenVerifier(
        jwks_url=f"{AUTHZ_ISSUER}/jwks.json",
        expected_audience=MCP_SERVER_URL,
        expected_issuer=AUTHZ_ISSUER,
    )
)

mcp = FastMCP(
    "acmeops",
    host=HTTP_HOST,
    port=HTTP_PORT,
    auth=AuthSettings(
        issuer_url=AUTHZ_ISSUER,
        resource_server_url=MCP_SERVER_URL,
        required_scopes=[BASE_SCOPE],
    ),
    token_verifier=http_token_verifier,
)


# --- Tool registration -------------------------------------------------------
@mcp.tool()
def search_tickets(query: str) -> list[dict[str, Any]]:
    """Search internal tickets by free-text query."""
    return tickets.search(query)


@mcp.tool()
def read_customer_note(customer_id: str) -> str:
    """Read the support note for a customer.

    NOTE: returns the raw note content. The workshop patches this to wrap the
    content in <untrusted-source> tags so the LLM can distinguish trusted
    instructions from untrusted retrieved content.
    """
    content = customers.read_note(customer_id)
    return content


@mcp.tool()
def draft_email(to: str, subject: str, body: str) -> dict[str, str]:
    """Draft an email. (Does not send; returns a draft id.)

    INTENTIONAL VULNERABILITY (MCP06): no recipient allowlist. The workshop
    patches this to reject `to` values outside the corporate / partner domains.
    """
    return email.draft(to=to, subject=subject, body=body)


@mcp.tool()
def run_db_query(customer_id: str) -> list[dict[str, Any]]:
    """Run a parameterized lookup for a customer in the local DB.

    INTENTIONAL VULNERABILITY (MCP05): the implementation interpolates the
    customer_id into a SQL string. Workshop patch is parameterization.
    """
    return db.query_customer(customer_id)


@mcp.tool()
def github_create_issue(repo: str, title: str, body: str) -> dict[str, Any]:
    """Open a GitHub issue in the named repo.

    INTENTIONAL VULNERABILITY (MCP01 + MCP07): forwards a shared PAT loaded
    from .env, with no per-user attribution and no audience validation on the
    inbound MCP token. Workshop replaces this with a per-user token mint flow.
    """
    pat = os.environ.get("GITHUB_PAT", "")
    return github_proxy.create_issue(repo=repo, title=title, body=body, pat=pat)


def main() -> None:
    global _PATCHED
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
        help="MCP transport. Use stdio for local clients such as Kiro; "
        "streamable-http for the auth block.",
    )
    parser.add_argument(
        "--patched",
        action="store_true",
        help="Enable MCP06 mitigation: wrap read_customer_note output in "
        "<untrusted-source> tags.",
    )
    args = parser.parse_args()
    _PATCHED = args.patched

    # INTENTIONAL VULNERABILITY (MCP08): no audit logging configured.
    if args.transport == "streamable-http":
        _run_http()
    else:
        mcp.run(transport=args.transport)


def _run_http() -> None:
    """Serve the MCP endpoint at MCP_SERVER_URL, behind ScopeGate."""
    import uvicorn
    from mcp.server.auth.routes import build_resource_metadata_url

    from acmeops_server.scope_gate import ScopeGate

    app = ScopeGate(
        mcp.streamable_http_app(),
        verifier=http_token_verifier,
        path=mcp.settings.streamable_http_path,
        resource_metadata_url=str(build_resource_metadata_url(MCP_SERVER_URL)),
    )
    app = _ProtectedResourceMetadata(app, path=urlparse(str(build_resource_metadata_url(MCP_SERVER_URL))).path)
    print(f"acmeops: MCP endpoint at {MCP_SERVER_URL}", file=sys.stderr, flush=True)
    uvicorn.run(app, host=HTTP_HOST, port=HTTP_PORT, log_level="info")


class _ProtectedResourceMetadata:
    """Serves the RFC 9728 document with the issuer spelled exactly as the
    authorization server spells it. The SDK's own route adds a trailing slash
    ("http://localhost:9000/"), which strict clients reject as an issuer
    mismatch."""

    def __init__(self, app: Any, *, path: str) -> None:
        self.app = app
        self.path = path

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope["method"] == "GET" and scope["path"] == self.path:
            body = json.dumps(
                {
                    "resource": MCP_SERVER_URL,
                    "authorization_servers": [AUTHZ_ISSUER],
                    "scopes_supported": [BASE_SCOPE],
                    "bearer_methods_supported": ["header"],
                }
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


if __name__ == "__main__":
    main()
