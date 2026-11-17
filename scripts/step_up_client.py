"""Reference MCP client for Problem 4: least privilege and step-up authorization.

Connects to acmeops over HTTP the way a spec-compliant MCP client does, using
the MCP SDK's own OAuth implementation:

  1. Calls the server without a token, gets 401, discovers the authorization
     server from the protected resource metadata.
  2. Registers itself, runs the PKCE authorization code flow and gets a token
     with only the scope the server advertises: acme:tickets:read.
  3. Calls search_tickets (allowed with the base scope).
  4. Calls draft_email. If the server enforces per-tool scopes, it answers
     403 insufficient_scope, and the client re-authorizes with
     acme:emails:write, then retries the call.

The consent step is automatic: this script opens the authorization server's
consent page and clicks Allow itself instead of opening a browser. Every
authorization request is printed, so you can see when the client asks for more.

Start both servers first, each in its own terminal:
    uv run python -m fake_authz_server
    uv run python -m acmeops_server --transport streamable-http

Then run:
    uv run python scripts/step_up_client.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import sys
from urllib.parse import parse_qs, urlparse

import httpx
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

MCP_URL = "http://localhost:8000/mcp"
REDIRECT_URI = "http://localhost:8765/callback"  # never served, the redirect is read directly


class MemoryStorage(TokenStorage):
    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None
        self.client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens
        print(f"    token issued, scope: {_scope_of(tokens.access_token)}")

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.client_info = client_info


_pending: asyncio.Queue[tuple[str, str | None]] = asyncio.Queue()


async def auto_consent(authorization_url: str) -> None:
    """Stand-in for the browser: open the consent page, click Allow, keep the code."""
    scope = parse_qs(urlparse(authorization_url).query).get("scope", ["<none>"])[0]
    print(f"  -> authorization request, scope asked: {scope} (consent auto-approved)")
    async with httpx.AsyncClient(follow_redirects=False) as client:
        page = await client.get(authorization_url)
        match = re.search(r'name="request_id" value="([^"]+)"', page.text)
        if page.status_code != 200 or not match:
            sys.exit(f"authorization failed: {page.status_code} {page.text[:200]}")
        resp = await client.post(
            authorization_url.split("?")[0] + "/decision",
            data={"request_id": match.group(1), "decision": "approve"},
        )
    if resp.status_code not in (302, 303, 307):
        sys.exit(f"consent failed: {resp.status_code} {resp.text}")
    params = parse_qs(urlparse(resp.headers["location"]).query)
    await _pending.put((params["code"][0], params.get("state", [None])[0]))


async def callback() -> tuple[str, str | None]:
    return await _pending.get()


def _scope_of(jwt_token: str) -> str:
    payload = jwt_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload)).get("scope", "")


async def main() -> None:
    auth = OAuthClientProvider(
        server_url=MCP_URL,
        client_metadata=OAuthClientMetadata(
            client_name="step-up-demo",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=MemoryStorage(),
        redirect_handler=auto_consent,
        callback_handler=callback,
    )

    print("1. Connect (the client discovers the authorization server and logs in)")
    async with streamablehttp_client(MCP_URL, auth=auth) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("\n2. Read-only call: search_tickets")
            result = await session.call_tool("search_tickets", {"query": "CUST-42"})
            print(f"    isError={result.isError}")

            print("\n3. Call with an external effect: draft_email")
            result = await session.call_tool(
                "draft_email",
                {"to": "sam@acme.com", "subject": "Follow-up", "body": "Hello from the step-up demo."},
            )
            text = result.content[0].text if result.content else ""
            print(f"    isError={result.isError}  {text[:120]}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except httpx.ConnectError as exc:
        sys.exit(f"Cannot connect ({exc}). Start fake_authz_server and acmeops_server --transport streamable-http first.")
