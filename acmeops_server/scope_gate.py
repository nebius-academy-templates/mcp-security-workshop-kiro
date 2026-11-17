"""Per-tool scope enforcement for the HTTP transport (Problem 4).

The MCP SDK can only require scopes for the whole server (``required_scopes``).
That is enough for least privilege at connection time: every token needs the
base scope ``acme:tickets:read``. It is not enough for step-up authorization,
where a single tool needs more than the base scope.

``ScopeGate`` sits in front of the MCP endpoint. For each ``tools/call``
request it looks up the scope the tool needs in ``TOOL_SCOPES``. If the
caller's token does not have it, the gate answers like the MCP authorization
spec says a resource server should:

    HTTP 403
    WWW-Authenticate: Bearer error="insufficient_scope",
                      scope="acme:tickets:read acme:emails:write", ...

A spec-compliant client reads that header, asks the user to grant the extra
scope, gets a new token and retries the call.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.auth.provider import TokenVerifier
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# --- INTENTIONAL VULNERABILITY (MCP02): scope creep ---------------------------
# Tool name -> scope required to call it. Tools not listed here only need the
# base scope that every token already has.
#
# As shipped, nothing is listed, so a read-only token can also call
# draft_email, a tool with an external effect. Problem 4 fixes this.
TOOL_SCOPES: dict[str, str] = {}


class ScopeGate:
    """ASGI middleware that enforces TOOL_SCOPES on tools/call requests."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: TokenVerifier,
        path: str,
        resource_metadata_url: str,
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.path = path
        self.resource_metadata_url = resource_metadata_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"].rstrip("/") != self.path:
            await self.app(scope, receive, send)
            return

        # Read the body once, then replay it to the MCP app.
        body = b""
        more = True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        needed = _scopes_needed(body)
        if needed:
            token = _bearer_token(scope)
            # No token or an invalid token: let the SDK answer 401 as usual.
            access = await self.verifier.verify_token(token) if token else None
            if access is not None:
                missing = needed - set(access.scopes)
                if missing:
                    # Ask for what the token already has plus what is missing,
                    # so the new token does not lose the base scope.
                    wanted = " ".join(sorted(set(access.scopes) | needed))
                    await self._insufficient_scope(send, wanted, missing)
                    return

        await self.app(scope, replay, send)

    async def _insufficient_scope(self, send: Send, wanted: str, missing: set[str]) -> None:
        description = f"This tool requires {' '.join(sorted(missing))}"
        header = (
            f'Bearer error="insufficient_scope", scope="{wanted}", '
            f'resource_metadata="{self.resource_metadata_url}", '
            f'error_description="{description}"'
        )
        payload = json.dumps({"error": "insufficient_scope", "error_description": description}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                    (b"www-authenticate", header.encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})


def _scopes_needed(body: bytes) -> set[str]:
    """Return the scopes required by the tool calls in a JSON-RPC body."""
    try:
        data: Any = json.loads(body)
    except ValueError:
        return set()
    messages = data if isinstance(data, list) else [data]
    needed: set[str] = set()
    for msg in messages:
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            name = (msg.get("params") or {}).get("name")
            if name in TOOL_SCOPES:
                needed.add(TOOL_SCOPES[name])
    return needed


def _bearer_token(scope: Scope) -> str | None:
    for key, value in scope.get("headers", []):
        if key == b"authorization":
            text = value.decode("latin-1")
            if text.lower().startswith("bearer "):
                return text[7:].strip()
    return None
