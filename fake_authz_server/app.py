from __future__ import annotations

import base64
import hashlib
import html
import json
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import jwt
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route

KEYS_DIR = Path(__file__).resolve().parent / "keys"
ISSUER = "http://localhost:9000"
# Resource indicators (RFC 8707) this server issues tokens for. The token's
# audience is the resource the client asked for.
#   - http://localhost:8000/mcp : acmeops over HTTP, used by the MCP client (Problem 4)
#   - https://acmeops.internal  : the audience used by the token demos (Problem 3)
MCP_RESOURCE = "http://localhost:8000/mcp"
RESOURCE = "https://acmeops.internal"
ALLOWED_RESOURCES = {MCP_RESOURCE, RESOURCE}

# Loaded on startup
_PRIVATE_KEY: str = ""
_PUBLIC_JWK: dict[str, Any] = {}

_clients: dict[str, dict[str, Any]] = {}      # client_id -> metadata
_codes: dict[str, dict[str, Any]] = {}        # auth_code -> {client_id, code_challenge, scope, sub}


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _load_keys() -> None:
    global _PRIVATE_KEY, _PUBLIC_JWK
    KEYS_DIR.mkdir(exist_ok=True)
    priv = KEYS_DIR / "private.pem"
    pub = KEYS_DIR / "public.pem"
    if not priv.exists():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        pub.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    _PRIVATE_KEY = priv.read_text()

    from cryptography.hazmat.primitives import serialization
    pub_key = serialization.load_pem_public_key(pub.read_bytes())
    nums = pub_key.public_numbers()  # type: ignore[union-attr]
    _PUBLIC_JWK = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "fake-authz-1",
        "n": _b64url(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")),
    }


# --- Metadata endpoints ------------------------------------------------------
async def as_metadata(_: Request) -> JSONResponse:
    """RFC 8414 — Authorization Server Metadata."""
    return JSONResponse(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "registration_endpoint": f"{ISSUER}/register",
            "jwks_uri": f"{ISSUER}/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [
                "acme:tickets:read",
                "acme:emails:write",
                "acme:db:read",
                "acme:github:write",
            ],
        }
    )


async def resource_metadata(_: Request) -> JSONResponse:
    """RFC 9728 — Protected Resource Metadata.

    The MCP spec uses this to discover the AS from the resource server's URL.
    """
    return JSONResponse(
        {
            "resource": MCP_RESOURCE,
            "authorization_servers": [ISSUER],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [
                "acme:tickets:read",
                "acme:emails:write",
                "acme:db:read",
                "acme:github:write",
            ],
        }
    )


async def jwks(_: Request) -> JSONResponse:
    return JSONResponse({"keys": [_PUBLIC_JWK]})


# --- Dynamic Client Registration (RFC 7591) ----------------------------------
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _redirect_uri_allowed(requested: str, registered: list[str]) -> bool:
    """Exact match, except for loopback redirect URIs, where the port may
    differ (RFC 8252 section 7.3). Native clients such as Kiro open a new
    random local port for each authorization, so a later login (for example
    a step-up for a new scope) comes back on a different port."""
    if requested in registered:
        return True
    req = urlsplit(requested)
    if req.scheme != "http" or req.hostname not in _LOOPBACK_HOSTS:
        return False
    for uri in registered:
        reg = urlsplit(uri)
        if (reg.scheme, reg.hostname, reg.path, reg.query) == (req.scheme, req.hostname, req.path, req.query):
            return True
    return False

async def register(request: Request) -> JSONResponse:
    body = await request.json()
    client_id = f"mcp-{uuid.uuid4().hex[:12]}"
    redirect_uris = body.get("redirect_uris") or []
    if not redirect_uris:
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    _clients[client_id] = {
        "client_id": client_id,
        "redirect_uris": redirect_uris,
        "client_name": body.get("client_name", "unknown"),
        "token_endpoint_auth_method": "none",  # public client, PKCE only
        "registered_at": int(time.time()),
        "granted_scopes": [],
    }
    _save_clients()
    return JSONResponse({k: v for k, v in _clients[client_id].items() if k != "granted_scopes"})


# --- Client persistence --------------------------------------------------------
# Registrations are saved to disk so that restarting this server does not
# break clients that registered earlier (they keep their client_id).
CLIENTS_FILE = Path(__file__).resolve().parent / "clients.json"


def _load_clients() -> None:
    if CLIENTS_FILE.exists():
        try:
            _clients.update(json.loads(CLIENTS_FILE.read_text(encoding="utf-8")))
        except ValueError:
            pass


def _save_clients() -> None:
    CLIENTS_FILE.write_text(json.dumps(_clients, indent=2), encoding="utf-8")


# --- Authorization with a consent screen ----------------------------------------
SCOPE_DESCRIPTIONS = {
    "acme:tickets:read": "Read support tickets and customer notes",
    "acme:emails:write": "Draft emails on behalf of Acme",
    "acme:db:read": "Query the customer database",
    "acme:github:write": "Create GitHub issues",
}

_pending: dict[str, dict[str, Any]] = {}  # request_id -> validated authorization request
PENDING_TTL = 300


async def authorize(request: Request) -> HTMLResponse | PlainTextResponse:
    qp = request.query_params
    client_id = qp.get("client_id", "")
    redirect_uri = qp.get("redirect_uri", "")
    code_challenge = qp.get("code_challenge", "")
    code_method = qp.get("code_challenge_method", "")
    scope = qp.get("scope", "acme:tickets:read")
    state = qp.get("state", "")
    resource = qp.get("resource", MCP_RESOURCE)

    recovered = False
    if client_id not in _clients:
        # Workshop convenience: a client registered before a restart of an
        # older version of this server (no persistence) comes back with a
        # client_id we no longer know. Accept it again for local redirect URIs
        # only, and say so on the consent screen.
        if not (client_id.startswith("mcp-") and _is_loopback(redirect_uri)):
            return PlainTextResponse("unknown client_id", status_code=400)
        _clients[client_id] = {
            "client_id": client_id,
            "redirect_uris": [redirect_uri],
            "client_name": "unknown (registration recovered)",
            "token_endpoint_auth_method": "none",
            "registered_at": int(time.time()),
            "granted_scopes": [],
        }
        _save_clients()
        recovered = True
    if not _redirect_uri_allowed(redirect_uri, _clients[client_id]["redirect_uris"]):
        return PlainTextResponse("redirect_uri mismatch", status_code=400)
    if code_method != "S256":
        return PlainTextResponse("PKCE S256 required", status_code=400)
    if resource.rstrip("/") not in ALLOWED_RESOURCES:
        return PlainTextResponse("resource indicator mismatch", status_code=400)

    now = time.time()
    for rid in [r for r, p in _pending.items() if p["created"] + PENDING_TTL < now]:
        del _pending[rid]
    request_id = secrets.token_urlsafe(16)
    _pending[request_id] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "scope": scope,
        "state": state,
        "resource": resource.rstrip("/"),
        "created": now,
    }
    return HTMLResponse(_consent_page(request_id, _clients[client_id], scope, resource, recovered))


async def decide(request: Request) -> RedirectResponse | PlainTextResponse:
    form = await request.form()
    pending = _pending.pop(str(form.get("request_id", "")), None)
    if pending is None:
        return PlainTextResponse("authorization request expired, start again from the MCP client", status_code=400)

    redirect_uri = pending["redirect_uri"]
    sep = "&" if "?" in redirect_uri else "?"
    state = quote(pending["state"], safe="")
    if form.get("decision") != "approve":
        return RedirectResponse(f"{redirect_uri}{sep}error=access_denied&state={state}", status_code=303)

    client = _clients[pending["client_id"]]
    client["granted_scopes"] = sorted(set(client.get("granted_scopes", [])) | set(pending["scope"].split()))
    _save_clients()

    code = secrets.token_urlsafe(24)
    _codes[code] = {
        "client_id": pending["client_id"],
        "code_challenge": pending["code_challenge"],
        "scope": pending["scope"],
        "resource": pending["resource"],
        "sub": f"user-{secrets.token_hex(4)}",  # workshop: anonymous fake user
        "expires_at": int(time.time()) + 60,
    }
    return RedirectResponse(f"{redirect_uri}{sep}code={code}&state={state}", status_code=303)


def _is_loopback(uri: str) -> bool:
    parts = urlsplit(uri)
    return parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS


def _consent_page(request_id: str, client: dict[str, Any], scope: str, resource: str, recovered: bool) -> str:
    already = set(client.get("granted_scopes", []))
    rows = []
    for s in scope.split():
        badge = "" if s in already else ' <strong class="new">new</strong>'
        desc = html.escape(SCOPE_DESCRIPTIONS.get(s, "Unknown permission"))
        rows.append(f"<li><code>{html.escape(s)}</code>{badge}<br><span>{desc}</span></li>")
    warning = (
        '<p class="warn" role="note">This client was not registered with this server (it was probably '
        "restarted). Its registration was recovered.</p>"
        if recovered
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize access to AcmeOps</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 32rem; margin: 3rem auto; padding: 0 1rem;
         color: #1a1a1a; background: #f7f7f7; line-height: 1.5; }}
  main {{ background: #fff; border: 1px solid #ccc; border-radius: 8px; padding: 1.5rem; }}
  h1 {{ font-size: 1.3rem; margin-top: 0; }}
  ul {{ padding-left: 1.2rem; }}
  li {{ margin-bottom: .6rem; }}
  li span {{ color: #444; }}
  .new {{ background: #8a4b00; color: #fff; border-radius: 4px; padding: 0 .4rem; font-size: .8rem; }}
  .warn {{ background: #fff4e5; color: #5c3b00; border: 1px solid #e0a040; border-radius: 6px; padding: .6rem; }}
  .actions {{ display: flex; gap: .8rem; margin-top: 1.2rem; }}
  button {{ font: inherit; padding: .5rem 1.2rem; border-radius: 6px; cursor: pointer; }}
  button[value=approve] {{ background: #0b5cad; color: #fff; border: 1px solid #0b5cad; }}
  button[value=deny] {{ background: #fff; color: #1a1a1a; border: 1px solid #666; }}
  button:focus-visible {{ outline: 3px solid #1a1a1a; outline-offset: 2px; }}
</style>
</head>
<body>
<main>
  <h1><strong>{html.escape(client.get("client_name", "unknown"))}</strong> wants access to AcmeOps</h1>
  {warning}
  <p>Resource: <code>{html.escape(resource)}</code></p>
  <p id="scopes-label">It is asking for these permissions:</p>
  <ul aria-labelledby="scopes-label">
    {"".join(rows)}
  </ul>
  <form method="post" action="/authorize/decision">
    <input type="hidden" name="request_id" value="{html.escape(request_id)}">
    <div class="actions">
      <button type="submit" name="decision" value="approve">Allow</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </div>
  </form>
</main>
</body>
</html>"""


async def token(request: Request) -> JSONResponse:
    form = await request.form()
    code = str(form.get("code", ""))
    verifier = str(form.get("code_verifier", ""))
    client_id = str(form.get("client_id", ""))

    record = _codes.pop(code, None)
    if not record or record["expires_at"] < time.time():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if record["client_id"] != client_id:
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    expected = _b64url(hashlib.sha256(verifier.encode()).digest())
    if expected != record["code_challenge"]:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": record["resource"],  # Critical: aud is the resource the client asked for, never a third party
        "sub": record["sub"],
        "scope": record["scope"],
        "iat": now,
        "exp": now + 600,       # 10-minute access tokens
        "client_id": client_id,
    }
    access_token = jwt.encode(
        claims,
        _PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": _PUBLIC_JWK["kid"]},
    )
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 600,
            "scope": record["scope"],
        }
    )


@asynccontextmanager
async def _lifespan(app: Starlette):
    _load_keys()
    _load_clients()
    yield


def make_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/.well-known/oauth-authorization-server", as_metadata),
            Route("/.well-known/oauth-protected-resource", resource_metadata),
            Route("/jwks.json", jwks),
            Route("/register", register, methods=["POST"]),
            Route("/authorize", authorize, methods=["GET"]),
            Route("/authorize/decision", decide, methods=["POST"]),
            Route("/token", token, methods=["POST"]),
        ],
        lifespan=_lifespan,
    )


def main() -> None:
    uvicorn.run(make_app(), host="127.0.0.1", port=9000, log_level="info")


if __name__ == "__main__":
    main()
