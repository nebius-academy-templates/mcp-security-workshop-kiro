# Checklist: Before the workshop

This self-serve checklist gets you ready for the Securing MCP Servers workshop. Work through it top to bottom; tick each box as you complete it. You should be done in **under 30 minutes** if your machine already has a recent Python and a working terminal.

Total: 7 steps. The workshop itself is not about installing MCP servers. Once you finish Step 5, you're ready for the workshop.

---

## Step 0 — Pre-read (~30 min the night before)

We'll discuss all of these during the workshop. Skimming them ahead of time means you can spend the workshop diving into the material instead of reading it for the first time. You do not need to memorize anything.

- [ ] [MCP specification 2025-11-25](https://modelcontextprotocol.io/specification/latest) — focus on the [Security Best Practices](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices) and [Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization) pages.
- [ ] [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) — read the top-level taxonomy. You do not need to memorize the IDs; recognizing the categories (tool poisoning, token passthrough, prompt injection, etc.) is enough.

---

## Step 1 — Get the code

- [ ] Clone the workshop repo:
  ```bash
  git clone https://github.com/nebius-academy-templates/mcp-security-workshop-kiro.git
  cd mcp-security-workshop-kiro
  ```
  No Git? Open the repo page on GitHub, click **Code > Download ZIP**, unzip it, and open a terminal in the unzipped folder (it is named `mcp-security-workshop-kiro-main`).
- [ ] Every command below runs from this folder, the repo root.

---

## Step 2 — Local environment

- [ ] Confirm Python 3.11 or newer is installed:
  ```bash
  python3 --version    # need >= 3.11
  ```
  If you need to install it:
  ```bash
  # macOS:
  brew install python@3.11
  # Linux (pyenv):
  pyenv install 3.11.9 && pyenv global 3.11.9
  # Windows: install Python 3.11+ from https://www.python.org/downloads/
  ```
  If `python3` is not found, use `python` (or `py` on Windows).
- [ ] Install `uv` (the Python package/venv manager this repo uses):
  ```bash
  # macOS / Linux
  curl -LsSf https://astral.sh/uv/install.sh | sh
  exec $SHELL          # reload PATH so `uv` is on it
  uv --version         # sanity check — should print a version number
  ```
  ```powershell
  # Windows (PowerShell)
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  # then open a NEW terminal
  uv --version
  ```
- [ ] Sync dependencies (creates a project-local virtualenv and installs everything):
  ```bash
  uv sync
  ```

---

## Step 3 — Dependency sanity check

- [ ] Verify the core libraries actually import cleanly:
  ```bash
  uv run python -c "import mcp, httpx, jwt, yaml, starlette; print('ok')"
  ```
  Expected output: `ok`. Anything else means `uv sync` did not finish — re-run it and re-check.

---

## Step 4 — Open the repo in Kiro and check the MCP servers

The repo ships with `.kiro/settings/mcp.json`, which already declares both servers (`acmeops` and `summarizer_server`). You do not need to add anything. The workshop is not about wiring up MCP servers, so leave them connected for the whole workshop.

- [ ] Open the repo folder in **Kiro IDE** (File > Open Folder, pick `mcp-security-workshop-<firstname-lastname>`).
- [ ] Trust the workspace: when Kiro asks whether you trust this folder, choose to **trust** it. If you missed the prompt, open the command palette (Cmd+Shift+P on macOS, Ctrl+Shift+P on Windows/Linux), run **Workspaces: Manage Workspace Trust**, and trust the folder. Until the folder is trusted, Kiro does not load the repo's MCP configuration, so the servers will not appear. See [Workspace trust](https://kiro.dev/docs/permissions/#workspace-trust).
- [ ] Open the **Kiro** panel (ghost icon in the sidebar) and find the **MCP Servers** section. Both `acmeops` and `summarizer_server` should be listed and show as connected. If a server is still starting, wait a few seconds; the first start runs `uv` and can be slow.
- [ ] Set the chat to **Supervised** mode (not Autopilot). In Autopilot Kiro acts without asking, which skips the approval step the workshop relies on.
- [ ] Do **not** add the tools to `autoApprove`. When Kiro asks to run a tool, you approve it by hand. That is intended.

> **Do not edit or save `.kiro/settings/mcp.json` during the workshop.** Kiro restarts MCP servers whenever that file is saved, and that breaks the rug pull demo.

## Step 5 — Smoke-test each server (list one tool)

In Kiro's chat, send the prompt below once per server. Confirm that one of the expected tool names appears in the response. Don't worry about behaviour here as we'll do that during the workshop, only confirm Kiro can reach the server and read its tool list.

> "What tools does the `<server-name>` MCP server expose?"

Expected tools per server (any match is a pass):

- [ ] `acmeops` — `read_customer_note`, `draft_email`, `run_db_query`, etc.
- [ ] `summarizer_server` — `summarize`

If a server shows no tools or fails to connect, debug it now. Don't wait until right before the workshop.

---

## Step 6 — HTTP smoke-test the fake authz server

This is **not** an MCP server. It's a local OAuth 2.1 authorization server that you may get to use in one demo. Don't register it in your MCP client; just confirm that it runs.

- [ ] Start it in one terminal and leave it running:
  ```bash
  uv run python -m fake_authz_server
  ```
- [ ] In a **second** terminal, hit one of the "well-known" endpoints:
  ```bash
  # macOS / Linux
  curl -s http://localhost:9000/.well-known/oauth-authorization-server | python3 -m json.tool | head -10
  ```
  ```powershell
  # Windows (PowerShell)
  (Invoke-WebRequest http://localhost:9000/.well-known/oauth-authorization-server).Content
  ```
  Expected: a JSON object whose `issuer` field is `http://localhost:9000`.
- [ ] Stop the server with Ctrl+C in the first terminal.

---

## Step 7 — Final pre-flight

- [ ] Kiro's MCP Servers panel shows both `acmeops` and `summarizer_server` connected.
- [ ] Kiro is in **Supervised** mode.
- [ ] All smoke-test prompts in Step 5 returned the expected tool names.
- [ ] `uv run python -c "import mcp; print('ok')"` prints `ok`.
- [ ] You've at least skimmed the MCP 2025-11-25 spec's Security Best Practices section.

If every box is ticked, you're all set! See you on workshop day!
