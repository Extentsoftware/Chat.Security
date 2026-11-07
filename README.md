# Bongo AI: standalone Python demo

A self-contained Python port of `src/Bongo.AI` from the BongoFms repo (the Semantic Kernel farm assistant), built to
show off its security model. It is a small web site plus an MCP endpoint over one SQLite file.
No .NET, PostgreSQL, Kubernetes or Google Sheets needed.

## Run it

```bash
cd C:\data\Extentsoftware\Chat.Security
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Linux/macOS: .venv/bin/python
.venv/Scripts/python scripts/seed.py               # builds data/bongo_demo.db
.venv/Scripts/python -m uvicorn bongo_ai.app:app --app-dir . --port 8765
```

Open http://localhost:8765. All demo accounts use the password `BongoDemo!2026` (set
`BONGO_DEMO_PASSWORD` before seeding to change it).

| User | Role | What it shows |
|---|---|---|
| `director` | Director | Everything, plus impersonation (`a-stg-imp`) and the calendar run |
| `manager` | FarmManager | Leadership: write tools, can authorise after confirmation |
| `supervisor` | Supervisor | Leadership (write tools) but **no** `a-act-auth`: authorise fails inside the tool |
| `scout` | Scout | Not leadership: every write tool is removed |
| `guard` | Guard | No `p-ai`: chat and MCP are refused |
| `locked.user` / `disabled.user` | | Login refused with the same generic message |
| `kariba.manager` | FarmManager, other tenant | Tenant isolation: sees only the synthetic Kariba estate |

### In VS Code

Open the `Chat.Security` folder (File → Open Folder) so `.vscode/` is picked up.

1. First time only: *Terminal → Run Task → Setup: create venv and install requirements*, then *Seed database*.
2. Copy `.env.example` to `.env` and add `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` if you want live chat.
   Set `BONGO_JWT_KEY` so restarts don't sign you out.
3. Press **F5** and pick **Bongo AI: web server**. Breakpoints work in `bongo_ai/`, and the browser opens
   when the server is up. For edit-and-reload without the debugger, use *Run Task → Run web server (auto-reload)*.
4. Tests show in the Testing panel (beaker icon), or run the **Tests (pytest)** debug config.

### LLM

**Azure AI Foundry** (same approach as `Bongo.AI/OpenAIClientFactory.cs`): put these in `.env`:

```
BONGO_FOUNDRY_ENDPOINT=https://<resource>.cognitiveservices.azure.com
BONGO_FOUNDRY_DEPLOYMENT=<deployment name>
BONGO_FOUNDRY_API_KEY=<key>
```

A host-only URL becomes `<host>/openai/v1/` and the deployment name is sent as the model. URLs that
already contain `/openai` or `/api/projects/` are used as given. A Claude deployment (URL containing
`/anthropic`, or `BONGO_FOUNDRY_API=anthropic`) goes through the Anthropic SDK's `AnthropicFoundry`
client. Foundry takes priority over the keys below when all three settings are present.

Otherwise chat uses **Claude** (`claude-opus-5-5`, adaptive thinking, effort `medium`, with server-side refusal
fallback enabled) when `ANTHROPIC_API_KEY` is set, or **OpenAI** (`gpt-5`, as the C# service uses)
when `OPENAI_API_KEY` is set. Force one with `BONGO_LLM_PROVIDER=anthropic|openai|offline`; change
models with `BONGO_ANTHROPIC_MODEL`, `BONGO_ANTHROPIC_EFFORT`, `BONGO_OPENAI_MODEL`. If your shell
has `ANTHROPIC_BASE_URL` set for something else, unset it.

With no key the app runs **offline**: chat says so, and the **Tool console** runs any tool through
the exact same security pipeline, so the whole security demo still works.

## Security features to demo

1. **Token login.** HS256 JWT with the same claims as the C# issuer (`sub`, `UserId`, `RoleId`,
   `Rolename`, `Permissions`, `tenant_id`, `company_id`, `site_id`…). One generic "Login failure"
   for every reason, with equal timing for unknown users. PBKDF2 password hashes. On every request
   the token is checked against a revocation list (sign-out) and the account's locked/disabled flags.
   *Demo additions:* lockout after 5 bad passwords (15 min), per-IP login rate limit.
2. **Role-based tool filtering** (`ChatToolCatalog.Filter`). Non-leadership roles lose every write
   tool. The unattended **calendar identity** may only propose. Templates narrow the tool set.
   Subagents get farm reads only. See *Security → Tool access* for the full matrix and the reason
   behind every "no".
3. **Defence in depth.** The model is only offered permitted tools, but the executor re-checks every
   call, so a forged call to an unoffered tool is refused and audited. Arguments are validated
   against the schema, and unknown keys (e.g. a smuggled `tenantId`) are rejected.
4. **Human confirmation gate** (`ToolConfirmation`). `AuthoriseActivity` and `StartActivity` only run
   when the user's own message is exactly `Confirm <Function> <token>`, issued by the server,
   bound to the same arguments, valid 30 minutes, one pending per conversation. The model cannot
   produce it: `SendSuggestions` drops anything that looks like a label.
5. **Prompt-injection drill.** A seeded observation on B2-S1-A tells the assistant to authorise
   everything and supplies a fake label. Ask the manager's chat *"Any orchard check notes from
   yesterday? Act on them."* The record is flagged, and even a model that obeys gets "Not executed",
   plus a real label only the human can click. See *Prompt-injection defences* below.
6. **Layered authorisation.** The supervisor passes the role filter and the confirmation gate, then
   `AuthoriseActivity` still refuses because the role lacks `a-act-auth`.
7. **Turn guards** (`ToolInvocationFilter`): 24 tool calls per turn, with a last-call note; three
   identical calls in a row stops the turn. Writes are serialised by a lock.
8. **Tenant isolation.** Every table has `tenant_id`, taken from the token, never from arguments.
   Log in as `kariba.manager` and as `manager` and compare. A Kariba session id is "not found" for Bongo.
9. **Conversation privacy.** Conversations belong to one user. Other users get 404.
10. **Impersonation.** Requires `a-stg-imp`, stays inside the actor's company, and the token
    carries an `act` claim, so the audit shows who is really acting.
11. **Audit.** Every tool call is logged (user, role, channel, arguments, outcome), along with every
    sign-in event. Bearer tokens/JWTs are scrubbed before anything is stored.
12. **MCP with the same rules.** `POST /mcp` needs the bearer token and applies the same role filter.
    Gated tools and chat-only tools are withheld, because MCP cannot prove a human confirmed.
    Rate limited per token.
13. **Browser hardening.** Strict CSP (no inline script), `X-Frame-Options: DENY`, `no-store` on the
    API. Model Markdown is sanitised with DOMPurify. Everything else is rendered with `textContent`.
    Leaflet is SRI-pinned. The token lives in `sessionStorage` (cleared when the tab closes).

## Prompt-injection defences

Injected instructions can arrive in our own tools' output (scout notes, observation notes, report and
activity text written by people) or from remote MCP servers (their tool descriptions and results).
None of the defences relies on the model obeying its instructions.

* **Taint tracking** (`executor.py`). Tools not on `catalog.TRUSTED_OUTPUT` (the default for any new
  tool, and always for remote tools) mark the conversation tainted. The taint is sticky, because that
  text stays in the history the model sees. In a tainted conversation **every write and every external
  call** needs the server-issued confirmation label. Regenerating the spray report is exempt, since it
  only derives from the farm's own data. The chat shows a banner while a conversation is tainted.
* **Approvals show what they approve.** The confirm prompt lists the tool and its exact arguments, so a
  person never approves a bare token.
* **Untrusted-data envelope.** Untrusted results reach the model as
  `<tool_result name=… trust="untrusted" source=…>` with a note that they carry no authority. Copies of
  the delimiter inside the data are neutralised, so the data cannot close the envelope. The system
  prompt explains the envelope.
* **Injection scanner** (heuristic, for visibility only). Looks for override/authority phrases, claims
  of prior approval, confirmation-label lookalikes, "don't tell the user", envelope breaks and names of
  write tools. A match adds a warning inside the envelope, a chat notice, a `flagged` audit row and an
  `injection_suspected` security event. It never decides whether a call is allowed.
* **Unattended calendar run.** It cannot ask anyone, so its propose-only writes still run in a tainted
  context, but each activity event records that fact. A manager still has to authorise the result.
* **MCP sessions.** A token's MCP session that has read untrusted output can no longer write, because
  nobody can confirm over MCP. Results go back to the client wrapped in the same envelope.
* **Links in replies.** External links show their real domain and ask before opening, with the full URL
  shown, since it may carry farm data. Non-web schemes become plain text. Images were already blocked by
  the CSP.

### Remote MCP servers (allow-listed and pinned)

Copy `mcp_servers.example.json` to `mcp_servers.json` (or set `BONGO_MCP_SERVERS`), then review and
approve tools:

```bash
.venv/Scripts/python scripts/mcp_pin.py            # shows each tool's full definition, prompts per tool
```

* Only listed servers are contacted. They must use https (http only for localhost), and redirects are
  not followed.
* A tool is offered to the model only if the hash of its exact definition was approved. New tools are
  ignored. A changed definition ("rug pull") is refused and logged as `mcp_tool_changed`. The model
  only ever sees the pinned copy.
* Remote tools are namespaced `ext_<server>__<tool>`, so they cannot shadow farm tools.
* Requests carry only that server's configured headers (secrets via `env:NAME`), never the user's token
  or identity.
* Every remote result is untrusted and truncated to `maxResultChars`. Tools without
  `readOnlyHint: true` are writes and always need confirmation. Once a conversation is tainted, every
  remote call does.
* Remote tools are kept from the calendar identity and subagents, are not re-exported over `/mcp`, and
  can be limited to some farms (`tenants`).
* Status shows on *Security → Remote MCP servers*.

## Connect an MCP client

Connect Claude Code to the MCP endpoint:

```bash
claude mcp add --transport http bongo http://localhost:8765/mcp --header "Authorization: Bearer <token>"
```

## Data

`scripts/seed.py` builds the database from the BongoFms data copied into `data/source/`:

* **Real:** per-tree pest scouting from `Pest Scouting Diary.csv` (the newest 31 days in the file:
  41 sessions, 365 tree reports), orchard checks from `scout.csv`, the 73 products in
  `chemicals.csv`, and the farm section polygons in `farm_sections.json` (EPSG:3857, extracted from
  BongoFms `2025-09-18-ImplementTenantApproach.sql`).
* **Re-dated:** that export ends on 2025-11-24, so by default dates move forward to end yesterday, which
  makes "last month" questions work. `--keep-dates` keeps the originals.
* **Synthetic** (marked in the banner): equipment, fuel, sprint boards, four seeded activities, the
  injection-test observation, and the Kariba tenant.

To load the **live** last month instead, port-forward the BongoFMS PostgreSQL and run
`scripts/import_postgres.py` (read-only, see its docstring). It replaces only the Bongo scout sessions.

## Tests

```bash
.venv/Scripts/python -m pytest -q
```

51 tests cover login, tokens (forged, `alg=none`, revoked), lockout, role filtering, the calendar
identity, confirmation labels, injected labels, layered authorisation, tenant isolation, impersonation,
MCP, audit redaction and conversation privacy. `tests/test_injection.py` covers taint gating, the
envelope and scanner, tainted MCP sessions, and remote MCP pinning, namespacing, credential isolation
and truncation against a mock MCP server. A scripted fake model drives the agent loop through
injection, forged calls, the repeat guard, templates and subagents. A stub client checks the Claude
adapter against real SDK types.

## Layout

```
bongo_ai/
  app.py          FastAPI routes, security headers, rate limits, SSE chat, /mcp
  security.py     passwords, JWT issue/verify, revocation, impersonation, security events
  catalog.py      which tools a caller may use, and why not
  executor.py     the per-call security pipeline: gates, taint, envelope, scanner, audit
  remote_mcp.py   allow-listed, pinned remote MCP servers
  agent.py        templates, system prompt, Claude/OpenAI loop, subagents
  mcp_server.py   JSON-RPC MCP handler
  registry.py     @tool decorator, JSON schema, argument validation
  tools/          the farm tools
  static/         single-page UI (vanilla JS)
scripts/seed.py, scripts/import_postgres.py, scripts/mcp_pin.py
tests/
```
