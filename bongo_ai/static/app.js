"use strict";
// Bongo AI demo front end. Untrusted text is set with textContent; model Markdown goes through DOMPurify.

const S = { token: null, me: null, conversationId: null, template: "general", tools: null, busy: false, map: null };
const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined) n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return n;
};
const store = {
  get() { try { return sessionStorage.getItem("bongo.token"); } catch { return null; } },
  set(v) { try { v ? sessionStorage.setItem("bongo.token", v) : sessionStorage.removeItem("bongo.token"); } catch { /* private mode */ } },
};
const DEMO_USERS = ["director", "manager", "supervisor", "scout", "guard", "locked.user", "disabled.user", "kariba.manager"];

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(toast.timer); toast.timer = setTimeout(() => t.classList.add("hidden"), 4000);
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (S.token) headers.Authorization = `Bearer ${S.token}`;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401 && S.token) { signOut(false); toast("Session ended: " + ((await res.json().catch(() => ({}))).error || "sign in again")); throw new Error("401"); }
  if (!res.ok) { const body = await res.json().catch(() => ({})); throw new Error(body.error || body.detail || res.statusText); }
  return res.json();
}

function md(text) {
  const html = window.marked ? window.marked.parse(text || "", { breaks: true }) : (text || "");
  const clean = window.DOMPurify ? window.DOMPurify.sanitize(html, { FORBID_TAGS: ["style", "form", "input"], FORBID_ATTR: ["style"] }) : "";
  const div = el("div"); div.innerHTML = clean;
  div.querySelectorAll("a").forEach(guardLink);
  return div;
}

// Links in model output can carry farm data out in the URL (prompt-injection exfiltration), so an
// external link shows its real domain and asks before opening; non-web schemes become plain text.
function guardLink(a) {
  let url;
  try { url = new URL(a.getAttribute("href") || "", location.href); } catch { url = null; }
  if (!url || !["http:", "https:"].includes(url.protocol)) { a.replaceWith(document.createTextNode(a.textContent)); return; }
  a.rel = "noopener noreferrer nofollow";
  if (url.origin === location.origin) return;
  a.target = "_blank"; a.classList.add("ext-link");
  a.after(el("span", { class: "ext-domain", text: ` (${url.hostname})` }));
  a.addEventListener("click", (e) => {
    const shown = url.href.length > 300 ? `${url.href.slice(0, 300)}…` : url.href;
    if (!confirm(`This link was written by the AI and leaves Bongo for ${url.hostname}.

The address may contain farm data:
${shown}

Open it?`)) e.preventDefault();
  });
}

function showTaint(sources) {
  const b = $("#taint-banner");
  b.classList.toggle("hidden", !sources.length);
  b.textContent = sources.length
    ? `⚠ This conversation contains untrusted content (from ${sources.join(", ")}). Any change or external call the assistant makes from now on needs your confirmation.`
    : "";
}

// --- login -------------------------------------------------------------------------------------

function showLogin() {
  $("#app-view").classList.add("hidden"); $("#login-view").classList.remove("hidden");
  const box = $("#demo-user-buttons"); box.replaceChildren();
  DEMO_USERS.forEach((u) => box.append(el("button", { type: "button", text: u, onclick: () => { $("#login-user").value = u; $("#login-pass").focus(); } })));
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#login-error"); err.classList.add("hidden");
  const r = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: $("#login-user").value, password: $("#login-pass").value }) });
  const body = await r.json().catch(() => ({}));
  if (!r.ok || !body.isSuccess) { err.textContent = body.message || body.detail || "Login failure"; err.classList.remove("hidden"); return; }
  $("#login-pass").value = "";
  S.token = body.token; store.set(S.token); await boot();
});

async function signOut(callServer = true) {
  if (callServer && S.token) { try { await api("/api/auth/logout", { method: "POST" }); } catch { /* already gone */ } }
  S.token = null; S.me = null; S.conversationId = null; store.set(null); showLogin();
}
$("#logout-btn").addEventListener("click", () => signOut(true));

async function boot() {
  try { S.me = await api("/api/me"); } catch { return showLogin(); }
  $("#login-view").classList.add("hidden"); $("#app-view").classList.remove("hidden");
  const c = S.me.claims;
  $("#who-name").textContent = `${S.me.displayName} · ${S.me.tenant?.name || ""}`;
  $("#who-role").textContent = c.Rolename;
  const imp = $("#impersonation-badge");
  imp.classList.toggle("hidden", !c.impersonated_by); imp.textContent = c.impersonated_by ? `impersonated by ${c.impersonated_by}` : "";
  const prov = S.me.provider === "offline" ? "LLM: offline (no API key; Tool console still works)" : `LLM: ${S.me.model}`;
  $("#data-banner").textContent = `${prov}  ·  ${S.me.dataSource || ""}`;
  const sel = $("#template-select"), acc = $("#access-template");
  sel.replaceChildren(); acc.replaceChildren();
  S.me.templates.forEach((t) => { sel.append(el("option", { value: t.id, text: t.name })); acc.append(el("option", { value: t.id, text: t.name })); });
  $("#chat-disabled").classList.toggle("hidden", S.me.canChat);
  $("#chat-send").disabled = !S.me.canChat;
  newChat(); loadConversations(); switchTab("chat");
}

// --- tabs -----------------------------------------------------------------------------------------

document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));
function switchTab(name) {
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("hidden", t.id !== `tab-${name}`));
  ({ scout: loadScout, activities: loadActivities, console: loadConsole, security: loadSecurity }[name] || (() => {}))();
}

// --- chat ---------------------------------------------------------------------------------------------

function newChat() {
  S.conversationId = null; S.template = $("#template-select").value || "general";
  $("#chat-messages").replaceChildren(); $("#chat-suggestions").replaceChildren(); showTaint([]);
  const t = S.me.templates.find((x) => x.id === S.template);
  addMsg("event", `New ${t ? t.name : "chat"}. Every tool call is checked against your role (${S.me.claims.Rolename}) and logged.`);
  if (t && t.opening) showSuggestions({ suggestions: [t.opening] });
  document.querySelectorAll("#conversation-list li").forEach((li) => li.classList.remove("active"));
}
$("#new-chat-btn").addEventListener("click", newChat);
$("#template-select").addEventListener("change", newChat);

async function loadConversations() {
  const list = $("#conversation-list"); list.replaceChildren();
  try {
    (await api("/api/conversations")).forEach((c) => list.append(el("li", { text: c.title || "Chat", title: c.updated,
      class: c.id === S.conversationId ? "active" : "", onclick: () => openConversation(c.id) })));
  } catch { /* ignore */ }
}

async function openConversation(id) {
  const c = await api(`/api/conversations/${encodeURIComponent(id)}`);
  S.conversationId = c.id; S.template = c.template || "general";
  const box = $("#chat-messages"); box.replaceChildren(); $("#chat-suggestions").replaceChildren();
  for (const m of c.messages) {
    if (m.role === "User") addMsg("user", m.content);
    else if (m.role === "Assistant") addMsg("assistant", m.content);
    else if (m.role === "AssistantToolCall") addMsg("event", `→ ${m.tool}(${m.content})`);
    else if (m.role === "Tool" && /^(Not executed|Error)/.test(m.content || "")) addMsg("security", `${m.tool}: ${m.content}`);
  }
  showTaint(c.taint || []);
  const pc = c.pendingConfirmation;
  if (pc) showSuggestions({ suggestions: [pc.label], contextMessage: pc.reason || "Confirm this farm change", tool: pc.tool, argumentsObject: pc.arguments });
  loadConversations();
}

function addMsg(kind, text) {
  const box = $("#chat-messages");
  const n = el("div", { class: `msg ${kind}` });
  if (kind === "assistant") n.append(md(text)); else n.textContent = text;
  box.append(n); box.scrollTop = box.scrollHeight;
  return n;
}

function showSuggestions(ev) {
  const box = $("#chat-suggestions"); box.replaceChildren();
  if (ev.contextMessage) box.append(el("div", { class: "context", text: ev.contextMessage }));
  if (ev.tool && ev.argumentsObject) {
    // Show exactly what the label approves: a person should never confirm a bare token.
    const rows = Object.entries(ev.argumentsObject);
    box.append(el("div", { class: "approval" }, el("strong", { text: `You are approving: ${ev.tool}` }),
      rows.length ? el("table", { class: "table kv" }, rows.map(([k, v]) => el("tr", {}, el("td", { text: k }),
        el("td", { class: "wrap", text: typeof v === "object" ? JSON.stringify(v) : String(v) }))))
        : el("div", { class: "muted", text: "(no arguments)" })));
  }
  (ev.suggestions || []).forEach((s) => box.append(el("button", { type: "button", text: s,
    class: /^Confirm \w+ [0-9a-f]{8}$/.test(s) ? "confirm" : "", onclick: () => sendChat(s) })));
}

// Base maps. The page itself sends no Referer (Referrer-Policy: no-referrer), but the OpenStreetMap
// tile servers block requests without one, so tiles send only this site's origin.
function addBaseLayers(map) {
  const opts = { maxZoom: 19, referrerPolicy: "strict-origin-when-cross-origin" };
  const street = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",
    { ...opts, attribution: "&copy; OpenStreetMap contributors" });
  const satellite = L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
    { ...opts, maxZoom: 18, attribution: "Imagery &copy; Esri, Maxar, Earthstar Geographics" });
  satellite.addTo(map);
  L.control.layers({ Satellite: satellite, Map: street }, {}, { position: "topright" }).addTo(map);
}

function showMap(container, markers) {
  if (!window.L) return;
  const div = el("div", { class: "map" }); container.append(div);
  const m = L.map(div).setView([markers[0].lat, markers[0].lng], 15);
  addBaseLayers(m);
  const group = markers.map((p) => L.marker([p.lat, p.lng]).bindPopup(el("div", {}, el("strong", { text: p.title }), el("br"), p.description || "")));
  L.featureGroup(group).addTo(m); if (group.length > 1) m.fitBounds(L.featureGroup(group).getBounds().pad(0.2));
}

function tableFrom(rows) {
  const cols = [...new Set(rows.flatMap((r) => Object.keys(r || {})))].slice(0, 10);
  return el("table", { class: "table" }, el("tr", {}, cols.map((c) => el("th", { text: c }))),
    rows.map((r) => el("tr", {}, cols.map((c) => el("td", { class: "wrap", text: typeof r[c] === "object" ? JSON.stringify(r[c]) : (r[c] ?? "") })))));
}

$("#chat-form").addEventListener("submit", (e) => { e.preventDefault(); sendChat($("#chat-input").value); });
$("#chat-input").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat($("#chat-input").value); } });

async function sendChat(text) {
  text = (text || "").trim();
  if (!text || S.busy) return;
  S.busy = true; $("#chat-send").disabled = true; $("#chat-input").value = ""; $("#chat-suggestions").replaceChildren();
  addMsg("user", text);
  const typing = el("div", { class: "typing", text: "Thinking…" }); $("#chat-messages").append(typing);
  try {
    const res = await fetch("/api/chat", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${S.token}` },
      body: JSON.stringify({ prompt: text, conversationId: S.conversationId, template: S.template }) });
    if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.error || b.detail || res.statusText); }
    const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = "";
    for (;;) {
      const { value, done } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (line.startsWith("data: ")) handleEvent(JSON.parse(line.slice(6)), typing);
      }
    }
  } catch (err) { addMsg("error", String(err.message || err)); }
  finally { typing.remove(); S.busy = false; $("#chat-send").disabled = !S.me?.canChat; loadConversations(); }
}

function handleEvent(ev, typing) {
  const box = $("#chat-messages");
  switch (ev.type) {
    case "conversation": S.conversationId = ev.conversationId; break;
    case "progress": typing.textContent = ev.text; addMsg("event", `⚙ ${ev.text}`); break;
    case "text": addMsg("assistant", ev.text); break;
    case "suggestion": showSuggestions(ev); break;
    case "notification": toast(ev.message); break;
    case "map": showMap(addMsg("event", "Map"), ev.markers); break;
    case "table": { const n = addMsg("event", ev.title || "Data"); n.append(tableFrom(ev.rows || [])); break; }
    case "taint": showTaint(ev.sources || []); break;
    case "security": {
      const label = { flagged: "⚠ Possible prompt injection", blocked: "🔒 Waiting for confirmation", denied: "⛔ Refused", tool_limit: "⛔ Tool-call limit", doom_loop: "⛔ Repeat-call guard" }[ev.outcome] || ev.outcome;
      const n = addMsg(`security ${ev.outcome === "denied" ? "denied" : ev.outcome === "flagged" ? "flagged" : ""}`, `${label}${ev.tool ? ` · ${ev.tool}` : ""}: ${ev.detail || ""}`);
      n.title = "Enforced by the server-side tool executor"; break;
    }
    case "error": addMsg("error", ev.message); break;
    default: break;
  }
  box.scrollTop = box.scrollHeight;
  if (typing.isConnected) box.append(typing);
}

// --- scout data -------------------------------------------------------------------------------------------

async function loadScout() {
  const [sections, sessions] = await Promise.all([api("/api/sections").catch(() => []), api("/api/scout/sessions").catch((e) => { toast(e.message); return []; })]);
  const today = new Date();
  if (window.L) {
    if (!S.map) {
      S.map = L.map("scout-map");
      addBaseLayers(S.map);
    }
    S.map.eachLayer((l) => { if (!(l instanceof L.TileLayer)) S.map.removeLayer(l); });
    const layers = [];
    sections.forEach((s) => {
      const days = s.lastScouted ? Math.round((today - new Date(s.lastScouted)) / 864e5) : null;
      const color = days === null || days > 10 ? "#c62828" : days > 5 ? "#ef8f00" : "#2e7d32";
      const tip = `${s.code} · ${days === null ? "never scouted" : `scouted ${days}d ago`}`;
      const layer = s.polygon ? L.polygon(s.polygon, { color, weight: 2, fillOpacity: 0.25 }) : L.circleMarker([s.lat, s.lng], { color, radius: 8 });
      layer.bindTooltip(tip); layers.push(layer);
    });
    if (layers.length) { const g = L.featureGroup(layers).addTo(S.map); S.map.fitBounds(g.getBounds().pad(0.05)); }
    setTimeout(() => S.map.invalidateSize(), 50);
  }
  const t = $("#sessions-table"); t.replaceChildren(el("tr", {}, ["Date", "Section", "Trees", "With findings", "Scout"].map((h) => el("th", { text: h }))));
  sessions.forEach((s) => t.append(el("tr", { class: "click", onclick: () => showSession(s.id) },
    el("td", { text: s.date }), el("td", { text: s.section }), el("td", { text: s.trees }), el("td", { text: s.treesWithFindings }), el("td", { text: s.scout || "" }))));
}

async function showSession(id) {
  const s = await api(`/api/scout/sessions/${encodeURIComponent(id)}`);
  const box = $("#session-detail"); box.classList.remove("hidden"); box.replaceChildren(
    el("h2", { text: `${s.sectionCode} · ${s.scoutDate} · ${s.status}` }),
    el("p", { class: "muted", text: `Scout: ${s.scout || "?"} · Phenology: ${s.phenologyStage || "-"} · Orchard checks: ${s.orchardChecksSummary}` }),
    s.notes ? el("p", { text: `Notes: ${s.notes}` }) : null);
  const t = el("table", { class: "table" }, el("tr", {}, ["Line", "Tree", "Findings", "Notes"].map((h) => el("th", { text: h }))));
  s.trees.forEach((tr) => {
    const chips = el("div", { class: "chips" },
      tr.pests.map((f) => el("span", { text: `${f.name} ${f.count}` })), tr.diseases.map((f) => el("span", { class: "dis", text: `${f.name} ${f.count}` })),
      tr.beneficials.map((f) => el("span", { class: "ben", text: `${f.name} ${f.count}` })));
    t.append(el("tr", {}, el("td", { text: tr.treeLineNumber ?? "" }), el("td", { text: tr.treeNumber ?? "" }),
      el("td", {}, tr.nothingFound ? el("span", { class: "muted", text: "nothing found" }) : chips), el("td", { text: tr.notes || "" })));
  });
  box.append(s.trees.length ? t : el("p", { class: "muted", text: "Orchard-check-only session (no tree reports)." }));
  box.scrollIntoView({ behavior: "smooth" });
}

// --- activities ---------------------------------------------------------------------------------------------

async function loadActivities() {
  const box = $("#activities-list"); box.replaceChildren();
  let acts; try { acts = await api("/api/activities"); } catch (e) { box.append(el("p", { class: "error", text: e.message })); return; }
  const cls = { Proposed: "warn", Planned: "", InProgress: "good", Complete: "good", Discarded: "bad", OnHold: "warn" };
  acts.forEach((a) => box.append(el("div", { class: "activity" },
    el("div", {}, el("span", { class: `badge ${cls[a.state] || ""}`, text: a.state }), " ", el("strong", { text: a.title || a.type }),
      el("span", { class: "muted", text: ` · ${a.type} · ${a.priority || ""} · created by ${a.createdBy}` })),
    el("div", { class: "timeline" }, a.events.map((ev) => el("div", { text: `${ev.at.slice(0, 16).replace("T", " ")} · ${ev.actor}: ${ev.fromState || "∅"} → ${ev.toState}${ev.note ? ` (${ev.note})` : ""}` }))))));
}

// --- tool console -----------------------------------------------------------------------------------------------

async function loadConsole() {
  S.tools = await api("/api/tools");
  const sel = $("#console-tool"); const current = sel.value; sel.replaceChildren();
  const byPlugin = {};
  S.tools.chat.forEach((t) => (byPlugin[t.plugin] ||= []).push(t));
  Object.entries(byPlugin).forEach(([plugin, tools]) => {
    const g = el("optgroup", { label: plugin });
    tools.forEach((t) => g.append(el("option", { value: t.name, text: `${t.allowed ? "" : "🚫 "}${t.name}${t.gated ? " 🔒" : ""}${t.mutating ? " ✎" : ""}` })));
    sel.append(g);
  });
  if (current) sel.value = current;
  renderConsoleArgs();
}
$("#console-tool").addEventListener("change", renderConsoleArgs);

function renderConsoleArgs() {
  const t = S.tools?.chat.find((x) => x.name === $("#console-tool").value); if (!t) return;
  $("#console-desc").textContent = `${t.description}${t.allowed ? "" : `  (Not permitted for you: ${t.reason}. You can still try: the server refuses it.)`}`;
  const box = $("#console-args"); box.replaceChildren();
  Object.entries(t.schema.properties).forEach(([name, p]) => {
    const req = t.schema.required.includes(name);
    const input = p.type === "boolean" ? el("select", { "data-arg": name, "data-type": p.type }, el("option", { value: "", text: "" }), el("option", { value: "true", text: "true" }), el("option", { value: "false", text: "false" }))
      : el("input", { "data-arg": name, "data-type": p.type, placeholder: p.description || "" });
    box.append(el("label", { class: "field" }, `${name}${req ? " *" : ""} `, el("span", { class: "muted", text: `(${p.type})` }), input));
  });
}

$("#console-run").addEventListener("click", async () => {
  const name = $("#console-tool").value; const args = {};
  document.querySelectorAll("#console-args [data-arg]").forEach((i) => {
    if (i.value === "") return;
    const ty = i.dataset.type;
    args[i.dataset.arg] = ty === "integer" ? parseInt(i.value, 10) : ty === "number" ? parseFloat(i.value) : ty === "boolean" ? i.value === "true"
      : ty === "array" ? i.value.split(",").map((s) => s.trim()) : i.value;
  });
  const out = $("#console-result"); out.replaceChildren(el("span", { class: "muted", text: "Running…" }));
  try {
    const r = await api(`/api/tools/${encodeURIComponent(name)}/invoke`, { method: "POST", body: JSON.stringify({ arguments: args, userMessage: $("#console-message").value }) });
    const cls = { ok: "good", blocked: "warn", denied: "bad", error: "bad" }[r.outcome] || "";
    out.replaceChildren(el("div", { class: "outcome" }, el("span", { class: `badge ${cls}`, text: r.outcome })));
    r.events.filter((e) => e.type === "suggestion").forEach((e) => e.suggestions.forEach((s) => out.append(
      el("p", {}, `Server issued: `, el("code", { text: s }), " ", el("button", { class: "ghost", text: "Use as my message", onclick: () => { $("#console-message").value = s; } })))));
    out.append(el("pre", { text: r.json ? JSON.stringify(r.json, null, 2) : r.content }));
  } catch (e) { out.replaceChildren(el("p", { class: "error", text: e.message })); }
});

// --- security -------------------------------------------------------------------------------------------------------

async function loadSecurity() {
  const c = S.me.claims; const t = $("#claims-table"); t.replaceChildren();
  Object.entries(c).forEach(([k, v]) => { if (v !== null && v !== "") t.append(el("tr", {}, el("td", { text: k }), el("td", { class: "wrap", text: String(v) }))); });
  const origin = location.origin;
  $("#mcp-snippet").textContent =
`# Claude Code
claude mcp add --transport http bongo ${origin}/mcp --header "Authorization: Bearer <token>"

# raw JSON-RPC
curl -s ${origin}/mcp -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

(Use the token from POST /api/auth/login. It is never shown on this page.)`;

  const canImp = S.me.permissions.includes("a-stg-imp");
  $("#impersonate-card").classList.toggle("hidden", !canImp);
  if (canImp) {
    const list = $("#impersonate-list"); list.replaceChildren();
    (await api("/api/users")).forEach((u) => list.append(el("div", { class: "activity" },
      el("strong", { text: u.username }), el("span", { class: "muted", text: ` · ${u.rolename} · ${u.tenant}${u.locked ? " · locked" : ""}${u.disabled ? " · disabled" : ""} ` }),
      el("button", { class: "ghost", text: "Act as", onclick: async () => {
        try { const r = await api("/api/auth/impersonate", { method: "POST", body: JSON.stringify({ userId: u.id }) }); S.token = r.token; store.set(S.token); toast(`Now acting as ${r.username}`); await boot(); }
        catch (e) { toast(e.message); } } }))));
  }
  $("#calendar-card").classList.toggle("hidden", !S.me.permissions.includes("a-act-auth"));
  renderAccess();
  const audit = $("#audit"); audit.replaceChildren();
  if (!S.me.permissions.includes("p-sec")) { audit.append(el("p", { class: "muted", text: "Needs permission p-sec (Director, FarmManager)." })); return; }
  renderRemoteMcp();
  const a = await api("/api/security/audit");
  const cls = { ok: "good", blocked: "warn", denied: "bad", error: "bad", limit: "bad", loop: "bad" };
  audit.append(el("h3", { text: "Tool calls" }), el("div", { class: "scroll" }, el("table", { class: "table" },
    el("tr", {}, ["When", "User", "Channel", "Tool", "Outcome", "Arguments / detail"].map((h) => el("th", { text: h }))),
    a.tools.map((r) => el("tr", {}, el("td", { text: r.at.slice(0, 19).replace("T", " ") }), el("td", { text: `${r.username} (${r.rolename})` }),
      el("td", { text: r.channel }), el("td", { text: r.tool }), el("td", {}, el("span", { class: `badge ${cls[r.outcome] || ""}`, text: r.outcome })),
      el("td", { class: "wrap", text: `${r.arguments || ""} ${r.detail || ""}` }))))));
  audit.append(el("h3", { text: "Sign-in events" }), el("div", { class: "scroll" }, el("table", { class: "table" },
    el("tr", {}, ["When", "User", "Event", "Detail"].map((h) => el("th", { text: h }))),
    a.events.map((r) => el("tr", {}, el("td", { text: r.at.slice(0, 19).replace("T", " ") }), el("td", { text: r.username || "" }),
      el("td", { text: r.event }), el("td", { class: "wrap", text: r.detail || "" }))))));
}

async function renderRemoteMcp() {
  const card = $("#remote-card"); const box = $("#remote-mcp");
  let r; try { r = await api("/api/mcp/remote"); } catch { card.classList.add("hidden"); return; }
  card.classList.remove("hidden"); box.replaceChildren();
  const names = Object.keys(r.servers);
  if (!names.length) {
    box.append(el("p", { class: "muted", text: `No remote MCP servers are allow-listed (${r.configFile}). See mcp_servers.example.json and scripts/mcp_pin.py.` }));
    return;
  }
  names.forEach((n) => {
    const s = r.servers[n];
    box.append(el("div", { class: "activity" },
      el("strong", { text: n }), " ", el("span", { class: `badge ${s.state === "connected" ? "good" : s.state === "error" ? "bad" : ""}`, text: s.state }),
      el("span", { class: "muted", text: ` ${s.url || ""}` }),
      s.error ? el("div", { class: "error", text: s.error }) : null,
      el("div", { class: "muted", text: `Approved: ${(s.approved || []).join(", ") || "none"}` }),
      (s.unapproved || []).length ? el("div", { class: "muted", text: `Not approved (ignored): ${s.unapproved.join(", ")}` }) : null,
      (s.changed || []).length ? el("div", { class: "error", text: `Definition changed since approval (refused): ${s.changed.join(", ")}` }) : null));
  });
}

$("#access-template").addEventListener("change", renderAccess);
async function renderAccess() {
  const tools = await api(`/api/tools?template=${encodeURIComponent($("#access-template").value || "general")}`);
  const mcp = Object.fromEntries(tools.mcp.map((t) => [t.name, t]));
  const cal = new Set(tools.calendar);
  $("#access-table").replaceChildren(el("div", { class: "scroll" }, el("table", { class: "table" },
    el("tr", {}, ["Plugin", "Tool", "Chat (you)", "MCP (you)", "Calendar identity"].map((h) => el("th", { text: h }))),
    tools.chat.map((t) => el("tr", {}, el("td", { class: "muted", text: t.plugin }),
      el("td", {}, el("code", { text: t.name }), t.gated ? " 🔒" : "", t.mutating ? " ✎" : ""),
      el("td", {}, el("span", { class: `badge ${t.allowed ? "good" : "bad"}`, text: t.allowed ? "yes" : "no" }), t.allowed ? "" : el("div", { class: "muted", text: t.reason })),
      el("td", {}, el("span", { class: `badge ${mcp[t.name].allowed ? "good" : "bad"}`, text: mcp[t.name].allowed ? "yes" : "no" }), mcp[t.name].allowed ? "" : el("div", { class: "muted", text: mcp[t.name].reason })),
      el("td", {}, el("span", { class: `badge ${cal.has(t.name) ? "good" : ""}`, text: cal.has(t.name) ? "yes" : "no" })))))));
}

$("#calendar-run").addEventListener("click", async () => {
  const box = $("#calendar-result"); box.replaceChildren(el("p", { class: "muted", text: "Running…" }));
  try { const r = await api("/api/calendar/spray-run", { method: "POST" }); box.replaceChildren(md(r.answer)); }
  catch (e) { box.replaceChildren(el("p", { class: "error", text: e.message })); }
});

// --- start ---------------------------------------------------------------------------------------------------------
S.token = store.get();
if (S.token) boot(); else showLogin();
