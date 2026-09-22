"use strict";
/* Dashboard: health cards, device table with live ping, Connect buttons. */

const Dash = {
  view: { filter: "all", q: "", sort: "ip", dir: 1, open: new Set() },
  devices: [], categories: {}, pings: {}, pingTh: { green_ms: 30, yellow_ms: 100 },
  scanWasRunning: false, networkLabel: null, health: null,
};
const CONF = { high: 3, medium: 2, low: 1, none: 0 };

// ------------------------------------------------------------------ health
function latencyCard(el, title, r, hist, threshold, extra) {
  const val = r.latency_ms == null ? `<div class="value text">No reply</div>` : `<div class="value">${r.latency_ms}<small>ms</small></div>`;
  el.className = `card s-${sKey(r.status)}`;
  el.innerHTML = `
    <div class="card-head"><span class="card-title">${title}</span>${chicklet(r.status)}</div>
    ${val}
    <div class="detail">${esc(r.summary)}</div>
    <div class="spark"></div>
    <div class="meta"><span>${esc(extra)}</span><span>${r.loss_pct != null ? `${r.loss_pct}% loss` : ""}</span><span>via ${esc(r.method)}</span></div>`;
  const pts = (hist || []).map((p) => ({ t: p.t, v: p.ms, loss: p.loss }));
  const max = Math.max(threshold * 1.25, ...pts.map((p) => p.v || 0));
  lineChart(el.querySelector(".spark"), pts, {
    height: 44, yMin: 0, yMax: max, refs: [{ v: threshold, label: `${threshold} ms` }], markNull: true, label: `${title} latency`,
    fmt: (p) => (p.v == null ? "No reply" : `<b>${p.v} ms</b>${p.loss ? ` · ${p.loss}% loss` : ""}`),
  });
}

function renderHealth(h) {
  if (!h || !h.internet) return;
  Dash.health = h;
  const th = h.thresholds.latency_green_ms;
  latencyCard($("card-internet"), "Internet", h.internet, h.history.internet, th, `to ${h.internet.target}`);
  latencyCard($("card-gateway"), "Gateway (router)", h.gateway, h.history.gateway, th, h.gateway.target ? `to ${h.gateway.target}` : "no gateway");

  const d = h.dns, dc = $("card-dns");
  dc.className = `card s-${sKey(d.status)}`;
  const lookups = d.lookups.map((l) => `<span class="pill" title="${esc(l.ok ? l.address : l.error)}">${l.ok ? "✓" : "✕"} ${esc(l.name)}</span>`).join("");
  dc.innerHTML = `
    <div class="card-head"><span class="card-title">DNS</span>${chicklet(d.status)}</div>
    ${d.worst_ms != null ? `<div class="value">${Math.round(d.worst_ms)}<small>ms</small></div>` : `<div class="value text">Failing</div>`}
    <div class="detail">${esc(d.summary)}</div>
    <div class="pills" style="margin-top:10px">${lookups}</div>
    <div class="meta"><span>Servers: ${esc(d.servers.join(", ") || "unknown")}</span></div>`;

  const w = h.wifi, wc = $("card-wifi");
  wc.className = `card s-${sKey(w.status)}`;
  let big;
  if (!w.is_wifi) big = `<div class="value text">Ethernet</div>`;
  else if (w.ssid) big = `<div class="value text" title="${esc(w.ssid)}">${esc(w.ssid)}</div>`;
  else if (w.ssid_hidden_by_os) big = `<div class="value text">Hidden</div>`;
  else big = `<div class="value text">Unknown</div>`;
  const note = w.is_wifi && !w.ssid && w.ssid_hidden_by_os
    ? `<div class="detail dim">macOS hides the network name unless Terminal has Location access (System Settings › Privacy & Security › Location Services).</div>` : "";
  const meta = [];
  if (w.rssi_dbm != null) meta.push(`Signal ${w.rssi_dbm} dBm`);
  if (w.channel) meta.push(`Ch ${esc(w.channel)}`);
  if (w.tx_rate_mbps) meta.push(`${w.tx_rate_mbps} Mbps`);
  if (!meta.length && w.interface) meta.push(`Interface ${esc(w.interface)}`);
  wc.innerHTML = `
    <div class="card-head"><span class="card-title">Wi-Fi network</span>${chicklet(w.status)}</div>
    ${big}<div class="detail">${esc(w.summary)}</div>${note}
    ${w.is_wifi ? `<a class="link small" href="#/survey">${svg(I.wifi)} Open signal meter</a>` : ""}
    <div class="meta">${meta.map((m) => `<span>${m}</span>`).join("")}</div>`;

  const L = h.local;
  $("netline").textContent = [L.hostname, L.ip, L.network && `network ${L.network}`, L.interface && `via ${L.interface}`].filter(Boolean).join("  ·  ");
  $("updated").textContent = "Updated " + fmtTime(h.timestamp);
  const label = (h.identity && h.identity.label) || null;
  $("netname").textContent = label || "your network";
}

// ------------------------------------------------------------------ devices
function pingOf(d) { return Dash.pings[d.ip]; }

function sortKey(d, k) {
  if (k === "ip") return ipNum(d.ip);
  if (k === "confidence") return -CONF[d.confidence];
  if (k === "category") return d.category_label;
  if (k === "model") return (d.model || d.os || "~").toLowerCase();
  if (k === "ping") { const p = pingOf(d); return p && p.ms != null ? p.ms : 1e9; }
  return String(d[k] || "~").toLowerCase();
}

function renderChips() {
  const counts = {};
  Dash.devices.forEach((d) => { counts[d.category] = (counts[d.category] || 0) + 1; });
  const order = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  if (Dash.view.filter !== "all" && !counts[Dash.view.filter]) Dash.view.filter = "all";
  const chip = (key, label, n, icon) =>
    `<button class="chip" data-f="${key}" aria-pressed="${Dash.view.filter === key}">${icon ? svg(I[icon] || I.unknown) : ""}${esc(label)} <b>${n}</b></button>`;
  $("chips").innerHTML = chip("all", "All", Dash.devices.length) + order.map((k) => chip(k, Dash.categories[k] || k, counts[k], k)).join("");
}

function pingCell(d) {
  if (d.is_self) return `<span class="dim">—</span>`;
  if (!d.online) return `<span class="dim">offline</span>`;
  const p = pingOf(d);
  if (!p) return `<span class="dim">…</span>`;
  if (p.ms == null) return dotval("red", "No reply", "No answer to ping — the device may be asleep or blocking ping");
  const how = p.method && p.method.startsWith("tcp") ? ` (${p.method}, device ignores ping)` : "";
  return dotval(p.status, `${p.ms < 10 ? p.ms.toFixed(1) : Math.round(p.ms)} ms`, `Round-trip time${how}`);
}

function row(d) {
  const tags = [];
  if (d.is_self) tags.push("This computer");
  if (d.is_gateway) tags.push("Gateway");
  if (!d.online) tags.push("Offline");
  const name = d.name ? `<span class="name">${esc(d.name)}</span>` : `<span class="dim">Unnamed</span>`;
  const vendor = d.vendor ? esc(d.vendor) : d.randomized ? `<span class="dim">Private address</span>` : `<span class="dim">—</span>`;
  const model = [d.model, d.os && d.os !== d.model ? d.os : null].filter(Boolean).map(esc).join(" · ") || `<span class="dim">—</span>`;
  const bars = [1, 2, 3].map((i) => `<i class="${CONF[d.confidence] >= i ? "on" : ""}"></i>`).join("");
  const key = d.mac || d.ip;
  const sess = Sessions.forIp(d.ip);
  const action = d.is_self ? "" : sess
    ? `<a class="btn small ok" href="#/device/${esc(sess.id)}">View report</a>`
    : `<button class="btn small" data-connect="${esc(d.ip)}" ${d.online ? "" : "disabled"}>Connect</button>`;
  return `<tr class="row ${d.online ? "" : "offline"}" data-key="${esc(key)}" aria-expanded="${Dash.view.open.has(key)}">
    <td><span class="type"><span class="ico">${svg(I[d.category] || I.unknown)}</span>${esc(d.category_label)}</span></td>
    <td>${name}${tags.map((t) => `<span class="tag">${t}</span>`).join("")}</td>
    <td class="mono">${esc(d.ip)}</td>
    <td class="ping">${pingCell(d)}</td>
    <td class="mono">${d.mac ? esc(d.mac) : `<span class="dim">—</span>`}</td>
    <td class="wrap">${vendor}</td>
    <td class="wrap">${model}</td>
    <td><span class="conf" aria-hidden="true">${bars}</span><span class="conf-label">${esc(d.confidence)}</span></td>
    <td>${action}</td>
  </tr>` + (Dash.view.open.has(key) ? detailRow(d) : "");
}

function detailRow(d) {
  const m = d.mdns || {}, s = d.ssdp || {}, nb = d.netbios || {}, sd = s.description || {};
  const list = (arr) => (arr && arr.length ? `<div class="pills">${arr.map((x) => `<span class="pill">${esc(x)}</span>`).join("")}</div>` : `<span class="dim">None found</span>`);
  const upnp = [sd.friendlyName, sd.manufacturer, sd.modelName, sd.modelDescription].filter(Boolean);
  return `<tr class="detail-row"><td colspan="9"><div class="detail-grid">
    <div><h4>Why we think it's a ${esc(d.category_label.toLowerCase())}</h4>${d.evidence.length ? `<ul>${d.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : `<span class="dim">Not enough clues yet</span>`}</div>
    <div><h4>Open ports</h4>${list(d.ports.map(String))}</div>
    <div><h4>Bonjour services</h4>${list(m.services)}</div>
    <div><h4>Other names</h4>${list([d.hostname, nb.name && `NetBIOS: ${nb.name}`, nb.workgroup && `Workgroup: ${nb.workgroup}`, ...(m.hostnames || [])].filter(Boolean))}</div>
    <div><h4>UPnP</h4>${list(upnp)}${s.server ? `<div class="dim mono" style="margin-top:4px">${esc(s.server)}</div>` : ""}</div>
    <div><h4>Seen</h4>First ${new Date(d.first_seen * 1000).toLocaleString()}<br>Last ${new Date(d.last_seen * 1000).toLocaleString()}</div>
  </div></td></tr>`;
}

function renderDevices() {
  const v = Dash.view, q = v.q.toLowerCase();
  const shown = Dash.devices
    .filter((d) => v.filter === "all" || d.category === v.filter)
    .filter((d) => !q || [d.name, d.ip, d.mac, d.vendor, d.model, d.os, d.category_label, d.hostname].some((x) => x && String(x).toLowerCase().includes(q)))
    .sort((a, b) => { const x = sortKey(a, v.sort), y = sortKey(b, v.sort); return (x > y ? 1 : x < y ? -1 : ipNum(a.ip) - ipNum(b.ip)) * v.dir; });
  $("devbody").innerHTML = shown.map(row).join("");
  $("empty").hidden = shown.length > 0 || Dash.devices.length === 0;
  const online = Dash.devices.filter((d) => d.online).length;
  $("devcount").textContent = Dash.devices.length ? `${online} online${Dash.devices.length > online ? `, ${Dash.devices.length - online} offline` : ""}` : "";
  renderChips();
}

/* Only the ping cells change every 5 s — update them in place so open rows/hover aren't disturbed. */
function updatePingCells() {
  document.querySelectorAll("#devbody tr.row").forEach((tr) => {
    const d = Dash.devices.find((x) => (x.mac || x.ip) === tr.dataset.key);
    if (d) tr.querySelector("td.ping").innerHTML = pingCell(d);
  });
}

function renderScan(st) {
  const running = st.running;
  $("scan").disabled = running;
  $("scan").textContent = running ? "Scanning…" : "Scan now";
  $("progress").hidden = !running;
  $("bar").style.width = (st.progress || 0) + "%";
  if (running) $("scanstate").textContent = `${st.phase}…`;
  else if (st.error) $("scanstate").textContent = `Scan failed: ${st.error}`;
  else if (st.finished) $("scanstate").textContent = `Last scan ${fmtTime(st.finished, false)} · ${st.targets} addresses on ${st.network}`;
  if (running && !Dash.devices.length) $("devbody").innerHTML = `<tr><td colspan="9" class="empty">Scanning your network… this takes about 15 seconds.</td></tr>`;
  // Network changed → the list was cleared. Tell the user once.
  if (st.network_changed_at && st.network_changed_at !== Dash.changedAt) {
    if (Dash.changedAt !== undefined) showBanner(`Switched to ${esc(st.network_label || "a new network")} — cleared devices from the previous network and started a new scan.`);
    Dash.changedAt = st.network_changed_at;
  } else if (Dash.changedAt === undefined) Dash.changedAt = st.network_changed_at || null;
}

function showBanner(html, ms = 12000) {
  const b = $("banner"); b.innerHTML = html; b.hidden = false;
  clearTimeout(showBanner.t); showBanner.t = setTimeout(() => { b.hidden = true; }, ms);
}

async function pollHealth() {
  try { renderHealth(await api("/api/health")); } catch (e) { $("netline").textContent = "Lost contact with the local agent — is it still running?"; }
}
async function pollDevices() {
  try {
    const r = await api("/api/devices");
    renderScan(r.state);
    const cleared = !r.devices.length && Dash.devices.length;
    if (!r.state.running || Dash.scanWasRunning !== r.state.running || !Dash.devices.length || cleared) {
      Dash.devices = r.devices;
      if (App.current === "dashboard") renderDevices();
    }
    Dash.scanWasRunning = r.state.running;
    setTimeout(pollDevices, r.state.running ? 1000 : 4000);
  } catch (e) { setTimeout(pollDevices, 5000); }
}
async function pollPings() {
  try {
    const r = await api("/api/pings");
    Dash.pings = r.results || {}; Dash.pingTh = r.thresholds || Dash.pingTh;
    if (App.current === "dashboard") updatePingCells();
  } catch (e) {}
  setTimeout(pollPings, 5000);
}

function initDashboard() {
  $("scan").addEventListener("click", async () => {
    $("scan").disabled = true;
    try { await api("/api/scan", {}); } catch (e) {}
  });
  $("search").addEventListener("input", (e) => { Dash.view.q = e.target.value; renderDevices(); });
  $("chips").addEventListener("click", (e) => { const b = e.target.closest(".chip"); if (b) { Dash.view.filter = b.dataset.f; renderDevices(); } });
  document.querySelector("#devtable thead").addEventListener("click", (e) => {
    const th = e.target.closest("th[data-sort]"); if (!th) return;
    const v = Dash.view;
    v.dir = v.sort === th.dataset.sort ? -v.dir : 1; v.sort = th.dataset.sort;
    document.querySelectorAll("#devtable th").forEach((t) => t.classList.remove("sorted", "desc"));
    th.classList.add("sorted"); if (v.dir < 0) th.classList.add("desc");
    renderDevices();
  });
  $("devbody").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-connect]");
    if (btn) { const d = Dash.devices.find((x) => x.ip === btn.dataset.connect); if (d) Connect.open(d); return; }
    if (e.target.closest("a,button")) return;
    const tr = e.target.closest("tr.row"); if (!tr) return;
    const k = tr.dataset.key; Dash.view.open.has(k) ? Dash.view.open.delete(k) : Dash.view.open.add(k); renderDevices();
  });
}
