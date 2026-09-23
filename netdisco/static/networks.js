"use strict";
/* Networks view: the router's route table (other subnets / VLANs you can scan) and the Wi-Fi
   networks (SSIDs) it broadcasts. The same panels appear in a connected router's report. */

const Nets = { data: null };
const ROUTE_TYPES = {
  connected: { label: "Connected", tip: "A subnet the router is directly on (often a VLAN or a separate LAN)" },
  static: { label: "Static route", tip: "Reached through another router or firewall" },
  dynamic: { label: "Dynamic", tip: "Learned from a routing protocol (OSPF/BGP/RIP)" },
  vpn: { label: "VPN", tip: "Reached over a VPN tunnel" },
  virtual: { label: "Virtual", tip: "Container or virtual-machine network inside the device" },
};

function routeAction(n) {
  if (n.is_local) return `<span class="tag">You're here</span>`;
  if (n.tab) return `<a class="btn small ok" href="#/" data-open-tab="${esc(n.tab)}">Open tab</a>`;
  if (!n.scannable) return `<span class="dim small" title="${esc(n.why_not || "")}">Can't scan — ${esc(n.why_not || "not scannable")}</span>`;
  return `<button class="btn small" data-scan-net="${esc(n.network)}" data-label="${esc(n.label || "")}" data-source="${esc(n.source === "this computer" ? "this computer" : "router")}">Scan</button>`;
}

function routesTable(nets, opts = {}) {
  if (!nets || !nets.length) return `<p class="empty">${esc(opts.empty || "No routes found.")}</p>`;
  return `<div class="table-wrap flat"><table><thead><tr><th>Network</th><th>Name / VLAN</th><th>Type</th><th>${opts.gwHead || "Router address / next hop"}</th><th>Addresses</th><th><span class="sr">Action</span></th></tr></thead><tbody>
    ${nets.map((n) => {
      const t = ROUTE_TYPES[n.type] || { label: n.type, tip: "" };
      return `<tr class="${n.scannable || n.is_local ? "" : "muted-row"}">
        <td class="mono"><b>${esc(n.network)}</b></td>
        <td>${esc(n.label || "—")}${n.iface && !(n.label || "").toLowerCase().includes(n.iface.toLowerCase()) ? ` <span class="dim mono small">${esc(n.iface)}</span>` : ""}</td>
        <td><span class="tag" title="${esc(t.tip)}">${esc(t.label)}</span>${n.table ? ` <span class="dim small">table ${esc(n.table)}</span>` : ""}</td>
        <td class="mono">${n.via ? `via ${esc(n.via)}` : esc(n.router_ip || "—")}</td>
        <td>${num(n.hosts)}</td>
        <td>${routeAction(n)}</td></tr>`;
    }).join("")}</tbody></table></div>`;
}

function ssidTable(ssids, currentSsid) {
  if (!ssids || !ssids.length) return `<p class="empty">No Wi-Fi networks found in the router's settings.</p>`;
  return `<div class="table-wrap flat"><table><thead><tr><th>Network name (SSID)</th><th>Bands</th><th>Security</th><th>Visibility</th><th>Guest / isolation</th><th>VLAN / network</th><th>State</th></tr></thead><tbody>
    ${ssids.map((s) => `<tr class="${s.enabled ? "" : "muted-row"}">
      <td><span class="name">${esc(s.ssid)}</span>${currentSsid && s.ssid === currentSsid ? `<span class="tag">You're on this</span>` : ""}</td>
      <td>${s.bands && s.bands.length ? s.bands.map((b) => `<span class="pill">${esc(b)}</span>`).join(" ") : "—"}${s.channels && s.channels.length ? ` <span class="dim small">ch ${s.channels.map(esc).join(", ")}</span>` : ""}</td>
      <td>${s.security ? dotval(s.security_status, esc(s.security), s.security_status === "red" ? "Weak or no encryption" : s.security_status === "yellow" ? "Allows old, weak WPA/TKIP" : "Modern encryption") : `<span class="dim">unknown</span>`}${s.wps ? ` <span class="tag warn" title="Wi-Fi Protected Setup is on">WPS</span>` : ""}</td>
      <td>${s.hidden ? `<span class="tag">Hidden</span>` : "Broadcast"}</td>
      <td>${s.guest ? `Guest${s.isolated === true ? " · isolated" : s.isolated === false ? ` · <span class="warn-text">not isolated</span>` : ""}` : s.isolated ? "Clients isolated" : "—"}</td>
      <td>${s.vlan ? `VLAN ${esc(s.vlan)}` : esc(s.network || "—")}</td>
      <td>${s.enabled ? dotval("green", "On") : dotval("unknown", "Off")}</td></tr>`).join("")}
    </tbody></table></div><p class="dim small">Passwords are never read or shown. Source: ${esc([...new Set(ssids.map((s) => s.source))].join(", "))}.</p>`;
}

/* Panels for a connected router's report (device.js). */
function reportNetworksHtml(r) {
  let html = "";
  if (r.networks && r.networks.length) {
    const nets = r.networks.map((n) => Object.assign({}, n, { tab: Nets.tabFor(n.network), is_local: Dash.health && Dash.health.local && Dash.health.local.network === n.network }));
    const scannable = nets.filter((n) => n.scannable && !n.tab && !n.is_local).length;
    html += `<section class="panel"><div class="panel-head"><h3>Routes &amp; networks <span class="count">${nets.length}</span></h3>
      <span class="dim small">${scannable ? `${scannable} network${scannable > 1 ? "s" : ""} you haven't scanned yet` : "From the router's routing table"}</span></div>${routesTable(nets)}</section>`;
  }
  if (r.ssids && r.ssids.length) {
    const cur = Dash.health && Dash.health.wifi && Dash.health.wifi.ssid;
    html += `<section class="panel"><div class="panel-head"><h3>Wi-Fi networks (SSIDs) <span class="count">${r.ssids.length}</span></h3>
      <span class="dim small">Configured on this device</span></div>${ssidTable(r.ssids, cur)}</section>`;
  }
  return html;
}
Nets.tabFor = (network) => { const t = (Dash.tabs || []).find((x) => x.spec === network); return t ? t.id : null; };

async function gatewayDevice() {
  const r = await api("/api/devices?tab=local").catch(() => null);
  return r && (r.devices || []).find((d) => d.is_gateway);
}

async function showNetworks() {
  const el = $("networks-body");
  if (!Nets.data) el.innerHTML = `<p class="empty">Loading…</p>`;
  const d = Nets.data = await api("/api/networks").catch(() => null);
  if (!d) { el.innerHTML = `<p class="empty">Lost contact with the local agent.</p>`; return; }
  const cur = Dash.health && Dash.health.wifi && Dash.health.wifi.ssid;
  let html = "";
  const newCount = d.suggestions.length;
  if (newCount) {
    html += `<div class="callout">${svg(I.network)}<div><b>${newCount} network${newCount > 1 ? "s" : ""} not scanned yet.</b>
      Each one gets its own tab on the dashboard.</div><button class="btn primary" data-scan-all>Scan all ${newCount}</button></div>`;
  }
  if (!d.sources.length) {
    html += `<section class="panel"><div class="panel-head"><h3>Your router</h3></div>
      <div class="connect-cta"><p>Sign in to your router to read its <b>route table</b> (other subnets and VLANs behind it) and the <b>Wi-Fi networks it broadcasts</b>.
      Works with Synology routers (web sign-in) and OpenWrt or other Linux-based routers (SSH). Everything is read-only.</p>
      <button class="btn primary" data-connect-gw>${svg(I.plug)} Connect to router</button></div></section>`;
  }
  for (const s of d.sources) {
    const hdr = `${esc(s.name)} <span class="dim small">${esc([s.model, s.os].filter(Boolean).join(" · "))}</span>`;
    html += `<section class="panel"><div class="panel-head"><h3>Routes on ${hdr}</h3>
      <span class="dim small">read ${fmtTime(s.collected_at, false)} · <a class="link small" href="#/device/${esc(s.session_id)}">full report</a></span></div>
      ${routesTable(s.networks, { empty: "The router didn't report any routes (this SRM/firmware version may not expose them — see Raw data in its report)." })}</section>`;
    html += `<section class="panel"><div class="panel-head"><h3>Wi-Fi networks on ${esc(s.name)}</h3></div>${ssidTable(s.ssids, cur)}</section>`;
  }
  const extra = d.local_routes.filter((n) => !n.is_local || d.local_routes.length > 1);
  html += `<section class="panel"><div class="panel-head"><h3>Routes on this computer</h3><span class="dim small">VPNs and extra adapters add these</span></div>
    ${routesTable(extra, { empty: "Only the default route — this computer sends everything through your router.", gwHead: "Next hop" })}</section>`;
  el.innerHTML = html;
}

async function scanNetwork(network, label, source) {
  const r = await api("/api/subnets", { spec: network, label, source }).catch(() => ({ ok: false, message: "Lost contact with the local agent." }));
  if (!r.ok) { showBanner(esc(r.message || "Couldn't add that subnet.")); return null; }
  await pollSubnets();
  return r.added && r.added[0];
}

function initNetworks() {
  $("net-refresh").addEventListener("click", showNetworks);
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-scan-net]");
    if (b) {
      b.disabled = true; b.textContent = "Adding…";
      const t = await scanNetwork(b.dataset.scanNet, b.dataset.label, b.dataset.source);
      if (t) { Dash.tab = null; location.hash = "#/"; selectTab(t.id); }
      return;
    }
    const o = e.target.closest("[data-open-tab]");
    if (o) { e.preventDefault(); location.hash = "#/"; selectTab(o.dataset.openTab); return; }
    if (e.target.closest("[data-scan-all]")) {
      const btn = e.target.closest("[data-scan-all]"); btn.disabled = true;
      for (const x of (Nets.data && Nets.data.suggestions) || []) await scanNetwork(x.network, x.label, x.source === "this computer" ? "this computer" : "router");
      showNetworks(); return;
    }
    if (e.target.closest("[data-connect-gw]")) {
      const gw = await gatewayDevice();
      if (gw) Connect.open(gw);
      else showBanner("The router hasn't been found yet — wait for the first scan to finish on the Dashboard.");
    }
  });
}
