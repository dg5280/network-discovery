"use strict";
/* Connect dialog, session list, and the device health report. */

const Sessions = {
  list: [], reports: {},
  forIp(ip) { return this.list.find((s) => s.device_ip === ip || s.host === ip); },
  async refreshList() {
    try { this.list = await api("/api/sessions"); } catch (e) { return; }
    const n = this.list.length;
    $("sesscount").hidden = !n; $("sesscount").textContent = n;
  },
};

// ------------------------------------------------------------------ connect dialog
const Connect = {
  device: null,
  isSynology(d) {
    const p = d.ports || [];
    return /synology/i.test(d.vendor || "") || [5000, 5001, 8000, 8001].some((x) => p.includes(x)) && /synology/i.test(JSON.stringify(d.ssdp || {}) + JSON.stringify(d.mdns || {}));
  },
  webPort(d) {
    const p = d.ports || [];
    for (const x of [5001, 5000, 8001, 8000]) if (p.includes(x)) return String(x);
    return d.is_gateway || d.category === "router" || d.category === "network" ? "8001" : "5001";
  },
  open(d) {
    this.device = d;
    const f = $("connect-form");
    f.reset();
    f.method.value = this.isSynology(d) ? "synology" : "ssh";
    f.port.value = "";
    f.host.value = d.ip;
    f.username.value = localStore.get("nd-user-" + d.ip) || "";
    $("connect-title").textContent = `Connect to ${d.name || d.ip}`;
    $("connect-sub").textContent = [d.category_label, d.vendor, d.ip].filter(Boolean).join(" · ");
    $("trust-wrap").hidden = true;
    this.msg("");
    this.methodChanged();
    $("connect-dlg").showModal();
    (f.username.value ? f.password : f.username).focus();
  },
  methodChanged() {
    const f = $("connect-form"), m = f.method.value;
    const d = this.device || {};
    const hasSsh = (d.ports || []).includes(22);
    if (!f.port.value || ["22", "5000", "5001", "8000", "8001"].includes(f.port.value)) f.port.value = m === "ssh" ? "22" : this.webPort(d);
    $("method-hint").innerHTML = m === "ssh"
      ? `Runs read-only commands: uptime, load, memory, disks, RAID, interface errors, kernel &amp; system logs, updates, and Wi-Fi clients if it's an access point.${hasSsh ? "" : " <b>Port 22 didn't answer during the scan</b> — SSH may be disabled on this device."}`
      : `Signs in like the Synology web page (with 2-step verification). <b>NAS (DSM):</b> drives, SMART, pools, volumes, updates, logs. <b>Router (SRM):</b> Wi-Fi clients with signal strength. Ports: DSM 5000/5001, SRM 8000/8001 — HTTP vs HTTPS is detected automatically. Use an admin account.`;
  },
  msg(text, kind = "error") {
    const m = $("connect-msg");
    m.hidden = !text; m.className = `form-msg ${kind}`; m.innerHTML = text;
  },
  async submit(ev) {
    ev.preventDefault();
    const f = $("connect-form");
    const body = {
      method: f.method.value, host: f.host.value.trim(), port: parseInt(f.port.value, 10) || null,
      username: f.username.value.trim(), password: f.password.value, otp: f.otp.value.trim(),
      trust_new_key: f.trust_new_key.checked, device_ip: this.device && this.device.ip,
    };
    const go = $("connect-go");
    go.disabled = true; go.textContent = "Connecting…";
    this.msg("Signing in and running checks — this can take up to 30 seconds.", "info");
    let r;
    try { r = await api("/api/connect", body); } catch (e) { r = { ok: false, message: "Lost contact with the local agent." }; }
    go.disabled = false; go.textContent = "Connect & check";
    f.password.value = body.password; // keep for a retry with a code; cleared on close
    if (r.ok) {
      localStore.set("nd-user-" + (body.device_ip || body.host), body.username);
      f.password.value = ""; f.otp.value = "";
      $("connect-dlg").close();
      Sessions.reports[r.session_id] = r.report;
      await Sessions.refreshList();
      location.hash = `#/device/${r.session_id}`;
      return;
    }
    const details = r.trace ? `<details class="trace"><summary>Sign-in details (share these if it keeps failing)</summary><pre>${
      r.trace.map((t) => esc(Object.entries(t).map(([k, v]) => `${k}=${v}`).join("  "))).join("\n")}</pre></details>` : "";
    const show = (text, kind) => this.msg(text + details, kind);
    if (r.error === "otp_required") {
      show(esc(r.message || "Enter your one-time code, then press Connect again."), "info");
      f.otp.value = ""; f.otp.focus();
    } else if (r.error === "otp_failed") {
      show(esc(r.message), "error"); f.otp.value = ""; f.otp.focus();
    } else if (r.error === "hostkey_mismatch") {
      this.msg(esc(r.message), "error"); $("trust-wrap").hidden = false;
    } else if (r.error === "auth_failed") {
      show(esc(r.message), "error"); f.password.select();
    } else {
      show(esc(r.message || "Couldn't connect."), "error");
    }
  },
};

const localStore = {
  get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
};

// ------------------------------------------------------------------ report view
function tile(label, value, sub = "", status = null) {
  return `<div class="stat ${status ? "s-" + sKey(status) : ""}"><span class="stat-label">${label}</span><span class="stat-value">${value}</span>${sub ? `<span class="stat-sub">${sub}</span>` : ""}</div>`;
}
const pctStatus = (p, warn, crit) => (p == null ? "unknown" : p >= crit ? "red" : p >= warn ? "yellow" : "green");

function findingsHtml(fs) {
  return `<ul class="findings">${fs.map((f) => {
    const s = SEV[f.severity] || SEV.info;
    return `<li class="finding sev-${esc(f.severity)}">
      <div class="f-head">${chicklet(s.status, s.label)}<span class="f-title">${esc(f.title)}</span><span class="f-area">${esc(f.area)}</span></div>
      ${f.detail ? `<div class="f-detail">${esc(f.detail)}</div>` : ""}
      ${f.remedy ? `<div class="f-remedy"><b>What to do:</b> ${esc(f.remedy)}</div>` : ""}</li>`;
  }).join("")}</ul>`;
}

function clientsHtml(w) {
  if (!w || !w.clients || !w.clients.length) return "";
  const unit = w.unit === "dBm" ? " dBm" : "%";
  const bands = w.by_band ? Object.entries(w.by_band).map(([b, n]) => `<span class="pill">${esc(b)}: ${n}</span>`).join("") : "";
  const nodes = (w.nodes || []).length ? `<div class="pills">${w.nodes.map((n) => `<span class="pill">${svg(I.router)} ${esc(n.name || n.ip)}${n.status ? ` · ${esc(n.status)}` : ""}</span>`).join("")}</div>` : "";
  const legend = w.unit === "dBm" ? "Good ≥ −67 dBm · Fair −67 to −75 · Weak below −75" : "Signal as reported by the router (%): good ≥ 60 · fair 40–60 · weak below 40";
  return `<section class="panel"><div class="panel-head"><h3>Wi-Fi clients <span class="count">${w.clients.length}</span></h3>
      <span class="dim small">from ${esc(w.source)}${w.wired_devices != null ? ` · plus ${w.wired_devices} wired` : ""}</span></div>
    <div class="pills" style="margin-bottom:8px">${bands}</div>${nodes}
    <div class="table-wrap flat"><table><thead><tr><th>Device</th><th>IP</th><th>MAC</th><th>Signal</th><th>Band / channel</th><th>Link rate</th><th>Access point</th><th>Connected</th></tr></thead><tbody>
    ${w.clients.map((c) => `<tr>
      <td><span class="name">${esc(c.name || "Unknown")}</span></td>
      <td class="mono">${esc(c.ip || "—")}</td><td class="mono">${esc(c.mac)}</td>
      <td>${c.signal_dbm != null || c.signal != null ? dotval(c.status, `${c.signal_dbm ?? c.signal}${unit}${c.signal_estimated ? " (est.)" : ""}`) : "—"}</td>
      <td>${esc(c.band || c.channel || "—")}</td>
      <td>${c.tx_rate_mbps ? `${Math.round(c.tx_rate_mbps)} Mb/s` : "—"}${c.max_rate_mbps ? ` <span class="dim">of ${Math.round(c.max_rate_mbps)}</span>` : ""}</td>
      <td>${esc(c.node || c.interface || c.ssid || "—")}</td>
      <td>${c.connected_s ? esc(fmtDur(c.connected_s)) : "—"}</td></tr>`).join("")}
    </tbody></table></div><p class="dim small">${legend}. Weakest first.</p></section>`;
}
// ------------------------------------------------------------------ interfaces
const fmtRate = (bps) => (bps == null ? "—" : bps >= 1e9 ? `${(bps / 1e9).toFixed(2)} Gb/s` : bps >= 1e6 ? `${(bps / 1e6).toFixed(1)} Mb/s`
  : bps >= 1e3 ? `${(bps / 1e3).toFixed(0)} kb/s` : `${Math.round(bps)} b/s`);
const fmtSpeed = (m) => (m == null ? "" : m >= 1000 ? `${m % 1000 ? (m / 1000).toFixed(1) : m / 1000} Gb/s` : `${m} Mb/s`);
const KIND = { ethernet: "Ethernet", wifi: "Wi-Fi", bond: "Bond", bridge: "Bridge", vlan: "VLAN", virtual: "Virtual", tunnel: "Tunnel", ppp: "PPP" };
const has = (v) => v !== undefined && v !== null;

function ifErrStatus(i) {
  const hw = Object.entries(i.hw_counters || {}).filter(([k]) => /crc|align|symbol|fcs|jabber|fragment/i.test(k)).reduce((a, [, v]) => a + v, 0);
  if (!has(i.rx_errors)) return null;
  const e = i.rx_errors + i.tx_errors;
  return i.error_pct >= 1 || hw >= 1000 ? "red" : e > 0 || hw > 0 ? "yellow" : "green";
}

function ifRow(i, idx) {
  const up = i.state === "up";
  const usedBefore = (i.rx_packets || 0) + (i.tx_packets || 0) > 0;   // down + had traffic = unplugged/failed since boot
  const link = i.state ? dotval(up ? "green" : i.physical && i.kind === "ethernet" && usedBefore ? "red" : "unknown",
    `${up ? "Up" : esc(i.state[0].toUpperCase() + i.state.slice(1))}${up && i.speed_mbps ? ` · ${fmtSpeed(i.speed_mbps)}` : ""}${up && i.duplex ? ` ${esc(i.duplex)}` : ""}`) : "—";
  const speedWarn = up && i.kind === "ethernet" && (i.speed_mbps === 10 || i.speed_mbps === 100 || i.duplex === "half");
  const es = ifErrStatus(i);
  const errs = es ? dotval(es, `${num(i.rx_errors + i.tx_errors)}${i.error_pct ? ` <span class="dim">(${i.error_pct}%)</span>` : ""}`) : `<span class="dim">n/a</span>`;
  const now = has(i.rx_bps) ? `<span class="rate">↓ ${fmtRate(i.rx_bps)}</span><span class="rate">↑ ${fmtRate(i.tx_bps)}</span>${has(i.util_pct) ? `<span class="dim small">${i.util_pct}% of link</span>` : ""}` : "—";
  return `<tr class="row if-row" data-if="${idx}">
    <td><span class="name mono">${esc(i.name)}</span> <span class="tag">${esc(KIND[i.kind] || i.kind)}</span>${i.master ? ` <span class="dim small">in ${esc(i.master)}</span>` : ""}
      ${i.driver ? `<div class="dim small">${esc(i.driver)}</div>` : ""}</td>
    <td>${link}${speedWarn ? ` <span class="tag warn">check cable</span>` : ""}</td>
    <td class="stack">${now}</td>
    <td class="stack">${has(i.rx_bytes) ? `${bytes(i.rx_bytes)}<span class="dim small">${num(i.rx_packets)} pkts</span>` : "—"}</td>
    <td class="stack">${has(i.tx_bytes) ? `${bytes(i.tx_bytes)}<span class="dim small">${num(i.tx_packets)} pkts</span>` : "—"}</td>
    <td>${errs}</td>
    <td>${has(i.rx_dropped) ? `${num(i.rx_dropped + i.tx_dropped)}${i.drop_pct ? ` <span class="dim">(${i.drop_pct}%)</span>` : ""}` : `<span class="dim">n/a</span>`}</td>
    <td>${i.carrier_changes ?? "—"}</td>
    <td class="stack mono small">${esc(i.mac || "—")}<span class="dim">${[i.mtu ? `MTU ${Math.round(i.mtu)}` : "", i.ip ? esc(i.ip) : ""].filter(Boolean).join(" · ")}</span></td>
  </tr>`;
}

function ifDetail(i) {
  const kv = (k, v) => (has(v) && v !== "" ? `<div><span class="dim">${k}</span> <b>${typeof v === "number" ? num(v) : esc(v)}</b></div>` : "");
  const hw = Object.entries(i.hw_counters || {});
  return `<tr class="detail-row"><td colspan="9"><div class="detail-grid">
    <div><h4>Receive counters</h4>${kv("Bytes", i.rx_bytes)}${kv("Packets", i.rx_packets)}${kv("Multicast", i.rx_multicast)}${kv("Errors", i.rx_errs)}${kv("Frame (CRC/alignment)", i.rx_frame)}${kv("FIFO overruns", i.rx_fifo)}${kv("Dropped", i.rx_dropped)}</div>
    <div><h4>Transmit counters</h4>${kv("Bytes", i.tx_bytes)}${kv("Packets", i.tx_packets)}${kv("Errors", i.tx_errs)}${kv("Carrier errors", i.tx_carrier)}${kv("Collisions", i.collisions)}${kv("FIFO errors", i.tx_fifo)}${kv("Dropped", i.tx_dropped)}</div>
    <div><h4>Link</h4>${kv("Speed", fmtSpeed(i.speed_mbps))}${kv("Duplex", i.duplex)}${kv("Auto-negotiation", i.autoneg)}${kv("Port type", i.port)}${kv("Driver", i.driver)}${kv("Firmware", i.firmware)}${kv("Link changes since boot", i.carrier_changes)}${kv("Bond mode", i.bond_mode)}</div>
    <div><h4>NIC hardware counters (non-zero)</h4>${hw.length ? hw.map(([k, v]) => `<div class="mono small">${esc(k)}: <b>${num(v)}</b></div>`).join("") : `<span class="dim">${has(i.rx_bytes) ? "None reported (all zero, or ethtool not available)" : "Not available over this connection"}</span>`}
      ${(i.members || []).length ? `<h4 style="margin-top:10px">Bond members</h4>${i.members.map((m) => `<div>${esc(m.name)} ${m.status ? `· ${esc(m.status)}` : ""}${has(m.failures) ? ` · ${m.failures} link failures` : ""}</div>`).join("")}` : ""}</div>
  </div></td></tr>`;
}

function interfacesHtml(r) {
  const all = r.interfaces || [];
  if (!all.length) return "";
  const phys = all.filter((i) => i.physical), virt = all.filter((i) => !i.physical);
  const head = `<thead><tr><th>Interface</th><th>Link</th><th>Now</th><th>Received</th><th>Sent</th><th>Errors</th><th>Dropped</th><th>Link changes</th><th>MAC / MTU</th></tr></thead>`;
  const body = (list, offset) => list.map((i, k) => ifRow(i, offset + k) + (IfOpen.has(`${r.collected_at}:${offset + k}`) ? ifDetail(i) : "")).join("");
  return `<section class="panel ifaces"><div class="panel-head"><h3>Physical interfaces <span class="count">${phys.length}</span></h3>
      <span class="dim small">${esc(r.interfaces_note || "Counters since boot · “Now” measured over 2 s during the check · click a row for every counter")}</span></div>
    <div class="table-wrap flat"><table>${head}<tbody>${body(phys, 0)}</tbody></table></div>
    ${virt.length ? `<details class="virt"><summary>Virtual interfaces (${virt.length}) — bridges, VLANs, containers, tunnels</summary>
      <div class="table-wrap flat"><table>${head}<tbody>${body(virt, phys.length)}</tbody></table></div></details>` : ""}</section>`;
}
const IfOpen = new Set();

function fmtDur(s) { const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60); return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`; }

function reportHtml(sess, r) {
  const dev = r.device || {}, sys = r.system || {}, conn = r.connection || {};
  const title = dev.hostname || dev.model || sess.host;
  const head = `<div class="report-head">
      <a class="btn ghost" href="#/">${svg(I.back)} Dashboard</a>
      <div class="rh-main"><h2>${esc(title)} ${chicklet(r.status, r.status === "green" ? "Healthy" : r.status === "yellow" ? "Needs attention" : "Problems found")}</h2>
        <p class="dim">${[dev.model, dev.os, dev.kernel && `kernel ${dev.kernel}`, dev.arch].filter(Boolean).map(esc).join(" · ")}</p>
        <p class="dim small">${esc(conn.method)} ${esc(conn.user)}@${esc(conn.host)}:${esc(conn.port)} · checked ${fmtTime(r.collected_at)}${conn.new_host_key ? ` · first connection — saved SSH key ${esc(conn.host_key)}` : ""}</p></div>
      <div class="rh-actions"><button class="btn" data-act="refresh">${svg(I.refresh)} Re-run checks</button><button class="btn ghost" data-act="disconnect">Disconnect</button></div>
    </div>`;
  const mem = sys.memory || {};
  const maxTemp = (sys.temperatures || []).reduce((a, t) => Math.max(a, t.celsius), -Infinity);
  const drives = r.drives || [];
  const badDrives = drives.filter((d) => !["", "normal", "initialized", "not_use"].includes(d.status) || !["", "normal", "safe"].includes(d.smart)).length;
  const tiles = r.kind === "dsm" ? [
    tile("Uptime", esc(sys.uptime || "—")),
    tile("CPU", sys.cpu_pct != null ? `${Math.round(sys.cpu_pct)}%` : "—", "", pctStatus(sys.cpu_pct, 70, 90)),
    tile("Memory", sys.memory_pct != null ? `${Math.round(sys.memory_pct)}%` : "—", sys.ram_mb ? `of ${bytes(sys.ram_mb * 1048576)}` : "", pctStatus(sys.memory_pct, 85, 95)),
    tile("System temp", sys.temp_c != null ? `${Math.round(sys.temp_c)}°C` : "—", "", sys.temp_c != null ? (sys.temp_c >= 70 ? "yellow" : "green") : null),
    tile("Drives", drives.length ? `${drives.length - badDrives} of ${drives.length} healthy` : "—", "", drives.length ? (badDrives ? "red" : "green") : null),
    tile("DSM", r.updates && r.updates.available ? "Update available" : "Up to date", esc(dev.os || ""), r.updates && r.updates.available ? "yellow" : "green"),
  ] : r.kind === "srm" ? [
    tile("Uptime", esc(sys.uptime || "—")),
    tile("CPU", sys.cpu_pct != null ? `${Math.round(sys.cpu_pct)}%` : "—", "", pctStatus(sys.cpu_pct, 70, 90)),
    tile("Memory", sys.memory_pct != null ? `${Math.round(sys.memory_pct)}%` : "—", "", pctStatus(sys.memory_pct, 85, 95)),
    tile("Firmware", r.updates && r.updates.available ? "Update available" : "Up to date", esc(dev.os || ""), r.updates && r.updates.available ? "yellow" : "green"),
    tile("Wi-Fi clients", r.wireless ? r.wireless.clients.length : "—", r.wireless ? `${r.wireless.total_devices} devices total` : ""),
  ] : [
    tile("Uptime", esc(sys.uptime || "—")),
    tile("Load (1 / 5 / 15 min)", sys.load ? sys.load.map((x) => x.toFixed(2)).join(" / ") : "—", `${sys.cpus} CPU core${sys.cpus > 1 ? "s" : ""}`,
      sys.load ? (sys.load[1] / sys.cpus >= 2 ? "red" : sys.load[1] / sys.cpus >= 1 ? "yellow" : "green") : null),
    tile("Memory used", mem.used_pct != null ? `${mem.used_pct}%` : "—", `${bytes(mem.available)} free of ${bytes(mem.total)}`, pctStatus(mem.used_pct, 90, 95)),
    tile("Swap used", mem.swap_total ? `${mem.swap_pct}%` : "none", mem.swap_total ? bytes(mem.swap_used) : "", mem.swap_total ? pctStatus(mem.swap_pct, 50, 80) : null),
    tile("Hottest sensor", isFinite(maxTemp) ? `${maxTemp}°C` : "—", "", isFinite(maxTemp) ? (maxTemp >= 90 ? "red" : maxTemp >= 80 ? "yellow" : "green") : null),
    tile("Updates", r.updates && r.updates.count != null ? r.updates.count : "—", r.updates && r.updates.manager ? esc(r.updates.manager) : "",
      r.updates && r.updates.count ? (r.updates.security ? "yellow" : "unknown") : r.updates && r.updates.count === 0 ? "green" : null),
  ];
  let html = head + `<div class="stats tiles">${tiles.join("")}</div>`;
  html += `<section class="panel"><div class="panel-head"><h3>Findings</h3><span class="dim small">${r.findings.filter((f) => f.severity === "critical").length} critical · ${r.findings.filter((f) => f.severity === "warning").length} warnings</span></div>${findingsHtml(r.findings)}</section>`;
  html += clientsHtml(r.wireless);

  if (r.disks && r.disks.length) {
    html += `<section class="panel"><div class="panel-head"><h3>Storage</h3></div><div class="table-wrap flat"><table><thead><tr><th>Mount</th><th>Filesystem</th><th style="width:34%">Used</th><th>Free</th><th>Size</th></tr></thead><tbody>
      ${r.disks.map((d) => `<tr><td class="mono">${esc(d.mount)}${d.status && !["normal", "background"].includes(d.status) ? ` <span class="tag">${esc(d.status)}</span>` : ""}</td><td class="mono dim">${esc(d.filesystem)}</td>
        <td><div class="usage">${meter(d.used_pct, 0, 100, [{ from: 0, to: 85, s: "green" }, { from: 85, to: 95, s: "yellow" }, { from: 95, to: 100, s: "red" }], { cls: "thin" })}${dotval(pctStatus(d.used_pct, 85, 95), `${d.used_pct}%`)}</div></td>
        <td>${bytes(d.avail)}</td><td>${bytes(d.total)}</td></tr>`).join("")}</tbody></table></div>
      ${r.raid && r.raid.length ? `<div class="pills" style="margin-top:10px">${r.raid.map((a) => `<span class="pill">${esc(a.name)} ${esc(a.level || "")} ${a.status ? `[${esc(a.status)}]` : ""} ${a.degraded ? "— DEGRADED" : a.rebuilding ? `— ${esc(a.rebuilding)}` : "— OK"}</span>`).join("")}</div>` : ""}</section>`;
  }
  if (drives.length) {
    const ds = (d) => (["crashed", "failing", "damage"].includes(d.status) || ["failing", "abnormal", "damage", "crashed"].includes(d.smart) ? "red"
      : !["", "normal", "initialized", "not_use"].includes(d.status) || !["", "normal", "safe"].includes(d.smart) ? "yellow" : "green");
    html += `<section class="panel"><div class="panel-head"><h3>Drives</h3></div><div class="table-wrap flat"><table><thead><tr><th>Drive</th><th>Model</th><th>Status</th><th>SMART</th><th>Temp</th><th>Size</th></tr></thead><tbody>
      ${drives.map((d) => `<tr><td class="name">${esc(d.name)}</td><td>${esc(d.model || "—")}</td><td>${dotval(ds(d), esc(d.status || "—"))}</td><td>${esc(d.smart || "—")}</td>
        <td>${d.temp_c != null ? dotval(d.temp_c >= 60 ? "yellow" : "green", `${Math.round(d.temp_c)}°C`) : "—"}</td><td>${bytes(d.size)}</td></tr>`).join("")}</tbody></table></div></section>`;
  }
  html += interfacesHtml(r);
  const logs = r.logs || {};
  if ((logs.hits && logs.hits.length) || (logs.recent_errors && logs.recent_errors.length) || (logs.entries && logs.entries.length)) {
    html += `<section class="panel"><div class="panel-head"><h3>Logs</h3><span class="dim small">${esc((logs.sources || []).join(", ") || "")}</span></div>
      ${(logs.hits || []).map((h) => `<details class="loghit"><summary>${chicklet((SEV[h.severity] || SEV.info).status, (SEV[h.severity] || SEV.info).label)} ${esc(h.title)} <span class="dim">· ${h.count} line(s)</span></summary><pre>${h.examples.map(esc).join("\n")}</pre></details>`).join("")}
      ${logs.recent_errors && logs.recent_errors.length ? `<details><summary>Recent error lines (${logs.error_count})</summary><pre>${logs.recent_errors.map(esc).join("\n")}</pre></details>` : ""}
      ${logs.entries && logs.entries.length ? `<details open><summary>${esc((logs.sources || [])[0] || "Device log")} (${logs.entries.length})</summary><pre>${logs.entries.slice(0, 60).map((e) => esc(`${e.time || ""} ${e.level ? "[" + e.level + "] " : ""}${e.message}`)).join("\n")}</pre></details>` : ""}
    </section>`;
  }
  if (r.updates && r.updates.packages && r.updates.packages.length) {
    html += `<section class="panel"><div class="panel-head"><h3>Pending updates (${r.updates.count})</h3></div><div class="pills">${r.updates.packages.map((p) => `<span class="pill mono">${esc(p)}</span>`).join("")}</div></section>`;
  }
  if (sys.top && sys.top.length) {
    html += `<section class="panel"><div class="panel-head"><h3>Busiest processes</h3></div><div class="table-wrap flat"><table><thead><tr><th>Process</th><th>PID</th><th>CPU</th><th>Memory</th></tr></thead><tbody>
      ${sys.top.map((p) => `<tr><td class="mono">${esc(p.command)}</td><td class="mono dim">${esc(p.pid)}</td><td>${p.cpu_pct}%</td><td>${p.mem_pct}%</td></tr>`).join("")}</tbody></table></div></section>`;
  }
  html += `<details class="panel raw"><summary>Raw data (for troubleshooting)</summary>${Object.entries(r.raw || {}).map(([k, v]) => `<h4 class="mono">${esc(k)}</h4><pre>${esc(v)}</pre>`).join("")}</details>`;
  return html;
}

async function showDevice(sid) {
  const el = $("view-device");
  let r = Sessions.reports[sid];
  let sess = Sessions.list.find((s) => s.id === sid);
  if (!r || !sess) {
    const s = await api(`/api/sessions/${encodeURIComponent(sid)}`).catch(() => null);
    if (!s || s.error) { el.innerHTML = `<p class="empty">That session has ended. <a href="#/">Back to the dashboard</a> and connect again.</p>`; return; }
    r = Sessions.reports[sid] = s.report; sess = s;
  }
  el.innerHTML = reportHtml(sess, r);
  el.onclick = async (e) => {
    const tr = e.target.closest("tr.if-row");
    if (tr) {
      const key = `${r.collected_at}:${tr.dataset.if}`;
      IfOpen.has(key) ? IfOpen.delete(key) : IfOpen.add(key);
      const openVirt = el.querySelector("details.virt")?.open;
      el.innerHTML = reportHtml(sess, r);
      if (openVirt) el.querySelector("details.virt").open = true;
      return;
    }
    const b = e.target.closest("[data-act]"); if (!b) return;
    if (b.dataset.act === "refresh") {
      b.disabled = true; b.innerHTML = `${svg(I.refresh, "spin")} Checking…`;
      const x = await api(`/api/sessions/${encodeURIComponent(sid)}/refresh`, {}).catch(() => ({ ok: false, message: "Lost contact with the local agent." }));
      if (x.ok) { Sessions.reports[sid] = x.report; showDevice(sid); } else { showBanner(esc(x.message)); b.disabled = false; b.textContent = "Re-run checks"; }
    } else if (b.dataset.act === "disconnect") {
      await api(`/api/sessions/${encodeURIComponent(sid)}/disconnect`, {}).catch(() => {});
      delete Sessions.reports[sid];
      await Sessions.refreshList();
      location.hash = "#/";
    }
  };
}

function showSessions() {
  const el = $("session-list");
  if (!Sessions.list.length) { el.innerHTML = `<p class="empty">Not connected to any devices. Use <b>Connect</b> on a row in the dashboard.</p>`; return; }
  el.innerHTML = `<div class="table-wrap flat"><table><thead><tr><th>Device</th><th>Method</th><th>Signed in as</th><th>Status</th><th>Since</th><th></th></tr></thead><tbody>
    ${Sessions.list.map((s) => `<tr><td class="mono">${esc(s.host)}</td><td>${s.method === "ssh" ? "SSH" : "Synology (web)"}</td><td>${esc(s.user)}</td>
      <td>${chicklet(s.status)}</td><td>${fmtTime(s.created, false)}</td><td><a class="btn small" href="#/device/${esc(s.id)}">Open report</a></td></tr>`).join("")}
    </tbody></table></div>`;
}

function initConnect() {
  $("connect-form").addEventListener("submit", (e) => Connect.submit(e));
  $("connect-form").addEventListener("change", (e) => { if (e.target.name === "method") Connect.methodChanged(); });
  $("connect-cancel").addEventListener("click", () => $("connect-dlg").close());
  $("connect-dlg").addEventListener("close", () => { const f = $("connect-form"); f.password.value = ""; f.otp.value = ""; });
}
