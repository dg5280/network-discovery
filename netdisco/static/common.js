"use strict";
/* Shared helpers. Everything that came from the network is untrusted: always esc() it. */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (t, sec = true) => new Date(t * 1000).toLocaleTimeString([], sec ? { hour: "numeric", minute: "2-digit", second: "2-digit" } : { hour: "numeric", minute: "2-digit" });
const ipNum = (ip) => String(ip || "0.0.0.0").split(".").reduce((a, o) => a * 256 + +o, 0);

function bytes(n) {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"]; let i = 0;
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : Math.round(n)) + " " + u[i];
}
const num = (n) => (n == null ? "—" : Number(n).toLocaleString());

async function api(url, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const r = await fetch(url, opts);
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : {};
  if (!r.ok && !("ok" in data)) throw new Error(`HTTP ${r.status}`);
  return data;
}

// ------------------------------------------------------------------ icons
const I = {
  router: '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M12 13V9M8.5 6.5a5 5 0 0 1 7 0M6 4a8.5 8.5 0 0 1 12 0"/>',
  network: '<rect x="2" y="8" width="20" height="8" rx="2"/><path d="M6 12h.01M10 12h.01M14 12h.01M18 12h.01"/>',
  mac: '<rect x="4" y="4" width="16" height="11" rx="1.5"/><path d="M2 19h20l-1.5-4h-17z"/>',
  windows: '<rect x="3" y="3" width="18" height="13" rx="1.5"/><path d="M8 21h8M12 16v5"/>',
  linux: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M12 15h5"/>',
  computer: '<rect x="3" y="3" width="18" height="13" rx="1.5"/><path d="M8 21h8M12 16v5"/>',
  phone: '<rect x="7" y="2" width="10" height="20" rx="2.5"/><path d="M11 18h2"/>',
  printer: '<path d="M6 9V3h12v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M6 14h12v7H6z"/>',
  camera: '<path d="M15 10l5-3v10l-5-3z"/><rect x="3" y="6" width="12" height="12" rx="2"/>',
  security: '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  storage: '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  tv: '<rect x="2" y="5" width="20" height="13" rx="2"/><path d="M8 21h8"/>',
  speaker: '<rect x="6" y="2" width="12" height="20" rx="2"/><circle cx="12" cy="14" r="3.5"/><path d="M12 6.5h.01"/>',
  smarthome: '<path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><path d="M10 21v-6h4v6"/>',
  console: '<path d="M6 8h12a4 4 0 0 1 4 4v1a4 4 0 0 1-7 2.6L14 15h-4l-1 .6A4 4 0 0 1 2 13v-1a4 4 0 0 1 4-4z"/><path d="M7 11v3M5.5 12.5h3M16 12h.01M18 13.5h.01"/>',
  unknown: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 0 1 4.8 1c0 1.7-2.3 2-2.3 3.5M12 17h.01"/>',
  wifi: '<path d="M2 8.5a15 15 0 0 1 20 0M5 12a10.5 10.5 0 0 1 14 0M8.5 15.5a5.5 5.5 0 0 1 7 0M12 19h.01"/>',
  plug: '<path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0zM12 17v5"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.4M21 3v6h-6"/>',
  back: '<path d="M15 18l-6-6 6-6"/>',
  pin: '<path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/>',
};
const svg = (inner, cls = "") => `<svg viewBox="0 0 24 24" class="${cls}" aria-hidden="true">${inner}</svg>`;

const STATUS = {
  green:   { label: "Good",    icon: '<path d="M5 12.5l4.5 4.5L19 7.5"/>' },
  yellow:  { label: "Fair",    icon: '<path d="M12 6v7M12 17.5h.01"/>' },
  red:     { label: "Problem", icon: '<path d="M7 7l10 10M17 7L7 17"/>' },
  unknown: { label: "Unknown", icon: '<path d="M12 17.5h.01M10 9a2 2 0 1 1 3 1.7c-.8.5-1 1-1 2"/>' },
};
const sKey = (s) => (s in STATUS ? s : "unknown");
const chicklet = (s, label) => {
  const st = STATUS[sKey(s)];
  return `<span class="chicklet s-${sKey(s)}"><span class="dot">${svg(st.icon)}</span>${esc(label || st.label)}</span>`;
};
/* Compact status: small icon dot + value (icon keeps it readable without colour). */
const dotval = (s, text, title = "") =>
  `<span class="dotval s-${sKey(s)}" title="${esc(title)}"><span class="dot">${svg(STATUS[sKey(s)].icon)}</span>${text}</span>`;

const SEV = {
  critical: { status: "red", label: "Critical" },
  warning: { status: "yellow", label: "Warning" },
  info: { status: "unknown", label: "Info" },
  ok: { status: "green", label: "OK" },
};

// ------------------------------------------------------------------ tooltip
const tip = $("tooltip");
function showTip(html, x, y) {
  tip.innerHTML = html; tip.hidden = false;
  const r = tip.getBoundingClientRect();
  let left = x + 12, top = y - r.height - 10;
  if (left + r.width > innerWidth - 8) left = x - r.width - 12;
  if (top < 8) top = y + 14;
  tip.style.left = left + "px"; tip.style.top = top + "px";
}
const hideTip = () => { tip.hidden = true; };

// ------------------------------------------------------------------ line chart
/* opts: {height, yMin, yMax, refs:[{v,label}], bands:[{from,to,cls}], fmt(v), events:[{t,label}], pad} */
function lineChart(el, pts, opts = {}) {
  const W = el.clientWidth || 300, H = opts.height || 44;
  const padL = opts.padL ?? 3, padR = opts.padR ?? 3, padT = opts.padT ?? 4, padB = opts.padB ?? 3;
  if (pts.length < 2) { el.innerHTML = `<div class="dim small" style="padding:8px 0">Collecting…</div>`; return; }
  const vals = pts.map((p) => p.v).filter((v) => v != null);
  const yMin = opts.yMin ?? 0, yMax = opts.yMax ?? Math.max(...vals, 1);
  const t0 = pts[0].t, t1 = pts[pts.length - 1].t, span = opts.span || (t1 - t0) || 1;
  const tStart = opts.span ? t1 - span : t0;
  const x = (t) => padL + ((t - tStart) / span) * (W - padL - padR);
  const y = (v) => padT + (1 - (Math.max(yMin, Math.min(yMax, v)) - yMin) / (yMax - yMin)) * (H - padT - padB);
  let d = "", pen = false, prevT = null;
  const gap = opts.gap || Infinity;
  pts.forEach((p) => {
    if (p.v == null || (prevT != null && p.t - prevT > gap)) pen = false;
    if (p.v != null) { d += `${pen ? "L" : "M"}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`; pen = true; }
    prevT = p.t;
  });
  const bands = (opts.bands || []).map((b) => `<rect class="${b.cls}" x="${padL}" width="${W - padL - padR}" y="${y(b.to)}" height="${Math.max(0, y(b.from) - y(b.to))}"/>`).join("");
  const refs = (opts.refs || []).map((r) => `<line class="ref" x1="${padL}" x2="${W - padR}" y1="${y(r.v)}" y2="${y(r.v)}"/>` +
    (r.label ? `<text class="reflabel" x="${padL > 20 ? padL - 4 : W - padR - 2}" y="${y(r.v) + (padL > 20 ? 3 : -3)}" text-anchor="end">${esc(r.label)}</text>` : "")).join("");
  const events = (opts.events || []).filter((e) => e.t >= tStart).map((e) =>
    `<line class="event" x1="${x(e.t)}" x2="${x(e.t)}" y1="${padT}" y2="${H - padB}"/><text class="eventlabel" x="${x(e.t) + 3}" y="${padT + 9}">${esc(e.label)}</text>`).join("");
  const losses = opts.markNull ? pts.filter((p) => p.v == null).map((p) => `<rect class="loss" x="${x(p.t) - 1.5}" y="${H - padB - 4}" width="3" height="4" rx="1"/>`).join("") : "";
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${esc(opts.label || "chart")}">
      ${bands}${refs}${events}<path class="line" d="${d}"/>${losses}
      <g class="hover" visibility="hidden"><line class="cross" y1="${padT}" y2="${H - padB}"/><circle class="pt" r="4"/></g>
    </svg>`;
  const s = el.querySelector("svg"), g = s.querySelector(".hover"), cross = g.querySelector("line"), pt = g.querySelector("circle");
  s.addEventListener("pointermove", (ev) => {
    const rect = s.getBoundingClientRect();
    const tx = tStart + (((ev.clientX - rect.left) / rect.width) * W - padL) / (W - padL - padR) * span;
    let best = pts[0];
    for (const p of pts) if (Math.abs(p.t - tx) < Math.abs(best.t - tx)) best = p;
    cross.setAttribute("x1", x(best.t)); cross.setAttribute("x2", x(best.t));
    if (best.v != null) { pt.setAttribute("cx", x(best.t)); pt.setAttribute("cy", y(best.v)); pt.style.display = ""; } else pt.style.display = "none";
    g.setAttribute("visibility", "visible");
    showTip(`${fmtTime(best.t)}<br>${opts.fmt ? opts.fmt(best) : best.v}`, ev.clientX, ev.clientY);
  });
  s.addEventListener("pointerleave", () => { g.setAttribute("visibility", "hidden"); hideTip(); });
}

/* Horizontal meter with coloured zones and a marker (used for RSSI and disk usage). */
function meter(value, min, max, zones, opts = {}) {
  const pct = (v) => Math.max(0, Math.min(100, ((v - min) / (max - min)) * 100));
  const segs = zones.map((z) => `<span class="zone z-${z.s}" style="left:${pct(z.from)}%;width:${pct(z.to) - pct(z.from)}%"></span>`).join("");
  const ticks = (opts.ticks || []).map((t) => `<span class="tick" style="left:${pct(t)}%"><i></i><b>${t}</b></span>`).join("");
  const mark = value == null ? "" : `<span class="marker" style="left:${pct(value)}%"></span>`;
  return `<div class="meter ${opts.cls || ""}" role="meter" aria-valuemin="${min}" aria-valuemax="${max}" aria-valuenow="${value ?? ""}">${segs}${mark}${ticks}</div>`;
}
