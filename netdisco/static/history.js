"use strict";
/* History log: incidents recorded by the agent (internet / router / DNS / Wi-Fi), with a timeline. */

const Hist = { range: 86400, kind: "all", info: false, data: null, timer: null };
const KIND_ORDER = ["internet", "gateway", "dns", "wifi", "network", "app"];
const KIND_ICON = { internet: "network", gateway: "router", dns: "network", wifi: "wifi", network: "plug", app: "refresh" };

function fmtDuration(s) {
  if (s == null) return "—";
  s = Math.round(s);
  if (s < 60) return `${s}s`;
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return sec && m < 10 ? `${m}m ${sec}s` : `${m}m`;
}
function fmtWhen(t) {
  const d = new Date(t * 1000), now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  const y = new Date(now); y.setDate(now.getDate() - 1);
  const day = sameDay ? "Today" : d.toDateString() === y.toDateString() ? "Yesterday"
    : d.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
  return `${day} ${d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
}
const sevStatus = (e) => (e.severity === "critical" ? "red" : e.severity === "warning" ? "yellow" : "unknown");

function worstText(e) {
  const parts = [];
  if (e.max_loss != null && e.max_loss > 0) parts.push(`${Math.round(e.max_loss)}% loss`);
  if (e.worst_ms != null) parts.push(`${Math.round(e.worst_ms)} ms`);
  if (e.min_rssi != null) parts.push(`${e.min_rssi} dBm`);
  return parts.join(" · ") || "—";
}

function visibleEvents() {
  const d = Hist.data; if (!d) return [];
  return d.events.filter((e) => (Hist.kind === "all" || e.kind === Hist.kind) && (Hist.info || e.severity !== "info"));
}

function renderHistStats() {
  const d = Hist.data, now = d.now, since = Hist.range ? now - Hist.range : 0;
  const prob = d.events.filter((e) => !e.point);
  const clip = (e) => Math.max(0, (e.end || now) - Math.max(e.start, since));
  const outages = prob.filter((e) => e.kind === "internet" && e.severity === "critical");
  const slow = prob.filter((e) => e.kind === "internet" && e.severity !== "critical");
  const router = prob.filter((e) => e.kind === "gateway");
  const dns = prob.filter((e) => e.kind === "dns");
  const drops = prob.filter((e) => (e.kind === "wifi" && /disconnect/i.test(e.title)) || e.kind === "network");
  const weak = prob.filter((e) => e.kind === "wifi" && /weak/i.test(e.title));
  const down = outages.reduce((a, e) => a + clip(e), 0);
  const covered = Hist.range || (now - (d.stats.first_event || now));
  const uptime = covered > 0 ? Math.max(0, 100 * (1 - down / covered)) : null;
  const st = (n, warnAt = 1, critAt = 3) => (n >= critAt ? "red" : n >= warnAt ? "yellow" : "green");
  $("hist-stats").innerHTML = [
    tile("Internet outages", String(outages.length), outages.length ? `${fmtDuration(down)} offline` : "none", st(outages.length, 1, 2)),
    tile("Internet uptime", uptime == null ? "—" : `${uptime >= 99.995 ? "100" : uptime.toFixed(uptime >= 99.9 ? 2 : 1)}%`, "while monitoring", uptime == null ? null : uptime >= 99.9 ? "green" : uptime >= 99 ? "yellow" : "red"),
    tile("Slow internet", String(slow.length), slow.length ? `${fmtDuration(slow.reduce((a, e) => a + clip(e), 0))} total` : "none", st(slow.length, 1, 5)),
    tile("Router problems", String(router.length), router.length ? `${fmtDuration(router.reduce((a, e) => a + clip(e), 0))} total` : "none", st(router.length)),
    tile("DNS failures", String(dns.length), dns.length ? `${fmtDuration(dns.reduce((a, e) => a + clip(e), 0))} total` : "none", st(dns.length)),
    tile("Wi-Fi drops", String(drops.length), weak.length ? `${weak.length} weak-signal period${weak.length > 1 ? "s" : ""}` : "no weak-signal periods", st(drops.length + weak.length, 1, 4)),
  ].join("");
}

function renderHistNow() {
  const on = (Hist.data.ongoing || []);
  $("hist-now").innerHTML = on.length ? `<div class="now-box">${on.map((e) => `<div class="now-item s-${sevStatus(e)}">
      ${chicklet(sevStatus(e), "Now")}<b>${esc(e.title)}</b><span class="dim">for ${fmtDuration(e.duration_s)}${worstText(e) !== "—" ? ` · worst ${esc(worstText(e))}` : ""}</span>
      <div class="dim small">${esc(e.detail || "")}</div></div>`).join("")}</div>` : "";
}

function renderTimeline() {
  const d = Hist.data, el = $("hist-timeline");
  const now = d.now, first = d.stats.first_event || now - 3600;
  const t0 = Hist.range ? now - Hist.range : Math.min(first, now - 3600), span = now - t0;
  const rows = [["internet", "Internet"], ["gateway", "Router"], ["dns", "DNS"], ["wifi", "Wi-Fi"], ["network", "Connection"]];
  const W = el.clientWidth || 900, padL = 84, padR = 8, rowH = 22, H = rows.length * rowH + 22;
  const x = (t) => padL + ((t - t0) / span) * (W - padL - padR);
  let g = "";
  rows.forEach(([k, label], i) => {
    const y = i * rowH + 4;
    g += `<text class="tl-label" x="${padL - 10}" y="${y + 12}" text-anchor="end">${label}</text>
          <rect class="tl-track" x="${padL}" y="${y + 3}" width="${W - padL - padR}" height="${rowH - 10}" rx="3"/>`;
    d.events.filter((e) => e.kind === k).forEach((e) => {
      const end = e.end || (e.open ? now : e.start);
      if (end < t0) return;
      const xs = x(Math.max(e.start, t0)), xe = x(end);
      if (e.point) {
        if (!Hist.info) return;
        g += `<rect class="tl-point" data-id="${esc(e.id)}" x="${xs - 1}" y="${y + 1}" width="2" height="${rowH - 6}"/>`;
      } else {
        g += `<rect class="tl-seg s-${sevStatus(e)}${e.open ? " open" : ""}" data-id="${esc(e.id)}" x="${xs}" y="${y + 3}" width="${Math.max(3, xe - xs)}" height="${rowH - 10}" rx="2"/>`;
      }
    });
  });
  // time axis ticks
  const ticks = 6;
  for (let i = 0; i <= ticks; i++) {
    const t = t0 + (span * i) / ticks, xx = x(t);
    const lab = span <= 2 * 86400 ? new Date(t * 1000).toLocaleTimeString([], { hour: "numeric", minute: span < 6 * 3600 ? "2-digit" : undefined })
      : new Date(t * 1000).toLocaleDateString([], { month: "short", day: "numeric" });
    g += `<line class="tl-grid" x1="${xx}" x2="${xx}" y1="4" y2="${rows.length * rowH + 2}"/><text class="tl-tick" x="${xx}" y="${H - 4}" text-anchor="${i === 0 ? "start" : i === ticks ? "end" : "middle"}">${i === ticks ? "now" : esc(lab)}</text>`;
  }
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Timeline of network problems">${g}</svg>`;
  $("hist-span").textContent = `${fmtWhen(t0)} → now`;
  const byId = Object.fromEntries(d.events.map((e) => [e.id, e]));
  el.querySelector("svg").addEventListener("pointermove", (ev) => {
    const r = ev.target.closest("[data-id]");
    if (!r) { hideTip(); return; }
    const e = byId[r.dataset.id];
    showTip(`<b>${esc(e.title)}</b><br>${fmtWhen(e.start)}${e.point ? "" : ` · ${e.open ? "ongoing, " : ""}${fmtDuration(e.duration_s)}`}${worstText(e) !== "—" ? `<br>Worst: ${esc(worstText(e))}` : ""}`, ev.clientX, ev.clientY);
  });
  el.querySelector("svg").addEventListener("pointerleave", hideTip);
}

function renderHistChips() {
  const counts = {};
  Hist.data.events.filter((e) => Hist.info || e.severity !== "info").forEach((e) => { counts[e.kind] = (counts[e.kind] || 0) + 1; });
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const labels = Hist.data.labels || {};
  $("hist-chips").innerHTML = `<button class="chip" data-k="all" aria-pressed="${Hist.kind === "all"}">All <b>${total}</b></button>` +
    KIND_ORDER.filter((k) => counts[k]).map((k) => `<button class="chip" data-k="${k}" aria-pressed="${Hist.kind === k}">${svg(I[KIND_ICON[k]] || I.unknown)}${esc(labels[k] || k)} <b>${counts[k]}</b></button>`).join("");
}

function renderHistTable() {
  const evs = visibleEvents(), labels = Hist.data.labels || {};
  $("hist-count").textContent = evs.length ? String(evs.length) : "";
  $("hist-body").innerHTML = evs.map((e) => `<tr class="${e.open ? "ongoing" : ""}">
    <td class="nowrap">${fmtWhen(e.start)}</td>
    <td class="nowrap">${e.point ? `<span class="dim">—</span>` : e.open ? `<span class="tag warn">ongoing</span> ${fmtDuration(e.duration_s)}` : fmtDuration(e.duration_s)}</td>
    <td><span class="type"><span class="ico">${svg(I[KIND_ICON[e.kind]] || I.unknown)}</span>${esc(labels[e.kind] || e.kind)}</span></td>
    <td class="wrapwide">${dotval(sevStatus(e), `<b>${esc(e.title)}</b>`)}${e.detail ? `<div class="dim small">${esc(e.detail)}</div>` : ""}</td>
    <td class="nowrap">${esc(worstText(e))}</td>
    <td class="wrap">${esc(e.network || "—")}</td></tr>`).join("");
  const empty = $("hist-empty");
  empty.hidden = evs.length > 0;
  empty.textContent = Hist.data.events.length ? "Nothing matches this filter." :
    Hist.range ? "No problems recorded in this period. Problems are logged only while Network Discovery is running." : "Nothing logged yet.";
}

function renderHistory() {
  if (!Hist.data) return;
  renderHistNow(); renderHistStats(); renderTimeline(); renderHistChips(); renderHistTable();
  $("hist-export").href = `/api/events.csv?since=${Hist.range ? Math.floor(Hist.data.now - Hist.range) : 0}`;
}

async function pollHistory() {
  clearTimeout(Hist.timer);
  try {
    const since = Hist.range ? Date.now() / 1000 - Hist.range : 0;
    const d = await api(`/api/events?since=${since}`);
    Hist.data = d;
    const n = (d.ongoing || []).filter((e) => e.severity !== "info").length;
    $("histcount").hidden = !n; $("histcount").textContent = n;
    if (App.current === "history") renderHistory();
  } catch (e) {}
  Hist.timer = setTimeout(pollHistory, App.current === "history" ? 10000 : 30000);
}

function showHistory() { renderHistory(); pollHistory(); }

function initHistory() {
  $("hist-range").addEventListener("change", (e) => { Hist.range = +e.target.value; localStore.set("nd-hrange", Hist.range); pollHistory(); });
  { const r = localStore.get("nd-hrange"); if (r != null && document.querySelector(`#hist-range input[value="${r}"]`)) { Hist.range = +r; document.querySelector(`#hist-range input[value="${r}"]`).checked = true; } }
  $("hist-chips").addEventListener("click", (e) => { const b = e.target.closest(".chip"); if (b) { Hist.kind = b.dataset.k; renderHistChips(); renderHistTable(); } });
  $("hist-info").addEventListener("change", (e) => { Hist.info = e.target.checked; renderHistory(); });
  $("hist-clear").addEventListener("click", async (e) => {
    if (!confirmInline(e.currentTarget, "Delete every logged event", "Click again to clear")) return;
    await api("/api/events/clear", {}).catch(() => {});
    pollHistory();
  });
  let rz; addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => { if (App.current === "history" && Hist.data) renderTimeline(); }, 150); });
}
