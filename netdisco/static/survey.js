"use strict";
/* Wi-Fi survey: live signal meter for walking the office. */

const Survey = { samples: [], events: [], marks: [], since: 0, mode: null, timer: null, current: null };
const RSSI_ZONES = [{ from: -95, to: -75, s: "red" }, { from: -75, to: -67, s: "yellow" }, { from: -67, to: -30, s: "green" }];
const SNR_TXT = (snr) => (snr == null ? "unknown" : snr >= 25 ? "green" : snr >= 15 ? "yellow" : "red");
const WINDOW_S = 180;

function surveyAdvice(c) {
  if (!c || c.rssi_dbm == null) return "Not connected to Wi-Fi.";
  const r = c.rssi_dbm, snr = c.snr_db;
  if (r >= -60) return "Excellent — video calls and large transfers will be smooth here.";
  if (r >= -67) return "Good — reliable for calls and everyday work.";
  if (r >= -75) return "Fair — browsing is fine, but calls may stutter. An access point closer to this spot would help.";
  return `Poor — expect drop-outs and slow speeds${snr != null && snr < 15 ? " (noisy channel too)" : ""}. This spot needs better coverage.`;
}

function renderMeter() {
  const c = Survey.current;
  const el = $("meter-panel");
  if (!c) { el.innerHTML = `<div class="dim">Waiting for Wi-Fi readings…</div>`; return; }
  const rssi = c.rssi_dbm;
  el.className = `panel meter-panel s-${sKey(c.status)}`;
  el.innerHTML = `
    <div class="panel-head"><h3>Signal strength</h3>${chicklet(c.status, c.quality)}</div>
    <div class="big-reading"><span class="big">${rssi ?? "—"}</span><span class="unit">dBm</span></div>
    ${meter(rssi, -95, -30, RSSI_ZONES, { ticks: [-90, -75, -67, -60, -50, -40], cls: "rssi" })}
    <div class="meter-legend"><span>Weaker</span><span>Stronger</span></div>
    <p class="advice">${esc(surveyAdvice(c))}</p>`;
}

function renderStats() {
  const c = Survey.current || {};
  const snr = c.snr_db;
  const ch = c.channel ? `${c.channel}${c.band ? ` · ${c.band}` : ""}${c.width_mhz ? ` · ${c.width_mhz} MHz` : ""}` : (c.channel_text || "—");
  const tile = (label, value, extra = "") => `<div class="stat"><span class="stat-label">${label}</span><span class="stat-value">${value}</span>${extra}</div>`;
  $("survey-stats").innerHTML = `
    <div class="panel-head"><h3>Connection</h3></div>
    <div class="stats">
      ${tile("Network", c.ssid ? esc(c.ssid) : `<span class="dim">Hidden by macOS</span>`)}
      ${tile("Signal-to-noise", snr != null ? dotval(SNR_TXT(snr), `${snr} dB`, "25 dB+ good, 15–25 fair, under 15 poor") : "—")}
      ${tile("Noise floor", c.noise_dbm != null ? `${c.noise_dbm} dBm` : "—")}
      ${tile("Link rate", c.tx_rate_mbps ? `${Math.round(c.tx_rate_mbps)} Mb/s` : "—")}
      ${tile("Channel", esc(ch))}
      ${tile("Access point", c.bssid ? `<span class="mono">${esc(c.bssid)}</span>` : `<span class="dim">Hidden by macOS</span>`)}
    </div>
    ${!c.bssid && !c.ssid ? `<p class="hint">To see network and access-point names, allow Location Services for Terminal (System Settings › Privacy &amp; Security › Location Services), then restart the app.</p>` : ""}`;
}

function renderSurveyChart() {
  const now = Date.now() / 1000;
  const pts = Survey.samples.filter((s) => s.t > now - WINDOW_S).map((s) => ({ t: s.t, v: s.rssi_dbm, s }));
  const roams = Survey.events.filter((e) => e.type === "roam" && e.t > now - WINDOW_S);
  const el = $("survey-chart");
  lineChart(el, pts, {
    height: 220, yMin: -95, yMax: -30, span: WINDOW_S, padL: 44, padB: 18, padT: 8, gap: 5,
    bands: [{ from: -95, to: -75, cls: "band-red" }, { from: -75, to: -67, cls: "band-yellow" }],
    refs: [{ v: -67, label: "-67" }, { v: -75, label: "-75" }, { v: -50, label: "-50" }, { v: -90, label: "-90" }],
    events: roams.map((e) => ({ t: e.t, label: "Roamed" })), label: "Signal strength over time",
    fmt: (p) => `<b>${p.v} dBm</b>${p.s.snr_db != null ? ` · SNR ${p.s.snr_db} dB` : ""}${p.s.bssid ? `<br>AP ${esc(p.s.bssid)}` : ""}`,
  });
  // x-axis labels
  el.insertAdjacentHTML("beforeend", `<div class="xaxis"><span>3 min ago</span><span>2 min</span><span>1 min</span><span>now</span></div>`);
  const last = roams[roams.length - 1];
  $("roam-note").textContent = last ? `Roamed to ${last.to} at ${fmtTime(last.t)}` : "";
}

function renderMarks() {
  const tb = $("marks");
  $("marks-empty").hidden = Survey.marks.length > 0;
  tb.innerHTML = Survey.marks.slice().reverse().map((m) => `<tr>
    <td><span class="name">${esc(m.label)}</span></td>
    <td>${dotval(m.status, `${m.rssi_dbm} dBm`, `Lowest in sample: ${m.min_rssi} dBm`)}</td>
    <td>${esc(m.quality)}</td>
    <td>${m.snr_db != null ? dotval(SNR_TXT(m.snr_db), `${m.snr_db} dB`) : "—"}</td>
    <td>${m.tx_rate_mbps ? `${Math.round(m.tx_rate_mbps)} Mb/s` : "—"}</td>
    <td class="mono">${esc(m.bssid || "—")}</td>
    <td>${m.channel ? esc(`${m.channel}${m.band ? " · " + m.band : ""}`) : "—"}</td>
    <td>${fmtTime(m.t, false)}</td></tr>`).join("");
}

async function pollSurvey() {
  if (App.current !== "survey") { Survey.timer = null; return; }
  try {
    const r = await api(`/api/wifi/live?since=${Survey.since}`);
    const lastT = Survey.samples.length ? Survey.samples[Survey.samples.length - 1].t : 0;
    const lastE = Survey.events.length ? Survey.events[Survey.events.length - 1].t : 0;
    Survey.samples.push(...r.samples.filter((s) => s.t > lastT));
    Survey.events.push(...r.events.filter((e) => e.t > lastE));
    const cut = Date.now() / 1000 - 900;
    Survey.samples = Survey.samples.filter((s) => s.t > cut);
    if (r.samples.length) Survey.since = r.samples[r.samples.length - 1].t;
    Survey.current = r.current;
    Survey.marks = r.marks;
    Survey.mode = r.mode;
    $("survey-mode").textContent = r.mode === "fast" ? "Live · updates every second"
      : r.mode === "demo" ? "Demo data" : r.mode === "slow" ? "Updates every few seconds (fast reader unavailable)" : "Starting…";
    renderMeter(); renderStats(); renderSurveyChart(); renderMarks();
  } catch (e) { $("survey-mode").textContent = "Lost contact with the local agent"; }
  Survey.timer = setTimeout(pollSurvey, 1000);
}

function csvCell(v) { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }

function initSurvey() {
  const doMark = async () => {
    const r = await api("/api/wifi/mark", { label: $("mark-label").value });
    if (!r.ok) { showBanner(esc(r.message || "Couldn't mark this spot.")); return; }
    $("mark-label").value = ""; $("mark-label").focus();
    Survey.marks.push(r.mark); renderMarks();
  };
  $("mark-btn").addEventListener("click", doMark);
  $("mark-label").addEventListener("keydown", (e) => { if (e.key === "Enter") doMark(); });
  $("mark-clear").addEventListener("click", async () => { await api("/api/wifi/marks/clear", {}); Survey.marks = []; renderMarks(); });
  $("mark-export").addEventListener("click", () => {
    const head = ["Location", "Time", "Signal dBm", "Lowest dBm", "Quality", "SNR dB", "Noise dBm", "Link rate Mb/s", "SSID", "BSSID", "Channel", "Band", "Width MHz"];
    const rows = Survey.marks.map((m) => [m.label, new Date(m.t * 1000).toISOString(), m.rssi_dbm, m.min_rssi, m.quality, m.snr_db,
      m.noise_dbm, m.tx_rate_mbps, m.ssid, m.bssid, m.channel, m.band, m.width_mhz]);
    const csv = [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = `wifi-survey-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}.csv`;
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
}

function showSurvey() {
  Survey.since = 0; Survey.samples = []; Survey.events = [];
  if (!Survey.timer) pollSurvey();
}
