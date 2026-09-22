"use strict";
/* Router + startup. */

const App = { current: "dashboard" };

async function route() {
  const h = location.hash || "#/";
  let view = "dashboard", arg = null;
  if (h.startsWith("#/survey")) view = "survey";
  else if (h.startsWith("#/sessions")) view = "sessions";
  else if (h.startsWith("#/device/")) { view = "device"; arg = decodeURIComponent(h.slice(9)); }
  App.current = view;
  document.querySelectorAll("main.view").forEach((m) => { m.hidden = m.id !== `view-${view}`; });
  document.querySelectorAll(".tabs a").forEach((a) => a.setAttribute("aria-current", a.dataset.view === view || (view === "device" && a.dataset.view === "sessions") ? "page" : "false"));
  hideTip();
  if (view === "dashboard") { renderDevices(); if (Dash.health) renderHealth(Dash.health); }
  if (view === "survey") showSurvey();
  if (view === "sessions") { await Sessions.refreshList(); showSessions(); }
  if (view === "device") showDevice(arg);
  scrollTo(0, 0);
}

$("theme").addEventListener("click", () => {
  const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const next = cur === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStore.set("nd-theme", next);
  if (App.current === "dashboard") pollHealth();
});
{ const t = localStore.get("nd-theme"); if (t) document.documentElement.dataset.theme = t; }
let rz; addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => { if (App.current === "dashboard" && Dash.health) renderHealth(Dash.health); }, 150); });
addEventListener("hashchange", route);

(async function init() {
  try { Dash.categories = await api("/api/categories"); } catch (e) {}
  initDashboard(); initSurvey(); initConnect();
  await Sessions.refreshList();
  route();
  pollHealth(); setInterval(pollHealth, 5000);
  pollDevices(); pollPings();
  setInterval(() => Sessions.refreshList().then(() => { if (App.current === "sessions") showSessions(); }), 20000);
})();
