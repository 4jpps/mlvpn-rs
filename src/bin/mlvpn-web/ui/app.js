// mlvpn-web dashboard. Plain JavaScript, no libraries; everything from the
// API is put on the page as text (never as HTML).
"use strict";

const COLORS = ["#d9ad6b", "#5aa9e6", "#7bd389", "#e07a5f", "#b892ff", "#f2cc8f", "#4dd0c8"];
const $ = (id) => document.getElementById(id);
const state = { ui: null, snapshot: null, history: [], since: 0, events: [], busy: false, colors: {} };

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k === "style") Object.assign(e.style, v);
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

const SVG = "http://www.w3.org/2000/svg";
function svg(tag, attrs) {
  const e = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}

function mbps(v) {
  if (v === null || v === undefined) return "—";
  return v >= 100 ? `${v.toFixed(0)} Mbps` : v >= 10 ? `${v.toFixed(1)} Mbps` : `${v.toFixed(2)} Mbps`;
}
const ms = (v) => (v === null || v === undefined ? "—" : `${v.toFixed(v >= 100 ? 0 : 1)} ms`);
const pct = (v) => (v === null || v === undefined ? "—" : `${v.toFixed(v >= 10 ? 0 : 1)}%`);
function duration(secs) {
  if (secs === null || secs === undefined) return "—";
  const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${Math.floor(secs % 60)}s`;
  return `${Math.floor(secs)}s`;
}
function bytes(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function colorFor(name) {
  if (!state.colors[name]) state.colors[name] = COLORS[Object.keys(state.colors).length % COLORS.length];
  return state.colors[name];
}

// A small line chart of the last 5 minutes, as on OmniBridge's System tab.
// `max` fixes the top of the scale; without it the scale follows the data.
function lineChart(host, series, format, max) {
  const W = 600, H = 140;
  const n = Math.max(2, ...series.map((s) => s.values.length));
  const all = series.flatMap((s) => s.values.filter((v) => v !== null && v !== undefined));
  const top = max ?? Math.max(1, ...all) * 1.15;
  const x = (i) => (i / (n - 1)) * W;
  const y = (v) => H - (Math.min(v, top) / top) * H;
  const box = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img" });
  for (const f of [0.25, 0.5, 0.75]) box.append(svg("line", { x1: 0, x2: W, y1: H * f, y2: H * f }));
  for (const s of series) {
    let d = "";
    const offset = n - s.values.length;
    s.values.forEach((v, i) => {
      if (v === null || v === undefined) return;
      const prev = s.values[i - 1];
      d += `${d === "" || prev === null || prev === undefined ? "M" : "L"}${x(i + offset).toFixed(1)},${y(v).toFixed(1)} `;
    });
    if (d) box.append(svg("path", { d, stroke: s.color }));
  }
  const legend = el("div", { class: "legend" }, el("span", { class: "scale" }, `top ${format(top)}`));
  for (const s of series) {
    const last = [...s.values].reverse().find((v) => v !== null && v !== undefined);
    legend.append(el("span", {}, el("i", { style: { background: s.color } }), `${s.label}: `, el("strong", {}, last === undefined ? "—" : format(last))));
  }
  host.replaceChildren(el("div", { class: "chart" }, box, legend));
}

function linkSeries(field) {
  const names = [];
  for (const sample of state.history) for (const l of sample.links) if (!names.includes(l.name)) names.push(l.name);
  return names.map((name) => ({
    label: name,
    color: colorFor(name),
    values: state.history.map((s) => {
      const l = s.links.find((x) => x.name === name);
      return l ? l[field] : null;
    }),
  }));
}

function drawCharts() {
  const h = state.history;
  lineChart($("chart-tunnel"), [
    { label: "Received", color: COLORS[1], values: h.map((s) => s.rx_mbps) },
    { label: "Sent", color: COLORS[0], values: h.map((s) => s.tx_mbps) },
  ], mbps);
  lineChart($("chart-rx"), linkSeries("rx_mbps"), mbps);
  lineChart($("chart-tx"), linkSeries("tx_mbps"), mbps);
  lineChart($("chart-rtt"), linkSeries("rtt_ms"), ms);
  const loss = linkSeries("loss_pct");
  const worst = Math.max(0, ...loss.flatMap((s) => s.values.filter((v) => v !== null)));
  lineChart($("chart-loss"), loss, pct, worst < 5 ? 5 : undefined);
}

function healthClass(health) {
  switch ((health || "").toUpperCase()) {
    case "HEALTHY": return "ok";
    case "DEGRADED": case "FAILOVER": case "STARTING": return "warn";
    case "DOWN": return "bad";
    default: return "off";
  }
}

function linkDisabled(link) {
  return link.admin_disabled || (state.ui && state.ui.disabled_by_web.includes(link.name));
}

function facts(pairs) {
  const dl = el("dl", { class: "facts" });
  for (const [k, v] of pairs) if (v !== null && v !== undefined && v !== "") dl.append(el("dt", {}, k), el("dd", {}, v));
  return dl;
}

function drawHeader() {
  const snap = state.snapshot;
  const ui = state.ui || {};
  $("title").textContent = ui.title || (snap && snap.tunnel_name) || "mlvpn";
  document.title = `${$("title").textContent} · mlvpn`;
  if (ui.who && ui.who !== "local") $("who").textContent = `Signed in as ${ui.who}`;
  if (!snap) return;
  const t = snap.daemon.telemetry;
  const health = $("health");
  health.textContent = t.health;
  health.className = `pill ${healthClass(t.health)}`;
  $("subtitle").textContent = `${snap.tunnel_name} · ${snap.mode} · up ${duration(t.tunnel_uptime_secs)}${t.health_reason ? " · " + t.health_reason : ""}`;
  const d = snap.daemon;
  const sys = d.system || {};
  const mem = sys.mem_total_kb && sys.mem_available_kb ? `${bytes((sys.mem_total_kb - sys.mem_available_kb) * 1000)} of ${bytes(sys.mem_total_kb * 1000)}` : null;
  $("facts").replaceWith(Object.assign(facts([
    ["This end", d.local_version ? `mlvpnd ${d.local_version}` : null],
    ["Other end", d.peer_version ? `mlvpnd ${d.peer_version}${d.peer_version !== d.local_version ? " (different version)" : ""}` : "not reported yet"],
    ["Scheduler", t.scheduler_mode],
    ["Tunnel MTU", d.local_tunnel_mtu],
    ["Queue", `${d.outbound_queue_len} / ${d.outbound_queue_capacity}${d.outbound_queue_dropped_total ? `, ${d.outbound_queue_dropped_total} dropped` : ""}`],
    ["Reroutes", t.reroutes_total],
    ["Load", sys.load1 !== null && sys.load1 !== undefined ? `${sys.load1.toFixed(2)} ${sys.load5.toFixed(2)} ${sys.load15.toFixed(2)}` : null],
    ["Memory used", mem],
    ["Host up", sys.uptime_secs ? duration(sys.uptime_secs) : null],
  ]), { id: "facts" }));
}

function drawLinks() {
  const snap = state.snapshot;
  if (!snap) return;
  const actions = state.ui && state.ui.actions;
  const cards = snap.links.map((l) => {
    const off = linkDisabled(l);
    const cls = off ? "off" : l.state === "up" ? "ok" : l.state === "down" ? "bad" : "warn";
    const card = el("article", { class: "card link", style: { borderLeftColor: colorFor(l.name) } },
      el("div", { class: "link__head" },
        el("span", { class: "link__name" }, l.name, l.is_primary ? el("span", { class: "badge" }, "primary") : null),
        el("span", { class: `pill ${cls}` }, off ? "turned off" : l.state)),
      facts([
        ["Interface", `${l.bind_interface}${l.remote_addr ? " → " + l.remote_addr : ""}`],
        ["In state for", duration(l.state_duration_ms / 1000)],
        ["Round trip", `${ms(l.local_rtt_ms)}${l.local_jitter_ms !== null && l.local_jitter_ms !== undefined ? ` (±${ms(l.local_jitter_ms)})` : ""}`],
        ["Loss", pct(l.local_loss_pct)],
        ["Now", `↓ ${mbps(l.local_rx_throughput_mbps)}   ↑ ${mbps(l.local_tx_throughput_mbps)}`],
        ["Capacity", l.local_confirmed_ceiling_mbps ? mbps(l.local_confirmed_ceiling_mbps) : l.local_active_bandwidth_mbps ? `${mbps(l.local_active_bandwidth_mbps)} (measured)` : null],
        ["Total", `↓ ${bytes(l.rx_bytes)}   ↑ ${bytes(l.tx_bytes)}`],
      ]));
    if (actions) {
      const row = el("div", { class: "link__actions" });
      if (off) row.append(el("button", { onclick: () => setLink(l.name, true) }, "Turn on"));
      else row.append(el("button", { class: "danger", onclick: () => setLink(l.name, false) }, "Turn off"));
      row.append(el("button", { class: "secondary", onclick: () => runTest(l.name) }, "Test this link"));
      for (const b of row.querySelectorAll("button")) b.disabled = state.busy;
      card.append(row);
    }
    return card;
  });
  $("links").replaceChildren(...cards);

  const pick = $("test-link");
  const chosen = pick.value;
  pick.replaceChildren(el("option", { value: "" }, "every link"), ...snap.links.map((l) => el("option", { value: l.name }, l.name)));
  pick.value = chosen;
}

function drawEvents() {
  const list = $("events");
  if (!state.events.length) return;
  list.replaceChildren(...state.events.slice(-80).reverse().map((e) => {
    const when = new Date(e.unix_ts_ms);
    return el("li", {},
      el("time", { datetime: when.toISOString(), title: when.toLocaleString() }, when.toLocaleTimeString()),
      el("span", { class: `sev-${e.severity}` }, e.link ? `${e.link}: ${e.message}` : e.message));
  }));
}

async function api(path) {
  const r = await fetch(path, { cache: "no-store", credentials: "same-origin" });
  const body = await r.json().catch(() => null);
  return { ok: r.ok, status: r.status, body };
}

async function action(path, payload) {
  const r = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-MLVPN-Action": "1" },
    body: JSON.stringify(payload),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}

function setBusy(busy, message) {
  state.busy = busy;
  for (const b of document.querySelectorAll("button")) b.disabled = busy;
  if (message !== undefined) $("tool-status").textContent = message;
}

async function setLink(name, enabled) {
  if (!enabled && !confirm(`Turn off ${name}? Traffic moves to the other links until you turn it back on (or mlvpnd restarts).`)) return;
  setBusy(true);
  try {
    await action("/api/v1/actions/link", { link: name, enabled });
    await refreshUi();
  } catch (e) {
    alert(`Couldn't turn ${name} ${enabled ? "on" : "off"}: ${e.message}`);
  }
  setBusy(false);
  drawLinks();
}

async function runTest(link) {
  const secs = Number($("test-secs").value);
  const both = $("test-both").checked;
  const name = link ?? ($("test-link").value || null);
  setBusy(true, `Testing ${name || "every link"} for ${secs} s${both ? " each way" : ""}… the links carry test traffic meanwhile.`);
  $("test-results").hidden = true;
  try {
    const r = await action("/api/v1/actions/selftest", { link: name, duration_secs: secs, bidirectional: both });
    const rows = (r.results || []).map((x) => el("tr", {}, el("td", {}, x.link), el("td", {}, mbps(x.upload_mbps)), el("td", {}, both ? mbps(x.download_mbps) : "not tested")));
    $("test-results").querySelector("tbody").replaceChildren(...rows);
    $("test-results").hidden = rows.length === 0;
    setBusy(false, rows.length ? `Done. Upload is this end sending to the other end.` : "Done, but no link reported a result.");
  } catch (e) {
    setBusy(false, `The test failed: ${e.message}`);
  }
}

async function runDiag() {
  setBusy(true, "Taking a diagnostic dump…");
  try {
    const r = await action("/api/v1/actions/diag", {});
    $("diag-text").textContent = r.text || "(empty)";
    $("diag").hidden = false;
    setBusy(false, "Diagnostic dump below. It includes recent log lines; share it only with whoever is helping you.");
  } catch (e) {
    setBusy(false, `Couldn't take a dump: ${e.message}`);
  }
}

function saveDiag() {
  const blob = new Blob([$("diag-text").textContent], { type: "text/plain" });
  const a = el("a", { href: URL.createObjectURL(blob), download: `mlvpn-diag-${(state.ui && state.ui.title) || "dump"}-${new Date().toISOString().replace(/[:.]/g, "-")}.txt` });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

async function refreshUi() {
  const r = await api("/api/v1/ui");
  if (r.ok && r.body) state.ui = r.body.data;
}

async function tickFast() {
  const r = await api("/api/v1/snapshot");
  const stale = $("stale");
  if (r.ok && r.body) {
    state.snapshot = r.body.data;
    const old = r.body.age_ms !== null && r.body.age_ms > 5000;
    stale.hidden = r.body.connected && !old;
    stale.textContent = !r.body.connected ? "mlvpn-web has lost contact with mlvpnd: showing the last known state." : "The numbers are more than 5 seconds old.";
    drawHeader();
    if (!state.busy) drawLinks();
  } else {
    stale.hidden = false;
    stale.textContent = r.status === 503 ? "Waiting for mlvpnd: is the tunnel daemon running?" : `The dashboard API answered ${r.status}.`;
  }
}

async function tickSlow() {
  const [h, e] = await Promise.all([api("/api/v1/history?limit=600"), api(`/api/v1/events?since=${state.since}&limit=200`)]);
  if (h.ok && h.body && h.body.data) {
    state.history = h.body.data.samples || [];
    drawCharts();
  }
  if (e.ok && e.body && e.body.data) {
    const page = e.body.data;
    if (page.events.length && page.events[0].seq <= state.since) state.events = [];
    state.events.push(...page.events);
    if (state.events.length > 500) state.events = state.events.slice(-500);
    state.since = page.next_since ?? state.since;
    drawEvents();
  }
}

function every(ms, fn) {
  const run = async () => {
    if (!document.hidden) {
      try { await fn(); } catch (_) { /* the next tick tries again */ }
    }
    setTimeout(run, ms);
  };
  run();
}

async function start() {
  await refreshUi().catch(() => {});
  if (state.ui && state.ui.actions) {
    $("tools").hidden = false;
    $("test-run").addEventListener("click", () => runTest(null));
    $("diag-run").addEventListener("click", runDiag);
    $("diag-save").addEventListener("click", saveDiag);
    $("diag-copy").addEventListener("click", () => navigator.clipboard.writeText($("diag-text").textContent));
    const secs = $("test-secs");
    for (const o of [...secs.options]) if (Number(o.value) > state.ui.max_test_secs) o.remove();
  }
  $("footer").textContent = "Updates every second; charts show the last 5 minutes.";
  every(1000, tickFast);
  every(2000, tickSlow);
  every(15000, refreshUi);
}

start();
