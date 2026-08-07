const stage = document.getElementById("stage");
const results = document.getElementById("results");
const queryMeta = document.getElementById("query-meta");
const input = document.getElementById("q");
const form = document.getElementById("search-form");
let timer = null;

function severityClass(score, severity) {
  const s = (severity || "").toUpperCase();
  if (s.includes("CRIT")) return "crit";
  if (s.includes("HIGH")) return "high";
  if (s.includes("MED")) return "med";
  if (s.includes("LOW")) return "low";
  const n = Number(score);
  if (Number.isFinite(n)) {
    if (n >= 9) return "crit";
    if (n >= 7) return "high";
    if (n >= 4) return "med";
    if (n > 0) return "low";
  }
  return "cvss";
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function edbBadges(r) {
  const ids = r.edb_ids || (r.edb || []).map((e) => e.edb_id);
  if (!ids || !ids.length) return "";
  const shown = ids.slice(0, 6);
  const extra = ids.length - shown.length;
  const cveHref = r.cve_id ? `/cve/${escapeHtml(r.cve_id)}` : "";
  return `<div class="hit-links">${shown
    .map((id) =>
      cveHref
        ? `<a class="badge edb" href="${cveHref}#edb-${escapeHtml(id)}">EDB-${escapeHtml(id)}</a>`
        : `<span class="badge edb">EDB-${escapeHtml(id)}</span>`
    )
    .join("")}${
    extra > 0 ? `<span class="badge edb">+${extra} more</span>` : ""
  }</div>`;
}

function cveBadges(r) {
  const ids = r.cve_ids || (r.cves || []).map((c) => c.cve_id);
  if (!ids || !ids.length) return "";
  const shown = ids.slice(0, 6);
  const extra = ids.length - shown.length;
  return `<div class="hit-links">${shown
    .map((id) => `<a class="badge cve" href="/cve/${escapeHtml(id)}">${escapeHtml(id)}</a>`)
    .join("")}${
    extra > 0 ? `<span class="badge cve">+${extra} more</span>` : ""
  }</div>`;
}

function renderResults(data) {
  const cves = data.cves || [];
  const exploits = data.exploits || [];
  const q = data.query || {};

  if (queryMeta) {
    if (q.product || q.version || q.cve_id || q.edb_id) {
      queryMeta.hidden = false;
      const bits = [];
      if (q.product) bits.push(`product <strong>${escapeHtml(q.product)}</strong>`);
      if (q.version) bits.push(`version <strong>${escapeHtml(q.version)}</strong>`);
      if (q.cve_id) bits.push(`id <strong>${escapeHtml(q.cve_id)}</strong>`);
      if (q.edb_id) bits.push(`EDB <strong>${escapeHtml(q.edb_id)}</strong>`);
      queryMeta.innerHTML = `Matched on ${bits.join(" · ")}`;
    } else {
      queryMeta.hidden = true;
      queryMeta.innerHTML = "";
    }
  }

  if (!cves.length && !exploits.length) {
    results.innerHTML = `<p class="empty">No version-specific matches in the local database.</p>`;
    return;
  }

  let html = "";
  if (cves.length) {
    html += `<div class="results-block"><h2>CVE matches (${cves.length})</h2>${cves
      .map((r) => {
        const score = r.cvss_score != null ? Number(r.cvss_score).toFixed(1) : "—";
        const sev = severityClass(r.cvss_score, r.severity);
        const ver = r.matched_version
          ? `<span class="badge ver">v ${escapeHtml(r.matched_version)}</span>`
          : q.version
            ? `<span class="badge ver">v ${escapeHtml(q.version)}</span>`
            : "";
        const edbCount =
          r.edb_count != null
            ? Number(r.edb_count)
            : (r.edb_ids || r.edb || []).length;
        const edbHint =
          edbCount > 0
            ? `<span class="badge edb">${edbCount} EDB</span>`
            : `<span class="badge muted">no EDB</span>`;
        return `<article class="hit">
          <div class="hit-top">
            <span class="id"><a class="cve-link" href="/cve/${escapeHtml(r.cve_id)}">${escapeHtml(r.cve_id)}</a></span>
            <span class="badge cvss ${sev}">CVSS ${score}</span>
            ${r.severity ? `<span class="badge ${sev}">${escapeHtml(r.severity)}</span>` : ""}
            ${ver}
            ${edbHint}
          </div>
          <div class="desc">${escapeHtml(r.description || "")}</div>
          ${edbBadges(r)}
          <div class="reason">${escapeHtml(r.match_reason || "match")}</div>
        </article>`;
      })
      .join("")}</div>`;
  }

  if (exploits.length) {
    html += `<div class="results-block"><h2>Exploit-DB matches (${exploits.length})</h2>${exploits
      .map((r) => {
        const ver = r.matched_version
          ? `<span class="badge ver">v ${escapeHtml(r.matched_version)}</span>`
          : "";
        return `<article class="hit">
          <div class="hit-top">
            <span class="id">EDB-${escapeHtml(r.edb_id)}</span>
            <span class="badge cvss">${escapeHtml(r.platform || "n/a")}</span>
            <span class="badge cvss">${escapeHtml(r.type || "")}</span>
            ${ver}
          </div>
          <div class="desc">${escapeHtml(r.title || "")}</div>
          ${cveBadges(r)}
          <div class="reason">${escapeHtml(r.match_reason || "match")}</div>
        </article>`;
      })
      .join("")}</div>`;
  }
  results.innerHTML = html;
}

async function runSearch(q) {
  if (q.length < 2) {
    results.innerHTML = "";
    if (queryMeta) queryMeta.hidden = true;
    stage.classList.remove("has-results");
    return;
  }
  stage.classList.add("has-results");
  const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
  const data = await res.json();
  renderResults(data);
}

input.addEventListener("input", () => {
  clearTimeout(timer);
  timer = setTimeout(() => runSearch(input.value.trim()), 280);
});
form.addEventListener("submit", (e) => {
  e.preventDefault();
  runSearch(input.value.trim());
});

function fmtNum(n) {
  const v = Number(n) || 0;
  return v.toLocaleString("en-US");
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function setDonut(id, pct, offset) {
  const el = document.getElementById(id);
  if (!el) return;
  const p = Number(pct) || 0;
  el.setAttribute("stroke-dasharray", `${p} ${100 - p}`);
  el.setAttribute("stroke-dashoffset", String(offset ?? 0));
}

function updateHomeOverview(payload) {
  const ov = payload.overview || {};
  const vuln = ov.vulnerabilities || {};
  const visual = payload.visual || null;

  setText("ov-products", fmtNum(ov.affected_products));
  setText("ov-categories", fmtNum(ov.threat_categories));
  setText("ov-vulns-total", fmtNum(vuln.total || vuln.rated));
  setText("ov-crit", fmtNum(vuln.critical));
  setText("ov-high", fmtNum(vuln.high));
  setText("ov-med", fmtNum(vuln.medium));
  setText("ov-low", fmtNum(vuln.low));

  if (!visual || (visual.total == null && visual.rated == null && !visual.bar)) {
    return;
  }

  const bar = visual.bar || {};
  const pct = visual.pct || {};
  const offsets = visual.donut_offset || {};

  const stack = document.getElementById("sev-stack");
  if (stack && Number(visual.rated) > 0) {
    stack.innerHTML = `
      <span class="seg crit" id="seg-crit" style="flex: ${Number(visual.critical) || 0}" title="Critical ${fmtNum(visual.critical)}"></span>
      <span class="seg high" id="seg-high" style="flex: ${Number(visual.high) || 0}" title="High ${fmtNum(visual.high)}"></span>
      <span class="seg med" id="seg-med" style="flex: ${Number(visual.medium) || 0}" title="Medium ${fmtNum(visual.medium)}"></span>
      <span class="seg low" id="seg-low" style="flex: ${Number(visual.low) || 0}" title="Low ${fmtNum(visual.low)}"></span>
    `;
  }

  const barMap = [
    ["bar-crit", "num-crit", bar.critical, visual.critical],
    ["bar-high", "num-high", bar.high, visual.high],
    ["bar-med", "num-med", bar.medium, visual.medium],
    ["bar-low", "num-low", bar.low, visual.low],
  ];
  for (const [barId, numId, width, count] of barMap) {
    const b = document.getElementById(barId);
    if (b) b.style.width = `${Number(width) || 0}%`;
    setText(numId, fmtNum(count));
  }

  setText("meta-rated", `${fmtNum(visual.rated)} rated`);
  setText("meta-unrated", `${fmtNum(visual.unrated)} unrated`);
  setText("meta-total", `${fmtNum(visual.total)} total`);

  setDonut("donut-crit", pct.critical, offsets.critical);
  setDonut("donut-high", pct.high, offsets.high);
  setDonut("donut-med", pct.medium, offsets.medium);
  setDonut("donut-low", pct.low, offsets.low);
  setText("donut-center", fmtNum(visual.rated));
  setText("pct-crit", `${Number(pct.critical) || 0}%`);
  setText("pct-high", `${Number(pct.high) || 0}%`);
  setText("pct-med", `${Number(pct.medium) || 0}%`);
  setText("pct-low", `${Number(pct.low) || 0}%`);

  const catBars = document.getElementById("cat-bars");
  if (catBars) {
    const cats = visual.categories || [];
    if (!cats.length) {
      catBars.innerHTML = `<p class="empty-inline">Sync CVE List + Exploit-DB to populate categories.</p>`;
    } else {
      catBars.innerHTML = cats
        .map(
          (c) => `<div class="sev-bar-row">
            <span class="lbl">${escapeHtml(c.name || "")}</span>
            <div class="bar-track"><span class="bar cat" style="width: ${Number(c.width) || 0}%"></span></div>
            <span class="num">${fmtNum(c.count)}</span>
          </div>`
        )
        .join("");
    }
  }
}

let overviewTimer = null;
let lastOverviewRefresh = 0;

let overviewEndpoint = "/api/home_overview";

async function fetchHomeOverview(_wantRefresh) {
  // Always hit the cheap cached overview. Forcing refresh=1 on ~370k NVD rows
  // can stall Flask for minutes; Sync DB already recomputes overview_stats_json.
  const q = "";
  let res = await fetch(`${overviewEndpoint}${q}`);
  if (res.status === 404 && overviewEndpoint === "/api/home_overview") {
    overviewEndpoint = "/api/stats";
    res = await fetch(`${overviewEndpoint}${q}`);
  }
  if (!res.ok) {
    throw new Error(`overview http ${res.status}`);
  }
  const data = await res.json();
  if (data && data.overview) {
    return data;
  }
  return {
    overview: (data && data.overview) || {},
    visual: (data && data.visual) || null,
    job_running: data && data.job_running,
  };
}

async function pollHomeOverview() {
  if (!document.getElementById("home-overview")) return;
  // Skip while search results are showing
  if (stage && stage.classList.contains("has-results")) return;
  try {
    const now = Date.now();
    let running = false;
    try {
      const statusRes = await fetch("/api/job_state");
      if (statusRes.ok) {
        const jobState = await statusRes.json();
        running = Boolean(jobState && jobState.running);
      }
    } catch (_) {
      /* ignore */
    }
    const wasRunning = Boolean(pollHomeOverview._wasRunning);
    pollHomeOverview._wasRunning = running;
    // Force recompute: first paint, after Sync finishes, or on interval.
    const refreshEveryMs = running ? 15000 : 30000;
    const wantRefresh =
      !pollHomeOverview._primed ||
      (wasRunning && !running) ||
      now - lastOverviewRefresh >= refreshEveryMs;
    const data = await fetchHomeOverview(wantRefresh);
    pollHomeOverview._primed = true;
    if (wantRefresh) lastOverviewRefresh = now;
    if (data.visual) {
      updateHomeOverview(data);
    } else if (data.overview) {
      updateHomeOverview({ overview: data.overview, visual: null });
    }
  } catch (_) {
    /* ignore transient poll errors */
  }
}

if (document.getElementById("home-overview")) {
  pollHomeOverview();
  overviewTimer = setInterval(pollHomeOverview, 5000);
}
