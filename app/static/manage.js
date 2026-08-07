function fmtTime(v) {
  if (!v) return "—";
  return String(v).replace("T", " ").replace(/\+00:00$/, "Z").slice(0, 19);
}

function shortJson(v) {
  if (v == null) return "";
  if (typeof v === "string") return v;
  try {
    const s = JSON.stringify(v);
    return s.length > 160 ? s.slice(0, 157) + "…" : s;
  } catch (_) {
    return String(v);
  }
}

function setStatusCurrent(kind, title, detail, progress, opts) {
  const box = document.getElementById("status-current");
  const titleEl = document.getElementById("status-title");
  const detailEl = document.getElementById("status-detail");
  const wrap = document.getElementById("status-progress-wrap");
  const bar = document.getElementById("status-progress-bar");
  const ptext = document.getElementById("status-progress-text");
  const stopBtn = document.getElementById("stop-job-btn");
  if (!box || !titleEl || !detailEl) return;
  box.classList.remove("idle", "busy", "ok", "err");
  box.classList.add(kind || "idle");
  titleEl.textContent = title;
  detailEl.textContent = detail || "";

  const showStop = !!(opts && opts.showStop);
  const stopping = !!(opts && opts.stopping);
  if (stopBtn) {
    stopBtn.hidden = !showStop;
    stopBtn.disabled = stopping;
    stopBtn.textContent = stopping ? "Stopping…" : "Stop job";
  }

  if (!wrap || !bar || !ptext) return;
  const p = progress || {};
  const donePhase = String(p.phase || "").endsWith("_done") || /complete|finished|done/i.test(String(p.label || ""));
  const hasProgress = !!(p.label || p.current || p.total || p.phase);
  // Hide the animated bar once a job has finished (ok/err) or progress is a "done" phase
  if (!hasProgress || kind === "idle" || kind === "ok" || kind === "err" || donePhase) {
    wrap.hidden = true;
    return;
  }
  wrap.hidden = false;
  const current = Number(p.current || 0);
  const total = Number(p.total || 0);
  const unit = p.unit || "";
  const pct = p.percent != null ? Number(p.percent) : total > 0 ? (current / total) * 100 : null;
  bar.parentElement.classList.toggle("indeterminate", !(total > 0));
  if (total > 0 && pct != null) {
    bar.style.width = `${Math.max(0, Math.min(100, pct))}%`;
    ptext.textContent = `${p.label || "Progress"} — ${current.toLocaleString()} / ${total.toLocaleString()} ${unit} (${pct.toFixed(1)}%)`.trim();
  } else {
    bar.style.width = "35%";
    ptext.textContent = `${p.label || "Progress"}${p.detail ? " · " + p.detail : ""}`.trim();
  }
}

function progressSummary(p) {
  if (!p || !p.label) return "";
  const current = Number(p.current || 0);
  const total = Number(p.total || 0);
  const unit = p.unit || "";
  const donePhase = String(p.phase || "").endsWith("_done") || /complete|finished|done/i.test(String(p.label || ""));
  if (donePhase) return p.detail || "complete";
  if (total > 0) {
    const pct = p.percent != null ? Number(p.percent).toFixed(1) : ((current / total) * 100).toFixed(1);
    return `${current.toLocaleString()} / ${total.toLocaleString()} ${unit} (${pct}%)`;
  }
  if (current > 0) return `${current.toLocaleString()} ${unit}`.trim();
  return p.detail || "";
}

function renderJobs(jobs, runningName) {
  const body = document.getElementById("jobs-body");
  if (!body) return;
  if (!jobs || !jobs.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty-row">No jobs yet.</td></tr>`;
    return;
  }
  body.innerHTML = jobs
    .map((j) => {
      const st = (j.status || "").toLowerCase();
      let cls = "";
      if (st === "ok" || st === "success") cls = "st-ok";
      else if (st === "error" || st === "failed") cls = "st-err";
      else if (st === "cancelled" || st === "stopped") cls = "st-err";
      else if (st === "running") cls = "st-run";
      return `<tr data-job-id="${j.id}">
        <td>${escapeHtml(j.job_name || "")}</td>
        <td class="${cls}">${escapeHtml(j.status || "")}</td>
        <td class="msg">${escapeHtml(j.message || "")}</td>
        <td>${fmtTime(j.started_at)}</td>
      </tr>`;
    })
    .join("");
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setStopSyncVisible(show, stopping) {
  // legacy no-op: single Stop job button lives in Live status
  void show;
  void stopping;
}

async function stopRunningJob() {
  const stopBtn = document.getElementById("stop-job-btn");
  if (stopBtn) {
    stopBtn.disabled = true;
    stopBtn.textContent = "Stopping…";
  }
  setStatusCurrent("busy", "Stopping…", "Waiting for the sync/job to halt safely.", null, {
    showStop: true,
    stopping: true,
  });
  await postAction("/api/jobs/stop");
  refreshStatus();
}

function updateCounts(stats, schedule, syncFeeds) {
  if (!stats) return;
  const map = {
    "count-cves": stats.cves,
    "count-exploits": stats.exploits,
    "count-nvd": stats.nvd_cves,
    "count-cwe": stats.cwe,
    "count-cisa-kev": stats.cisa_kev,
    "count-nuclei": stats.nuclei_templates,
    "count-metasploit": stats.metasploit_modules,
    "count-nessus": stats.nessus_plugins,
    "count-msrc": stats.msrc_cves,
    "count-capec": stats.capec,
    "count-debian": stats.debian_cves,
    "count-ubuntu": stats.ubuntu_cves,
    "count-osv": stats.osv_vulns,
    "count-ghsa": stats.ghsa_advisories,
    "count-poc-github": stats.poc_github,
    "count-products": stats.cve_products,
    "count-cpes": stats.cve_cpes,
  };
  Object.keys(map).forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.textContent = Number(map[id] || 0).toLocaleString();
  });
  const lastSync = document.getElementById("meta-last-sync");
  if (lastSync) lastSync.textContent = fmtTime(stats.last_sync);
  updateScheduleDisplay(schedule);
  if (syncFeeds) applyFeedToggles(syncFeeds);
}

/** True while local toggle edits are pending save — blocks status-poll overwrite. */
let feedTogglesDirty = false;
let feedToggleTimer = null;

function applyFeedToggles(syncFeeds, { force = false } = {}) {
  // Status polls every 2.5s; without this guard they reset Off→On before POST lands.
  if (feedTogglesDirty && !force) return;
  if (!syncFeeds || typeof syncFeeds !== "object") return;
  document.querySelectorAll("[data-feed-toggle]").forEach((input) => {
    const key = input.getAttribute("data-feed-toggle");
    if (!key) return;
    const on = syncFeeds[key] !== false;
    if (input.checked !== on) input.checked = on;
    const row = input.closest(".feed-row");
    if (row) row.classList.toggle("is-disabled", !on);
    const label = input.parentElement && input.parentElement.querySelector(".switch-label");
    if (label) label.textContent = on ? "On" : "Off";
  });
}

async function persistFeedToggles() {
  const sync_feeds = {};
  document.querySelectorAll("[data-feed-toggle]").forEach((input) => {
    const key = input.getAttribute("data-feed-toggle");
    if (key) sync_feeds[key] = !!input.checked;
  });
  const msg = document.getElementById("feed-toggle-msg");
  try {
    const { ok, data } = await postAction("/api/sync/feeds", { sync_feeds });
    if (msg) {
      msg.hidden = false;
      msg.textContent = ok ? "Sync source toggles saved." : data.error || "Could not save toggles";
      if (ok) setTimeout(() => { msg.hidden = true; }, 2500);
    }
    if (ok) {
      feedTogglesDirty = false;
      if (data.sync_feeds) applyFeedToggles(data.sync_feeds, { force: true });
    }
  } catch (_) {
    if (msg) {
      msg.hidden = false;
      msg.textContent = "Could not save toggles";
    }
  }
}

function wireFeedToggles() {
  document.querySelectorAll("[data-feed-toggle]").forEach((input) => {
    input.addEventListener("change", () => {
      feedTogglesDirty = true;
      const row = input.closest(".feed-row");
      if (row) row.classList.toggle("is-disabled", !input.checked);
      const label = input.parentElement && input.parentElement.querySelector(".switch-label");
      if (label) label.textContent = input.checked ? "On" : "Off";
      if (feedToggleTimer) clearTimeout(feedToggleTimer);
      feedToggleTimer = setTimeout(persistFeedToggles, 250);
    });
  });
}

function updateScheduleDisplay(schedule) {
  if (!schedule) return;
  const nextEl = document.getElementById("schedule-next");
  const lastEl = document.getElementById("schedule-last");
  const metaNext = document.getElementById("meta-next-schedule");
  const nextTxt = schedule.enabled ? fmtTime(schedule.next_run_at) : "—";
  const lastTxt = fmtTime(schedule.last_run_at);
  if (nextEl) nextEl.textContent = nextTxt;
  if (lastEl) lastEl.textContent = lastTxt;
  if (metaNext) metaNext.textContent = nextTxt;
}

function toDatetimeLocalValue(iso) {
  if (!iso) return "";
  const s = String(iso).replace(" ", "T").slice(0, 16);
  return s;
}

async function refreshStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    const job = data.job || {};
    const progress = job.progress || {};
    updateCounts(data.stats, data.schedule, data.sync_feeds);
    renderJobs(data.jobs || [], job.running);

    if (job.running) {
      const stopping = !!(job.stop_requested || progress.cancel_requested);
      const nums = progressSummary(progress);
      setStopSyncVisible(true, stopping);
      setStatusCurrent(
        "busy",
        stopping
          ? `Stopping: ${job.running}`
          : progress.label || `Running: ${job.running}`,
        nums
          ? `${nums}${progress.detail ? " · " + progress.detail : ""} · started ${fmtTime(job.started_at)}`
          : `Started ${fmtTime(job.started_at)}`,
        progress,
        { showStop: true, stopping }
      );
      return;
    }
    setStopSyncVisible(false, false);
    if (job.last) {
      const lastProg = job.last.progress || progress;
      if (job.last.stopped) {
        setStatusCurrent(
          "err",
          `Stopped: ${job.last.job}`,
          job.last.error || `Stopped at ${fmtTime(job.last.finished_at)}`,
          null,
          { showStop: false }
        );
      } else if (job.last.ok === false || job.last.error) {
        setStatusCurrent("err", `Failed: ${job.last.job}`, job.last.error || "Unknown error", null, {
          showStop: false,
        });
      } else {
        const nums = progressSummary(lastProg);
        const resultBits = [];
        const res = job.last.result || {};
        if (res.bytes) resultBits.push(`${(Number(res.bytes) / (1024 * 1024)).toFixed(1)} MB`);
        if (res.counts && res.counts.cves != null) resultBits.push(`${Number(res.counts.cves).toLocaleString()} CVEs`);
        if (res.counts && res.counts.exploits != null) resultBits.push(`${Number(res.counts.exploits).toLocaleString()} exploits`);
        setStatusCurrent(
          "ok",
          lastProg.label || `Finished: ${job.last.job}`,
          resultBits.join(" · ") ||
            nums ||
            shortJson(job.last.result) ||
            `Completed at ${fmtTime(job.last.finished_at)}`,
          null,
          { showStop: false }
        );
      }
      return;
    }
    setStatusCurrent("idle", "Idle", "No ingest or sync job is running.", null, { showStop: false });
  } catch (_) {
    setStopSyncVisible(false, false);
    setStatusCurrent("err", "Status offline", "Could not reach /api/status", null, { showStop: false });
  }
}

async function postAction(url, jsonBody) {
  const opts = { method: "POST", headers: {} };
  if (jsonBody) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(jsonBody);
  }
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

document.querySelectorAll("[data-action]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const url = btn.getAttribute("data-action");
    let body = null;
    const raw = btn.getAttribute("data-json");
    if (raw) body = JSON.parse(raw);
    setStatusCurrent("busy", "Starting job…", url, null, { showStop: false });
    const { ok, status, data } = await postAction(url, body);
    if (status === 409) {
      setStatusCurrent("busy", `Busy: ${data.running || "another job"}`, "Wait for the current job to finish.", null, {
        showStop: true,
      });
      return;
    }
    if (!ok) {
      setStatusCurrent("err", "Failed to start", shortJson(data), null, { showStop: false });
      return;
    }
    refreshStatus();
  });
});

const stopJobBtn = document.getElementById("stop-job-btn");
if (stopJobBtn) {
  stopJobBtn.addEventListener("click", () => stopRunningJob());
}

const jobsBody = document.getElementById("jobs-body");

const clearJobsBtn = document.getElementById("clear-jobs-btn");
if (clearJobsBtn) {
  clearJobsBtn.addEventListener("click", async () => {
    clearJobsBtn.disabled = true;
    clearJobsBtn.textContent = "Clearing…";
    await fetch("/api/jobs", { method: "DELETE" });
    clearJobsBtn.disabled = false;
    clearJobsBtn.textContent = "Clear";
    refreshStatus();
  });
}

refreshStatus();
setInterval(refreshStatus, 2500);
wireFeedToggles();

const purgeDbBtn = document.getElementById("purge-db-btn");
if (purgeDbBtn) {
  purgeDbBtn.addEventListener("click", async () => {
    if (
      !confirm(
        "Purge all ingested data from the live database?\n\nThis deletes CVE, Exploit-DB, NVD, MSRC, and other feed rows. Settings and download caches are kept. A pre-purge backup is attempted first."
      )
    ) {
      return;
    }
    const typed = window.prompt('Type PURGE to confirm permanently clearing ingested data:', "");
    if ((typed || "").trim().toUpperCase() !== "PURGE") {
      setStatusCurrent("idle", "Purge cancelled", "Confirmation token not entered.", null, { showStop: false });
      return;
    }
    purgeDbBtn.disabled = true;
    purgeDbBtn.textContent = "Purging…";
    setStatusCurrent("busy", "Purging database…", "Clearing ingested tables", null, { showStop: false });
    const { ok, status, data } = await postAction("/api/purge", { confirm: "PURGE" });
    purgeDbBtn.disabled = false;
    purgeDbBtn.textContent = "Purge DB…";
    if (status === 409) {
      setStatusCurrent("busy", `Busy: ${data.running || "another job"}`, "Stop the running job before purging.", null, {
        showStop: true,
      });
      return;
    }
    if (!ok) {
      setStatusCurrent("err", "Purge failed", data.error || shortJson(data), null, { showStop: false });
      return;
    }
    setStatusCurrent(
      "ok",
      "Database purged",
      `Removed ${Number(data.rows_deleted || 0).toLocaleString()} rows · run Sync DB to reload`,
      null,
      { showStop: false }
    );
    refreshStatus();
    if (typeof refreshBackups === "function") refreshBackups();
  });
}

function fmtBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function setBackupMsg(text, kind) {
  const el = document.getElementById("backup-msg");
  if (!el) return;
  if (!text) {
    el.hidden = true;
    el.textContent = "";
    el.className = "backup-msg";
    return;
  }
  el.hidden = false;
  el.textContent = text;
  el.className = `backup-msg ${kind || ""}`.trim();
}

function renderBackups(rows) {
  const body = document.getElementById("backup-body");
  if (!body) return;
  if (!rows || !rows.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty-row">No backups yet.</td></tr>`;
    return;
  }
  body.innerHTML = rows
    .map((b) => {
      const name = escapeHtml(b.name || "");
      const enc = encodeURIComponent(b.name || "");
      const tag = b.includes_settings ? " · settings" : "";
      return `<tr data-backup="${name}">
        <td class="msg">${name}${tag ? `<span class="backup-tag">${tag}</span>` : ""}</td>
        <td>${escapeHtml(fmtBytes(b.size))}</td>
        <td>${fmtTime(b.created_at)}</td>
        <td class="backup-row-actions">
          <a class="backup-link" href="/api/backup/${enc}">Download</a>
          <button type="button" class="backup-mini" data-restore="${name}">Restore</button>
          <button type="button" class="backup-mini danger" data-delete="${name}">Delete</button>
        </td>
      </tr>`;
    })
    .join("");
}

async function refreshBackups() {
  try {
    const res = await fetch("/api/backup");
    const data = await res.json();
    renderBackups(data.backups || []);
  } catch (_) {
    const body = document.getElementById("backup-body");
    if (body) body.innerHTML = `<tr><td colspan="4" class="empty-row">Could not load backups.</td></tr>`;
  }
}

const backupCreateBtn = document.getElementById("backup-create-btn");
if (backupCreateBtn) {
  backupCreateBtn.addEventListener("click", async () => {
    backupCreateBtn.disabled = true;
    backupCreateBtn.textContent = "Creating…";
    setBackupMsg("Creating backup…", "");
    const { ok, status, data } = await postAction("/api/backup", { include_settings: true });
    backupCreateBtn.disabled = false;
    backupCreateBtn.textContent = "Create backup";
    if (status === 409) {
      setBackupMsg(`Busy: wait for ${data.running || "the current job"} to finish.`, "err");
      return;
    }
    if (!ok) {
      setBackupMsg(data.error || shortJson(data) || "Backup failed", "err");
      return;
    }
    setBackupMsg(`Saved ${data.name} (${fmtBytes(data.size)})`, "ok");
    refreshBackups();
    refreshStatus();
  });
}

const backupBody = document.getElementById("backup-body");
if (backupBody) {
  backupBody.addEventListener("click", async (ev) => {
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    const restoreName = t.getAttribute("data-restore");
    const deleteName = t.getAttribute("data-delete");
    if (restoreName) {
      if (
        !confirm(
          `Restore database from:\n${restoreName}\n\nThis replaces the live DB. A pre-restore snapshot will be created first.`
        )
      ) {
        return;
      }
      t.disabled = true;
      setBackupMsg(`Restoring ${restoreName}…`, "");
      const { ok, status, data } = await postAction("/api/backup/restore", {
        name: restoreName,
        restore_settings: true,
      });
      t.disabled = false;
      if (status === 409) {
        setBackupMsg(`Busy: wait for ${data.running || "the current job"} to finish.`, "err");
        return;
      }
      if (!ok) {
        setBackupMsg(data.error || shortJson(data) || "Restore failed", "err");
        return;
      }
      setBackupMsg(
        `Restored from ${data.restored_from}${data.settings_restored ? " (settings included)" : ""}`,
        "ok"
      );
      refreshBackups();
      refreshStatus();
      return;
    }
    if (deleteName) {
      if (!confirm(`Delete backup ${deleteName}?`)) return;
      t.disabled = true;
      const res = await fetch(`/api/backup/${encodeURIComponent(deleteName)}`, { method: "DELETE" });
      const data = await res.json().catch(() => ({}));
      t.disabled = false;
      if (!res.ok) {
        setBackupMsg(data.error || "Delete failed", "err");
        return;
      }
      setBackupMsg(`Deleted ${deleteName}`, "ok");
      refreshBackups();
    }
  });
}

const backupUploadInput = document.getElementById("backup-upload-input");
if (backupUploadInput) {
  backupUploadInput.addEventListener("change", async () => {
    const file = backupUploadInput.files && backupUploadInput.files[0];
    backupUploadInput.value = "";
    if (!file) return;
    if (
      !confirm(
        `Restore database from uploaded file:\n${file.name}\n\nThis replaces the live DB.`
      )
    ) {
      return;
    }
    setBackupMsg(`Uploading and restoring ${file.name}…`, "");
    const fd = new FormData();
    fd.append("file", file);
    fd.append("restore_settings", "1");
    try {
      const res = await fetch("/api/backup/upload", { method: "POST", body: fd });
      const data = await res.json().catch(() => ({}));
      if (res.status === 409) {
        setBackupMsg(`Busy: wait for ${data.running || "the current job"} to finish.`, "err");
        return;
      }
      if (!res.ok) {
        setBackupMsg(data.error || "Upload restore failed", "err");
        return;
      }
      setBackupMsg(
        `Restored from ${data.restored_from || file.name}${data.saved_as ? ` (kept as ${data.saved_as})` : ""}`,
        "ok"
      );
      refreshBackups();
      refreshStatus();
    } catch (_) {
      setBackupMsg("Upload restore failed", "err");
    }
  });
}

refreshBackups();
setInterval(refreshBackups, 15000);

const scheduleSaveBtn = document.getElementById("schedule-save-btn");
if (scheduleSaveBtn) {
  scheduleSaveBtn.addEventListener("click", async () => {
    const enabled = !!(document.getElementById("schedule-enabled") || {}).checked;
    const startInput = document.getElementById("schedule-start");
    const freqInput = document.getElementById("schedule-frequency");
    const msg = document.getElementById("schedule-msg");
    const startAt = startInput ? startInput.value : "";
    const frequency = freqInput ? freqInput.value : "daily";
    if (enabled && !startAt) {
      if (msg) {
        msg.hidden = false;
        msg.textContent = "Pick a start date and time first.";
        msg.className = "hint is-err";
      }
      return;
    }
    scheduleSaveBtn.disabled = true;
    scheduleSaveBtn.textContent = "Saving…";
    const { ok, data } = await postAction("/api/schedule", {
      enabled,
      frequency,
      start_at: startAt,
      reset_last: false,
    });
    scheduleSaveBtn.disabled = false;
    scheduleSaveBtn.textContent = "Save schedule";
    if (!ok) {
      if (msg) {
        msg.hidden = false;
        msg.textContent = data.error || shortJson(data) || "Could not save schedule";
        msg.className = "hint is-err";
      }
      return;
    }
    const sch = data.schedule || {};
    if (startInput && sch.start_at) startInput.value = toDatetimeLocalValue(sch.start_at);
    if (freqInput && sch.frequency) freqInput.value = sch.frequency;
    const en = document.getElementById("schedule-enabled");
    if (en) en.checked = !!sch.enabled;
    updateScheduleDisplay(sch);
    if (msg) {
      msg.hidden = false;
      msg.textContent = sch.enabled
        ? `Saved — next run ${fmtTime(sch.next_run_at)}`
        : "Schedule disabled";
      msg.className = "hint is-ok";
    }
  });
}
