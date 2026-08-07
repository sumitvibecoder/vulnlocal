async function saveSettings(ev) {
  ev.preventDefault();
  const status = document.getElementById("settings-status");
  const btn = document.getElementById("settings-save-btn");
  const urls = {};
  document.querySelectorAll("[data-url]").forEach((el) => {
    urls[el.getAttribute("data-url")] = el.value.trim();
  });
  const body = {
    proxy: {
      enabled: !!document.getElementById("proxy-enabled").checked,
      type: document.getElementById("proxy-type").value.trim(),
      host: document.getElementById("proxy-host").value.trim(),
      port: document.getElementById("proxy-port").value.trim(),
      url: document.getElementById("proxy-url").value.trim(),
      username: document.getElementById("proxy-username").value.trim(),
      password: document.getElementById("proxy-password").value,
    },
    urls,
  };
  const setStatus = (text, cls) => {
    if (!status) return;
    status.textContent = text;
    status.classList.remove("is-ok", "is-err", "is-busy");
    if (cls) status.classList.add(cls);
  };
  setStatus("Saving changes…", "is-busy");
  if (btn) btn.disabled = true;
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setStatus(data.error || "Save failed", "is-err");
      return;
    }
    setStatus("Saved. New proxy and sync URLs apply on the next download/sync.", "is-ok");
  } catch (_) {
    setStatus("Network error — could not reach the local API.", "is-err");
  } finally {
    if (btn) btn.disabled = false;
  }
}

const form = document.getElementById("settings-form");
if (form) form.addEventListener("submit", saveSettings);
