const I18N = {
  en: {
    loginTitle: "Admin panel",
    loginSub: "Sign in to manage relay domains and traffic.",
    password: "Password",
    signIn: "Sign in",
    panelLabel: "Control",
    tabDashboard: "Dashboard",
    tabTraffic: "Traffic by IP",
    tabDomains: "Domains",
    tabQueries: "Query log",
    tabHosts: "Hosts",
    tabSettings: "Settings",
    logout: "Logout",
    queriesTitle: "DNS query log",
    topDomains: "Top domains",
    autoRefresh: "Auto",
    clearLog: "Clear",
    qFilterDomain: "domain…",
    qFilterClient: "client IP…",
    colTime: "Time",
    colType: "Type",
    colDomain: "Domain",
    colAction: "Status",
    colAnswer: "Answer",
    colCount: "Count",
    queriesDisabled: "Set DNSMASQ_QUERY_LOG and enable dnsmasq log-queries (see README).",
    queriesEnabled: "Tailing",
    confirmClearLog: "Clear all DNS query log rows?",
    kpiActive: "Active",
    kpiSessions: "Sessions",
    kpiBytes: "Bytes",
    kpiErrors: "Errors",
    kpiUpstream: "Upstream",
    dailyTraffic: "Daily traffic",
    trafficTitle: "Traffic by client IP",
    refresh: "Refresh",
    colIp: "IP",
    colUp: "Upload",
    colDown: "Download",
    colTotal: "Total",
    colSessions: "Sessions",
    colLast: "Last seen",
    domainsTitle: "DNS domains",
    addDomain: "Add",
    import: "Import",
    exportDnsmasq: "Export",
    applyDnsmasq: "Save & reload",
    importPlaceholder: "One domain per line, or paste address=/ / server=/ lines",
    hostsTitle: "SNIrelay hosts allowlist",
    hostsHint: "Catch-all .* allows every SNI/Host. Changes hot-reload.",
    saveHosts: "Save hosts",
    settingsTitle: "Settings",
    changePassword: "Change password",
    currentPassword: "Current password",
    newPassword: "New password",
  },
  fa: {
    loginTitle: "پنل مدیریت",
    loginSub: "برای مدیریت دامنه‌ها و ترافیک وارد شوید.",
    password: "رمز عبور",
    signIn: "ورود",
    panelLabel: "کنترل",
    tabDashboard: "داشبورد",
    tabTraffic: "ترافیک IP",
    tabDomains: "دامنه‌ها",
    tabQueries: "لاگ DNS",
    tabHosts: "Hosts",
    tabSettings: "تنظیمات",
    logout: "خروج",
    queriesTitle: "لاگ کوئری DNS",
    topDomains: "دامنه‌های پرتکرار",
    autoRefresh: "خودکار",
    clearLog: "پاک‌کردن",
    qFilterDomain: "دامنه…",
    qFilterClient: "آی‌پی کلاینت…",
    colTime: "زمان",
    colType: "نوع",
    colDomain: "دامنه",
    colAction: "وضعیت",
    colAnswer: "پاسخ",
    colCount: "تعداد",
    queriesDisabled: "DNSMASQ_QUERY_LOG را تنظیم کنید و log-queries را در dnsmasq فعال کنید (README).",
    queriesEnabled: "در حال خواندن",
    confirmClearLog: "همه ردیف‌های لاگ DNS پاک شوند؟",
    kpiActive: "فعال",
    kpiSessions: "سشن‌ها",
    kpiBytes: "بایت",
    kpiErrors: "خطا",
    kpiUpstream: "آپ‌استریم",
    dailyTraffic: "ترافیک روزانه",
    trafficTitle: "ترافیک به‌تفکیک IP",
    refresh: "بروزرسانی",
    colIp: "آی‌پی",
    colUp: "آپلود",
    colDown: "دانلود",
    colTotal: "مجموع",
    colSessions: "سشن",
    colLast: "آخرین بازدید",
    domainsTitle: "دامنه‌های DNS",
    addDomain: "افزودن",
    import: "ورود انبوه",
    exportDnsmasq: "خروجی",
    applyDnsmasq: "ذخیره و reload",
    importPlaceholder: "هر خط یک دامنه، یا خطوط address=/ و server=/",
    hostsTitle: "لیست hosts اس‌ان‌آی‌رله",
    hostsHint: "الگوی .* همه دامنه‌ها را مجاز می‌کند. تغییرات بلافاصله اعمال می‌شود.",
    saveHosts: "ذخیره hosts",
    settingsTitle: "تنظیمات",
    changePassword: "تغییر رمز",
    currentPassword: "رمز فعلی",
    newPassword: "رمز جدید",
  },
};

let lang = localStorage.getItem("snirelay_lang") || "en";

function t(key) {
  return (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key;
}

function applyI18n() {
  document.documentElement.lang = lang === "fa" ? "fa" : "en";
  document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
  document.body.classList.toggle("rtl", lang === "fa");
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"));
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.getAttribute("data-i18n-placeholder"));
  });
  const toggle = document.getElementById("lang-toggle");
  if (toggle) toggle.textContent = lang === "fa" ? "EN" : "FA";
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || res.statusText);
    err.status = res.status;
    throw err;
  }
  return data;
}

function fmtBytes(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(n) || 0;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function show(view) {
  document.getElementById("login-view").classList.toggle("hidden", view !== "login");
  document.getElementById("app-view").classList.toggle("hidden", view !== "app");
}

async function checkAuth() {
  try {
    await api("/api/auth/me");
    show("app");
    await refreshAll();
  } catch {
    show("login");
  }
}

async function refreshStats() {
  const s = await api("/api/stats");
  document.getElementById("kpi-active").textContent = s.active_connections;
  document.getElementById("kpi-sessions").textContent = s.total_connections;
  document.getElementById("kpi-bytes").textContent = fmtBytes(s.bytes_proxied);
  document.getElementById("kpi-errors").textContent = s.connection_errors;
  const up = document.getElementById("kpi-upstream");
  up.textContent = s.upstream_ok ? "OK" : "DOWN";
  up.style.color = s.upstream_ok ? "var(--ok)" : "var(--bad)";
}

async function refreshDaily() {
  const range = document.getElementById("dash-range").value;
  const data = await api(`/api/traffic/daily?range=${range}`);
  const max = Math.max(1, ...data.items.map((x) => x.bytes_up + x.bytes_down));
  const root = document.getElementById("daily-chart");
  root.innerHTML = "";
  data.items.forEach((row) => {
    const total = row.bytes_up + row.bytes_down;
    const el = document.createElement("div");
    el.className = "bar";
    el.style.height = `${Math.max(4, (total / max) * 140)}px`;
    el.title = `${row.day}: ${fmtBytes(total)}`;
    const label = document.createElement("span");
    label.textContent = row.day.slice(5);
    el.appendChild(label);
    root.appendChild(el);
  });
}

async function refreshTraffic() {
  const range = document.getElementById("traffic-range").value;
  const data = await api(`/api/traffic/ips?range=${range}&limit=200`);
  const body = document.getElementById("traffic-body");
  body.innerHTML = "";
  data.items.forEach((row) => {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.innerHTML = `
      <td>${row.client_ip}</td>
      <td>${fmtBytes(row.bytes_up)}</td>
      <td>${fmtBytes(row.bytes_down)}</td>
      <td>${fmtBytes(row.bytes_up + row.bytes_down)}</td>
      <td>${row.sessions}</td>
      <td>${row.last_seen.replace("T", " ").slice(0, 19)}</td>`;
    tr.onclick = () => showIpDetail(row.client_ip, range);
    body.appendChild(tr);
  });
}

async function showIpDetail(ip, range) {
  const data = await api(`/api/traffic/ips/${encodeURIComponent(ip)}?range=${range}`);
  const box = document.getElementById("ip-detail");
  box.classList.remove("hidden");
  const lines = data.domains
    .map((d) => `<tr><td>${d.domain}</td><td>${fmtBytes(d.bytes_up)}</td><td>${fmtBytes(d.bytes_down)}</td><td>${d.sessions}</td></tr>`)
    .join("");
  box.innerHTML = `<h3>${ip}</h3>
    <table><thead><tr><th>Domain</th><th>Up</th><th>Down</th><th>Sessions</th></tr></thead>
    <tbody>${lines || "<tr><td colspan=4>—</td></tr>"}</tbody></table>`;
}

let domainsCache = [];

async function refreshDomains() {
  const data = await api("/api/domains");
  domainsCache = data.items || [];
  const meta = document.getElementById("domains-meta");
  const src = document.getElementById("domains-source");
  meta.textContent = `${domainsCache.length} domains`;
  if (data.source === "dnsmasq") {
    src.textContent = `Live dnsmasq · ${data.conf_dir} · relay=${data.relay_file} · bypass=${data.bypass_file} · IP=${data.relay_ip}`;
  } else {
    src.textContent = "SQLite store (set DNSMASQ_CONF_DIR to use live files)";
  }
  renderDomainsTable();
}

function renderDomainsTable() {
  const q = (document.getElementById("dom-search").value || "").toLowerCase();
  const filter = document.getElementById("dom-filter").value;
  const body = document.getElementById("domains-body");
  body.innerHTML = "";
  domainsCache
    .filter((d) => {
      const mode = d.mode === "direct" ? "bypass" : d.mode;
      if (filter !== "all" && mode !== filter) return false;
      if (q && !d.pattern.includes(q) && !(d.source || "").includes(q)) return false;
      return true;
    })
    .forEach((d) => {
      const mode = d.mode === "direct" ? "bypass" : d.mode;
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${d.pattern}</td>
        <td><select data-pat="${d.pattern}" data-old="${mode}" class="mode-sel">
          <option value="relay" ${mode === "relay" ? "selected" : ""}>relay</option>
          <option value="bypass" ${mode === "bypass" ? "selected" : ""}>bypass</option>
        </select></td>
        <td class="muted">${d.source || "—"}</td>
        <td><button class="ghost" type="button">✕</button></td>`;
      tr.querySelector("button").onclick = async () => {
        await api(`/api/domains/${encodeURIComponent(d.pattern)}?mode=${mode}`, { method: "DELETE" });
        refreshDomains();
      };
      tr.querySelector(".mode-sel").onchange = async (ev) => {
        const newMode = ev.target.value;
        await api(`/api/domains/${encodeURIComponent(d.pattern)}`, {
          method: "PUT",
          body: JSON.stringify({ pattern: d.pattern, mode: newMode }),
        });
        refreshDomains();
      };
      body.appendChild(tr);
    });
}

document.getElementById("dom-search").oninput = renderDomainsTable;
document.getElementById("dom-filter").onchange = renderDomainsTable;
document.getElementById("reload-domains").onclick = refreshDomains;

async function refreshHosts() {
  const data = await api("/api/hosts");
  document.getElementById("hosts-json").value = JSON.stringify(data.hosts, null, 2);
}

function actionBadge(action) {
  const a = (action || "query").toLowerCase();
  return `<span class="badge badge-${a}">${a}</span>`;
}

async function refreshQueries() {
  const domain = document.getElementById("q-domain").value.trim();
  const client = document.getElementById("q-client").value.trim();
  const action = document.getElementById("q-action").value;
  const params = new URLSearchParams({ limit: "300" });
  if (domain) params.set("domain", domain);
  if (client) params.set("client", client);
  if (action) params.set("action", action);
  const data = await api(`/api/dns/queries?${params}`);
  const hint = document.getElementById("queries-hint");
  const meta = document.getElementById("queries-meta");
  if (data.enabled) {
    hint.textContent = `${t("queriesEnabled")}: ${data.log_path || ""} · retain ${data.retain_hours || "?"}h`;
  } else {
    hint.textContent = t("queriesDisabled");
  }
  meta.textContent = `${data.total || 0} rows`;
  const body = document.getElementById("queries-body");
  body.innerHTML = "";
  (data.items || []).forEach((row) => {
    const tr = document.createElement("tr");
    const ts = (row.ts || "").replace("T", " ").slice(0, 19);
    tr.innerHTML = `
      <td class="muted">${ts}</td>
      <td>${row.client_ip || "—"}</td>
      <td>${row.qtype || ""}</td>
      <td>${row.domain || ""}</td>
      <td>${actionBadge(row.action)}</td>
      <td class="muted">${row.answer || ""}</td>`;
    body.appendChild(tr);
  });
  const top = await api("/api/dns/queries/top?limit=30");
  const topBody = document.getElementById("queries-top-body");
  topBody.innerHTML = "";
  (top.items || []).forEach((row) => {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.innerHTML = `<td>${row.domain}</td><td>${row.count}</td>`;
    tr.onclick = () => {
      document.getElementById("q-domain").value = row.domain;
      refreshQueries();
    };
    topBody.appendChild(tr);
  });
}

async function refreshSettings() {
  const data = await api("/api/config/summary");
  document.getElementById("config-summary").textContent = JSON.stringify(data, null, 2);
}

async function refreshAll() {
  await Promise.all([
    refreshStats(),
    refreshDaily(),
    refreshTraffic(),
    refreshDomains(),
    refreshQueries(),
    refreshHosts(),
    refreshSettings(),
  ]);
}

document.getElementById("lang-toggle").onclick = () => {
  lang = lang === "fa" ? "en" : "fa";
  localStorage.setItem("snirelay_lang", lang);
  applyI18n();
};

document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.onclick = () => {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  };
});

document.getElementById("login-form").onsubmit = async (e) => {
  e.preventDefault();
  const password = document.getElementById("password").value;
  const err = document.getElementById("login-error");
  err.textContent = "";
  try {
    await api("/api/auth/login", { method: "POST", body: JSON.stringify({ password }) });
    show("app");
    await refreshAll();
  } catch (ex) {
    err.textContent = ex.message;
  }
};

document.getElementById("logout-btn").onclick = async () => {
  await api("/api/auth/logout", { method: "POST", body: "{}" });
  show("login");
};

document.getElementById("dash-range").onchange = refreshDaily;
document.getElementById("traffic-range").onchange = refreshTraffic;
document.getElementById("refresh-traffic").onclick = refreshTraffic;

document.getElementById("refresh-queries").onclick = refreshQueries;
document.getElementById("q-domain").oninput = () => {
  clearTimeout(window._qFilterTimer);
  window._qFilterTimer = setTimeout(refreshQueries, 300);
};
document.getElementById("q-client").oninput = () => {
  clearTimeout(window._qFilterTimer);
  window._qFilterTimer = setTimeout(refreshQueries, 300);
};
document.getElementById("q-action").onchange = refreshQueries;
document.getElementById("clear-queries").onclick = async () => {
  if (!confirm(t("confirmClearLog"))) return;
  await api("/api/dns/queries", { method: "DELETE" });
  refreshQueries();
};

document.getElementById("domain-form").onsubmit = async (e) => {
  e.preventDefault();
  const msg = document.getElementById("domains-msg");
  try {
    await api("/api/domains", {
      method: "POST",
      body: JSON.stringify({
        pattern: document.getElementById("dom-pattern").value,
        mode: document.getElementById("dom-mode").value,
      }),
    });
    document.getElementById("dom-pattern").value = "";
    msg.textContent = "Saved & reloaded";
    refreshDomains();
  } catch (ex) {
    msg.textContent = ex.message;
  }
};

document.getElementById("import-btn").onclick = async () => {
  const msg = document.getElementById("domains-msg");
  try {
    const res = await api("/api/domains/import", {
      method: "POST",
      body: JSON.stringify({
        text: document.getElementById("import-text").value,
        mode: document.getElementById("import-mode").value,
      }),
    });
    document.getElementById("import-text").value = "";
    msg.textContent = `Imported ${res.imported || "OK"}`;
    refreshDomains();
  } catch (ex) {
    msg.textContent = ex.message;
  }
};

document.getElementById("export-dnsmasq").onclick = async () => {
  const data = await api("/api/dnsmasq/export");
  const out = document.getElementById("dnsmasq-out");
  out.classList.remove("hidden");
  out.textContent = data.content;
};

document.getElementById("apply-dnsmasq").onclick = async () => {
  const msg = document.getElementById("domains-msg");
  try {
    const data = await api("/api/dnsmasq/apply", { method: "POST", body: "{}" });
    msg.textContent = `Normalized → ${data.relay_file || ""} / ${data.bypass_file || ""} · reload=${data.reload_ok}`;
    refreshDomains();
  } catch (ex) {
    msg.textContent = ex.message;
  }
};

document.getElementById("save-hosts").onclick = async () => {
  const msg = document.getElementById("hosts-msg");
  try {
    const hosts = JSON.parse(document.getElementById("hosts-json").value);
    const res = await api("/api/hosts", { method: "PUT", body: JSON.stringify({ hosts }) });
    msg.textContent = res.persist;
  } catch (ex) {
    msg.textContent = ex.message;
  }
};

document.getElementById("password-form").onsubmit = async (e) => {
  e.preventDefault();
  const msg = document.getElementById("pw-msg");
  try {
    await api("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({
        current: document.getElementById("pw-current").value,
        new_password: document.getElementById("pw-new").value,
      }),
    });
    msg.textContent = "OK";
    e.target.reset();
  } catch (ex) {
    msg.textContent = ex.message;
  }
};

applyI18n();
checkAuth();
setInterval(() => {
  if (!document.getElementById("app-view").classList.contains("hidden")) {
    refreshStats().catch(() => {});
  }
}, 5000);
setInterval(() => {
  if (document.getElementById("app-view").classList.contains("hidden")) return;
  if (!document.getElementById("tab-queries").classList.contains("active")) return;
  if (!document.getElementById("q-autorefresh").checked) return;
  refreshQueries().catch(() => {});
}, 3000);
