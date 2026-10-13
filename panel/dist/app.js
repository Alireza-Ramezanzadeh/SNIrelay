const I18N = {
  en: {
    loginTitle: "Admin panel",
    loginSub: "Sign in to manage relay domains and traffic.",
    password: "Password",
    signIn: "Sign in",
    panelLabel: "Control",
    navGroupOverview: "Overview",
    navGroupDns: "DNS",
    navGroupRouting: "Routing",
    navGroupSystem: "System",
    tabDashboard: "Dashboard",
    dashSub: "Live proxy health and daily volume.",
    trafficSub: "Bytes and sessions per client, with upstream assignment.",
    settingsSub: "Runtime config summary and admin password.",
    configSummary: "Config summary",
    tabTraffic: "Traffic by IP",
    tabDomains: "Domains",
    tabQueries: "Query log",
    tabUpstreams: "Upstreams",
    tabWhitelist: "Whitelist",
    tabHosts: "Hosts",
    tabSettings: "Settings",
    whitelistTitle: "Client IP whitelist",
    whitelistHint: "Empty = all clients allowed. Non-empty = only listed IPs may use the proxy (panel is never blocked).",
    whitelistUfw: "Sync UFW",
    whitelistAdd: "Add & save",
    colUsername: "Username",
    usernameRequired: "Username is required",
    whitelistEmpty: "No IPs — ACL is open (everyone allowed).",
    whitelistModeOpen: "Mode: open (ACL off)",
    whitelistModeStrict: "Mode: enforce whitelist",
    whitelistUfwOk: "ufw available",
    whitelistUfwMissing: "ufw not available in container",
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
    colUpstream: "Upstream",
    colName: "Name",
    colEndpoint: "Endpoint",
    queriesDisabled: "Set DNSMASQ_QUERY_LOG and enable dnsmasq log-queries (see README).",
    queriesEnabled: "Tailing",
    confirmClearLog: "Clear all DNS query log rows?",
    upstreamsTitle: "Upstream profiles",
    upstreamsHint: "Named SOCKS/HTTP profiles. Edits save to config.yaml and hot-reload.",
    defaultUpstream: "Default",
    upstreamFailover: "Failover",
    saveUpstreams: "Save",
    addUpstream: "Add / update",
    clientUpstreamsTitle: "Client → upstream",
    clientUpstreamsHint: "Exact client IP uses this profile; others use Default. Changes save immediately.",
    clientUpstreamsEmpty: "No per-IP routes yet. Unmapped clients use the default profile.",
    addMapping: "Add & save",
    confirmDeleteUpstream: "Delete this upstream profile?",
    invalidClientIp: "Enter a valid IPv4/IPv6 address",
    colHost: "Host",
    colPort: "Port",
    pickProfile: "Select a profile",
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
    searchPlaceholder: "Search…",
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
    navGroupOverview: "نمای کلی",
    navGroupDns: "DNS",
    navGroupRouting: "مسیریابی",
    navGroupSystem: "سیستم",
    tabDashboard: "داشبورد",
    dashSub: "وضعیت پروکسی و حجم روزانه.",
    trafficSub: "بایت و سشن به‌ازای هر کلاینت، با آپ‌استریم.",
    settingsSub: "خلاصه کانفیگ و رمز ادمین.",
    configSummary: "خلاصه کانفیگ",
    tabTraffic: "ترافیک IP",
    tabDomains: "دامنه‌ها",
    tabQueries: "لاگ DNS",
    tabUpstreams: "آپ‌استریم",
    tabWhitelist: "Whitelist",
    tabHosts: "Hosts",
    tabSettings: "تنظیمات",
    whitelistTitle: "لیست سفید IP کلاینت",
    whitelistHint: "خالی = همه مجاز. اگر پر باشد فقط این IPها به پروکسی وصل می‌شوند (پنل فیلتر نمی‌شود).",
    whitelistUfw: "همگام‌سازی UFW",
    whitelistAdd: "افزودن و ذخیره",
    colUsername: "نام کاربری",
    usernameRequired: "نام کاربری لازم است",
    whitelistEmpty: "IPای نیست — ACL باز است (همه مجاز).",
    whitelistModeOpen: "حالت: باز (ACL خاموش)",
    whitelistModeStrict: "حالت: اعمال whitelist",
    whitelistUfwOk: "ufw در دسترس است",
    whitelistUfwMissing: "ufw در کانتینر در دسترس نیست",
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
    colUpstream: "آپ‌استریم",
    colName: "نام",
    colEndpoint: "آدرس",
    queriesDisabled: "DNSMASQ_QUERY_LOG را تنظیم کنید و log-queries را در dnsmasq فعال کنید (README).",
    queriesEnabled: "در حال خواندن",
    confirmClearLog: "همه ردیف‌های لاگ DNS پاک شوند؟",
    upstreamsTitle: "پروفایل‌های آپ‌استریم",
    upstreamsHint: "پروفایل‌های SOCKS/HTTP. تغییرات در config.yaml ذخیره و بلافاصله اعمال می‌شوند.",
    defaultUpstream: "پیش‌فرض",
    upstreamFailover: "Failover",
    saveUpstreams: "ذخیره",
    addUpstream: "افزودن / به‌روزرسانی",
    clientUpstreamsTitle: "کلاینت → آپ‌استریم",
    clientUpstreamsHint: "IP دقیق کلاینت این پروفایل را می‌گیرد؛ بقیه از پیش‌فرض. تغییرات فوری ذخیره می‌شوند.",
    clientUpstreamsEmpty: "هنوز مسیر per-IP نیست. کلاینت‌های بدون مپ از پروفایل پیش‌فرض استفاده می‌کنند.",
    addMapping: "افزودن و ذخیره",
    confirmDeleteUpstream: "این پروفایل آپ‌استریم حذف شود؟",
    invalidClientIp: "یک آدرس IPv4/IPv6 معتبر وارد کنید",
    colHost: "هاست",
    colPort: "پورت",
    pickProfile: "یک پروفایل انتخاب کنید",
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
    searchPlaceholder: "جستجو…",
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
  const label = lang === "fa" ? "EN" : "FA";
  document.querySelectorAll("#lang-toggle, #lang-toggle-mobile").forEach((el) => {
    el.textContent = label;
  });
  syncPageTitle();
}

function syncPageTitle() {
  const active = document.querySelector(".tab.active");
  const key = active && active.dataset.titleKey;
  const title = document.getElementById("page-title");
  if (title && key) title.textContent = t(key);
}

function setNavOpen(open) {
  document.body.classList.toggle("nav-open", !!open);
  const backdrop = document.getElementById("nav-backdrop");
  if (backdrop) backdrop.hidden = !open;
}

function switchTab(tabName) {
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab").forEach((sec) => {
    sec.classList.toggle("active", sec.id === `tab-${tabName}`);
  });
  syncPageTitle();
  setNavOpen(false);
  window.scrollTo({ top: 0, behavior: "smooth" });
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

let upstreamsCache = {
  upstreams: {},
  default_upstream: "default",
  client_upstreams: {},
  upstream_failover: false,
};

function profileForIp(ip) {
  const map = upstreamsCache.client_upstreams || {};
  if (map[ip]) return map[ip];
  return upstreamsCache.default_upstream || "default";
}

async function refreshTraffic() {
  const range = document.getElementById("traffic-range").value;
  const data = await api(`/api/traffic/ips?range=${range}&limit=200`);
  const body = document.getElementById("traffic-body");
  body.innerHTML = "";
  data.items.forEach((row) => {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    const profile = profileForIp(row.client_ip);
    tr.innerHTML = `
      <td class="primary-cell" data-label="${t("colIp")}"><code>${row.client_ip}</code></td>
      <td data-label="${t("colUpstream")}"><span class="badge badge-cached">${profile}</span></td>
      <td data-label="${t("colUp")}">${fmtBytes(row.bytes_up)}</td>
      <td data-label="${t("colDown")}">${fmtBytes(row.bytes_down)}</td>
      <td data-label="${t("colTotal")}"><strong>${fmtBytes(row.bytes_up + row.bytes_down)}</strong></td>
      <td data-label="${t("colSessions")}">${row.sessions}</td>
      <td data-label="${t("colLast")}">${row.last_seen.replace("T", " ").slice(0, 19)}</td>`;
    tr.onclick = () => showIpDetail(row.client_ip, range);
    body.appendChild(tr);
  });
}

async function showIpDetail(ip, range) {
  const data = await api(`/api/traffic/ips/${encodeURIComponent(ip)}?range=${range}`);
  const box = document.getElementById("ip-detail");
  box.classList.remove("hidden");
  const domainRows = data.domains
    .map(
      (d) => `<tr>
      <td class="primary-cell" data-label="${t("colDomain")}">${d.domain}</td>
      <td data-label="${t("colUp")}">${fmtBytes(d.bytes_up)}</td>
      <td data-label="${t("colDown")}">${fmtBytes(d.bytes_down)}</td>
      <td data-label="${t("colSessions")}">${d.sessions}</td>
    </tr>`
    )
    .join("");
  box.innerHTML = `<h3>${ip}</h3>
    <div class="table-wrap"><table class="data-table cards-ok">
      <thead><tr><th>${t("colDomain")}</th><th>${t("colUp")}</th><th>${t("colDown")}</th><th>${t("colSessions")}</th></tr></thead>
      <tbody>${domainRows || `<tr><td colspan="4">—</td></tr>`}</tbody>
    </table></div>`;
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
    src.textContent =
      data.dnsmasq_hint ||
      "SQLite store — mount /etc/dnsmasq.d and set panel.dnsmasq_conf_dir or DNSMASQ_CONF_DIR";
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
      tr.innerHTML = `<td class="primary-cell" data-label="Pattern"><code>${d.pattern}</code></td>
        <td data-label="Mode"><select data-pat="${d.pattern}" data-old="${mode}" class="mode-sel">
          <option value="relay" ${mode === "relay" ? "selected" : ""}>relay</option>
          <option value="bypass" ${mode === "bypass" ? "selected" : ""}>bypass</option>
        </select></td>
        <td class="muted" data-label="Source">${d.source || "—"}</td>
        <td class="row-actions"><button class="ghost" type="button" aria-label="delete">✕</button></td>`;
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

function profileNames() {
  return Object.keys(upstreamsCache.upstreams || {}).sort();
}

function isValidIp(ip) {
  const s = (ip || "").trim();
  if (!s) return false;
  // IPv4
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(s)) {
    return s.split(".").every((o) => {
      const n = Number(o);
      return n >= 0 && n <= 255;
    });
  }
  // loose IPv6 (enough to catch typos; server also validates)
  if (s.includes(":")) {
    return /^[0-9a-fA-F:]+$/.test(s) && s.split(":").length >= 3;
  }
  return false;
}

function fillProfileSelects() {
  const names = profileNames();
  const defSel = document.getElementById("upstream-default");
  const cupSel = document.getElementById("cup-profile");
  const curDef = upstreamsCache.default_upstream;
  const curCup = cupSel.value;
  defSel.innerHTML = names.map((n) => `<option value="${n}">${n}</option>`).join("");
  cupSel.innerHTML = names.length
    ? names.map((n) => `<option value="${n}">${n}</option>`).join("")
    : `<option value="">${t("pickProfile")}</option>`;
  if (names.includes(curDef)) defSel.value = curDef;
  else if (names.length) defSel.value = names[0];
  if (names.includes(curCup)) cupSel.value = curCup;
  else if (names.length) cupSel.value = names[0];
}

function endpointLabel(p) {
  if (!p || p.type === "direct") return "direct";
  return `${p.host || "?"}:${p.port || "?"}`;
}

function setMsg(id, text, isError) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text || "";
  el.style.color = isError ? "var(--bad)" : "var(--muted)";
}

function proxyPayloadFromCache() {
  const out = {};
  Object.entries(upstreamsCache.upstreams || {}).forEach(([name, p]) => {
    if (p.type === "direct") {
      out[name] = { type: "direct" };
    } else if (p.type === "http") {
      out[name] = { type: "http", host: p.host || "", port: Number(p.port) || 0 };
    } else {
      const row = {
        type: "socks5",
        host: p.host || "",
        port: Number(p.port) || 0,
      };
      if (p.username) row.username = p.username;
      out[name] = row;
    }
  });
  return out;
}

async function persistUpstreams(opts = {}) {
  const msgId = opts.msgId || "upstreams-msg";
  const names = profileNames();
  if (!names.length) {
    setMsg(msgId, "Need at least one profile", true);
    return false;
  }
  const defaultName =
    document.getElementById("upstream-default").value ||
    upstreamsCache.default_upstream ||
    names[0];
  if (!names.includes(defaultName)) {
    setMsg(msgId, `default_upstream '${defaultName}' missing`, true);
    return false;
  }
  // Drop stale client routes pointing at deleted profiles
  Object.keys(upstreamsCache.client_upstreams || {}).forEach((ip) => {
    if (!names.includes(upstreamsCache.client_upstreams[ip])) {
      delete upstreamsCache.client_upstreams[ip];
    }
  });
  try {
    const res = await api("/api/upstreams", {
      method: "PUT",
      body: JSON.stringify({
        upstreams: proxyPayloadFromCache(),
        default_upstream: defaultName,
        client_upstreams: upstreamsCache.client_upstreams || {},
        upstream_failover: document.getElementById("upstream-failover").checked,
      }),
    });
    upstreamsCache.default_upstream = defaultName;
    upstreamsCache.upstream_failover = !!res.upstream_failover;
    setMsg(
      msgId,
      `OK · ${res.persist} · profiles=${res.profiles} routes=${res.client_routes} failover=${res.upstream_failover}`,
      false
    );
    await refreshUpstreams();
    await refreshTraffic().catch(() => {});
    return true;
  } catch (ex) {
    setMsg(msgId, ex.message, true);
    return false;
  }
}

function renderUpstreams() {
  fillProfileSelects();
  const body = document.getElementById("upstreams-body");
  body.innerHTML = "";
  profileNames().forEach((name) => {
    const p = upstreamsCache.upstreams[name];
    const tr = document.createElement("tr");
    const isDefault = name === upstreamsCache.default_upstream;
    tr.innerHTML = `
      <td class="primary-cell" data-label="${t("colName")}">${name}${isDefault ? ' <span class="badge badge-relay">default</span>' : ""}</td>
      <td data-label="${t("colType")}">${p.type || "?"}</td>
      <td class="muted" data-label="${t("colEndpoint")}">${endpointLabel(p)}</td>
      <td class="row-actions"><button class="ghost" type="button" aria-label="delete">✕</button></td>`;
    tr.querySelector("button").onclick = async () => {
      if (profileNames().length <= 1) {
        setMsg("upstreams-msg", "Need at least one profile", true);
        return;
      }
      if (!confirm(t("confirmDeleteUpstream"))) return;
      delete upstreamsCache.upstreams[name];
      Object.keys(upstreamsCache.client_upstreams).forEach((ip) => {
        if (upstreamsCache.client_upstreams[ip] === name) {
          delete upstreamsCache.client_upstreams[ip];
        }
      });
      if (upstreamsCache.default_upstream === name) {
        upstreamsCache.default_upstream = profileNames()[0];
      }
      await persistUpstreams({ msgId: "upstreams-msg" });
    };
    body.appendChild(tr);
  });
  renderClientUpstreams();
}

function renderClientUpstreams() {
  fillProfileSelects();
  const body = document.getElementById("client-up-body");
  const empty = document.getElementById("client-up-empty");
  body.innerHTML = "";
  const entries = Object.entries(upstreamsCache.client_upstreams || {}).sort(([a], [b]) =>
    a.localeCompare(b)
  );
  empty.classList.toggle("hidden", entries.length > 0);
  entries.forEach(([ip, profile]) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="primary-cell" data-label="${t("colIp")}"><code>${ip}</code></td>
      <td data-label="${t("colUpstream")}">
        <select data-ip="${ip}" class="cup-sel">
          ${profileNames()
            .map((n) => `<option value="${n}" ${n === profile ? "selected" : ""}>${n}</option>`)
            .join("")}
        </select>
      </td>
      <td class="row-actions"><button class="ghost" type="button" aria-label="delete">✕</button></td>`;
    tr.querySelector(".cup-sel").onchange = async (ev) => {
      try {
        const res = await api("/api/upstreams/client", {
          method: "POST",
          body: JSON.stringify({ ip, profile: ev.target.value }),
        });
        upstreamsCache.client_upstreams = res.client_upstreams || {};
        setMsg("client-up-msg", `OK · ${res.persist}`, false);
        renderClientUpstreams();
      } catch (ex) {
        setMsg("client-up-msg", ex.message, true);
        refreshUpstreams().catch(() => {});
      }
    };
    tr.querySelector("button").onclick = async () => {
      try {
        const res = await api(`/api/upstreams/client/${encodeURIComponent(ip)}`, {
          method: "DELETE",
        });
        upstreamsCache.client_upstreams = res.client_upstreams || {};
        setMsg("client-up-msg", `OK · ${res.persist}`, false);
        renderClientUpstreams();
      } catch (ex) {
        setMsg("client-up-msg", ex.message, true);
      }
    };
    body.appendChild(tr);
  });
}

async function refreshUpstreams() {
  const data = await api("/api/upstreams");
  upstreamsCache = {
    upstreams: data.upstreams || {},
    default_upstream: data.default_upstream || "default",
    client_upstreams: { ...(data.client_upstreams || {}) },
    upstream_failover: !!data.upstream_failover,
  };
  document.getElementById("upstream-failover").checked = !!upstreamsCache.upstream_failover;
  renderUpstreams();
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
    tr.innerHTML = `<td class="primary-cell" data-label="${t("colDomain")}">${row.domain}</td>
      <td data-label="${t("colCount")}">${row.count}</td>`;
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

let whitelistCache = {
  ips: [],
  entries: [],
  ufw_sync: true,
  open: true,
  ufw_available: false,
};

function renderWhitelist() {
  const body = document.getElementById("whitelist-body");
  const empty = document.getElementById("wl-empty");
  const mode = document.getElementById("wl-mode");
  body.innerHTML = "";
  const entries = whitelistCache.entries || [];
  empty.classList.toggle("hidden", entries.length > 0);
  mode.textContent = entries.length
    ? `${t("whitelistModeStrict")} · ${entries.length} IP`
    : t("whitelistModeOpen");
  document.getElementById("wl-ufw-sync").checked = !!whitelistCache.ufw_sync;
  const ufwStatus = document.getElementById("wl-ufw-status");
  ufwStatus.textContent = whitelistCache.ufw_available
    ? t("whitelistUfwOk")
    : t("whitelistUfwMissing");
  ufwStatus.style.color = whitelistCache.ufw_available ? "var(--ok)" : "var(--bad)";

  entries.forEach((row) => {
    const ip = row.ip;
    const user = row.username || "—";
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="primary-cell" data-label="${t("colIp")}"><code>${ip}</code></td>
      <td data-label="${t("colUsername")}">${user}</td>
      <td class="row-actions"><button class="ghost" type="button" aria-label="delete">✕</button></td>`;
    tr.querySelector("button").onclick = async () => {
      try {
        const res = await api(`/api/whitelist/${encodeURIComponent(ip)}`, { method: "DELETE" });
        whitelistCache.ips = res.ips || [];
        whitelistCache.entries = res.entries || [];
        whitelistCache.open = !!res.open;
        setMsg(
          "wl-msg",
          `Removed ${ip} · ${res.persist}${res.ufw ? ` · ufw: ${res.ufw}` : ""}`,
          false
        );
        renderWhitelist();
      } catch (ex) {
        setMsg("wl-msg", ex.message, true);
      }
    };
    body.appendChild(tr);
  });
}

async function refreshWhitelist() {
  const data = await api("/api/whitelist");
  whitelistCache = {
    ips: data.ips || [],
    entries: data.entries || (data.ips || []).map((ip) => ({ ip, username: "" })),
    ufw_sync: !!data.ufw_sync,
    open: !!data.open,
    ufw_available: !!data.ufw_available,
  };
  renderWhitelist();
}

async function refreshAll() {
  await Promise.all([
    refreshStats(),
    refreshDaily(),
    refreshDomains(),
    refreshQueries(),
    refreshUpstreams(),
    refreshWhitelist(),
    refreshHosts(),
    refreshSettings(),
  ]);
  // traffic after upstreams so profile badges are accurate
  await refreshTraffic();
}

function toggleLang() {
  lang = lang === "fa" ? "en" : "fa";
  localStorage.setItem("snirelay_lang", lang);
  applyI18n();
  // Refresh dynamic labels (table data-label, badges, messages)
  if (!document.getElementById("app-view").classList.contains("hidden")) {
    renderDomainsTable();
    renderUpstreams();
    renderWhitelist();
    refreshTraffic().catch(() => {});
    refreshQueries().catch(() => {});
  }
}
document.getElementById("lang-toggle").onclick = toggleLang;
const langMobile = document.getElementById("lang-toggle-mobile");
if (langMobile) langMobile.onclick = toggleLang;

document.getElementById("nav-open").onclick = () => setNavOpen(true);
document.getElementById("nav-close").onclick = () => setNavOpen(false);
document.getElementById("nav-backdrop").onclick = () => setNavOpen(false);
window.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") setNavOpen(false);
});

document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.onclick = () => switchTab(btn.dataset.tab);
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

async function doLogout() {
  await api("/api/auth/logout", { method: "POST", body: "{}" }).catch(() => {});
  show("login");
}
document.getElementById("logout-btn").onclick = doLogout;
const logoutMobile = document.getElementById("logout-btn-mobile");
if (logoutMobile) logoutMobile.onclick = doLogout;

document.getElementById("dash-range").onchange = refreshDaily;
document.getElementById("traffic-range").onchange = refreshTraffic;
document.getElementById("refresh-traffic").onclick = refreshTraffic;

document.getElementById("upstream-default").onchange = async (ev) => {
  upstreamsCache.default_upstream = ev.target.value;
  await persistUpstreams({ msgId: "upstreams-msg" });
};
document.getElementById("upstream-failover").onchange = async (ev) => {
  upstreamsCache.upstream_failover = !!ev.target.checked;
  await persistUpstreams({ msgId: "upstreams-msg" });
};

function syncUpstreamFormType() {
  const direct = document.getElementById("up-type").value === "direct";
  document.getElementById("up-host").disabled = direct;
  document.getElementById("up-port").disabled = direct;
}
document.getElementById("up-type").onchange = syncUpstreamFormType;
syncUpstreamFormType();

document.getElementById("upstream-form").onsubmit = async (e) => {
  e.preventDefault();
  const name = document.getElementById("up-name").value.trim();
  const type = document.getElementById("up-type").value;
  const host = document.getElementById("up-host").value.trim();
  const port = Number(document.getElementById("up-port").value) || 0;
  if (!name) return;
  if (type !== "direct" && (!host || !port)) {
    setMsg("upstreams-msg", "host and port are required", true);
    return;
  }
  if (type === "direct") {
    upstreamsCache.upstreams[name] = { type: "direct" };
  } else {
    upstreamsCache.upstreams[name] = { type, host, port };
  }
  if (!upstreamsCache.default_upstream || !profileNames().includes(upstreamsCache.default_upstream)) {
    upstreamsCache.default_upstream = name;
  }
  document.getElementById("up-name").value = "";
  await persistUpstreams({ msgId: "upstreams-msg" });
};

document.getElementById("client-up-form").onsubmit = async (e) => {
  e.preventDefault();
  const ip = document.getElementById("cup-ip").value.trim();
  const profile = document.getElementById("cup-profile").value;
  if (!profile) {
    setMsg("client-up-msg", t("pickProfile"), true);
    return;
  }
  if (!isValidIp(ip)) {
    setMsg("client-up-msg", t("invalidClientIp"), true);
    return;
  }
  try {
    const res = await api("/api/upstreams/client", {
      method: "POST",
      body: JSON.stringify({ ip, profile }),
    });
    upstreamsCache.client_upstreams = res.client_upstreams || {};
    document.getElementById("cup-ip").value = "";
    setMsg("client-up-msg", `OK · ${res.persist}`, false);
    renderClientUpstreams();
    await refreshTraffic().catch(() => {});
  } catch (ex) {
    setMsg("client-up-msg", ex.message, true);
  }
};

document.getElementById("save-upstreams").onclick = async () => {
  await persistUpstreams({ msgId: "upstreams-msg" });
};

document.getElementById("whitelist-form").onsubmit = async (e) => {
  e.preventDefault();
  const ip = document.getElementById("wl-ip").value.trim();
  const username = (document.getElementById("wl-user")?.value || "").trim();
  if (!isValidIp(ip)) {
    setMsg("wl-msg", t("invalidClientIp"), true);
    return;
  }
  if (!username) {
    setMsg("wl-msg", t("usernameRequired"), true);
    return;
  }
  try {
    const res = await api("/api/whitelist/add", {
      method: "POST",
      body: JSON.stringify({ ip, username }),
    });
    whitelistCache.ips = res.ips || [];
    whitelistCache.entries = res.entries || [];
    whitelistCache.open = !!res.open;
    document.getElementById("wl-ip").value = "";
    const wu = document.getElementById("wl-user");
    if (wu) wu.value = "";
    setMsg(
      "wl-msg",
      `${res.added ? "Added" : "Updated"} ${ip} (${res.username}) · ${res.persist}${
        res.ufw_comment ? ` · ${res.ufw_comment}` : ""
      }${res.ufw ? ` · ufw: ${res.ufw}` : ""}`,
      String(res.ufw || "").startsWith("ERROR")
    );
    renderWhitelist();
  } catch (ex) {
    setMsg("wl-msg", ex.message, true);
  }
};

document.getElementById("wl-ufw-sync").onchange = async (ev) => {
  try {
    const res = await api("/api/whitelist", {
      method: "PUT",
      body: JSON.stringify({
        entries: whitelistCache.entries || [],
        ufw_sync: !!ev.target.checked,
      }),
    });
    whitelistCache.ufw_sync = !!res.ufw_sync;
    whitelistCache.ips = res.ips || [];
    whitelistCache.entries = res.entries || [];
    whitelistCache.open = !!res.open;
    setMsg("wl-msg", `ufw_sync=${res.ufw_sync} · ${res.persist}`, false);
    renderWhitelist();
  } catch (ex) {
    setMsg("wl-msg", ex.message, true);
    ev.target.checked = !ev.target.checked;
  }
};

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
