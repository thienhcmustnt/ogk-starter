/**
 * OGK Parent Web Dashboard — Working Starter Client (for Member B to expand).
 * Connects directly to FastAPI `/api/v1/*` endpoints with session cookie + `X-CSRF-Token`.
 */

const state = {
  user: null,
  csrfToken: "",
  children: [],
  activeChildId: null,
  policy: null,       // PolicyConfigPayload from GET /api/v1/policy/{child_id}
  usageChart: null,
  isDraggingGrid: false,
  dragPaintValue: true,
};

const DAY_LABELS = ["T2", "T3", "T4", "T5", "T6", "T7", "CN"];

// ---------------------------------------------------------------------------
// Helpers & Toast
// ---------------------------------------------------------------------------
function showToast(msg, isError = false) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = `fixed bottom-4 right-4 z-50 max-w-sm rounded-xl px-4 py-3 text-sm text-white shadow-lg ${
    isError ? "bg-rose-600" : "bg-emerald-600"
  }`;
  el.classList.remove("hidden");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add("hidden"), 3500);
}

async function apiFetch(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && !(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  const method = (options.method || "GET").toUpperCase();
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && state.csrfToken) {
    headers["X-CSRF-Token"] = state.csrfToken;
  }
  const res = await fetch(url, { credentials: "same-origin", ...options, headers });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { detail: text };
  }
  if (!res.ok) {
    const detail = Array.isArray(data?.detail)
      ? data.detail.map((d) => d.msg || JSON.stringify(d)).join("; ")
      : data?.detail || `HTTP ${res.status}`;
    throw new Error(detail);
  }
  return data;
}

function formatDuration(sec) {
  const mins = Math.round((sec || 0) / 60);
  if (mins < 60) return `${mins} phút`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return `${h}g ${m}p`;
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------------------------------------------------------------------------
// Auth & Bootstrapping
// ---------------------------------------------------------------------------
async function initApp() {
  document.addEventListener("mouseup", () => {
    state.isDraggingGrid = false;
  });

  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    document.getElementById("login-msg").textContent = "";
    try {
      const data = await apiFetch("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: document.getElementById("email").value,
          password: document.getElementById("password").value,
        }),
      });
      onAuthenticated(data);
    } catch (err) {
      document.getElementById("login-msg").textContent = err.message;
    }
  });

  // Auto-restore existing session on page refresh
  try {
    const me = await apiFetch("/api/v1/auth/me");
    onAuthenticated(me);
  } catch {
    // Not logged in yet
  }
}

function onAuthenticated(data) {
  if (data.user.role === "child-view") {
    window.location.href = "/child-view";
    return;
  }
  state.user = data.user;
  state.csrfToken = data.csrf_token;
  state.children = data.children || [];
  state.activeChildId = state.children[0]?.id ?? null;

  document.getElementById("login-section").classList.add("hidden");
  document.getElementById("dashboard-section").classList.remove("hidden");
  document.getElementById("welcome-title").textContent = `Xin chào, ${data.user.full_name}`;

  const sel = document.getElementById("child-select");
  sel.innerHTML = state.children
    .map((c) => `<option value="${c.id}">${escapeHtml(c.display_name)} (${escapeHtml(c.age_group)} tuổi)</option>`)
    .join("");

  if (state.activeChildId) {
    refreshAll();
  }
}

async function logout() {
  try {
    await apiFetch("/api/v1/auth/logout", { method: "POST" });
  } finally {
    window.location.reload();
  }
}

function onChildChange() {
  state.activeChildId = Number(document.getElementById("child-select").value);
  refreshAll();
}

function switchTab(tabName) {
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
  document.getElementById(`tab-${tabName}`).classList.remove("hidden");
  document.querySelectorAll(".tab-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabName);
  });
}

// ---------------------------------------------------------------------------
// Load All Dashboard Data
// ---------------------------------------------------------------------------
async function refreshAll() {
  if (!state.activeChildId) return;
  const cid = state.activeChildId;
  try {
    const [summary, policyEnv, devices, reqs, audits] = await Promise.all([
      apiFetch(`/api/v1/reports/${cid}/summary?days=7`),
      apiFetch(`/api/v1/policy/${cid}`),
      apiFetch(`/api/v1/enroll/devices/${cid}`),
      apiFetch(`/api/v1/requests/${cid}`),
      apiFetch(`/api/v1/reports/${cid}/audit-logs?limit=50`),
    ]);
    state.policy = policyEnv.policy;
    renderOverview(summary, devices);
    renderPolicyForms(state.policy);
    renderFilters(state.policy);
    renderDevices(devices);
    renderRequests(reqs);
    renderAuditLogs(audits);
  } catch (err) {
    showToast(`Không tải được dữ liệu: ${err.message}`, true);
  }
}

// ---------------------------------------------------------------------------
// Tab 1: Overview & Chart.js
// ---------------------------------------------------------------------------
function renderOverview(summary, devices) {
  document.getElementById("kpi-duration").textContent = formatDuration(summary.total_duration_sec);
  document.getElementById("kpi-blocked").textContent = summary.total_blocked_events;
  document.getElementById("kpi-requests").textContent = summary.pending_requests_count;
  const activeCount = devices.filter((d) => !d.revoked_at).length;
  document.getElementById("kpi-devices").textContent = activeCount;

  const pill = document.getElementById("pending-req-pill");
  if (summary.pending_requests_count > 0) {
    pill.textContent = summary.pending_requests_count;
    pill.classList.remove("hidden");
  } else {
    pill.classList.add("hidden");
  }

  // Daily Bar Chart
  const ctx = document.getElementById("usage-chart");
  if (state.usageChart) state.usageChart.destroy();
  state.usageChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: summary.daily_usage.map((d) => d.date.slice(5)),
      datasets: [
        {
          label: "Phút sử dụng",
          data: summary.daily_usage.map((d) => Math.round(d.total_duration_sec / 60)),
          backgroundColor: "#4f46e5",
          borderRadius: 6,
        },
        {
          label: "Lượt bị chặn",
          data: summary.daily_usage.map((d) => d.blocked_count),
          backgroundColor: "#f43f5e",
          borderRadius: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: { y: { beginAtZero: true } },
    },
  });

  // Top Apps
  const appsEl = document.getElementById("top-apps-list");
  appsEl.innerHTML = summary.top_apps.length
    ? summary.top_apps
        .map(
          (a) => `<div class="flex justify-between items-center bg-slate-50 px-3 py-2 rounded-lg">
            <span class="font-mono text-xs font-semibold">${escapeHtml(a.subject)}</span>
            <span class="text-xs text-slate-600">${formatDuration(a.total_duration_sec)} (${a.count} lượt)</span>
          </div>`
        )
        .join("")
    : `<p class="text-xs text-slate-400">Chưa có dữ liệu ứng dụng.</p>`;

  // Top Domains
  const domEl = document.getElementById("top-domains-list");
  domEl.innerHTML = summary.top_domains.length
    ? summary.top_domains
        .map(
          (d) => `<div class="flex justify-between items-center bg-slate-50 px-3 py-2 rounded-lg">
            <span class="font-mono text-xs font-semibold">${escapeHtml(d.subject)}</span>
            <span class="text-xs text-slate-600">${d.count} truy vấn · ${formatDuration(d.total_duration_sec)}</span>
          </div>`
        )
        .join("")
    : `<p class="text-xs text-slate-400">Chưa có dữ liệu tên miền.</p>`;
}

function exportReport(format) {
  window.open(`/api/v1/reports/${state.activeChildId}/export?format=${format}&days=7`, "_blank");
}

async function purgeAllData() {
  if (!confirm("Bạn chắc chắn muốn XÓA TOÀN BỘ dữ liệu hoạt động của con trên máy chủ và gửi lệnh xóa cache về máy trẻ?")) {
    return;
  }
  try {
    const res = await apiFetch(`/api/v1/reports/${state.activeChildId}/purge`, { method: "DELETE" });
    showToast(`Đã xóa ${res.events_deleted} sự kiện và gửi lệnh PURGE_CACHE tới ${res.devices_notified} thiết bị.`);
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

// ---------------------------------------------------------------------------
// Tab 2: Quota & Interactive 7x48 Schedule Matrix
// ---------------------------------------------------------------------------
function renderPolicyForms(pol) {
  document.getElementById("policy-ver-badge").textContent = `v${pol.version}`;
  document.getElementById("inp-weekday-quota").value = pol.weekday_quota_minutes;
  document.getElementById("inp-weekend-quota").value = pol.weekend_quota_minutes;
  document.getElementById("inp-grace-sec").value = pol.grace_period_seconds;
  document.getElementById("chk-safesearch").checked = !!pol.enforce_safesearch;
  document.getElementById("chk-doh").checked = !!pol.block_doh_endpoints;
  renderScheduleGrid(pol.schedule_matrix);
}

function renderScheduleGrid(matrix) {
  const table = document.getElementById("schedule-grid");
  let headerHtml = `<thead><tr><th class="pr-2 text-left">Ngày</th>`;
  for (let h = 0; h < 24; h++) {
    headerHtml += `<th colspan="2" class="text-center text-slate-400 font-normal border-l border-slate-200">${String(h).padStart(2, "0")}</th>`;
  }
  headerHtml += `</tr></thead><tbody>`;

  for (let d = 0; d < 7; d++) {
    headerHtml += `<tr><td class="pr-2 font-bold text-slate-600">${DAY_LABELS[d]}</td>`;
    for (let s = 0; s < 48; s++) {
      const allowed = !!matrix[d][s];
      const cls = allowed ? "bg-emerald-400 hover:bg-emerald-500" : "bg-slate-200 hover:bg-slate-300";
      headerHtml += `<td class="slot-cell border border-white ${cls}" data-d="${d}" data-s="${s}" title="${DAY_LABELS[d]} ${String(Math.floor(s / 2)).padStart(2, "0")}:${s % 2 ? "30" : "00"}"></td>`;
    }
    headerHtml += `</tr>`;
  }
  headerHtml += `</tbody>`;
  table.innerHTML = headerHtml;

  table.querySelectorAll(".slot-cell").forEach((cell) => {
    cell.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const d = Number(cell.dataset.d);
      const s = Number(cell.dataset.s);
      state.isDraggingGrid = true;
      state.dragPaintValue = !state.policy.schedule_matrix[d][s];
      paintCell(cell, d, s, state.dragPaintValue);
    });
    cell.addEventListener("mouseenter", () => {
      if (!state.isDraggingGrid) return;
      paintCell(cell, Number(cell.dataset.d), Number(cell.dataset.s), state.dragPaintValue);
    });
  });
}

function paintCell(cell, d, s, val) {
  state.policy.schedule_matrix[d][s] = val;
  cell.className = `slot-cell border border-white ${
    val ? "bg-emerald-400 hover:bg-emerald-500" : "bg-slate-200 hover:bg-slate-300"
  }`;
}

function applyPresetSchedule(kind) {
  if (!state.policy) return;
  state.policy.schedule_matrix = Array.from({ length: 7 }, () =>
    Array.from({ length: 48 }, (_, slot) => (kind === "all" ? true : slot >= 14 && slot < 42))
  );
  renderScheduleGrid(state.policy.schedule_matrix);
}

async function savePolicy(customNote = null) {
  if (!state.policy) return;
  const payload = {
    ...state.policy,
    weekday_quota_minutes: Number(document.getElementById("inp-weekday-quota").value),
    weekend_quota_minutes: Number(document.getElementById("inp-weekend-quota").value),
    grace_period_seconds: Number(document.getElementById("inp-grace-sec").value),
    enforce_safesearch: document.getElementById("chk-safesearch").checked,
    block_doh_endpoints: document.getElementById("chk-doh").checked,
    change_note: customNote || document.getElementById("inp-change-note").value.trim() || "Cập nhật chính sách từ Dashboard",
  };
  delete payload.child_id;
  delete payload.version;

  try {
    const updated = await apiFetch(`/api/v1/policy/${state.activeChildId}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    state.policy = updated.policy;
    document.getElementById("inp-change-note").value = "";
    showToast(`Đã lưu Policy v${updated.policy.version} và ký HMAC-SHA256 thành công!`);
    refreshAll();
  } catch (err) {
    showToast(`Lỗi lưu Policy: ${err.message}`, true);
  }
}

// ---------------------------------------------------------------------------
// Tab 3: Blocked Domains & Apps (NT4 / NT6)
// ---------------------------------------------------------------------------
function renderFilters(pol) {
  const domList = document.getElementById("blocked-domains-list");
  domList.innerHTML = pol.blocked_domains.length
    ? pol.blocked_domains
        .map(
          (item, idx) => `<div class="py-2 flex items-start justify-between gap-2">
            <div>
              <p class="font-mono font-semibold text-xs text-slate-800">${escapeHtml(item.target)}</p>
              <p class="text-xs text-slate-600">Lý do (NT4): ${escapeHtml(item.reason)}</p>
              <p class="text-[11px] text-slate-400">Đặt bởi: ${escapeHtml(item.created_by)}</p>
            </div>
            <button onclick="removeRule('domain', ${idx})" class="text-xs text-rose-600 hover:underline">Gỡ</button>
          </div>`
        )
        .join("")
    : `<p class="text-xs text-slate-400 py-2">Chưa có tên miền nào trong danh sách chặn riêng.</p>`;

  const appList = document.getElementById("blocked-apps-list");
  appList.innerHTML = pol.blocked_apps.length
    ? pol.blocked_apps
        .map(
          (item, idx) => `<div class="py-2 flex items-start justify-between gap-2">
            <div>
              <p class="font-mono font-semibold text-xs text-slate-800">${escapeHtml(item.target)}</p>
              ${item.sha256 ? `<p class="font-mono text-[10px] text-slate-400 break-all">SHA-256: ${escapeHtml(item.sha256)}</p>` : ""}
              <p class="text-xs text-slate-600">Lý do (NT4): ${escapeHtml(item.reason)}</p>
              <p class="text-[11px] text-slate-400">Đặt bởi: ${escapeHtml(item.created_by)}</p>
            </div>
            <button onclick="removeRule('app', ${idx})" class="text-xs text-rose-600 hover:underline">Gỡ</button>
          </div>`
        )
        .join("")
    : `<p class="text-xs text-slate-400 py-2">Chưa có ứng dụng nào bị chặn.</p>`;

  document.getElementById("nt6-whitelist-badges").innerHTML = pol.whitelist_emergency
    .map((d) => `<span class="bg-amber-100 text-amber-900 px-2 py-0.5 rounded font-mono text-xs">${escapeHtml(d)}</span>`)
    .join("");
}

async function addRule(e, kind) {
  e.preventDefault();
  if (!state.policy) return;
  const createdBy = state.user.full_name || state.user.email;
  if (kind === "domain") {
    const target = document.getElementById("new-domain-target").value.trim().toLowerCase();
    const reason = document.getElementById("new-domain-reason").value.trim();
    state.policy.blocked_domains.push({ target, reason, created_by: createdBy });
    document.getElementById("new-domain-target").value = "";
    document.getElementById("new-domain-reason").value = "";
    await savePolicy(`Thêm chặn tên miền: ${target}`);
  } else {
    const target = document.getElementById("new-app-target").value.trim().toLowerCase();
    const sha256 = document.getElementById("new-app-sha256").value.trim().toLowerCase() || null;
    const reason = document.getElementById("new-app-reason").value.trim();
    state.policy.blocked_apps.push({ target, sha256, reason, created_by: createdBy });
    document.getElementById("new-app-target").value = "";
    document.getElementById("new-app-sha256").value = "";
    document.getElementById("new-app-reason").value = "";
    await savePolicy(`Thêm chặn ứng dụng: ${target}`);
  }
}

async function removeRule(kind, idx) {
  if (!state.policy) return;
  const arr = kind === "domain" ? state.policy.blocked_domains : state.policy.blocked_apps;
  const removed = arr.splice(idx, 1)[0];
  await savePolicy(`Gỡ luật chặn: ${removed?.target || ""}`);
}

// ---------------------------------------------------------------------------
// Tab 4: Devices, Pairing Code & Real-time Commands
// ---------------------------------------------------------------------------
async function createPairingCode() {
  try {
    const data = await apiFetch("/api/v1/enroll/code", {
      method: "POST",
      body: JSON.stringify({ child_id: state.activeChildId }),
    });
    const box = document.getElementById("pairing-box");
    box.classList.remove("hidden");
    box.innerHTML = `
      <div>
        <p class="text-xs text-emerald-800">Mã ghép đôi (chỉ dùng 1 lần, hết hạn lúc ${new Date(data.expires_at).toLocaleTimeString()}):</p>
        <p class="text-2xl font-mono font-extrabold tracking-widest text-emerald-900 mt-1">${escapeHtml(data.code)}</p>
      </div>
      <button onclick="navigator.clipboard?.writeText('${escapeHtml(data.code)}'); showToast('Đã sao chép mã!');"
              class="bg-emerald-700 text-white px-3 py-1.5 rounded-lg text-xs">Sao chép</button>
    `;
    showToast("Đã tạo mã ghép đôi 8 ký tự!");
  } catch (err) {
    showToast(err.message, true);
  }
}

function renderDevices(devices) {
  const el = document.getElementById("devices-list");
  if (!devices.length) {
    el.innerHTML = `<p class="text-xs text-slate-400">Chưa có thiết bị nào được ghép đôi.</p>`;
    return;
  }
  el.innerHTML = devices
    .map((d) => {
      const revoked = !!d.revoked_at;
      return `<div class="border rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 ${revoked ? "opacity-55 bg-slate-50" : "bg-white"}">
        <div>
          <p class="font-bold text-sm">${escapeHtml(d.device_name)} <span class="font-mono text-xs text-slate-400">(${escapeHtml(d.id)})</span></p>
          <p class="text-xs text-slate-500">
            ${escapeHtml(d.os_version)} · Policy v${d.last_policy_version} · Đã dùng hôm nay: ${formatDuration(d.last_quota_used_sec)}
            · Tray UI: ${d.tray_visible ? '<span class="text-emerald-600 font-semibold">Đang hiện (NT1)</span>' : '<span class="text-rose-600 font-semibold">Cảnh báo ẩn!</span>'}
          </p>
        </div>
        ${
          revoked
            ? `<span class="text-xs bg-slate-200 px-2.5 py-1 rounded-full">Đã thu hồi</span>`
            : `<div class="flex flex-wrap gap-1.5 text-xs">
                <button onclick="sendCommand('${d.id}', 'LOCK_NOW')" class="bg-rose-600 hover:bg-rose-700 text-white px-2.5 py-1.5 rounded-lg">Khóa ngay</button>
                <button onclick="sendCommand('${d.id}', 'UNLOCK_NOW')" class="bg-emerald-600 hover:bg-emerald-700 text-white px-2.5 py-1.5 rounded-lg">Mở khóa</button>
                <button onclick="sendCommand('${d.id}', 'ADD_15M', {minutes: 15})" class="bg-indigo-600 hover:bg-indigo-700 text-white px-2.5 py-1.5 rounded-lg">+15 phút</button>
                <button onclick="sendCommand('${d.id}', 'PAUSE_2H', {hours: 2})" class="bg-amber-500 hover:bg-amber-600 text-white px-2.5 py-1.5 rounded-lg">Tạm nghỉ 2h</button>
                <button onclick="revokeDevice('${d.id}')" class="bg-slate-200 hover:bg-slate-300 text-slate-700 px-2.5 py-1.5 rounded-lg">Thu hồi</button>
              </div>`
        }
      </div>`;
    })
    .join("");
}

async function sendCommand(deviceId, command, payload = {}) {
  try {
    const res = await apiFetch(`/api/v1/commands/${deviceId}`, {
      method: "POST",
      body: JSON.stringify({ command, payload }),
    });
    showToast(
      res.delivered_via_ws
        ? `Đã đẩy lệnh ${command} tức thì qua WebSocket!`
        : `Thiết bị đang offline — lệnh ${command} đã xếp hàng chờ heartbeat.`
    );
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function revokeDevice(deviceId) {
  if (!confirm("Thu hồi thiết bị này? Agent sẽ không thể tiếp tục kết nối.")) return;
  try {
    await apiFetch(`/api/v1/enroll/devices/${deviceId}`, { method: "DELETE" });
    showToast("Đã thu hồi thiết bị!");
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

// ---------------------------------------------------------------------------
// Tab 5: Child Requests (NT3) & Audit Logs (NT5)
// ---------------------------------------------------------------------------
function renderRequests(reqs) {
  const el = document.getElementById("requests-list");
  if (!reqs.length) {
    el.innerHTML = `<p class="text-xs text-slate-400">Chưa có yêu cầu nào từ trẻ.</p>`;
    return;
  }
  el.innerHTML = reqs
    .map((r) => {
      const badgeColor =
        r.status === "pending"
          ? "bg-amber-100 text-amber-800"
          : r.status === "approved"
          ? "bg-emerald-100 text-emerald-800"
          : "bg-rose-100 text-rose-800";
      const typeLabel = r.request_type === "unlock_request" ? "Xin thêm giờ" : "Báo chặn nhầm";
      return `<div class="border rounded-xl p-4 space-y-2 text-sm">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded-full text-xs font-semibold ${badgeColor}">${escapeHtml(r.status)}</span>
            <strong>${typeLabel}</strong>
            <span class="font-mono text-xs bg-slate-100 px-2 py-0.5 rounded">${escapeHtml(r.subject)}</span>
          </div>
          <span class="text-xs text-slate-400">${new Date(r.created_at).toLocaleString()}</span>
        </div>
        <p class="text-slate-700">"${escapeHtml(r.message)}"</p>
        ${
          r.status === "pending"
            ? `<div class="flex flex-wrap gap-2 pt-1">
                <input id="reply-${r.id}" type="text" value="${r.request_type === "unlock_request" ? "Đồng ý, con học xong rồi nghỉ mắt nhé!" : "Ba mẹ đã kiểm tra lại giúp con."}"
                       class="flex-1 min-w-[200px] border rounded-lg px-2.5 py-1.5 text-xs" />
                <button onclick="decideRequest(${r.id}, 'approved', ${r.requested_minutes || 15})" class="bg-emerald-600 text-white px-3 py-1.5 rounded-lg text-xs font-medium">Duyệt</button>
                <button onclick="decideRequest(${r.id}, 'rejected', 15)" class="bg-rose-600 text-white px-3 py-1.5 rounded-lg text-xs font-medium">Từ chối</button>
              </div>`
            : `<p class="text-xs text-slate-500">Phản hồi phụ huynh: <em>${escapeHtml(r.parent_response || "")}</em></p>`
        }
      </div>`;
    })
    .join("");
}

async function decideRequest(reqId, decision, grantMinutes) {
  const responseMessage = document.getElementById(`reply-${reqId}`)?.value.trim() || "Đã xem xét.";
  try {
    await apiFetch(`/api/v1/requests/${reqId}/decision`, {
      method: "POST",
      body: JSON.stringify({
        decision,
        response_message: responseMessage,
        grant_minutes: grantMinutes,
      }),
    });
    showToast(decision === "approved" ? "Đã duyệt yêu cầu của trẻ!" : "Đã từ chối và gửi phản hồi cho trẻ.");
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

function renderAuditLogs(audits) {
  const tbody = document.getElementById("audit-table-body");
  tbody.innerHTML = audits
    .map(
      (a) => `<tr>
        <td class="py-2 px-3 whitespace-nowrap text-slate-500">${new Date(a.created_at).toLocaleString()}</td>
        <td class="py-2 px-3 font-medium">${escapeHtml(a.actor_label)}</td>
        <td class="py-2 px-3 font-mono text-indigo-700">${escapeHtml(a.action)}</td>
        <td class="py-2 px-3 font-mono text-slate-500">${escapeHtml(a.ip_address)}</td>
        <td class="py-2 px-3 font-mono text-[11px] text-slate-600 break-all">${escapeHtml(JSON.stringify(a.new_value || {}))}</td>
      </tr>`
    )
    .join("");
}

document.addEventListener("DOMContentLoaded", initApp);
