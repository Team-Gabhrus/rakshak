/**
 * Rakshak — Global JS utilities
 * Handles: auth, API calls, PQC badge rendering, search, sidebar, toasts
 */

// ── Auth helpers ──────────────────────────────────────────────────────────
const API = {
    get token() { return localStorage.getItem('token'); },
    headers() { return { 'Content-Type': 'application/json', 'Authorization': `Bearer ${this.token}` }; },

    async fetch(url, opts = {}) {
        opts.headers = { ...this.headers(), ...(opts.headers || {}) };
        const res = await fetch(url, opts);
        if (res.status === 401) { logout(); return null; }
        return res;
    },

    async get(url)            { return this.fetch(url); },
    async post(url, body)     { return this.fetch(url, { method: 'POST', body: JSON.stringify(body) }); },
    async delete(url)         { return this.fetch(url, { method: 'DELETE' }); },
    async patch(url, body={}) { return this.fetch(url, { method: 'PATCH', body: JSON.stringify(body) }); },
};

function logout() {
    const theme = localStorage.getItem('rk-theme') || 'dark';
    localStorage.clear();
    localStorage.setItem('rk-theme', theme);
    document.cookie = 'access_token=; path=/; max-age=0';
    window.location.href = '/login';
}

window.logout = logout;

// ── Sidebar / topbar init ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const username = localStorage.getItem('username') || 'User';
    const role     = localStorage.getItem('role') || 'checker';
    const el = document.getElementById('currentUsername');
    const re = document.getElementById('currentRole');
    const profileUser = document.getElementById('profileModalUsername');
    const profileRole = document.getElementById('profileModalRole');
    if (el) el.textContent = username;
    if (re) re.textContent = role.charAt(0).toUpperCase() + role.slice(1);
    if (profileUser) profileUser.textContent = username;
    if (profileRole) profileRole.textContent = role.charAt(0).toUpperCase() + role.slice(1);

    // Highlight active nav
    const path = window.location.pathname;
    document.querySelectorAll('.rk-nav-item').forEach(a => {
        if (a.getAttribute('href') === path) a.classList.add('active');
    });

    // Hide admin elements if checker
    if (role === 'checker') {
        const navUsers = document.getElementById('nav-users');
        if (navUsers) navUsers.style.display = 'none';

        if (window.location.pathname === '/user-management') {
            document.body.innerHTML = '<div style="padding: 50px; text-align: center; color: white;"><h2>403 Forbidden</h2><p>Checkers have read-only access.</p><a href="/home" class="rk-btn rk-btn-primary">Go Home</a></div>';
        }

        const style = document.createElement('style');
        style.innerHTML = '.admin-only { display: none !important; }';
        document.head.appendChild(style);
    }

    // Global search
    const searchInput = document.getElementById('globalSearch');
    const searchDrop  = document.getElementById('searchDropdown');
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => doSearch(searchInput.value), 300);
        });
        document.addEventListener('click', (e) => {
            if (!searchInput.contains(e.target)) searchDrop?.classList.remove('show');
        });
    }

    // If not logged in on non-login pages, redirect
    if (window.location.pathname !== '/login') {
        const hasCookie = document.cookie.includes('access_token=');
        if (!localStorage.getItem('token') || !hasCookie) {
            logout();
        }

        loadTaskStatus();
        setInterval(loadTaskStatus, 10000);
    }
});

function openProfileModal() {
    const modalEl = document.getElementById('profileModal');
    if (!modalEl || typeof bootstrap === 'undefined') return;
    new bootstrap.Modal(modalEl).show();
}

function goToUsersFromProfile() {
    const modalEl = document.getElementById('profileModal');
    if (modalEl && typeof bootstrap !== 'undefined') {
        bootstrap.Modal.getOrCreateInstance(modalEl).hide();
    }
    window.location.href = '/user-management';
}

async function loadTaskStatus() {
    if (window.location.pathname === '/login') return;
    const badge = document.getElementById('taskBellBadge');
    if (!badge) return;

    try {
        const res = await API.get('/api/tasks/status');
        if (!res || !res.ok) return;
        const data = await res.json();
        badge.style.display = data.has_running_tasks ? 'block' : 'none';
        badge.dataset.counts = JSON.stringify(data.counts || {});
        badge.textContent = (data.counts?.total || 0).toString();
    } catch (err) {
        console.warn('Failed to load task status', err);
    }
}

async function openTaskStatusModal() {
    const modal = _initTaskStatusModal();
    const body = document.getElementById('rkTaskStatusBody');
    body.innerHTML = '<div class="text-muted text-center py-4">Loading running tasks…</div>';
    modal.show();

    try {
        const res = await API.get('/api/tasks');
        if (!res || !res.ok) throw new Error('Unable to load tasks');
        const data = await res.json();
        renderTaskStatusContent(data);
    } catch (err) {
        body.innerHTML = '<div class="text-danger">Failed to load task details.</div>';
    }
}

function _initTaskStatusModal() {
    let modalEl = document.getElementById('rkTaskStatusModal');
    if (!modalEl) {
        document.body.insertAdjacentHTML('beforeend', `
        <div class="modal fade" id="rkTaskStatusModal" tabindex="-1" aria-hidden="true">
          <div class="modal-dialog modal-dialog-centered modal-lg">
            <div class="modal-content" style="background:var(--rk-surface);border:1px solid var(--rk-border);color:var(--rk-text)">
              <div class="modal-header" style="border-color:var(--rk-border)">
                <h5 class="modal-title">Running Tasks</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
              </div>
              <div class="modal-body" id="rkTaskStatusBody"></div>
            </div>
          </div>
        </div>`);
        modalEl = document.getElementById('rkTaskStatusModal');
    }
    return bootstrap.Modal.getOrCreateInstance(modalEl);
}

function renderTaskStatusContent(data) {
    const body = document.getElementById('rkTaskStatusBody');
    if (!body) return;
    const scans = data.scans || [];
    const reports = data.reports || [];
    const discoveryJobs = data.discovery_jobs || [];
    const total = data.counts?.total || 0;

    if (!total) {
        body.innerHTML = '<div class="text-muted text-center py-4">No running tasks right now.</div>';
        return;
    }

    body.innerHTML = `
      <div class="d-flex flex-wrap gap-2 mb-3">
        <span class="badge bg-danger">${total} active</span>
        <span class="badge bg-warning text-dark">${scans.length} scans</span>
        <span class="badge bg-info text-dark">${reports.length} reports</span>
        <span class="badge bg-primary">${discoveryJobs.length} discoveries</span>
      </div>
      ${renderTaskSection('Scan Tasks', scans.map(task => renderTaskCard('scan', task)).join(''))}
      ${renderTaskSection('Subdomain Discovery', discoveryJobs.map(task => renderTaskCard('discovery', task)).join(''))}
      ${renderTaskSection('Reports', reports.map(task => renderTaskCard('report', task)).join(''))}
    `;
}

function renderTaskSection(title, inner) {
    if (!inner) return '';
    return `
      <div class="mb-4">
        <div class="fw-semibold mb-2">${title}</div>
        <div class="d-grid gap-2">${inner}</div>
      </div>
    `;
}

function renderTaskCard(type, task) {
    if (type === 'scan') {
        const status = task.display_status || task.status;
        const statusBadge = status === 'cancelling'
            ? '<span class="badge bg-warning text-dark">cancelling</span>'
            : status === 'cancelled'
                ? '<span class="badge bg-danger">cancelled</span>'
                : status === 'running'
                    ? '<span class="badge bg-warning text-dark">running</span>'
                    : '<span class="badge bg-secondary">' + status + '</span>';
        return `
        <div class="p-3 rounded" style="border:1px solid var(--rk-border);background:var(--rk-bg)">
          <div class="d-flex justify-content-between align-items-start gap-3">
            <div>
              <div class="fw-semibold d-flex align-items-center gap-2 flex-wrap">Scan #${task.id} ${statusBadge}</div>
              <div class="fs-12 text-muted mt-1">${task.last_message || 'Quantum vulnerability scan is running.'}</div>
              <div class="fs-12 text-muted mt-2">Progress: ${task.completed_count || 0}/${task.target_count || 0} completed, ${task.failed_count || 0} issues</div>
            </div>
            ${task.can_terminate ? `<button class="rk-btn rk-btn-sm" style="background:rgba(220,53,69,0.12);color:#dc3545;border:1px solid rgba(220,53,69,0.35)" onclick="terminateTask('scan', ${task.id})"><i class="bi bi-stop-circle"></i> Terminate</button>` : ''}
          </div>
        </div>`;
    }

    if (type === 'discovery') {
        return `
        <div class="p-3 rounded" style="border:1px solid var(--rk-border);background:var(--rk-bg)">
          <div class="d-flex justify-content-between align-items-start gap-3">
            <div>
              <div class="fw-semibold">${task.domain}</div>
              <div class="fs-12 text-muted mt-1">${task.last_message || 'Breadth-first recursive subdomain discovery is running.'}</div>
              <div class="fs-12 text-muted mt-2">${task.processed_count || 0} processed • ${task.live_count || 0} live • ${task.dead_count || 0} dead</div>
            </div>
            ${task.can_terminate ? `<button class="rk-btn rk-btn-sm" style="background:rgba(220,53,69,0.12);color:#dc3545;border:1px solid rgba(220,53,69,0.35)" onclick="terminateTask('discovery', '${task.job_id}')"><i class="bi bi-stop-circle"></i> Terminate</button>` : task.queued_scan_id ? `<span class="badge bg-success">Scan #${task.queued_scan_id} queued</span>` : ''}
          </div>
        </div>`;
    }

    return `
    <div class="p-3 rounded" style="border:1px solid var(--rk-border);background:var(--rk-bg)">
      <div class="fw-semibold">${task.title}</div>
      <div class="fs-12 text-muted mt-1">${task.status} • ${String(task.format || 'report').toUpperCase()} report</div>
    </div>`;
}

async function terminateTask(type, id) {
    if (type === 'scan') {
        const confirmed = await rkConfirm('Terminate this scan and keep only completed target results?', 'Terminate Scan');
        if (!confirmed) return;
        const res = await API.delete(`/api/scan/${id}`);
        if (!res || !res.ok) {
            showToast('Failed to terminate the scan', 'danger');
            return;
        }
        showToast(`Scan #${id} termination requested`, 'warning');
    } else if (type === 'discovery') {
        const confirmed = await rkConfirm('Terminate this discovery, save the results found so far, and queue a scan for the live targets?', 'Terminate Discovery');
        if (!confirmed) return;
        const res = await API.post(`/api/assets/discover/subdomains/${id}/terminate`, {});
        if (!res || !res.ok) {
            showToast('Failed to terminate subdomain discovery', 'danger');
            return;
        }
        const data = await res.json();
        showToast(data.message || 'Discovery termination requested', data.scan_started ? 'warning' : 'info');
        if (data.scan_started && typeof window.watchQueuedScan === 'function') {
            window.watchQueuedScan(data.scan_id, data.target_count || data.live_count || 0);
        }
    }

    await loadTaskStatus();
    await openTaskStatusModal();
}

async function confirmLargeScan(count) {
    if (count <= 100) return true;
    return rkConfirm(`Warning! You are about to scan ${count} targets. Continue?`, 'Large Scan Warning');
}

window.confirmLargeScan = confirmLargeScan;

function toggleSidebar() {
    document.getElementById('sidebar')?.classList.toggle('collapsed');
}

// ── Global search ─────────────────────────────────────────────────────────
async function doSearch(q) {
    if (q.length < 2) { document.getElementById('searchDropdown')?.classList.remove('show'); return; }
    const res = await API.get(`/api/assets?search=${encodeURIComponent(q)}&page_size=5`);
    if (!res) return;
    const data = await res.json();
    const drop = document.getElementById('searchDropdown');
    if (!drop) return;
    if (data.assets?.length) {
        drop.innerHTML = data.assets.map(a =>
            `<div class="rk-search-item" onclick="handleSearchClick('${a.url || ''}', '${a.name || ''}')">
                <strong>${a.name}</strong> <span class="text-muted fs-12 ms-2">${a.url}</span>
                <span class="ms-2">${pqcBadge(a.pqc_label)}</span>
            </div>`
        ).join('');
        drop.classList.add('show');
    } else {
        drop.innerHTML = '<div class="rk-search-item text-muted">No results found</div>';
        drop.classList.add('show');
    }
}

async function handleSearchClick(url, name) {
    try {
        const res = await API.get('/api/cbom');
        if (res && res.ok) {
            const snaps = await res.json();
            const searchTarget = url || name;
            const latest = snaps.find(s => s.target === url || (name && s.target.includes(name)));
            if (latest) {
                window.location.href = `/cbom?open_target=${encodeURIComponent(latest.target)}`;
                return;
            }
        }
    } catch (err) {
        console.error('Failed to resolve CBOM route', err);
    }
    // Fallback to asset inventory
    window.location.href = '/asset-inventory?search=' + encodeURIComponent(name || url);
}// ── Time filter ───────────────────────────────────────────────────────────
function applyTimeFilter() {
    const start = document.getElementById('filterStart')?.value;
    const end   = document.getElementById('filterEnd')?.value;
    window._timeFilter = { start, end };
    showToast('Time filter applied', 'info');
    if (typeof loadPageData === 'function') loadPageData();
    if (typeof loadScans === 'function') loadScans();
    if (typeof loadMetrics === 'function') loadMetrics();
    if (typeof loadAssets === 'function') loadAssets();
    if (typeof loadDiscoveries === 'function') loadDiscoveries();
    if (typeof loadCBOMMetrics === 'function') loadCBOMMetrics();
    if (typeof loadCBOMList === 'function') loadCBOMList();
    if (typeof loadRating === 'function') loadRating();
    if (typeof loadHistory === 'function') loadHistory();
    if (typeof loadPQCPosture === 'function') loadPQCPosture();
    if (typeof loadReports === 'function') loadReports();
}

// ── PQC Badge renderer ────────────────────────────────────────────────────
const PQC_BADGE_MAP = {
    'fully_quantum_safe': ['badge-fully-qs',  '🟢 Fully Quantum Safe'],
    'pqc_ready':          ['badge-pqc-ready', '🔵 PQC Ready'],
    'partially_quantum_safe': ['badge-qs',    '🟡 Partially Quantum-Safe'],
    'not_quantum_safe':   ['badge-not-qs',     '❌ Not Quantum-Safe'],
    'unknown':            ['badge-unknown',    '⚪ Unknown'],
};

function pqcBadge(label) {
    const [cls, text] = PQC_BADGE_MAP[label] || PQC_BADGE_MAP['unknown'];
    return `<span class="rk-badge-label ${cls}">${text}</span>`;
}

function riskBadge(risk) {
    const map = {
        critical: 'badge bg-danger',
        high:     'badge bg-warning text-dark',
        medium:   'badge bg-info text-dark',
        low:      'badge bg-success',
        unknown:  'badge bg-secondary',
    };
    return `<span class="${map[risk] || 'badge bg-secondary'}">${(risk||'unknown').toUpperCase()}</span>`;
}

// ── Chart helpers ─────────────────────────────────────────────────────────
const CHART_COLORS = {
    fully_quantum_safe: '#2ECC71',
    pqc_ready:          '#3498DB',
    partially_quantum_safe: '#F1C40F',
    not_quantum_safe:   '#E74C3C',
    unknown:            '#7D8590',
};

function createDonutChart(canvasId, labels, values, colors, onClick) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return;
    
    // Destroy existing chart if it exists to prevent overlap
    if (window[canvasId + 'Inst']) {
        window[canvasId + 'Inst'].destroy();
    }
    
    const chart = new Chart(ctx, {
        type: 'doughnut',
        data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }] },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '65%',
            plugins: { legend: { position: 'right', labels: { color: getComputedStyle(document.documentElement).getPropertyValue('--rk-text').trim(), font: { size: 12 }, padding: 12, boxWidth: 12 } } },
            onClick: onClick ? onClick : undefined,
            onHover: (event, chartElement) => {
                if (onClick) {
                    event.native.target.style.cursor = chartElement[0] ? 'pointer' : 'default';
                }
            }
        }
    });
    window[canvasId + 'Inst'] = chart;
    return chart;
}

function createBarChart(canvasId, labels, datasets) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return;
    return new Chart(ctx, {
        type: 'bar',
        data: { labels, datasets },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { labels: { color: getComputedStyle(document.documentElement).getPropertyValue('--rk-text').trim(), font: { size: 12 } } } },
            scales: {
                x: { ticks: { color: '#7D8590' }, grid: { color: 'rgba(45,63,85,0.5)' } },
                y: { ticks: { color: '#7D8590' }, grid: { color: 'rgba(45,63,85,0.5)' } },
            }
        }
    });
}

function createLineChart(canvasId, labels, datasets) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return;
    return new Chart(ctx, {
        type: 'line',
        data: { labels, datasets },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { labels: { color: getComputedStyle(document.documentElement).getPropertyValue('--rk-text').trim(), font: { size: 12 } } } },
            scales: {
                x: { ticks: { color: '#7D8590', maxTicksLimit: 8 }, grid: { color: 'rgba(45,63,85,0.3)' } },
                y: { ticks: { color: '#7D8590' }, grid: { color: 'rgba(45,63,85,0.3)' } },
            },
            elements: { line: { tension: 0.4 } }
        }
    });
}

// ── Score Gauge ───────────────────────────────────────────────────────────
function drawGauge(canvasId, score, maxScore = 1000) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return;
    const pct = score / maxScore;
    const color = score >= 800 ? '#2ECC71' : score >= 600 ? '#3498DB' : score >= 300 ? '#F1C40F' : '#E74C3C';
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, maxScore - score],
                backgroundColor: [color, 'rgba(45,63,85,0.4)'],
                borderWidth: 0,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            cutout: '72%', rotation: -90, circumference: 180,
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
        }
    });
}

// ── Toast notifications ───────────────────────────────────────────────────
function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const colorMap = { success: '#2ECC71', danger: '#E74C3C', error: '#E74C3C', info: '#3498DB', warning: '#F1C40F' };
    const id = 'toast-' + Date.now();
    container.insertAdjacentHTML('beforeend', `
        <div id="${id}" class="toast align-items-center text-white border-0 show" role="alert" style="background:var(--rk-surface);border:1px solid ${colorMap[type]}!important;min-width:280px">
            <div class="d-flex">
                <div class="toast-body" style="color:var(--rk-text)">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="document.getElementById('${id}').remove()"></button>
            </div>
        </div>
    `);
    setTimeout(() => document.getElementById(id)?.remove(), 4000);
}

// ── Pagination helper ─────────────────────────────────────────────────────
function renderPagination(containerId, currentPage, totalPages, onPageChange) {
    const cont = document.getElementById(containerId);
    if (!cont) return;
    let html = '<nav><ul class="pagination pagination-sm mb-0">';
    html += `<li class="page-item ${currentPage===1?'disabled':''}"><a class="page-link" href="#" onclick="(${onPageChange})(${currentPage-1})">‹</a></li>`;
    for (let p = Math.max(1, currentPage-2); p <= Math.min(totalPages, currentPage+2); p++) {
        html += `<li class="page-item ${p===currentPage?'active':''}"><a class="page-link" href="#" onclick="(${onPageChange})(${p})">${p}</a></li>`;
    }
    html += `<li class="page-item ${currentPage===totalPages?'disabled':''}"><a class="page-link" href="#" onclick="(${onPageChange})(${currentPage+1})">›</a></li>`;
    html += '</ul></nav>';
    cont.innerHTML = html;
}

// ── Date formatter ────────────────────────────────────────────────────────







function shiftToIST(dt) {
    if (!dt) return null;
    let d = new Date(dt);
    // Add 5 hours and 30 minutes (330 minutes) to convert from GMT to IST natively in the frontend
    d.setMinutes(d.getMinutes() + 330);
    return d;
}

function fmtDate(dt) {
    if (!dt) return '—';
    return shiftToIST(dt).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' });
}

function fmtDateTime(dt) {
    if (!dt) return '—';
    return shiftToIST(dt).toLocaleString('en-IN', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' });
}

// ── Session Idle Timeout ──────────────────────────────────────────────────
let _lastActivity = Date.now();
const _IDLE_TIMEOUT = 30 * 60 * 1000; // 30 minutes in ms

function _updateActivity() {
    const now = Date.now();
    // Throttle cookie updates to avoid excessive writing (e.g. once every 60s)
    if (now - _lastActivity > 60000) {
        const token = API.token;
        if (token) {
            document.cookie = `access_token=${token}; path=/; max-age=1800`;
        }
    }
    _lastActivity = now;
}

if (window.location.pathname !== '/login') {
    ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(evt => {
        document.addEventListener(evt, _updateActivity, { passive: true });
    });

    setInterval(() => {
        if (Date.now() - _lastActivity > _IDLE_TIMEOUT) {
            if (API.token) {
                logout();
            }
        }
    }, 10000);
}

// ── Global Custom Modal / Dialogs ──────────────────────────────────────────
let _rkGlobalModalInstance = null;

function _initRkModal() {
    let modalEl = document.getElementById('rkGlobalModal');
    if (!modalEl) {
        document.body.insertAdjacentHTML('beforeend', `
        <div class="modal fade" id="rkGlobalModal" tabindex="-1" aria-hidden="true" style="backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); z-index: 1055;">
          <div class="modal-dialog modal-dialog-centered" style="max-width: 420px;">
            <div class="modal-content" style="background: var(--rk-surface, transparent); color: var(--rk-text, #E6EDF3); border: 1px solid var(--rk-border, #30363d); border-radius: 16px; box-shadow: 0 16px 48px rgba(0,0,0,0.5);">
              <div class="modal-header align-items-center border-0" style="padding: 1.5rem 1.5rem 0.5rem;">
                <div class="d-flex align-items-center gap-3">
                  <div id="rkGlobalModalIconBox" style="width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.25rem;">
                    <i id="rkGlobalModalIcon"></i>
                  </div>
                  <h5 class="modal-title fw-bold m-0" id="rkGlobalModalTitle" style="color: var(--rk-text, #fff); font-size: 18px; letter-spacing: -0.3px;"></h5>
                </div>
                <button type="button" class="btn-close btn-close-white ms-auto" id="rkGlobalModalClose" aria-label="Close"></button>
              </div>
              <div class="modal-body fs-14" id="rkGlobalModalBody" style="padding: 1rem 1.5rem 1.5rem; color: var(--rk-text-muted, #8b949e); line-height: 1.5;">
              </div>
              <div class="modal-footer border-0" style="padding: 0 1.5rem 1.5rem; justify-content: flex-end; gap: 8px;">
                <button type="button" class="rk-btn rk-btn-outline" id="rkGlobalModalDecline" style="padding: 8px 20px; font-weight: 600;">Decline</button>
                <button type="button" class="rk-btn" id="rkGlobalModalConfirm" style="padding: 8px 20px; font-weight: 600; box-shadow: 0 4px 12px rgba(0,0,0,0.15);">Confirm</button>
              </div>
            </div>
          </div>
        </div>`);
        modalEl = document.getElementById('rkGlobalModal');
    }
    
    // Safety check for Bootstrap
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        if (!_rkGlobalModalInstance) {
            _rkGlobalModalInstance = new bootstrap.Modal(modalEl, { backdrop: 'static', keyboard: true });
        }
        return _rkGlobalModalInstance;
    } else {
        // Fallback for login.html which might not have bootstrap JS running
        return {
            show: () => {
                modalEl.classList.add('show');
                modalEl.style.display = 'block';
                document.body.insertAdjacentHTML('beforeend', '<div class="modal-backdrop fade show" id="rkModalBackdrop" style="backdrop-filter: blur(8px);"></div>');
            },
            hide: () => {
                modalEl.classList.remove('show');
                modalEl.style.display = 'none';
                const backdrop = document.getElementById('rkModalBackdrop');
                if (backdrop) backdrop.remove();
            }
        };
    }
}

function rkConfirm(message, title = 'Confirm Action', isDestructive = false) {
    return new Promise((resolve) => {
        const modal = _initRkModal();
        const el = document.getElementById('rkGlobalModal');
        
        document.getElementById('rkGlobalModalTitle').textContent = title;
        document.getElementById('rkGlobalModalBody').innerHTML = message;
        
        const iconBox = document.getElementById('rkGlobalModalIconBox');
        const icon = document.getElementById('rkGlobalModalIcon');
        const confirmBtn = document.getElementById('rkGlobalModalConfirm');
        const declineBtn = document.getElementById('rkGlobalModalDecline');
        const closeBtn = document.getElementById('rkGlobalModalClose');
        
        confirmBtn.textContent = isDestructive ? 'Delete' : 'Confirm';
        declineBtn.textContent = isDestructive ? 'Cancel' : 'Decline';
        declineBtn.style.display = 'inline-flex';
        
        if (isDestructive) {
            iconBox.style.background = 'rgba(220, 38, 38, 0.15)'; // red light
            icon.className = 'bi bi-exclamation-triangle-fill text-danger';
            confirmBtn.style.background = '#DC2626';
            confirmBtn.style.color = '#FFF';
            confirmBtn.style.border = '1px solid #DC2626';
            declineBtn.style.background = 'transparent';
            declineBtn.style.color = 'var(--rk-text)';
            declineBtn.style.border = '1px solid var(--rk-border)';
        } else {
            iconBox.style.background = 'rgba(249, 187, 26, 0.15)'; // yellow/accent
            icon.className = 'bi bi-question-circle-fill text-warning';
            confirmBtn.style.background = 'var(--rk-accent, #A3112E)';
            confirmBtn.style.color = '#FFF';
            confirmBtn.style.border = 'none';
            declineBtn.style.background = 'transparent';
            declineBtn.style.color = 'var(--rk-text)';
            declineBtn.style.border = '1px solid var(--rk-border)';
        }

        const handleConfirm = () => { cleanup(); resolve(true); modal.hide(); };
        const handleCancel = () => { cleanup(); resolve(false); modal.hide(); };
        
        confirmBtn.onclick = handleConfirm;
        declineBtn.onclick = handleCancel;
        closeBtn.onclick = handleCancel;
        
        const cleanup = () => {
            confirmBtn.onclick = null;
            declineBtn.onclick = null;
            closeBtn.onclick = null;
        };
        modal.show();
    });
}

function rkAlert(message, title = 'Information', type = 'info') {
    return new Promise((resolve) => {
        const modal = _initRkModal();
        const el = document.getElementById('rkGlobalModal');
        
        document.getElementById('rkGlobalModalTitle').textContent = title;
        document.getElementById('rkGlobalModalBody').innerHTML = message;
        
        const iconBox = document.getElementById('rkGlobalModalIconBox');
        const icon = document.getElementById('rkGlobalModalIcon');
        const confirmBtn = document.getElementById('rkGlobalModalConfirm');
        const declineBtn = document.getElementById('rkGlobalModalDecline');
        const closeBtn = document.getElementById('rkGlobalModalClose');
        
        confirmBtn.textContent = 'OK';
        confirmBtn.style.background = 'var(--rk-accent-bg, #f9bb1a)';
        confirmBtn.style.color = '#FFF';
        confirmBtn.style.border = 'none';
        declineBtn.style.display = 'none';

        if (type === 'success') {
            iconBox.style.background = 'rgba(34, 197, 94, 0.15)'; // green light
            icon.className = 'bi bi-check-circle-fill text-success';
        } else if (type === 'error') {
            iconBox.style.background = 'rgba(220, 38, 38, 0.15)'; // red light
            icon.className = 'bi bi-x-circle-fill text-danger';
        } else {
            iconBox.style.background = 'rgba(56, 189, 248, 0.15)'; // blue light
            icon.className = 'bi bi-info-circle-fill text-primary';
        }

        const handleConfirm = () => { cleanup(); resolve(true); modal.hide(); };
        const handleClose = () => { cleanup(); resolve(false); modal.hide(); };
        const cleanup = () => {
            confirmBtn.onclick = null;
            declineBtn.onclick = null;
            closeBtn.onclick = null;
        };
        confirmBtn.onclick = handleConfirm;
        closeBtn.onclick = handleClose;

        modal.show();
    });
}

window.rkConfirm = rkConfirm;
window.rkAlert = rkAlert;
window.openProfileModal = openProfileModal;
window.goToUsersFromProfile = goToUsersFromProfile;
window.openTaskStatusModal = openTaskStatusModal;
