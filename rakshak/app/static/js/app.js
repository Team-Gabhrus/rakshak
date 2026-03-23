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
    localStorage.clear();
    document.cookie = 'access_token=; path=/; max-age=0';
    window.location.href = '/login';
}

// ── Sidebar / topbar init ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const username = localStorage.getItem('username') || 'User';
    const role     = localStorage.getItem('role') || 'checker';
    const el = document.getElementById('currentUsername');
    const re = document.getElementById('currentRole');
    if (el) el.textContent = username;
    if (re) re.textContent = role.charAt(0).toUpperCase() + role.slice(1);

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
    if (window.location.pathname !== '/login' && !localStorage.getItem('token')) {
        window.location.href = '/login';
    }
});

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
            `<div class="rk-search-item" onclick="window.location='/asset-inventory?search=' + encodeURIComponent(a.name||a.url)">
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

// ── Time filter ───────────────────────────────────────────────────────────
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

function createDonutChart(canvasId, labels, values, colors) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return;
    return new Chart(ctx, {
        type: 'doughnut',
        data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }] },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '65%',
            plugins: { legend: { position: 'right', labels: { color: getComputedStyle(document.documentElement).getPropertyValue('--rk-text').trim(), font: { size: 12 }, padding: 12, boxWidth: 12 } } }
        }
    });
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
                x: { ticks: { color: '#7D8590' }, grid: { color: 'rgba(45,63,85,0.3)' } },
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
    const colorMap = { success: '#2ECC71', danger: '#E74C3C', info: '#3498DB', warning: '#F1C40F' };
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
