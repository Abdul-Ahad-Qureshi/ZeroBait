/* ==========================================================================
   Threat Intelligence — Luxury Monochrome JavaScript Engine & Forensic Suite
   ========================================================================== */

/* HTML Sanitizer (XSS Prevention) */
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
window.escapeHtml = escapeHtml;

/* Toast Notifications */
function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const icons = {
        success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
        error:   '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        info:    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
        warning: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    };
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span class="toast-icon">${icons[type] || icons.info}</span><span class="toast-msg">${escapeHtml(message)}</span><button class="toast-close" onclick="this.parentElement.remove()">×</button>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('toast-hide');
        setTimeout(() => toast.remove(), 400);
    }, duration);
}
window.showToast = showToast;

/* Particles.js initialization with ZeroBait Electric Cyan & Azure Palette */
if (typeof particlesJS !== 'undefined') {
    particlesJS("particles-js", {
        particles: {
            number: { value: 45, density: { enable: true, value_area: 900 } },
            color: { value: ["#ffffff", "#00d2ff", "#0084ff"] },
            opacity: { value: 0.25, random: true },
            size: { value: 2.2, random: true },
            line_linked: { enable: true, distance: 130, color: "#00d2ff", opacity: 0.12, width: 1 },
            move: { enable: true, speed: 0.6, direction: "none", random: true, out_mode: "out" }
        },
        interactivity: {
            detect_on: "canvas",
            events: {
                onhover: { enable: true, mode: "grab" },
                onclick: { enable: true, mode: "push" },
                resize: true
            },
            modes: { grab: { distance: 140, line_linked: { opacity: 0.25 } }, push: { particles_nb: 2 } }
        },
        retina_detect: true
    });
}

/* Scan form loading state */
const scanForm   = document.getElementById('scan-form');
const analyzeBtn = document.getElementById('analyze-btn');
if (scanForm && analyzeBtn) {
    scanForm.addEventListener('submit', () => {
        analyzeBtn.innerHTML = '<span class="spinner"></span><span>Evaluating…</span>';
        setTimeout(() => { analyzeBtn.disabled = true; }, 50);
    });
}

/* Tab switching (Single vs Bulk) */
function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    const tab   = document.getElementById('tab-'   + name);
    const panel = document.getElementById('panel-' + name);
    if (tab)   { tab.classList.add('active');   tab.setAttribute('aria-selected', 'true'); }
    if (panel) { panel.classList.add('active'); }
}
window.switchTab = switchTab;

/* Forensic Tabs Switching */
function switchForensicTab(tabId) {
    const panels = {
        'overview': document.getElementById('fpanel-overview'),
        'dns-mail': document.getElementById('fpanel-dns-mail'),
        'lexical': document.getElementById('fpanel-lexical')
    };
    
    document.querySelectorAll('.forensic-tab-btn').forEach(btn => btn.classList.remove('active'));
    Object.values(panels).forEach(p => { if (p) p.classList.remove('active'); });

    if (panels[tabId]) panels[tabId].classList.add('active');
    const clickedBtn = Array.from(document.querySelectorAll('.forensic-tab-btn')).find(b => b.getAttribute('onclick')?.includes(tabId));
    if (clickedBtn) clickedBtn.classList.add('active');
}
window.switchForensicTab = switchForensicTab;

/* URL Structure Visualizer */
function renderUrlChips(url) {
    const container = document.getElementById('url-chips');
    if (!container || !url) return;
    try {
        const parsed = new URL(url.trim());
        const chips  = [];

        chips.push({ label: parsed.protocol.replace(':', ''), cls: parsed.protocol === 'https:' ? 'chip-https' : 'chip-http' });

        const hostParts = parsed.hostname.split('.');
        if (hostParts.length > 2) {
            chips.push({ label: hostParts.slice(0, -2).join('.'), cls: 'chip-sub',    title: 'subdomain' });
            chips.push({ label: hostParts.slice(-2, -1)[0],       cls: 'chip-domain', title: 'domain' });
            chips.push({ label: '.' + hostParts.slice(-1)[0],     cls: 'chip-tld',    title: 'TLD' });
        } else if (hostParts.length === 2) {
            chips.push({ label: hostParts[0],               cls: 'chip-domain', title: 'domain' });
            chips.push({ label: '.' + hostParts[1],         cls: 'chip-tld',    title: 'TLD' });
        } else {
            chips.push({ label: parsed.hostname,            cls: 'chip-domain', title: 'host' });
        }

        if (parsed.port) chips.push({ label: ':' + parsed.port, cls: 'chip-port', title: 'port' });

        if (parsed.pathname && parsed.pathname !== '/') {
            const pathLabel = parsed.pathname.length > 30 ? parsed.pathname.slice(0, 28) + '…' : parsed.pathname;
            chips.push({ label: pathLabel, cls: 'chip-path', title: 'path' });
        }

        if (parsed.search) {
            const qLabel = parsed.search.length > 24 ? parsed.search.slice(0, 22) + '…' : parsed.search;
            chips.push({ label: qLabel, cls: 'chip-param', title: 'query parameters' });
        }

        container.innerHTML = chips.map(c =>
            `<span class="url-chip ${escapeHtml(c.cls)}" title="${escapeHtml(c.title || c.cls.replace('chip-', ''))}">${escapeHtml(c.label)}</span>`
        ).join('');
    } catch {
        container.innerHTML = `<span class="url-chip chip-domain" title="raw url">${escapeHtml(url)}</span>`;
    }
}
window.renderUrlChips = renderUrlChips;

/* SVG Arc Gauge Animation */
function animateGauge(targetScore, levelClass) {
    const arc     = document.getElementById('gauge-arc');
    const scoreEl = document.getElementById('score-value');
    if (!arc || !scoreEl) return;

    const totalLength = 251.2;
    let current = 0;
    const step  = targetScore / 50;
    const timer = setInterval(() => {
        current = Math.min(current + step, targetScore);
        arc.style.strokeDashoffset = totalLength - (current / 100) * totalLength;
        scoreEl.textContent = Math.round(current);
        if (current >= targetScore) clearInterval(timer);
    }, 16);
}
window.animateGauge = animateGauge;

/* Stats & Trend Loaders */
async function loadStats() {
    try {
        const res = await fetch('/api/stats');
        if (!res.ok) return;
        const s = await res.json();
        const heroTotal = document.getElementById('hero-stat-total');
        const heroHigh  = document.getElementById('hero-stat-high');

        if (heroTotal) heroTotal.textContent = (s.total_scans ?? 0).toLocaleString();
        if (heroHigh)  heroHigh.textContent  = (s.high_threat  ?? 0).toLocaleString();
    } catch {
        /* Gracefully suppress telemetry loading notice in production */
    }
}

async function loadTrend() {
    try {
        const res = await fetch('/api/trend');
        if (!res.ok) return;
        const data = await res.json();
        renderSparkline(data);
        const label = document.getElementById('trend-days-label');
        if (label && data.length) {
            label.textContent = `${data[0].date.slice(5)} – ${data[data.length - 1].date.slice(5)}`;
        }
    } catch { /* ignore */ }
}

function renderSparkline(data) {
    const svg = document.getElementById('sparkline-svg');
    if (!svg || !data || data.length < 2) return;

    const W = 160, H = 32, PAD = 4;
    const totals = data.map(d => d.total);
    const highs  = data.map(d => d.high);
    const maxVal = Math.max(...totals, 1);
    const xStep  = (W - PAD * 2) / (data.length - 1);

    const coord = (val, idx) => ({
        x: PAD + idx * xStep,
        y: H - PAD - ((val / maxVal) * (H - PAD * 2))
    });

    const pts  = totals.map(coord);
    const hPts = highs.map(coord);
    const poly = arr => arr.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');

    const area = [
        `M ${pts[0].x},${H - PAD}`,
        ...pts.map(p => `L ${p.x.toFixed(1)},${p.y.toFixed(1)}`),
        `L ${pts[pts.length - 1].x},${H - PAD}`,
        'Z'
    ].join(' ');

    svg.innerHTML = `
        <defs>
            <linearGradient id="spark-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%"   stop-color="#ffffff" stop-opacity="0.25"/>
                <stop offset="100%" stop-color="#ffffff" stop-opacity="0"/>
            </linearGradient>
        </defs>
        <path d="${area}" fill="url(#spark-grad)"/>
        <polyline points="${poly(pts)}"  fill="none" stroke="#ffffff" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
        <polyline points="${poly(hPts)}" fill="none" stroke="#737373" stroke-width="1" stroke-linejoin="round" stroke-linecap="round" stroke-dasharray="3 2"/>
        ${pts.map((p, i) => `
            <circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2" fill="#ffffff">
                <title>${data[i].date}: ${data[i].total} scans</title>
            </circle>`
        ).join('')}`;
}

/* Live Threat Activity Ticker */
async function loadTicker() {
    const tickerEl = document.getElementById('ticker-text');
    if (!tickerEl) return;
    try {
        const res = await fetch('/api/history?limit=5');
        if (!res.ok) return;
        const scans = await res.json();
        if (scans.length) {
            const items = scans.map(s => {
                const safeDomain = escapeHtml(s.url.replace(/^https?:\/\//, '').split('/')[0]);
                const safeScore = escapeHtml(s.score);
                const safeThreat = escapeHtml(s.threat_level);
                return `<strong>${safeDomain}</strong> (${safeScore}% · ${safeThreat})`;
            });
            tickerEl.innerHTML = `Telemetry Stream: ` + items.join(` &nbsp;·&nbsp; `);
        } else {
            tickerEl.textContent = "Autonomous engine monitoring telemetry feeds...";
        }
    } catch {
        tickerEl.textContent = "Telemetry engine active.";
    }
}

/* History Panel */
let historyFilter   = 'all';
let allHistoryItems = [];

function renderHistoryItems() {
    const container = document.getElementById('scan-history');
    if (!container) return;
    const filtered = historyFilter === 'all'
        ? allHistoryItems
        : allHistoryItems.filter(item => item.threat_level === historyFilter);

    if (!filtered.length) {
        const label = historyFilter !== 'all' ? escapeHtml(historyFilter.toLowerCase()) + ' threat ' : '';
        container.innerHTML = `<p class="muted-text">No ${label}inspections logged yet.</p>`;
        return;
    }
    container.innerHTML = filtered.map(item => {
        const rawLvl = (item.threat_level || 'low').toLowerCase();
        const lvl = rawLvl === 'high' ? 'high' : rawLvl === 'medium' ? 'medium' : 'low';
        const safeUrl = escapeHtml(item.url);
        const safeThreat = escapeHtml(item.threat_level || 'Low');
        const safeScore = escapeHtml(item.score);
        return `
        <div class="flag-item" style="margin-bottom: 0.5rem;">
            <a class="history-url" href="/?url=${encodeURIComponent(item.url)}" title="${safeUrl}" style="color: var(--mono-white); text-decoration: none; word-break: break-all; font-size: 0.85rem; font-family: var(--font-mono);">
                ${safeUrl}
            </a>
            <span class="history-pill pill-${lvl}">${safeScore}% · ${safeThreat}</span>
        </div>`;
    }).join('');
}

async function renderHistory() {
    const container = document.getElementById('scan-history');
    if (!container) return;
    try {
        const res = await fetch('/api/user/history?limit=10');
        if (!res.ok) throw new Error('bad response');
        allHistoryItems = await res.json();
        renderHistoryItems();
    } catch {
        container.innerHTML = '<p class="muted-text">Unable to load personal scan history.</p>';
    }
}
window.renderHistory = renderHistory;

/* Copy Link & Export JSON */
const copyLinkBtn = document.getElementById('copy-link-btn');
if (copyLinkBtn) {
    copyLinkBtn.addEventListener('click', () => {
        const urlEl = document.getElementById('analyzed-url');
        if (!urlEl) return;
        const shareUrl = `${location.origin}/?url=${encodeURIComponent(urlEl.textContent.trim())}`;
        navigator.clipboard.writeText(shareUrl).then(() => {
            showToast('Inspection link copied to clipboard.', 'success');
        }).catch(() => {
            showToast('Copy failed.', 'error');
        });
    });
}

const exportBtn = document.getElementById('export-btn');
if (exportBtn) {
    exportBtn.addEventListener('click', () => {
        const urlEl    = document.getElementById('analyzed-url');
        const gaugeEl  = document.getElementById('score-circle');
        const threatEl = document.querySelector('.threat-badge');
        if (!urlEl || !gaugeEl) return;

        const data = {
            url:          urlEl.textContent.trim(),
            score:        parseFloat(gaugeEl.getAttribute('data-score')),
            threat_level: threatEl ? threatEl.textContent.trim() : '—',
            exported_at:  new Date().toISOString()
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `threat_report_${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(link.href);
        showToast('Audit report exported as JSON.', 'success');
    });
}

/* Bulk Scanner */
const bulkScanBtn = document.getElementById('bulk-scan-btn');
const bulkInput   = document.getElementById('bulk-input');
const bulkResults = document.getElementById('bulk-results');

function renderBulkTable(results) {
    if (!bulkResults) return;

    const rows = results.map(r => {
        const rawUrl = r.url || '?';
        const safeUrl = escapeHtml(rawUrl);
        if (r.error) {
            return `<tr>
                <td title="${safeUrl}">${safeUrl}</td>
                <td colspan="3" style="color:#a3a3a3; font-size:0.8rem;">${escapeHtml(r.error)}</td>
            </tr>`;
        }
        const rawLvl = (r.threat_level || 'low').toLowerCase();
        const lvl = rawLvl === 'high' ? 'high' : rawLvl === 'medium' ? 'medium' : 'low';
        const flagsList = (r.flags || []).map(f => f.label).slice(0, 2).join(', ') || 'Benign Baseline';
        const safeFlags = escapeHtml(flagsList);
        const safeScore = escapeHtml(r.score);
        const safeThreat = escapeHtml(r.threat_level || 'Low');
        return `<tr>
            <td title="${safeUrl}">
                <a href="/?url=${encodeURIComponent(r.url)}" style="color:#ffffff; text-decoration:underline; font-family: var(--font-mono); font-size:0.85rem;" title="Full analysis">${safeUrl}</a>
            </td>
            <td data-score="${safeScore}"><strong>${safeScore}%</strong></td>
            <td><span class="history-pill pill-${lvl}">${safeThreat}</span></td>
            <td style="font-size:0.8rem; color:var(--text-secondary);">${safeFlags}</td>
        </tr>`;
    }).join('');

    bulkResults.innerHTML = `
        <table class="bulk-table" id="bulk-table">
            <thead><tr>
                <th>Target URL</th>
                <th>Risk Score</th>
                <th>Classification</th>
                <th>Key Threat Indicators</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
}

if (bulkScanBtn && bulkInput && bulkResults) {
    bulkScanBtn.addEventListener('click', async () => {
        const rawUrls = bulkInput.value.trim().split('\n').map(u => u.trim()).filter(Boolean);
        if (!rawUrls.length) { showToast('Please enter at least one URL.', 'warning'); return; }
        if (rawUrls.length > 25) { showToast('Maximum 25 URLs per batch.', 'warning'); return; }

        bulkScanBtn.disabled = true;
        bulkScanBtn.innerHTML = '<span class="spinner"></span> Inspecting Batch…';
        bulkResults.innerHTML = `<p class="muted-text">Processing ${rawUrls.length} targets...</p>`;

        try {
            const res = await fetch('/predict/bulk', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ urls: rawUrls })
            });
            if (!res.ok) throw new Error('Server error: ' + res.status);
            const results = await res.json();
            renderBulkTable(results);
            showToast(`Batch completed (${results.length} targets).`, 'success');
            loadStats();
            loadTrend();
            loadTicker();
        } catch (err) {
            showToast('Batch scan failed.', 'error');
        } finally {
            bulkScanBtn.disabled = false;
            bulkScanBtn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Analyze Batch';
        }
    });
}

/* Modals Management (Defanger, IOC, QR) */
function openDefangModal() {
    const m = document.getElementById('defang-modal');
    if (m) m.style.display = 'flex';
}
function closeDefangModal() {
    const m = document.getElementById('defang-modal');
    if (m) m.style.display = 'none';
}
function applyDefang() {
    const inp = document.getElementById('defang-input').value.trim();
    if (!inp) return;
    const defanged = inp.replace(/http:\/\//gi, 'hxxp://').replace(/https:\/\//gi, 'hxxps://').replace(/\./g, '[.]');
    document.getElementById('defang-output').textContent = defanged;
}
function applyRefang() {
    const inp = document.getElementById('defang-input').value.trim();
    if (!inp) return;
    const refanged = inp.replace(/hxxp:\/\//gi, 'http://').replace(/hxxps:\/\//gi, 'https://').replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.');
    document.getElementById('defang-output').textContent = refanged;
}
function copyDefanged() {
    const txt = document.getElementById('defang-output').textContent;
    if (txt && txt !== 'Awaiting input...') {
        navigator.clipboard.writeText(txt).then(() => showToast('Defanged string copied!', 'success'));
    }
}

function openIocModal() {
    const m = document.getElementById('ioc-modal');
    if (m) m.style.display = 'flex';
}
function closeIocModal() {
    const m = document.getElementById('ioc-modal');
    if (m) m.style.display = 'none';
}

function openQrModal(url) {
    const modal = document.getElementById('qr-modal');
    const img   = document.getElementById('qr-image');
    const txt   = document.getElementById('qr-url-text');
    if (!modal || !img || !txt) return;

    img.src = `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(url)}&color=000000&bgcolor=ffffff`;
    txt.textContent = url;
    modal.style.display = 'flex';
}
function closeQrModal() {
    const modal = document.getElementById('qr-modal');
    if (modal) modal.style.display = 'none';
}

window.openDefangModal = openDefangModal;
window.closeDefangModal = closeDefangModal;
window.applyDefang = applyDefang;
window.applyRefang = applyRefang;
window.copyDefanged = copyDefanged;
window.openIocModal = openIocModal;
window.closeIocModal = closeIocModal;
window.openQrModal = openQrModal;
window.closeQrModal = closeQrModal;

/* Initialization */
document.addEventListener('DOMContentLoaded', () => {

    const scrollBtn = document.getElementById('scroll-to-scan');
    if (scrollBtn) {
        scrollBtn.addEventListener('click', () => {
            const el = document.getElementById('scanner');
            if (el) el.scrollIntoView({ behavior: 'smooth' });
        });
    }

    const filters = document.getElementById('history-filters');
    if (filters) {
        filters.addEventListener('click', e => {
            const pill = e.target.closest('.filter-pill');
            if (!pill) return;
            filters.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            historyFilter = pill.dataset.filter;
            renderHistoryItems();
        });
    }

    loadStats();
    loadTrend();
    loadTicker();
});
