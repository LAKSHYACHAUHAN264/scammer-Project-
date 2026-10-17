/* ==========================================
   PhishGuard — Frontend JavaScript
   Communicates with FastAPI backend
   ========================================== */

// Automatically detect API host: relative path on Render/web, or localhost:8000 when opened via file://
const API_BASE = (window.location.protocol === 'file:')
  ? 'http://localhost:8000'
  : '';

// ── DOM References ──────────────────────────────────────────
const analyzeBtn     = document.getElementById('analyzeBtn');
const clearBtn       = document.getElementById('clearBtn');
const pasteBtn       = document.getElementById('pasteBtn');
const emailBody      = document.getElementById('emailBody');
const senderEmail    = document.getElementById('senderEmail');
const subjectLine    = document.getElementById('subjectLine');
const charCount      = document.getElementById('charCount');
const loadPhishingBtn= document.getElementById('loadPhishing');
const loadLegitBtn   = document.getElementById('loadLegit');
const reanalyzeBtn   = document.getElementById('reanalyzeBtn');
const serverStatus   = document.getElementById('serverStatus');
const serverStatusTxt= document.getElementById('serverStatusText');

const idleState      = document.getElementById('idleState');
const loadingState   = document.getElementById('loadingState');
const resultState    = document.getElementById('resultState');

// ── Sample Emails ───────────────────────────────────────────
const phishingSample = {
  sender: 'security-alert@payp4l-support.xyz',
  subject: 'URGENT: Your PayPal account has been limited!',
  body: `Dear Valued Customer,

We have detected unusual activity on your PayPal account and it has been temporarily limited.

To restore full access to your account, you must verify your information IMMEDIATELY.

Click here to verify: http://payp4l-secure.xyz/restore?token=abc123&redirect=true

If you do not verify within 24 hours, your account will be permanently suspended and all funds will be frozen.

You may also be held liable for any unauthorized transactions.

Verify Now: http://payp4l-secure.xyz/verify-account
Alternative link: http://bit.ly/3xPayPalFix

Thank you for your prompt attention to this matter.

PayPal Security Team
paypal.com (secure division)
Do not reply to this email.`
};

const legitSample = {
  sender: 'newsletter@github.com',
  subject: 'Your GitHub monthly digest - October 2026',
  body: `Hi there,

Here's your monthly GitHub digest for October 2026.

This month's highlights:
- GitHub Actions now supports ARM64 runners
- Copilot Workspace is generally available
- New security scanning features added to all plans

Trending repositories this week:
- microsoft/TypeScript: 98.4k stars
- facebook/react: 224k stars
- torvalds/linux: 175k stars

Check out what's new on GitHub: https://github.com/explore

Your repositories had 47 commits across 3 repos this month. Keep it up!

You're receiving this email because you signed up for GitHub updates.
Manage your notification preferences: https://github.com/settings/notifications
Unsubscribe: https://github.com/unsubscribe

GitHub, Inc. 88 Colin P Kelly Jr Street, San Francisco, CA 94107`
};

// ── Server Health Check ──────────────────────────────────────
async function checkServerHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      serverStatus.className = 'status-dot online';
      serverStatusTxt.textContent = 'API Online';
    } else {
      throw new Error('Bad response');
    }
  } catch {
    serverStatus.className = 'status-dot offline';
    serverStatusTxt.textContent = 'API Offline';
  }
}

checkServerHealth();
setInterval(checkServerHealth, 15000);

// ── Character Counter ────────────────────────────────────────
emailBody.addEventListener('input', () => {
  const len = emailBody.value.length;
  charCount.textContent = `${len.toLocaleString()} character${len !== 1 ? 's' : ''}`;
});

// ── Clear / Paste ────────────────────────────────────────────
clearBtn.addEventListener('click', () => {
  emailBody.value = '';
  senderEmail.value = '';
  subjectLine.value = '';
  charCount.textContent = '0 characters';
  showState('idle');
});

pasteBtn.addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    emailBody.value = text;
    charCount.textContent = `${text.length.toLocaleString()} characters`;
  } catch {
    alert('Clipboard access denied. Please paste manually.');
  }
});

// ── Sample Loaders ───────────────────────────────────────────
loadPhishingBtn.addEventListener('click', () => {
  senderEmail.value = phishingSample.sender;
  subjectLine.value = phishingSample.subject;
  emailBody.value   = phishingSample.body;
  charCount.textContent = `${phishingSample.body.length.toLocaleString()} characters`;
  showState('idle');
  document.getElementById('analyzer').scrollIntoView({ behavior: 'smooth' });
});

loadLegitBtn.addEventListener('click', () => {
  senderEmail.value = legitSample.sender;
  subjectLine.value = legitSample.subject;
  emailBody.value   = legitSample.body;
  charCount.textContent = `${legitSample.body.length.toLocaleString()} characters`;
  showState('idle');
  document.getElementById('analyzer').scrollIntoView({ behavior: 'smooth' });
});

reanalyzeBtn.addEventListener('click', () => showState('idle'));

// ── State Manager ────────────────────────────────────────────
function showState(state) {
  idleState.classList.add('hidden');
  loadingState.classList.add('hidden');
  resultState.classList.add('hidden');

  if (state === 'idle')    idleState.classList.remove('hidden');
  if (state === 'loading') loadingState.classList.remove('hidden');
  if (state === 'result')  resultState.classList.remove('hidden');
}

// ── Loading Steps Animation ──────────────────────────────────
const STEPS = ['step1','step2','step3','step4'];
let stepTimer = null;

function animateLoadingSteps() {
  STEPS.forEach(id => {
    const el = document.getElementById(id);
    el.classList.remove('active','done');
  });
  let current = 0;
  document.getElementById(STEPS[0]).classList.add('active');

  stepTimer = setInterval(() => {
    if (current < STEPS.length) {
      document.getElementById(STEPS[current]).classList.remove('active');
      document.getElementById(STEPS[current]).classList.add('done');
      current++;
      if (current < STEPS.length) {
        document.getElementById(STEPS[current]).classList.add('active');
      }
    } else {
      clearInterval(stepTimer);
    }
  }, 600);
}

// ── Main Analysis ────────────────────────────────────────────
analyzeBtn.addEventListener('click', async () => {
  const body    = emailBody.value.trim();
  const sender  = senderEmail.value.trim();
  const subject = subjectLine.value.trim();

  if (!body && !sender && !subject) {
    shakePanel();
    return;
  }

  showState('loading');
  analyzeBtn.classList.add('loading');
  animateLoadingSteps();

  try {
    const response = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender, subject, body }),
      signal: AbortSignal.timeout(15000)
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'Server error');
    }

    const data = await response.json();
    clearInterval(stepTimer);
    // Mark all steps done
    STEPS.forEach(id => {
      document.getElementById(id).classList.remove('active');
      document.getElementById(id).classList.add('done');
    });

    setTimeout(() => renderResults(data), 300);

  } catch (err) {
    clearInterval(stepTimer);
    showState('idle');
    showError(err.message.includes('timeout') ? 'Request timed out. Is the backend running?' : `Error: ${err.message}`);
  } finally {
    analyzeBtn.classList.remove('loading');
  }
});

// ── Render Results ───────────────────────────────────────────
function renderResults(data) {
  showState('result');

  // Verdict Banner
  const banner = document.getElementById('verdictBanner');
  const icon   = document.getElementById('verdictIcon');
  const label  = document.getElementById('verdictLabel');
  const desc   = document.getElementById('verdictDesc');

  banner.className = 'verdict-banner';
  const score = data.risk_score || 0;

  if (data.verdict === 'PHISHING') {
    banner.classList.add('danger');
    icon.textContent  = '🚨';
    label.textContent = 'Phishing Detected';
    desc.textContent  = 'High probability this email is a phishing attempt. Do not click any links.';
  } else if (data.verdict === 'SUSPICIOUS') {
    banner.classList.add('warning');
    icon.textContent  = '⚠️';
    label.textContent = 'Suspicious Email';
    desc.textContent  = 'This email shows several warning signs. Exercise extreme caution.';
  } else {
    banner.classList.add('safe');
    icon.textContent  = '✅';
    label.textContent = 'Appears Legitimate';
    desc.textContent  = 'No significant phishing indicators detected. Always stay cautious.';
  }

  // Risk Score Arc
  animateScoreArc(score, data.verdict);

  // Breakdown Bars
  renderBreakdown(data.breakdown || {});

  // Indicators
  renderIndicators(data.indicators || []);

  // URLs
  renderUrls(data.url_analysis || []);

  // Recommendations
  renderRecommendations(data.recommendations || []);
}

// ── Score Arc Animation ──────────────────────────────────────
function animateScoreArc(score, verdict) {
  const arc        = document.getElementById('scoreArc');
  const scoreNum   = document.getElementById('scoreNumber');
  const circumference = 251; // 2 * π * 40

  const colorMap = {
    PHISHING:   '#ff4757',
    SUSPICIOUS: '#ffa502',
    LEGITIMATE: '#2ed573'
  };
  arc.style.stroke = colorMap[verdict] || '#6c63ff';

  const offset = circumference - (score / 100) * circumference;
  requestAnimationFrame(() => {
    setTimeout(() => { arc.style.strokeDashoffset = offset; }, 100);
  });

  // Count-up animation
  let current = 0;
  const step = score / 60;
  const timer = setInterval(() => {
    current = Math.min(current + step, score);
    scoreNum.textContent = Math.round(current);
    if (current >= score) clearInterval(timer);
  }, 16);
}

// ── Breakdown Bars ───────────────────────────────────────────
function renderBreakdown(breakdown) {
  const container = document.getElementById('breakdownBars');
  container.innerHTML = '';

  const categories = [
    { key: 'url_risk',      label: 'URL Risk',          color: 'danger'  },
    { key: 'sender_risk',   label: 'Sender Risk',        color: 'warning' },
    { key: 'content_risk',  label: 'Content Risk',       color: 'warning' },
    { key: 'urgency_score', label: 'Urgency / Pressure', color: 'danger'  },
    { key: 'legitimacy',    label: 'Legitimacy Signals',  color: 'safe'    },
  ];

  categories.forEach(cat => {
    const val = Math.round((breakdown[cat.key] || 0) * 100);
    const item = document.createElement('div');
    item.className = 'breakdown-item';
    item.innerHTML = `
      <div class="breakdown-label">
        <span>${cat.label}</span>
        <span>${val}%</span>
      </div>
      <div class="breakdown-bar">
        <div class="breakdown-fill fill-${cat.color}" style="width:0%" data-target="${val}%"></div>
      </div>
    `;
    container.appendChild(item);
  });

  // Animate fills
  requestAnimationFrame(() => {
    setTimeout(() => {
      container.querySelectorAll('.breakdown-fill').forEach(fill => {
        fill.style.width = fill.dataset.target;
      });
    }, 200);
  });
}

// ── Indicators ───────────────────────────────────────────────
function renderIndicators(indicators) {
  const list = document.getElementById('indicatorsList');
  list.innerHTML = '';

  if (!indicators.length) {
    list.innerHTML = '<div class="indicator-item info"><span class="indicator-badge">INFO</span>No significant indicators detected.</div>';
    return;
  }

  indicators.forEach(ind => {
    const item = document.createElement('div');
    item.className = `indicator-item ${ind.severity.toLowerCase()}`;
    item.innerHTML = `
      <span class="indicator-badge">${ind.severity}</span>
      <span>${escapeHtml(ind.description)}</span>
    `;
    list.appendChild(item);
  });
}

// ── URL Analysis ─────────────────────────────────────────────
function renderUrls(urls) {
  const section = document.getElementById('urlsSection');
  const list    = document.getElementById('urlsList');

  if (!urls.length) {
    section.style.display = 'none';
    return;
  }
  section.style.display = 'block';
  list.innerHTML = '';

  urls.forEach(u => {
    const item = document.createElement('div');
    item.className = 'url-item';

    const flags = (u.flags || []).map(f => {
      const cls = f.level === 'danger' ? 'flag-danger' : f.level === 'warning' ? 'flag-warning' : 'flag-safe';
      return `<span class="url-flag ${cls}">${escapeHtml(f.label)}</span>`;
    }).join('');

    item.innerHTML = `
      <div class="url-text">${escapeHtml(u.url)}</div>
      <div class="url-flags">${flags}</div>
    `;
    list.appendChild(item);
  });
}

// ── Recommendations ──────────────────────────────────────────
function renderRecommendations(recs) {
  const list = document.getElementById('recommendationsList');
  list.innerHTML = '';

  if (!recs.length) {
    list.innerHTML = '<div class="rec-item"><span class="rec-icon">✔</span>No action required. The email appears safe.</div>';
    return;
  }

  recs.forEach(rec => {
    const item = document.createElement('div');
    item.className = 'rec-item';
    item.innerHTML = `<span class="rec-icon">${escapeHtml(rec.icon || '•')}</span><span>${escapeHtml(rec.text)}</span>`;
    list.appendChild(item);
  });
}

// ── Helpers ──────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function shakePanel() {
  const panel = document.querySelector('.input-panel');
  panel.style.animation = 'none';
  panel.offsetHeight; // reflow
  panel.style.animation = 'shake 0.4s cubic-bezier(0.36,0.07,0.19,0.97)';
  setTimeout(() => panel.style.animation = '', 500);
}

function showError(msg) {
  const errDiv = document.createElement('div');
  errDiv.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    background: rgba(255,71,87,0.15); border: 1px solid rgba(255,71,87,0.4);
    backdrop-filter: blur(20px); color: #ff8a94;
    padding: 14px 20px; border-radius: 12px; font-size: 0.875rem;
    font-weight: 600; max-width: 340px; animation: fadeInUp 0.3s both;
  `;
  errDiv.textContent = msg;
  document.body.appendChild(errDiv);
  setTimeout(() => errDiv.remove(), 5000);
}

// Add shake keyframe dynamically
const styleEl = document.createElement('style');
styleEl.textContent = `
  @keyframes shake {
    10%,90%  { transform: translateX(-2px); }
    20%,80%  { transform: translateX(4px); }
    30%,50%,70% { transform: translateX(-6px); }
    40%,60%  { transform: translateX(6px); }
  }
`;
document.head.appendChild(styleEl);

// ── Counter Animation (Stats Section) ───────────────────────
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const el = entry.target;
      const target = parseFloat(el.dataset.target);
      const isDecimal = target % 1 !== 0;
      const duration = 1800;
      const start = performance.now();

      function updateCounter(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 4);
        const current = target * eased;
        el.textContent = isDecimal ? current.toFixed(1) : Math.round(current);
        if (progress < 1) requestAnimationFrame(updateCounter);
      }
      requestAnimationFrame(updateCounter);
      observer.unobserve(el);
    }
  });
}, { threshold: 0.5 });

document.querySelectorAll('.stat-value').forEach(el => observer.observe(el));

// ── Nav Active Highlight on Scroll ───────────────────────────
const sections = document.querySelectorAll('section[id]');
const navLinks  = document.querySelectorAll('.nav-link');

const sectionObserver = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      navLinks.forEach(a => {
        a.classList.toggle('active', a.getAttribute('href') === `#${e.target.id}`);
      });
    }
  });
}, { threshold: 0.4 });

sections.forEach(s => sectionObserver.observe(s));
