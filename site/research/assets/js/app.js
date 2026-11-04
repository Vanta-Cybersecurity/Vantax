/* =====================================================================
   VANTAX Advanced Research Division — front-end behaviour
   - Wrapped in an IIFE: creates NO globals.
   - Reads optional overrides from window.VANTAX_ARD_CONFIG (if you define it)
     or from a data-vx-config JSON attribute on the .vantax-ard root.
   - Talks to the vantax-ard-backend API on the same origin (/api/*). When the
     API is reachable, real values replace the demo ones and the DEMO /
     SIMULATED tags switch to LIVE. When it is not, the clearly labelled demo
     values stay. The threat map and the analysis graph have no backend source
     and are ALWAYS demo (tagged DEMO).
   - No innerHTML: every node is created with DOM APIs (strict-CSP safe).
   ===================================================================== */
(function () {
  'use strict';

  var root = document.querySelector('.vantax-ard');
  if (!root) return;

  /* ---------- 1. Configuration ---------------------------------------
     MODULES drives both the sidebar "Research Division" list and the
     Research Domains card grid. Change `route` (or override via config)
     to point each card at a real page on vantax-cybersecurity.com.      */
  var MODULES = [
    { id: 'crypto', title: 'Cryptographic Security', icon: 'i-key', route: '#cryptographic-security',
      desc: 'Key forensics, certificate analysis, and crypto configuration auditing.' },
    { id: 'quantumCryptanalysis', title: 'Quantum Cryptanalysis / PQC', icon: 'i-lock', isNew: true, route: '#quantum-cryptanalysis',
      desc: 'Assess quantum impact and post-quantum migration readiness.' },
    { id: 'network', title: 'Network Protocols', icon: 'i-net', route: '#network-protocols',
      desc: 'Offline PCAP/TLS analysis and authorized local protocol testing.' },
    { id: 'experiments', title: 'Experiment Manager', icon: 'i-db', route: '#experiment-manager',
      desc: 'Track, store, and reproduce research experiments.' },
    { id: 'quantumAlgorithms', title: 'Quantum Algorithms', icon: 'i-cube', isNew: true, route: '#quantum-algorithms',
      desc: 'Classical simulation of quantum algorithms on tiny inputs.' },
    { id: 'quantumHardware', title: 'Quantum Hardware', icon: 'i-chip', isNew: true, route: '#quantum-hardware',
      desc: 'Classical simulation and analysis of small quantum circuits.' }
  ];

  // Demo feed items (simulated). Replace with a real source — see INTEGRATION.md.
  var FEED_POOL = [
    ['Suspicious PE detected (static analysis)', '#a855f7'],
    ['New IOC from malware sample', '#4cc9ff'],
    ['Quantum vuln. pattern identified', '#ec4899'],
    ['Network anomaly detected', '#22e39b'],
    ['Fuzzing crash (reproducible)', '#facc15'],
    ['Certificate chain audit completed', '#22d3ee'],
    ['Firmware image unpacked for review', '#a855f7'],
    ['Experiment #A-219 results archived', '#4cc9ff'],
    ['Post-quantum readiness report generated', '#ec4899']
  ];

  // Merge user config (routes overrides, options).
  var userCfg = {};
  try {
    if (root.dataset.vxConfig) userCfg = JSON.parse(root.dataset.vxConfig);
    else if (window.VANTAX_ARD_CONFIG) userCfg = window.VANTAX_ARD_CONFIG;
  } catch (e) { /* ignore bad config */ }
  var routes = userCfg.routes || {};
  if (typeof routes !== 'object' || routes === null) routes = {};
  // Clamp the ticker interval: 0/negative/NaN would otherwise spin the CPU.
  var feedIntervalMs = Math.max(1000, Number(userCfg.feedIntervalMs) || 4500);

  /* Only allow safe link targets from config: relative paths, #fragments,
     http(s) and mailto. Blocks javascript:, data:, vbscript: etc. (XSS). */
  function safeUrl(u) {
    if (typeof u !== 'string') return null;
    var t = u.replace(/[\u0000-\u0020\u007f]+/g, '');
    if (/^[a-z][a-z0-9+.-]*:/i.test(t)) return /^(https?|mailto):/i.test(t) ? u : null;
    if (t.replace(/\\/g, '/').indexOf('//') === 0) return null; // protocol-relative (incl. backslash forms)
    return u;
  }
  function routeFor(id, fallback) { return safeUrl(routes[id]) || fallback; }

  /* ---------- 2. Render module cards + sidebar list ------------------
     Built with DOM APIs only (no innerHTML anywhere in this file).      */
  var SVGNS = 'http://www.w3.org/2000/svg';
  function icon(id) {
    var svg = document.createElementNS(SVGNS, 'svg');
    svg.setAttribute('aria-hidden', 'true');
    var use = document.createElementNS(SVGNS, 'use');
    use.setAttribute('href', '#' + String(id).replace(/[^a-z0-9_-]/gi, ''));
    svg.appendChild(use);
    return svg;
  }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function badgeEl() { return el('span', 'vx-badge', 'NEW'); }

  var grid = root.querySelector('[data-vx-module-grid]');
  var sideNav = root.querySelector('[data-vx-module-nav]');
  var cardMeta = {}; // module id -> meta <p> (filled with live API status)
  MODULES.forEach(function (m) {
    var href = routeFor(m.id, m.route);
    if (grid) {
      var card = el('article', 'vx-card');
      card.setAttribute('data-vx-module', m.id);
      if (m.isNew) card.appendChild(badgeEl());
      var ic = el('div', 'vx-card-icon'); ic.appendChild(icon(m.icon)); card.appendChild(ic);
      card.appendChild(el('h3', null, m.title));
      card.appendChild(el('p', null, m.desc));
      var meta = el('p', 'vx-card-meta'); meta.hidden = true; card.appendChild(meta);
      cardMeta[m.id] = meta;
      var a = el('a', 'vx-link', 'EXPLORE ');
      a.setAttribute('href', href);
      a.setAttribute('aria-label', 'Explore ' + m.title);
      a.appendChild(icon('i-arrow'));
      card.appendChild(a);
      grid.appendChild(card);
    }
    if (sideNav) {
      var li = el('li'), sa = el('a');
      sa.setAttribute('href', href);
      sa.setAttribute('data-vx-route', m.id);
      sa.appendChild(icon(m.icon));
      sa.appendChild(document.createTextNode(m.title));
      if (m.isNew) sa.appendChild(badgeEl());
      li.appendChild(sa); sideNav.appendChild(li);
    }
  });

  // Apply route overrides to any static link with data-vx-route.
  root.querySelectorAll('a[data-vx-route]').forEach(function (a) {
    var r = safeUrl(routes[a.getAttribute('data-vx-route')]);
    if (r) a.setAttribute('href', r);
  });

  /* ---------- 3. Sidebar highlighting + mobile toggle ---------------- */
  var sideLinks = root.querySelectorAll('.vx-sidebar a');
  sideLinks.forEach(function (a) {
    a.addEventListener('click', function (ev) {
      if (a.getAttribute('href') === '#') ev.preventDefault(); // demo-only links
      sideLinks.forEach(function (l) { l.classList.remove('is-active'); l.removeAttribute('aria-current'); });
      a.classList.add('is-active'); a.setAttribute('aria-current', 'page');
      root.classList.remove('vx-sidebar-open');
    });
  });
  var toggle = root.querySelector('[data-vx-sidebar-toggle]');
  if (toggle) toggle.addEventListener('click', function () {
    var open = root.classList.toggle('vx-sidebar-open');
    toggle.setAttribute('aria-expanded', String(open));
  });

  /* ---------- 4. Animated counters (start when visible) -------------- */
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function runCounter(el) {
    if (el.hasAttribute('data-vx-is-live')) return; // real value already set
    var target = parseInt(el.getAttribute('data-vx-count'), 10) || 0;
    if (reduce) { el.textContent = target.toLocaleString('en-GB'); return; }
    var start = null, dur = 1600;
    function step(ts) {
      if (el.hasAttribute('data-vx-is-live')) return; // live data replaced the demo value
      if (!start) start = ts;
      var p = Math.min((ts - start) / dur, 1), eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(target * eased).toLocaleString('en-GB');
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
    // Safety net: if rAF is throttled (background tab, headless), still land on
    // the final value instead of leaving a misleading 0.
    setTimeout(function () {
      if (!el.hasAttribute('data-vx-is-live')) el.textContent = target.toLocaleString('en-GB');
    }, dur + 200);
  }
  var counters = root.querySelectorAll('[data-vx-count]');
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { runCounter(e.target); io.unobserve(e.target); } });
    }, { threshold: 0.3 });
    counters.forEach(function (c) { io.observe(c); });
  } else counters.forEach(runCounter);

  /* ---------- 5. Live feed: SIMULATED until the API provides real events */
  var feed = root.querySelector('[data-vx-feed]');
  var feedIdx = 0, MAX_FEED = 6, feedTimer = null;
  function feedItem(text, color, ago) {
    // DOM APIs only (no innerHTML, no inline style attribute): XSS-safe for
    // real API data and compatible with the strict CSP.
    var li = document.createElement('li');
    var dot = document.createElement('i');
    if (/^#[0-9a-f]{3,8}$/i.test(String(color))) dot.style.setProperty('--c', color);
    var span = document.createElement('span'); span.textContent = String(text);
    var time = document.createElement('time'); time.textContent = String(ago);
    li.appendChild(dot); li.appendChild(span); li.appendChild(time);
    return li;
  }
  function clearFeed() { while (feed && feed.firstChild) feed.removeChild(feed.firstChild); }
  function startDemoFeed() {
    if (!feed) return;
    clearFeed();
    ['2m ago', '5m ago', '9m ago', '12m ago', '24m ago'].forEach(function (ago, i) {
      feed.appendChild(feedItem(FEED_POOL[i][0], FEED_POOL[i][1], ago));
    });
    feedIdx = 5;
    if (!reduce && !feedTimer) feedTimer = setInterval(function () {
      if (document.hidden) return;
      var item = FEED_POOL[feedIdx++ % FEED_POOL.length];
      feed.insertBefore(feedItem(item[0], item[1], 'just now'), feed.firstChild);
      while (feed.children.length > MAX_FEED) feed.removeChild(feed.lastChild);
    }, feedIntervalMs);
  }
  function stopDemoFeed() { if (feedTimer) { clearInterval(feedTimer); feedTimer = null; } }
  startDemoFeed();

  /* ---------- 5b. Backend API wiring ----------------------------------
     Same-origin only (CSP connect-src 'self'). The session token lives in
     sessionStorage (cleared when the tab closes), never in a cookie or URL.
     Every value from the API is written with textContent.                 */
  var API = '/api';
  var TOKEN_KEY = 'vantax-ard-token';
  var POLL_MS = Math.max(5000, Number(userCfg.apiPollMs) || 10000);
  var pollTimer = null;
  var FEED_COLORS = { green: '#22e39b', red: '#f87171', blue: '#4cc9ff', amber: '#facc15' };
  function q(sel) { return root.querySelector(sel); }
  function getToken() { try { return sessionStorage.getItem(TOKEN_KEY); } catch (e) { return null; } }
  function setToken(t) { try { if (t) sessionStorage.setItem(TOKEN_KEY, t); else sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* storage disabled */ } }

  function api(path, opts) {
    opts = opts || {};
    var headers = { 'Accept': 'application/json' };
    var tok = getToken();
    if (tok && opts.auth !== false) headers['Authorization'] = 'Bearer ' + tok;
    if (opts.body) headers['Content-Type'] = 'application/json';
    return fetch(API + path, {
      method: opts.method || 'GET', headers: headers, credentials: 'omit', cache: 'no-store',
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (r) {
      return r.json().catch(function () { return null; }).then(function (j) { return { status: r.status, ok: r.ok, json: j }; });
    });
  }

  function setLive(name, value) {
    root.querySelectorAll('[data-vx-live="' + name + '"]').forEach(function (e) {
      e.setAttribute('data-vx-is-live', '');
      e.textContent = Number(value).toLocaleString('en-GB');
    });
  }
  function setTag(e, text, live) {
    if (!e) return;
    e.textContent = text;
    e.classList.toggle('vx-live-tag', !!live);
  }
  function setApiStatus(text, cls) {
    var e = q('[data-vx-api-status]');
    if (!e) return;
    e.textContent = text;
    e.classList.remove('is-online', 'is-offline');
    if (cls) e.classList.add(cls);
  }
  function setOk(text, state) {
    var ok = q('[data-vx-ok]'), t = q('[data-vx-ok-text]');
    if (t) t.textContent = text;
    if (ok) {
      ok.classList.toggle('vx-ok-unknown', state === 'unknown');
      ok.classList.toggle('vx-ok-bad', state === 'bad');
    }
  }
  function timeAgo(iso) {
    var t = Date.parse(iso);
    if (isNaN(t)) return '';
    var s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.round(s / 60) + 'm ago';
    if (s < 86400) return Math.round(s / 3600) + 'h ago';
    return Math.round(s / 86400) + 'd ago';
  }

  // Public readiness (no login needed): real module presence + status.
  function loadReady() {
    return api('/ready', { auth: false }).then(function (r) {
      if (!r.json || !r.json.checks) throw new Error('no ready payload');
      var c = r.json.checks;
      setLive('modules_total', c.modules_total);
      setLive('modules_present', c.modules_present);
      setOk(r.json.ready ? 'ALL MODULES READY' : 'DEGRADED ' + c.modules_present + '/' + c.modules_total, r.json.ready ? 'ok' : 'bad');
      setApiStatus('API online · readiness from /api/ready' + (getToken() ? '' : ' · sign in for job stats & feed'), 'is-online');
      return true;
    });
  }

  function renderModules(list) {
    var byId = {};
    (list || []).forEach(function (m) { if (m && typeof m.id === 'string') byId[m.id] = m; });
    Object.keys(cardMeta).forEach(function (id) {
      var meta = cardMeta[id], m = byId[id];
      meta.hidden = false;
      meta.classList.remove('is-ok', 'is-bad');
      if (!m) { meta.textContent = 'NO BACKEND MODULE'; meta.classList.add('is-bad'); return; }
      var subs = Array.isArray(m.subcommands) ? m.subcommands.length : 0;
      meta.textContent = (m.binary_present ? 'READY' : 'BINARY MISSING') + ' · ' + subs + ' API subcommands';
      meta.classList.add(m.binary_present ? 'is-ok' : 'is-bad');
    });
  }

  function renderStats(s) {
    var bs = s.by_status || {};
    setLive('total_jobs', s.total_jobs || 0);
    setLive('active', (bs.running || 0) + (bs.queued || 0));
    setLive('failed', bs.failed || 0);
    setLive('modules_total', s.modules_total || 0);
    setLive('modules_present', s.modules_present || 0);
    setOk(s.operational ? 'ALL MODULES READY' : 'DEGRADED ' + s.modules_present + '/' + s.modules_total, s.operational ? 'ok' : 'bad');
    setTag(q('[data-vx-status-tag]'), 'LIVE', true);
    var note = q('[data-vx-status-note]');
    if (note) note.textContent = 'Live values from /api/stats · updated ' + new Date().toLocaleTimeString('en-GB');
  }

  function renderFeed(f) {
    if (!feed) return;
    stopDemoFeed();
    clearFeed();
    var events = (f && Array.isArray(f.events)) ? f.events.slice(0, MAX_FEED) : [];
    if (!events.length) feed.appendChild(feedItem('No jobs yet', '#8b97c2', ''));
    events.forEach(function (e) {
      feed.appendChild(feedItem(String(e.text || ''), FEED_COLORS[e.color] || '#8b97c2', timeAgo(e.time)));
    });
    setTag(q('[data-vx-feed-tag]'), 'LIVE', true);
  }

  function showDemo(reason) {
    // Restore the clearly labelled demo state.
    setTag(q('[data-vx-status-tag]'), 'DEMO', false);
    setTag(q('[data-vx-feed-tag]'), 'SIMULATED', false);
    var note = q('[data-vx-status-note]');
    if (note) note.textContent = 'Demo placeholder values — not live telemetry.';
    if (!feedTimer) startDemoFeed();
    if (reason) setApiStatus(reason, 'is-offline');
  }

  function loadAuthed() {
    return Promise.all([api('/modules'), api('/stats'), api('/feed')]).then(function (rs) {
      if (rs.some(function (r) { return r.status === 401; })) {
        setToken(null); updateSessionUi(); showDemo(null); loadReady().catch(function () {});
        return false;
      }
      if (!rs.every(function (r) { return r.ok && r.json; })) throw new Error('api error');
      renderModules(rs[0].json.modules);
      renderStats(rs[1].json);
      renderFeed(rs[2].json);
      setApiStatus('API online · signed in · live data', 'is-online');
      return true;
    });
  }

  function refresh() {
    var p = getToken() ? loadAuthed() : loadReady();
    return p.catch(function () {
      showDemo('API unreachable · showing DEMO values');
      setOk('NOT LIVE', 'unknown');
    });
  }

  /* Secure Access: login panel */
  var loginPanel = q('[data-vx-login]'), loginForm = q('[data-vx-login-form]');
  var loginMsg = q('[data-vx-login-msg]'), sessionBox = q('[data-vx-session]');
  var accessBtn = q('[data-vx-secure-access]'), accessLabel = q('[data-vx-access-label]');
  function updateSessionUi() {
    var signedIn = !!getToken();
    if (loginForm) loginForm.hidden = signedIn;
    if (sessionBox) sessionBox.hidden = !signedIn;
    if (accessLabel) accessLabel.textContent = signedIn ? 'Signed In' : 'Secure Access';
  }
  if (accessBtn && loginPanel && !safeUrl(routes.secureAccess)) {
    accessBtn.addEventListener('click', function (ev) {
      ev.preventDefault();
      loginPanel.hidden = !loginPanel.hidden;
      accessBtn.setAttribute('aria-expanded', String(!loginPanel.hidden));
      if (!loginPanel.hidden && loginForm && !loginForm.hidden) {
        var u = loginForm.querySelector('input[name="username"]'); if (u) u.focus();
      }
    });
  }
  if (loginForm) loginForm.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var u = loginForm.elements.username.value, p = loginForm.elements.password.value;
    if (!u || !p) { loginMsg.textContent = 'Enter username and password.'; return; }
    loginMsg.textContent = 'Signing in…';
    api('/login', { method: 'POST', auth: false, body: { username: u, password: p } }).then(function (r) {
      loginForm.elements.password.value = '';
      if (r.ok && r.json && typeof r.json.token === 'string') {
        setToken(r.json.token); loginMsg.textContent = '';
        updateSessionUi(); refresh(); startPolling();
      } else if (r.status === 429) {
        loginMsg.textContent = 'Too many failed attempts. Try again later.';
      } else {
        loginMsg.textContent = 'Sign-in failed.';
      }
    }).catch(function () { loginMsg.textContent = 'API unreachable.'; });
  });
  var logoutBtn = q('[data-vx-logout]');
  if (logoutBtn) logoutBtn.addEventListener('click', function () {
    var done = function () { setToken(null); updateSessionUi(); showDemo(null); refresh(); };
    api('/logout', { method: 'POST' }).then(done, done);
  });

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(function () { if (!document.hidden) refresh(); }, POLL_MS);
  }
  if (userCfg.api !== false) {
    updateSessionUi();
    refresh();
    startPolling();
  }

  /* ---------- 6. Orb particles --------------------------------------- */
  var pWrap = root.querySelector('[data-vx-particles]');
  if (pWrap) {
    var frag = document.createDocumentFragment();
    for (var i = 0; i < 40; i++) {
      var s = document.createElement('span'), a = Math.random() * Math.PI * 2, r = 20 + Math.random() * 30;
      s.style.left = (50 + Math.cos(a) * r) + '%';
      s.style.top = (50 + Math.sin(a) * r) + '%';
      s.style.setProperty('--d', (2 + Math.random() * 3).toFixed(2) + 's');
      s.style.setProperty('--dl', (Math.random() * 3).toFixed(2) + 's');
      frag.appendChild(s);
    }
    pWrap.appendChild(frag);
  }

  /* ---------- 7. Dotted world map (stylised, approximate; DEMO) ------ */
  var dots = root.querySelector('[data-vx-map-dots]');
  if (dots) {
    // Rough continent blobs as [cx, cy, rx, ry] in a 360x180 box.
    var blobs = [[75, 55, 38, 22], [100, 125, 18, 32], [180, 50, 22, 14], [190, 105, 22, 32], [255, 55, 50, 22], [285, 130, 18, 10]];
    var dfrag = document.createDocumentFragment();
    var circle = function (cx, cy, r, fill) {
      var c = document.createElementNS(SVGNS, 'circle');
      c.setAttribute('cx', cx); c.setAttribute('cy', cy); c.setAttribute('r', r);
      if (fill) c.setAttribute('fill', fill);
      dfrag.appendChild(c);
    };
    for (var x = 4; x < 360; x += 6) for (var y = 4; y < 180; y += 6) {
      for (var b = 0; b < blobs.length; b++) {
        var B = blobs[b], dx = (x - B[0]) / B[2], dy = (y - B[1]) / B[3];
        if (dx * dx + dy * dy < 1) { circle(x, y, 1.3); break; }
      }
    }
    circle(70, 60, 3, '#ec4899'); circle(190, 55, 3, '#a855f7'); circle(290, 70, 3, '#22d3ee'); circle(110, 120, 3, '#facc15');
    dots.appendChild(dfrag);
  }

  /* ---------- 8. Real-time analysis graph (demo random walk) --------- */
  var line = root.querySelector('[data-vx-graph-line]'), area = root.querySelector('[data-vx-graph-area]');
  if (line && area) {
    var pts = [], N = 40, v = 50;
    for (var k = 0; k < N; k++) { v = Math.max(10, Math.min(90, v + (Math.random() - 0.5) * 22)); pts.push(v); }
    function draw() {
      var d = pts.map(function (p, i) { return (i ? 'L' : 'M') + (i * 300 / (N - 1)).toFixed(1) + ' ' + (100 - p).toFixed(1); }).join(' ');
      line.setAttribute('d', d);
      area.setAttribute('d', d + ' L300 100 L0 100 Z');
    }
    draw();
    if (!reduce) setInterval(function () {
      if (document.hidden) return;
      v = Math.max(10, Math.min(90, pts[pts.length - 1] + (Math.random() - 0.5) * 22));
      pts.shift(); pts.push(v); draw();
    }, 1200);
  }
  /* ---------- 9. PQC readiness from a LOCAL report file (real output) ---
     Loads data/pqc-report.json written by `vantax-pqc report --out data/`.
     Values are only shown when the file exists and parses; there is no
     fallback demo number for this panel. */
  var PQC_REPORT = 'data/pqc-report.json';
  function pqcInt(v) { var n = Number(v); return (isFinite(n) && n >= 0 && n < 1e9) ? Math.floor(n) : null; }
  function loadPqc() {
    var panel = q('[data-vx-pqc]'); if (!panel || typeof fetch !== 'function') return;
    fetch(PQC_REPORT, { credentials: 'omit', cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (rep) {
      var rd = rep && rep.readiness; if (!rd) throw new Error('not a vantax-pqc report');
      var set = function (k, v) { var e = panel.querySelector('[data-vx-pqc-field="' + k + '"]'); if (e) e.textContent = v; };
      var sc = pqcInt(rd.score);
      set('score', sc === null ? '—' : sc + '/100 (' + String(rd.grade || '?').slice(0, 2) + ')');
      ['vulnerable', 'hndl_urgent', 'items'].forEach(function (k) { var n = pqcInt(rd[k]); set(k, n === null ? '—' : n.toLocaleString('en-GB')); });
      setTag(q('[data-vx-pqc-tag]'), 'LOCAL REPORT', true);
      var note = q('[data-vx-pqc-note]');
      var meta = rep.meta || {};
      if (note) note.textContent = 'From local vantax-pqc report generated ' + String(meta.generated_at_utc || '?').slice(0, 40) +
        ' · inventory SHA-256 ' + String(rep.inventory_sha256 || '?').slice(0, 16) + '…';
    }).catch(function () { setTag(q('[data-vx-pqc-tag]'), 'NO LOCAL REPORT', false); });
  }
  loadPqc();
})();
