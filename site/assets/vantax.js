/* Vantax site chrome: theme, menus, copy buttons and prices in the visitor's
   currency. No dependencies. Every page loads this with `defer`. */
(function () {
  "use strict";
  var doc = document, root = doc.documentElement;

  function store(k, v) { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) {} }
  function load(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function $(s, el) { return (el || doc).querySelector(s); }
  function $$(s, el) { return Array.prototype.slice.call((el || doc).querySelectorAll(s)); }

  var apiBase = (($('meta[name="vantax-api"]') || {}).content || "").replace(/\/$/, "");
  var storeBase = (($('meta[name="vantax-store"]') || {}).content || apiBase).replace(/\/$/, "");

  function getJSON(url, ms) {
    var ctl = window.AbortController ? new AbortController() : null;
    if (ctl) setTimeout(function () { ctl.abort(); }, ms || 8000);
    return fetch(url, { headers: { Accept: "application/json" }, signal: ctl ? ctl.signal : undefined })
      .then(function (r) { if (!r.ok) { var e = new Error("HTTP " + r.status); e.status = r.status; throw e; } return r.json(); });
  }

  /* ── Theme: follows the system until the visitor picks one ─────────── */
  var THEME = "vantax-theme";
  function systemDark() { return window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches; }
  function current() { var t = root.getAttribute("data-theme"); return t || (systemDark() ? "dark" : "light"); }
  function setTheme(t) { root.setAttribute("data-theme", t); store(THEME, t); syncThemeButtons(); }
  function syncThemeButtons() {
    $$("[data-theme-toggle]").forEach(function (b) {
      var dark = current() === "dark";
      b.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
      b.setAttribute("aria-pressed", dark ? "true" : "false");
    });
  }
  $$("[data-theme-toggle]").forEach(function (b) {
    b.addEventListener("click", function () { setTheme(current() === "dark" ? "light" : "dark"); });
  });
  syncThemeButtons();

  /* ── Products menu and the mobile sheet ───────────────────────────── */
  function closeAll(except) {
    $$("[data-menu]").forEach(function (b) {
      if (b === except) return;
      b.setAttribute("aria-expanded", "false");
      var p = doc.getElementById(b.getAttribute("aria-controls")); if (p) p.hidden = true;
    });
  }
  $$("[data-menu]").forEach(function (b) {
    var panel = doc.getElementById(b.getAttribute("aria-controls"));
    if (!panel) return;
    b.addEventListener("click", function (e) {
      e.stopPropagation();
      var open = b.getAttribute("aria-expanded") === "true";
      closeAll(b);
      b.setAttribute("aria-expanded", open ? "false" : "true");
      panel.hidden = open;
      if (!open) { var first = panel.querySelector("a"); if (first && e.detail === 0) first.focus(); }
    });
  });
  doc.addEventListener("click", function (e) { if (!e.target.closest || !e.target.closest(".menu-wrap")) closeAll(); });
  doc.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    var open = $('[data-menu][aria-expanded="true"]');
    closeAll(); if (open) open.focus();
    if (doc.body.classList.contains("sheet-open")) toggleSheet(false);
  });
  var sheetBtn = $("[data-sheet]"), sheet = sheetBtn && doc.getElementById(sheetBtn.getAttribute("aria-controls"));
  function toggleSheet(open) {
    if (!sheet) return;
    sheet.hidden = !open; sheetBtn.setAttribute("aria-expanded", open ? "true" : "false");
    sheetBtn.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    doc.body.classList.toggle("sheet-open", open);
  }
  if (sheetBtn) sheetBtn.addEventListener("click", function () { toggleSheet(sheet.hidden); });
  if (sheet) $$("a", sheet).forEach(function (a) { a.addEventListener("click", function () { toggleSheet(false); }); });

  /* ── Copy buttons: data-copy="#id" or data-copy-text="…" ─────────── */
  $$("[data-copy],[data-copy-text]").forEach(function (b) {
    b.addEventListener("click", function () {
      var src = b.getAttribute("data-copy"), text = b.getAttribute("data-copy-text");
      var node = src ? $(src) : null;
      if (text == null) text = node ? (node.value != null && node.tagName !== "CODE" ? node.value : node.textContent).trim() : "";
      var label = b.textContent;
      function done(m) { b.textContent = m; setTimeout(function () { b.textContent = label; }, 1600); }
      function select() {
        if (!node) return done("Copy failed");
        var r = doc.createRange(); r.selectNodeContents(node); var s = getSelection(); s.removeAllRanges(); s.addRange(r); done("Selected");
      }
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { done("Copied"); }, select);
      else select();
    });
  });

  /* ── Money: prices shown in the visitor's own currency ─────────────── */
  // Rates come from the SOL price in every currency (CoinGecko), so one call
  // converts SOL, USD/USDC and any fiat into any other.
  var FIAT = ["USD", "GBP", "EUR", "CAD", "AUD", "NZD", "CHF", "JPY", "CNY", "HKD", "SGD", "KRW", "INR", "IDR", "PHP", "THB", "MYR", "AED", "SAR", "ILS", "TRY", "ZAR", "NGN", "BRL", "MXN", "ARS", "CLP", "SEK", "NOK", "DKK", "PLN", "CZK", "HUF"];
  var REGION = { GB: "GBP", IM: "GBP", JE: "GBP", GG: "GBP", US: "USD", CA: "CAD", AU: "AUD", NZ: "NZD", CH: "CHF", LI: "CHF", JP: "JPY", CN: "CNY", HK: "HKD", SG: "SGD", KR: "KRW", IN: "INR", ID: "IDR", PH: "PHP", TH: "THB", MY: "MYR", AE: "AED", SA: "SAR", IL: "ILS", TR: "TRY", ZA: "ZAR", NG: "NGN", BR: "BRL", MX: "MXN", AR: "ARS", CL: "CLP", SE: "SEK", NO: "NOK", DK: "DKK", PL: "PLN", CZ: "CZK", HU: "HUF",
    AT: "EUR", BE: "EUR", CY: "EUR", DE: "EUR", EE: "EUR", ES: "EUR", FI: "EUR", FR: "EUR", GR: "EUR", HR: "EUR", IE: "EUR", IT: "EUR", LT: "EUR", LU: "EUR", LV: "EUR", MT: "EUR", NL: "EUR", PT: "EUR", SI: "EUR", SK: "EUR" };
  var CUR = "vantax-currency";
  function detectCurrency() {
    var picked = load(CUR); if (picked) return picked;
    var langs = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || "en-GB"];
    for (var i = 0; i < langs.length; i++) {
      var m = /[-_]([A-Za-z]{2})$/.exec(langs[i] || "");
      if (m && REGION[m[1].toUpperCase()]) return REGION[m[1].toUpperCase()];
    }
    return "USD";
  }
  var money = {
    currency: detectCurrency(),
    rates: null, // SOL price in each currency, upper-case keys
    ready: null,
    toSol: function (amount, from) {
      from = (from || "SOL").toUpperCase();
      if (from === "SOL") return amount;
      if (!money.rates) return null;
      var r = money.rates[from === "USDC" || from === "USDT" ? "USD" : from];
      return r ? amount / r : null;
    },
    convert: function (amount, from, to) {
      to = (to || money.currency).toUpperCase(); from = (from || "SOL").toUpperCase();
      if (from === to) return amount;
      var sol = money.toSol(amount, from); if (sol == null) return null;
      if (to === "SOL") return sol;
      var r = money.rates && money.rates[to === "USDC" || to === "USDT" ? "USD" : to];
      return r ? sol * r : null;
    },
    format: function (amount, cur, opts) {
      cur = (cur || money.currency).toUpperCase(); opts = opts || {};
      if (cur === "SOL" || cur === "USDC" || cur === "USDT" || cur === "VANTAX") {
        var dp = amount >= 100 ? 0 : amount >= 10 ? 1 : amount >= 1 ? 2 : 3;
        if (opts.exact) dp = Math.max(dp, 2);
        return Number(amount).toLocaleString(undefined, { maximumFractionDigits: dp, minimumFractionDigits: 0 }) + " " + cur;
      }
      var big = Math.abs(amount) >= 1000 || !!opts.round;
      try {
        return new Intl.NumberFormat(undefined, { style: "currency", currency: cur, currencyDisplay: "narrowSymbol", maximumFractionDigits: big ? 0 : 2, minimumFractionDigits: big ? 0 : (amount % 1 ? 2 : 0) }).format(amount);
      } catch (e) { return cur + " " + Math.round(amount).toLocaleString(); }
    },
    render: function () {
      // <span data-money data-amount="3" data-base="SOL"> → "≈ £231"
      $$("[data-money]").forEach(function (el) {
        var amount = Number(el.getAttribute("data-amount")), base = el.getAttribute("data-base") || "SOL";
        var to = el.getAttribute("data-to") || money.currency;
        if (!(amount >= 0)) return;
        if (base.toUpperCase() === to.toUpperCase()) { el.textContent = el.hasAttribute("data-alt") ? "" : money.format(amount, to); return; }
        var v = money.convert(amount, base, to);
        if (v == null) { if (el.hasAttribute("data-alt")) el.textContent = ""; return; }
        var text = money.format(v, to, { round: el.hasAttribute("data-round") || (el.hasAttribute("data-alt") && v >= 20) });
        el.textContent = el.hasAttribute("data-alt") ? "≈ " + text + (el.getAttribute("data-suffix") || "") : text;
      });
      $$("[data-currency-picker]").forEach(function (s) { if (s.value !== money.currency) s.value = money.currency; });
      doc.dispatchEvent(new CustomEvent("vantax:money"));
    },
    set: function (cur) { money.currency = cur; store(CUR, cur); money.render(); }
  };
  var RATES = "vantax-rates";
  money.ready = (function () {
    try {
      var cached = JSON.parse(sessionStorage.getItem(RATES) || "null");
      if (cached && Date.now() - cached.t < 5 * 60e3) { money.rates = cached.r; return Promise.resolve(money.rates); }
    } catch (e) {}
    var url = "https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=" + FIAT.map(function (c) { return c.toLowerCase(); }).join(",");
    return getJSON(url, 7000).then(function (d) {
      var r = {}; var s = d && d.solana || {};
      Object.keys(s).forEach(function (k) { if (s[k] > 0) r[k.toUpperCase()] = s[k]; });
      if (!r.USD) throw new Error("no rates");
      money.rates = r;
      try { sessionStorage.setItem(RATES, JSON.stringify({ t: Date.now(), r: r })); } catch (e) {}
      return r;
    });
  })();
  function fillPickers() {
    $$("[data-currency-picker]").forEach(function (s) {
      if (s.options.length) return;
      ["SOL", "USDC"].concat(FIAT).forEach(function (c) {
        var o = doc.createElement("option"); o.value = c;
        var name = c;
        try { if (FIAT.indexOf(c) >= 0 && Intl.DisplayNames) name = new Intl.DisplayNames(undefined, { type: "currency" }).of(c) + " (" + c + ")"; } catch (e) {}
        if (c === "SOL") name = "Solana (SOL)"; if (c === "USDC") name = "USD Coin (USDC)";
        o.textContent = name; s.appendChild(o);
      });
      s.value = money.currency;
      s.addEventListener("change", function () { money.set(s.value); });
    });
  }
  fillPickers();
  money.ready.then(money.render, function () { money.render(); });
  if (money.rates) money.render();

  window.Vantax = { api: apiBase, store: storeBase, getJSON: getJSON, money: money, $: $, $$: $$ };
})();
