/**
 * frontend/js/app.js
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   UI controller for the static (GitHub Pages) build of the Password Strength
 *   Analyzer. It wires the local engine to the real-time meter, the findings
 *   and suggestion panels, the policy checker, the generator and the
 *   privacy-safe dashboard.
 *
 * PRIVACY RULES OBSERVED IN THIS FILE
 *   * The password value lives only in the input element and local variables.
 *   * It is never written to console.log, localStorage, sessionStorage,
 *     cookies, the URL, an analytics call or a network request.
 *   * The session dashboard keeps only metadata: score, classification,
 *     length, finding categories and a timestamp.
 *   * A counter records how many network requests this page makes (it must
 *     stay at zero) so the claim is visible instead of merely asserted.
 * ---------------------------------------------------------------------------
 */
(function () {
  "use strict";

  const engine = window.PSAEngine;
  const charts = window.PSACharts;

  /* =====================================================================
   * 0. "Zero network requests" instrumentation
   * ===================================================================== */
  let networkRequests = 0;
  (function countNetworkActivity() {
    const originalFetch = window.fetch;
    if (originalFetch) {
      window.fetch = function () {
        networkRequests += 1;
        updateNetworkStat();
        return originalFetch.apply(this, arguments);
      };
    }
    const OriginalXHR = window.XMLHttpRequest;
    if (OriginalXHR && OriginalXHR.prototype && OriginalXHR.prototype.open) {
      const originalOpen = OriginalXHR.prototype.open;
      OriginalXHR.prototype.open = function () {
        networkRequests += 1;
        updateNetworkStat();
        return originalOpen.apply(this, arguments);
      };
    }
    const OriginalBeacon = navigator.sendBeacon;
    if (OriginalBeacon) {
      navigator.sendBeacon = function () {
        networkRequests += 1;
        updateNetworkStat();
        return OriginalBeacon.apply(this, arguments);
      };
    }
  })();

  function updateNetworkStat() {
    const node = document.querySelector('[data-stat="requests"]');
    if (node) { node.textContent = String(networkRequests); }
  }

  /* =====================================================================
   * 1. Session analytics (metadata only, in memory)
   * ===================================================================== */
  const session = {
    analyses: [],          // {analysis_id, score, classification, length, weakness_count, categories, at}
    add(result) {
      this.analyses.push({
        analysis_id: result.analysis_id,
        score: result.score,
        classification: result.classification,
        length: result.metrics.length,
        weakness_count: result.metrics.weakness_count,
        categories: Object.keys(result.metrics.weakness_categories || {}),
        at: new Date()
      });
      if (this.analyses.length > 300) { this.analyses.shift(); }
    },
    reset() { this.analyses = []; }
  };

  /* =====================================================================
   * 2. Tab navigation
   * ===================================================================== */
  const TABS = ["analyzer", "generator", "dashboard", "learn", "privacy"];

  function activateTab(name) {
    if (TABS.indexOf(name) === -1) { name = "analyzer"; }
    TABS.forEach((tab) => {
      const button = document.getElementById("tab-" + tab);
      const panel = document.getElementById("panel-" + tab);
      const selected = tab === name;
      button.setAttribute("aria-selected", selected ? "true" : "false");
      panel.classList.toggle("is-active", selected);
    });
    if (name === "dashboard") { renderDashboard(); }
    if (location.hash.slice(1) !== name) {
      history.replaceState(null, "", "#" + name);
    }
  }

  document.querySelectorAll(".nav-btn").forEach((button) => {
    button.addEventListener("click", () => activateTab(button.dataset.tab));
  });
  document.querySelectorAll("[data-goto]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      activateTab(link.dataset.goto);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });
  window.addEventListener("hashchange", () => activateTab(location.hash.slice(1)));

  /* =====================================================================
   * 3. Small render helpers
   * ===================================================================== */
  const CLASS_COLORS = {
    "VERY WEAK": "#ff4d5e", "WEAK": "#ff9147", "MODERATE": "#ffd23f",
    "STRONG": "#4cd97b", "VERY STRONG": "#2ee6a8",
    "Awaiting input": "#7484a6"
  };
  const SEVERITY_ICON = {
    critical: "⛔", high: "⚠️", medium: "⚠️", low: "ℹ️", info: "💡", input: "✏️"
  };

  function escapeHtml(text) {
    return String(text).replace(/[&<>"']/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function formatBits(value) {
    return (value === undefined || value === null) ? "—" : Number(value).toFixed(1);
  }

  /* =====================================================================
   * 4. Analyzer: live analysis
   * ===================================================================== */
  const elements = {
    input: document.getElementById("password-input"),
    toggleVisibility: document.getElementById("toggle-visibility"),
    clear: document.getElementById("clear-input"),
    score: document.getElementById("score-value"),
    classificationPill: document.getElementById("classification-pill"),
    classificationText: document.getElementById("classification-text"),
    summary: document.getElementById("classification-summary"),
    gauge: document.getElementById("gauge-arc"),
    meterBar: document.getElementById("meter-bar"),
    meterFill: document.getElementById("meter-fill"),
    capBanner: document.getElementById("cap-banner"),
    findings: document.getElementById("findings-list"),
    suggestions: document.getElementById("suggestions-list"),
    breakdown: document.getElementById("breakdown-bars"),
    penalties: document.getElementById("penalty-bars"),
    entropy: document.getElementById("entropy-panel"),
    tiles: {
      length: document.getElementById("tile-length"),
      lengthNote: document.getElementById("tile-length-note"),
      types: document.getElementById("tile-types"),
      typesNote: document.getElementById("tile-types-note"),
      entropy: document.getElementById("tile-entropy"),
      entropyNote: document.getElementById("tile-entropy-note"),
      policy: document.getElementById("tile-policy"),
      policyNote: document.getElementById("tile-policy-note")
    },
    policyPanel: document.getElementById("policy-panel"),
    policyPreset: document.getElementById("policy-preset"),
    ctxFirst: document.getElementById("ctx-first"),
    ctxYear: document.getElementById("ctx-year"),
    ctxOrg: document.getElementById("ctx-org")
  };

  const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 52;

  function currentContext() {
    const context = {};
    const first = elements.ctxFirst.value.trim();
    const year = elements.ctxYear.value.trim();
    const org = elements.ctxOrg.value.trim();
    if (first) { context.first_name = first; }
    if (year) { context.birth_year = year; }
    if (org) { context.organisation = org; }
    return Object.keys(context).length ? context : null;
  }

  function renderMeter(result) {
    const color = CLASS_COLORS[result.classification] || "#7484a6";
    const score = result.score;

    elements.score.textContent = String(score);
    elements.classificationText.textContent = result.classification;
    elements.classificationPill.style.color = color;
    elements.summary.textContent = result.classification_summary || "";

    const offset = GAUGE_CIRCUMFERENCE * (1 - Math.max(0, Math.min(100, score)) / 100);
    elements.gauge.setAttribute("stroke", color);
    elements.gauge.setAttribute("stroke-dashoffset", offset.toFixed(1));

    elements.meterFill.style.width = Math.max(score, score > 0 ? 3 : 0) + "%";
    elements.meterFill.style.background = color;
    elements.meterBar.setAttribute("aria-valuenow", String(score));
    elements.meterBar.setAttribute("aria-valuetext", score + " out of 100, " + result.classification);

    if (result.score_cap_applied) {
      elements.capBanner.innerHTML =
        `<div class="notice notice--warn cap-banner"><span aria-hidden="true">🧱</span><span>
          <strong>Score cap applied:</strong> ${escapeHtml(result.score_cap_applied)}
        </span></div>`;
    } else {
      elements.capBanner.innerHTML = "";
    }
  }

  function renderTiles(result) {
    const m = result.metrics;
    const lengthGood = m.length >= 16;
    elements.tiles.length.textContent = String(m.length);
    elements.tiles.length.className = "tile-value " +
      (m.length >= 16 ? "is-ok" : m.length >= 12 ? "is-info" : m.length > 0 ? "is-warn" : "");
    elements.tiles.lengthNote.textContent = m.length_band + " · recommended ≥ " + m.recommended_minimum_length;

    elements.tiles.types.textContent = String(m.character_type_count);
    elements.tiles.types.className = "tile-value " + (m.character_type_count >= 3 ? "is-ok" : "is-warn");
    elements.tiles.typesNote.textContent = (m.character_types || []).join(", ") || "none detected";

    elements.tiles.entropy.textContent = formatBits(result.entropy.effective_bits);
    elements.tiles.entropy.className = "tile-value " +
      (result.entropy.effective_bits >= 70 ? "is-ok" : result.entropy.effective_bits >= 40 ? "is-info" : "is-warn");
    elements.tiles.entropyNote.textContent =
      "theoretical " + formatBits(result.entropy.theoretical_bits) + " · penalty −" +
      formatBits(result.entropy.pattern_penalty_bits) + " bits";

    const pass = result.policy.policy_pass;
    const hasInput = m.length > 0;
    elements.tiles.policy.textContent = hasInput ? (pass ? "PASS" : "FAIL") : "—";
    elements.tiles.policy.className = "tile-value " + (hasInput ? (pass ? "is-ok" : "is-bad") : "");
    elements.tiles.policyNote.textContent = hasInput
      ? (pass ? "meets the selected policy" : result.policy.failure_count + " requirement(s) unmet")
      : "no value yet";
    void lengthGood;
  }

  function renderPolicy(result) {
    const policy = result.policy;
    if (!policy.checks || !policy.checks.length) {
      elements.policyPanel.innerHTML = "";
      return;
    }
    const rows = policy.checks.map((check) => {
      const icon = check.passed ? "✅" : (check.required ? "❌" : "ℹ️");
      const opacity = check.required ? "1" : "0.75";
      return `<tr style="opacity:${opacity}">
        <td>${icon}</td>
        <td>${escapeHtml(check.label)}${check.required ? "" : ' <span class="text-faint small">(informational)</span>'}</td>
        <td class="mono">${escapeHtml(check.detail)}</td>
      </tr>`;
    }).join("");

    const banner = policy.policy_pass
      ? `<div class="notice notice--ok"><span aria-hidden="true">✅</span><span><strong>POLICY PASS</strong> — the value satisfies “${escapeHtml(policy.policy_name)}”. This says it is <em>allowed</em>, not that it is hard to guess.</span></div>`
      : `<div class="notice notice--bad"><span aria-hidden="true">❌</span><span><strong>POLICY FAIL</strong> — ${policy.failure_count} requirement(s) unmet for “${escapeHtml(policy.policy_name)}”. A password can fail policy while scoring well, and pass policy while being predictable.</span></div>`;

    elements.policyPanel.innerHTML = banner + `<div class="table-scroll mt-8"><table class="data">
      <thead><tr><th></th><th>Requirement</th><th>Observed</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  }

  function renderFindings(result) {
    const findings = result.findings || [];
    if (!findings.length) {
      elements.findings.innerHTML = `<div class="notice notice--ok"><span aria-hidden="true">✅</span><span>No predictable patterns, dictionary words, sequences, keyboard walks, repetitions or context overlaps were detected.</span></div>`;
      return;
    }
    elements.findings.innerHTML = findings.map((finding) => `
      <div class="finding finding--${escapeHtml(finding.severity)}">
        <span class="finding-icon" aria-hidden="true">${SEVERITY_ICON[finding.severity] || "•"}</span>
        <div class="finding-body">
          <div class="finding-title">
            <span class="sev sev--${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
            ${escapeHtml(finding.title)}
          </div>
          <p class="finding-desc">${escapeHtml(finding.description)}</p>
          ${finding.evidence ? `<p class="finding-desc mb-0">Masked evidence: <span class="masked">${escapeHtml(finding.evidence)}</span>${finding.positions && finding.positions.length ? ` <span class="text-faint small">at position ${finding.positions[0] + 1}</span>` : ""}</p>` : ""}
        </div>
      </div>`).join("");
  }

  function renderSuggestions(result) {
    const suggestions = result.suggestions || [];
    if (!suggestions.length) {
      elements.suggestions.innerHTML = `<div class="notice notice--info"><span aria-hidden="true">ℹ️</span><span>No specific fixes needed. Keep the value unique to this account and stored in a password manager.</span></div>`;
      return;
    }
    elements.suggestions.innerHTML = suggestions.map((suggestion) => `
      <div class="suggestion">
        <div class="suggestion-head">
          <span class="prio prio--${escapeHtml(suggestion.priority)}">${escapeHtml(suggestion.priority)}</span>
          <span class="suggestion-title">${escapeHtml(suggestion.title)}</span>
        </div>
        ${suggestion.risk ? `<p class="suggestion-risk">${escapeHtml(suggestion.risk)}</p>` : ""}
        <p class="suggestion-action">${escapeHtml(suggestion.action)}</p>
      </div>`).join("");
  }

  function renderBreakdown(result) {
    const components = result.score_breakdown.components || {};
    const rows = Object.entries(components).map(([key, value]) => {
      const percent = value.max ? Math.max((value.earned / value.max) * 100, 0) : 0;
      return `<div class="bar-row">
        <span class="text-dim">${escapeHtml(key.replace(/_/g, " "))}</span>
        <span class="bar-track"><span class="bar-fill" style="width:${percent.toFixed(1)}%"></span></span>
        <span class="bar-value">${Number(value.earned).toFixed(1)}/${value.max}</span>
      </div>
      <p class="small text-faint" style="margin:-6px 0 10px">${escapeHtml(value.detail || "")}</p>`;
    }).join("");

    const penalties = result.score_breakdown.penalties || { total: 0, by_category: {} };
    const penaltyRows = Object.entries(penalties.by_category || {}).map(([key, value]) => {
      const percent = penalties.total ? Math.max((value / penalties.total) * 100, 4) : 0;
      return `<div class="bar-row">
        <span class="text-dim">${escapeHtml(key.replace(/_/g, " "))}</span>
        <span class="bar-track"><span class="bar-fill bar-fill--penalty" style="width:${percent.toFixed(1)}%"></span></span>
        <span class="bar-value">−${value}</span>
      </div>`;
    }).join("");

    const caps = (result.score_breakdown.caps_evaluated || []).map((cap) =>
      `<li><strong>${escapeHtml(cap.rule)}</strong> caps the score at ${cap.cap} — ${escapeHtml(cap.reason)}</li>`
    ).join("");

    elements.breakdown.innerHTML =
      `<h4 class="mb-8">Positive contributions (raw total ${result.score_breakdown.raw_score})</h4>${rows}
       <h4 class="mb-8 mt-16">Penalties (total −${penalties.total})</h4>
       ${penaltyRows || '<p class="small text-faint">No category penalties applied.</p>'}
       ${caps ? `<h4 class="mb-8 mt-16">Structural score caps evaluated</h4><ul class="small">${caps}</ul>` : ""}
       <div class="notice notice--info mt-16"><span aria-hidden="true">📐</span><span>${escapeHtml(result.score_breakdown.rubric_note || "")}</span></div>`;

    elements.penalties.innerHTML = "";
  }

  function renderEntropy(result) {
    const entropy = result.entropy;
    const guess = result.guess_resistance || {};
    const rows = (guess.scenarios || []).map((scenario) => `
      <div class="bar-row" style="grid-template-columns:1fr auto">
        <span class="text-dim small">${escapeHtml(scenario.label)}<br><span class="text-faint">${scenario.guesses_per_second.toLocaleString()} guesses/sec assumed</span></span>
        <span class="mono" style="color:var(--accent)">${escapeHtml(scenario.estimate)}</span>
      </div>`).join("");

    elements.entropy.innerHTML = `
      <div class="tiles" style="grid-template-columns:repeat(3,1fr);margin-top:0">
        <div class="tile"><div class="tile-label">Theoretical</div><div class="tile-value is-info">${formatBits(entropy.theoretical_bits)}</div><div class="tile-note">bits (optimistic)</div></div>
        <div class="tile"><div class="tile-label">Effective</div><div class="tile-value ${entropy.effective_bits >= 70 ? "is-ok" : "is-warn"}">${formatBits(entropy.effective_bits)}</div><div class="tile-note">bits (after penalties)</div></div>
        <div class="tile"><div class="tile-label">Shannon variety</div><div class="tile-value">${formatBits(entropy.shannon_bits)}</div><div class="tile-note">bits (character spread)</div></div>
      </div>
      <p class="small mt-16"><code>${escapeHtml(entropy.formula || "")}</code> · pool size ${entropy.pool_size} ·
        ${entropy.is_passphrase_like ? "treated as a passphrase" : "treated as a single token"}</p>
      ${entropy.effective_bits_source ? `<p class="small text-faint">Effective-bits source: ${escapeHtml(entropy.effective_bits_source)}.</p>` : ""}
      ${entropy.passphrase_model_caveat ? `<div class="notice notice--warn"><span aria-hidden="true">⚠️</span><span>${escapeHtml(entropy.passphrase_model_caveat)}</span></div>` : ""}
      <h4 class="mt-16">Educational guess-resistance scenarios</h4>
      ${rows}
      <div class="notice notice--warn mt-8"><span aria-hidden="true">⚠️</span><span><strong>${escapeHtml(guess.estimate_label || "Educational estimate only")}.</strong> ${escapeHtml(guess.caveat || "")}</span></div>
      <p class="small text-faint mt-8">${escapeHtml(entropy.caveat || "")}</p>`;
  }

  // Debounce so a fast typist does not trigger an analysis per keystroke.
  let debounceTimer = null;
  function scheduleAnalysis() {
    window.clearTimeout(debounceTimer);
    debounceTimer = window.setTimeout(runAnalysis, 120);
  }

  function runAnalysis(recordInSession) {
    const password = elements.input.value;
    const context = currentContext();
    const policyKey = elements.policyPreset.value;
    const policy = engine.presetPolicies[policyKey];

    const result = engine.analyzePassword(password, { context: context, policy: policy });

    renderMeter(result);
    renderTiles(result);
    renderPolicy(result);
    renderFindings(result);
    renderSuggestions(result);
    renderBreakdown(result);
    renderEntropy(result);

    if (recordInSession !== false && password.length > 0) {
      session.add(result);
    }
    return result;
  }

  elements.input.addEventListener("input", scheduleAnalysis);
  elements.policyPreset.addEventListener("change", scheduleAnalysis);
  [elements.ctxFirst, elements.ctxYear, elements.ctxOrg].forEach((field) => {
    field.addEventListener("input", scheduleAnalysis);
  });

  /* ------------------------------------------------- show / hide password */
  elements.toggleVisibility.addEventListener("click", () => {
    const showing = elements.input.getAttribute("type") === "text";
    elements.input.setAttribute("type", showing ? "password" : "text");
    elements.toggleVisibility.setAttribute("aria-pressed", showing ? "false" : "true");
    elements.toggleVisibility.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    if (!showing) {
      // Focus is kept inside the field; nothing is copied anywhere.
      elements.input.focus();
    }
  });

  elements.clear.addEventListener("click", () => {
    elements.input.value = "";
    elements.input.focus();
    runAnalysis(false);
  });

  /* ------------------------------------------------------- demo walk-through */
  const DEMO_SEQUENCE = [
    "123456",
    "Password123!",
    "aaaaaaaaaaaaaaaa",
    "qwerty2026!",
    "Demo-Pattern-2026!",
    "Tundra-Basil-Falcon-Thistle-Prism"
  ];

  function loadDemo(value) {
    elements.input.value = value;
    activateTab("analyzer");
    runAnalysis(true);
  }

  document.querySelectorAll("#demo-chips .chip, [data-demo]").forEach((chip) => {
    chip.addEventListener("click", () => loadDemo(chip.dataset.demo));
  });

  document.getElementById("run-demo").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    const originalLabel = button.textContent;
    for (const value of DEMO_SEQUENCE) {
      loadDemo(value);
      await new Promise((resolve) => setTimeout(resolve, 850));
    }
    button.disabled = false;
    button.textContent = originalLabel;
  });

  document.getElementById("goto-generator").addEventListener("click", () => {
    activateTab("generator");
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  /* =====================================================================
   * 5. Generator
   * ===================================================================== */
  const generatorState = { mode: "password", last: null };

  const genElements = {
    length: document.getElementById("gen-length"),
    lengthLabel: document.getElementById("gen-length-label"),
    words: document.getElementById("gen-words"),
    wordsLabel: document.getElementById("gen-words-label"),
    separator: document.getElementById("gen-separator"),
    upper: document.getElementById("gen-upper"),
    lower: document.getElementById("gen-lower"),
    digits: document.getElementById("gen-digits"),
    symbols: document.getElementById("gen-symbols"),
    ambiguous: document.getElementById("gen-ambiguous"),
    output: document.getElementById("gen-output"),
    entropy: document.getElementById("gen-entropy"),
    pool: document.getElementById("gen-pool"),
    score: document.getElementById("gen-score"),
    copy: document.getElementById("copy-btn"),
    modePassword: document.getElementById("mode-password"),
    modePassphrase: document.getElementById("mode-passphrase"),
    passwordControls: document.getElementById("password-mode-controls"),
    passphraseControls: document.getElementById("passphrase-mode-controls")
  };

  function setGeneratorMode(mode) {
    generatorState.mode = mode;
    genElements.modePassword.setAttribute("aria-pressed", mode === "password" ? "true" : "false");
    genElements.modePassphrase.setAttribute("aria-pressed", mode === "passphrase" ? "true" : "false");
    genElements.passwordControls.hidden = mode !== "password";
    genElements.passphraseControls.hidden = mode !== "passphrase";
  }

  genElements.modePassword.addEventListener("click", () => setGeneratorMode("password"));
  genElements.modePassphrase.addEventListener("click", () => setGeneratorMode("passphrase"));

  genElements.length.addEventListener("input", () => {
    genElements.lengthLabel.textContent = genElements.length.value + " characters";
  });
  genElements.words.addEventListener("input", () => {
    genElements.wordsLabel.textContent = genElements.words.value + " words";
  });
  document.querySelectorAll("[data-preset]").forEach((button) => {
    button.addEventListener("click", () => {
      genElements.length.value = button.dataset.preset;
      genElements.lengthLabel.textContent = button.dataset.preset + " characters";
      generate();
    });
  });

  function generate() {
    let generated;
    if (generatorState.mode === "passphrase") {
      generated = engine.generatePassphrase({
        words: Number(genElements.words.value),
        separator: genElements.separator.value
      });
    } else {
      generated = engine.generatePassword({
        length: Number(genElements.length.value),
        use_uppercase: genElements.upper.checked,
        use_lowercase: genElements.lower.checked,
        use_digits: genElements.digits.checked,
        use_symbols: genElements.symbols.checked,
        avoid_ambiguous: genElements.ambiguous.checked
      });
    }

    generatorState.last = generated;
    genElements.output.textContent = generated.password;
    genElements.output.classList.remove("empty");
    genElements.entropy.textContent = generated.entropy_bits.toFixed(1);
    genElements.pool.textContent = generated.pool_size ? String(generated.pool_size)
      : (generated.wordlist_size ? generated.wordlist_size + " words" : "—");
    genElements.copy.disabled = false;

    // Analyze the generated value locally so the user sees it is strong.
    const analysis = engine.analyzePassword(generated.password);
    genElements.score.textContent = analysis.score + " · " + analysis.classification;
    session.add(analysis);
    return generated;
  }

  document.getElementById("generate-btn").addEventListener("click", generate);
  document.getElementById("generate-analyze-btn").addEventListener("click", () => {
    const generated = generate();
    elements.input.value = generated.password;
    activateTab("analyzer");
    runAnalysis(true);
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  genElements.copy.addEventListener("click", async () => {
    if (!generatorState.last) { return; }
    try {
      await navigator.clipboard.writeText(generatorState.last.password);
      genElements.copy.textContent = "✅ Copied — paste into your password manager";
      setTimeout(() => { genElements.copy.textContent = "📋 Copy to clipboard"; }, 2600);
    } catch (error) {
      genElements.copy.textContent = "⚠️ Clipboard blocked by the browser";
      setTimeout(() => { genElements.copy.textContent = "📋 Copy to clipboard"; }, 2600);
    }
  });

  document.getElementById("clear-gen-btn").addEventListener("click", () => {
    generatorState.last = null;
    genElements.output.textContent = "Cleared from the page. Nothing was ever stored.";
    genElements.output.classList.add("empty");
    genElements.copy.disabled = true;
    genElements.entropy.textContent = "—";
    genElements.pool.textContent = "—";
    genElements.score.textContent = "—";
  });

  /* =====================================================================
   * 6. Dashboard (aggregates of session metadata)
   * ===================================================================== */
  const SAMPLE_PASSWORDS = [
    "123456", "password", "qwerty123", "Summer2025!", "Rahul@123",
    "aaaaaaaaaaaaaaaa", "abcd1234", "Tr0ub4dor&3", "Sunset-Orchid-River",
    "x7#Kq2!mZ9@vL4$p", "Tundra-Basil-Falcon-Thistle-Prism", "!@#$%^&*()"
  ];

  function classificationColor(label) { return charts.palette[label] || "#4cc9f0"; }

  function renderDashboard() {
    const rows = session.analyses;
    document.getElementById("kpi-total").textContent = String(rows.length);

    if (!rows.length) {
      document.getElementById("kpi-average").textContent = "0";
      document.getElementById("kpi-weak-share").textContent = "0%";
      document.getElementById("kpi-top-weakness").textContent = "—";
      ["chart-distribution", "chart-histogram", "chart-weakness", "chart-length", "chart-patterns"]
        .forEach((id) => {
          document.getElementById(id).innerHTML =
            `<p class="text-faint small mb-0">No analyses in this session yet. Type a password, use the generator, or load the synthetic samples.</p>`;
        });
      document.getElementById("recent-rows").innerHTML =
        '<tr><td colspan="6" class="text-faint">No analyses in this session yet.</td></tr>';
      return;
    }

    const scores = rows.map((row) => row.score);
    const average = scores.reduce((a, b) => a + b, 0) / scores.length;
    const weakShare = Math.round((rows.filter((row) =>
      row.classification === "VERY WEAK" || row.classification === "WEAK").length / rows.length) * 100);

    const categoryCounts = {};
    rows.forEach((row) => row.categories.forEach((category) => {
      categoryCounts[category] = (categoryCounts[category] || 0) + 1;
    }));
    const categoryList = Object.entries(categoryCounts)
      .map(([label, value]) => ({ label: label, value: value }))
      .sort((a, b) => b.value - a.value);

    // "passphrase_structure" records a RECOGNISED SHAPE, not a weakness: it is
    // the finding that suppresses per-word dictionary penalties. Counting it as
    // a weakness would make a strong generated passphrase look like the worst
    // offender on the dashboard, so it is excluded here exactly as the Python
    // analytics layer excludes it (backend/services/audit_store.py).
    const weaknessList = categoryList.filter((item) => item.label !== "passphrase_structure");

    document.getElementById("kpi-average").textContent = average.toFixed(1);
    document.getElementById("kpi-weak-share").textContent = weakShare + "%";
    document.getElementById("kpi-top-weakness").textContent =
      weaknessList.length ? weaknessList[0].label.replace(/_/g, " ") : "none";

    // 1. Strength distribution
    const bands = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"];
    document.getElementById("chart-distribution").innerHTML = charts.verticalBars(
      bands.map((band) => ({
        label: band.replace(" ", "\n"),
        value: rows.filter((row) => row.classification === band).length,
        color: classificationColor(band)
      })));

    // 2. Score histogram
    const buckets = [];
    for (let start = 0; start < 100; start += 10) {
      const end = start === 90 ? 100 : start + 9;
      buckets.push({
        bucket: start + "-" + end,
        count: scores.filter((score) => score >= start && score <= end).length
      });
    }
    document.getElementById("chart-histogram").innerHTML = charts.histogram(buckets);

    // 3. Weakness frequency
    document.getElementById("chart-weakness").innerHTML = charts.horizontalBars(
      weaknessList.map((item) => ({
        label: item.label, value: item.value,
        color: ["common_password", "breach", "common_phrase"].indexOf(item.label) !== -1 ? "#ff4d5e"
          : ["keyboard_pattern", "sequence", "repeated_characters", "repeated_substring",
             "personal_info", "predictable_structure"].indexOf(item.label) !== -1 ? "#ff9147"
          : "#4cc9f0"
      })));

    // 4. Length distribution (length only, never the value)
    const lengthBuckets = { "1-7": 0, "8-11": 0, "12-15": 0, "16-19": 0, "20+": 0 };
    rows.forEach((row) => {
      const length = row.length;
      if (length <= 7) { lengthBuckets["1-7"] += 1; }
      else if (length <= 11) { lengthBuckets["8-11"] += 1; }
      else if (length <= 15) { lengthBuckets["12-15"] += 1; }
      else if (length <= 19) { lengthBuckets["16-19"] += 1; }
      else { lengthBuckets["20+"] += 1; }
    });
    document.getElementById("chart-length").innerHTML = charts.verticalBars(
      Object.entries(lengthBuckets).map(([label, value]) => ({
        label: label, value: value, color: "#4cc9f0"
      })));

    // 5. Average score per length bucket.
    // Deliberately NOT a second copy of the weakness chart: this view shows the
    // relationship between length and the average score in this session, using
    // the same five length buckets that the backend's analytics layer stores.
    const lengthOrder = ["1-7", "8-11", "12-15", "16-19", "20+"];
    document.getElementById("chart-patterns").innerHTML = charts.verticalBars(
      lengthOrder.map((bucket) => {
        const inBucket = rows.filter((row) => {
          const length = row.length;
          return bucket === "1-7" ? length <= 7
            : bucket === "8-11" ? length >= 8 && length <= 11
            : bucket === "12-15" ? length >= 12 && length <= 15
            : bucket === "16-19" ? length >= 16 && length <= 19
            : length >= 20;
        });
        const averageInBucket = inBucket.length
          ? Math.round(inBucket.reduce((sum, row) => sum + row.score, 0) / inBucket.length)
          : 0;
        return {
          label: bucket + " chars",
          value: averageInBucket,
          // Muted colour marks a bucket with no analyses yet, so a "0" is never
          // mistaken for "length 1-7 always scores zero".
          color: !inBucket.length ? "#3b4a68"
            : averageInBucket >= 81 ? charts.palette["VERY STRONG"]
            : averageInBucket >= 61 ? charts.palette.STRONG
            : averageInBucket >= 41 ? charts.palette.MODERATE
            : averageInBucket >= 21 ? charts.palette.WEAK : charts.palette["VERY WEAK"]
        };
      }), { maxOverride: 100 });

    // Recent metadata rows
    document.getElementById("recent-rows").innerHTML = rows.slice(-12).reverse().map((row) => `
      <tr>
        <td class="mono">${escapeHtml(row.analysis_id)}</td>
        <td><strong>${row.score}</strong></td>
        <td><span class="badge-inline" style="color:${classificationColor(row.classification)}">${escapeHtml(row.classification)}</span></td>
        <td class="mono">${row.length}</td>
        <td class="mono">${row.weakness_count}</td>
        <td class="mono">${row.at.toLocaleTimeString()}</td>
      </tr>`).join("");
  }

  document.getElementById("load-samples").addEventListener("click", () => {
    SAMPLE_PASSWORDS.forEach((password) => {
      const result = engine.analyzePassword(password, { policy: engine.presetPolicies.standard_account });
      session.add(result);
    });
    renderDashboard();
  });

  document.getElementById("reset-analytics").addEventListener("click", () => {
    session.reset();
    renderDashboard();
  });

  /* =====================================================================
   * 7. Education content (rules + interview Q&A), injected so the text stays
   *    in one place and can be reused in the written report.
   * ===================================================================== */
  const RULES = [
    ["Use a unique password for every account",
     "Reuse converts one breach into many compromised accounts. Credential stuffing simply replays leaked username/password pairs against other services."],
    ["Prefer length over clever substitutions",
     "Each additional character multiplies an attacker's work. Swapping “a” for “@” adds almost nothing, because tools try those substitutions automatically."],
    ["Avoid predictable personal information",
     "Names, birth years, phone numbers and organisation names are discoverable from profiles, resumes and breach data — and are tried first in targeted attacks."],
    ["Avoid common passwords and famous phrases",
     "Known passwords and well-known quotations occupy the first entries of every attack wordlist, so length alone will not protect them."],
    ["Never reuse a password across sites",
     "A single leaked database becomes a master key for your other accounts, including ones you consider low risk."],
    ["Use a password manager",
     "It generates and stores unique passwords, so you only memorise one strong secret and never need to invent a memorable one."],
    ["Enable MFA wherever it is offered",
     "MFA keeps an account protected even when the password leaks, and it defeats credential stuffing outright in most configurations."],
    ["Never share a password",
     "Sharing destroys accountability and usually spreads the secret through insecure channels such as chat or email."],
    ["Be sceptical of links and login pages",
     "Phishing bypasses password strength entirely by asking you to type your password into an attacker-controlled page."],
    ["Change a password when compromise is suspected or confirmed",
     "Modern guidance: rotate on evidence of compromise rather than on a calendar. Periodic forced rotation pushes users towards predictable increments."]
  ];

  document.getElementById("rule-grid").innerHTML = RULES.map(([title, why], index) => `
    <div class="rule">
      <div class="rule-num" aria-hidden="true">${index + 1}</div>
      <div><h4>${escapeHtml(title)}</h4><p>${escapeHtml(why)}</p></div>
    </div>`).join("");

  const QA = [
    ["Explain your project.",
     "I built a Password Strength Analyzer & Security Suggestion Tool that evaluates a password using many signals instead of only checking whether it contains uppercase, lowercase, digits and symbols. It measures length and character diversity, then looks for predictability: common passwords, dictionary words, numeric and alphabetic sequences, keyboard walks, repeated characters and blocks, predictable word-plus-number and word-plus-year shapes, and optional overlap with personal context the user volunteers. It also produces a theoretical and an effective entropy estimate and combines everything into a 0–100 score with a five-band classification, and generates specific suggestions for each weakness. The important privacy property is that the password is processed in memory only — it is never stored, never logged, never returned in the API response and never sent to an external service. The static build runs the whole engine in the browser, so the password never even leaves the page."],
    ["How does your analyzer decide whether a password is strong?",
     "It combines positive and negative signals. Positively: length (up to 35 points), character diversity (15), unique-character ratio (10), pattern resistance (20), not being a common password (10) and an unpredictability bonus (10). Negatively: capped penalties for each weakness category — a common-password or breach hit loses up to 45 points, personal information up to 20, predictable structures up to 15, sequences and keyboard walks up to 15 each, and so on. A few structural rules then cap the score, for example a value that is a single character repeated 16 times cannot score above 15 no matter how long it is. The result is more useful than a composition checklist because a predictable twelve-character password such as “Password123!” ends up in the VERY WEAK band while a longer random or passphrase-shaped value scores in the STRONG range."],
    ["What is password entropy, and what are its limitations?",
     "Entropy describes the uncertainty an attacker faces, measured in bits. The classic estimate is length multiplied by log base 2 of the assumed character pool. The limitation is that the formula assumes every character was chosen uniformly at random, and human-chosen passwords are not random — they take a memorable word and add a year or a symbol. That is why “Password123!” can look decent in a theoretical estimate while being one of the first values any tool tries. In my implementation I therefore report the theoretical estimate, subtract a penalty for every predictable structure detected to produce an effective estimate, and display it next to three clearly labelled guess-resistance scenarios rather than as a guaranteed crack time."],
    ["Why is “Password123!” not a strong password?",
     "It satisfies every composition rule — uppercase, lowercase, digit, symbol, twelve characters — but it is built from the single most common word in password lists plus a fixed numeric suffix plus a symbol. My analyzer flags it three ways: it matches the common-password list, it appears in the demo breach corpus, and it matches the predictable word-plus-number structure. Those findings trigger a hard cap that keeps it in the VERY WEAK band. It is the exact example I use to show why composition rules alone cannot be the test."],
    ["What is the difference between hashing and encryption?",
     "Encryption is reversible: with the correct key you can recover the original data. Password hashing is one-way verification. A production system stores a value derived from the password by a password-hashing function, and at login it derives the same value again and compares. The server never needs to recover the original password, so there is no key to steal that would reveal every user's password at once. Encryption protects data you must be able to read later; hashing protects a secret you only ever need to verify."],
    ["What is salting and why does it matter?",
     "A salt is a unique random value generated per user and mixed into the hashing process. Without a salt, two users with the same password produce identical stored hashes, so one precomputed rainbow table cracks every matching account at once and a single lookup reveals which accounts share a password. With a unique salt per record, identical passwords produce completely different stored values, which makes precomputation useless and forces an attacker to work per account. Modern password-hashing libraries handle salt generation for you, and my hashing demonstration page shows two salts producing two unrelated hashes for the same synthetic input."],
    ["Why shouldn't passwords be stored with a fast hash such as SHA-256 on its own?",
     "General-purpose hashes are designed to be fast, which is excellent for file integrity checks and terrible for password storage: fast verification means fast guessing. A GPU rig can compute billions of plain SHA-256 hashes per second, so a leaked database of fast hashes can be largely recovered. Password-hashing functions such as Argon2id, bcrypt, scrypt and PBKDF2 are deliberately slow and parameterisable, and memory-hard designs such as Argon2id and scrypt additionally resist the parallel hardware that makes fast hashes cheap to attack. In my project I demonstrate both sides: scrypt and PBKDF2 with high work factors, next to a fast hash that exists purely as an anti-pattern."],
    ["How did you protect user privacy in this project?",
     "Privacy is enforced by design, not by policy text. The value is used for one in-memory analysis and then discarded: it is never written to a database, never logged, never returned in the API response, never placed in a URL and never sent to an external service. The SQLite analytics schema has columns for score, classification, length, ratios, counts and timestamps — and no password column and no password-hash column. There is a logging filter that redacts anything that looks like a secret, and the audit helper function literally has no parameter that could accept a password. Every piece of evidence shown in the UI is masked with bullet characters. The static build makes zero network requests, and the page counts them so you can see the number stay at zero. Each of these is covered by an automated test rather than a promise."],
    ["Is a strong password enough to secure an account?",
     "No. Password strength is one layer. A real login system also needs MFA, secure password hashing with an appropriate work factor, rate limiting and account lockout, session protection, phishing defences, monitoring and safe account-recovery flows. A perfect password cannot protect a user who types it into a phishing page, and it cannot help if the service stored it in plaintext. Conversely MFA protects an account even when a strong password leaks. That is why my project ends with the message that password strength is necessary but not sufficient."],
    ["How would you improve this project in the future?",
     "First, add a peer-reviewed estimator such as a zxcvbn-style model and compare its output with mine, so the rubric is validated against established research rather than being project-defined. Second, replace the small demo breach corpus with a privacy-preserving lookup that sends only a five-character hash prefix and compares suffixes locally. Third, make the policy engine enterprise-configurable with audit export, and add education for MFA, passkeys and passwordless authentication. Fourth, improve accessibility and localisation, and add organisation-level aggregate reporting that still never collects a password. Finally, I would package the engine as a browser extension so scoring happens locally on any signup form."]
  ];

  document.getElementById("qa-list").innerHTML = QA.map(([question, answer], index) => `
    <details class="qa"${index === 0 ? " open" : ""}>
      <summary>Q${index + 1}. ${escapeHtml(question)}</summary>
      <div><p>${escapeHtml(answer)}</p></div>
    </details>`).join("");

  /* =====================================================================
   * 8. Hashing demonstration
   * ===================================================================== */
  document.getElementById("run-hash-demo").addEventListener("click", () => {
    window.PSAHashDemo.run(document.getElementById("hash-demo-output"));
  });

  /* =====================================================================
   * 9. Boot
   * ===================================================================== */
  (function boot() {
    const dataStats = engine.dataStats;
    const wordsNode = document.getElementById("stat-words");
    if (wordsNode && dataStats.passphrase_words) {
      wordsNode.textContent = dataStats.passphrase_words.toLocaleString();
    }
    const detectorsNode = document.getElementById("stat-detectors");
    if (detectorsNode) {
      // Count of independent detectors + structural + entropy + policy signals.
      detectorsNode.textContent = "14";
    }

    // Replace the placeholder stat block value for network requests.
    const statsGrid = document.querySelector(".stat-grid");
    if (statsGrid) {
      const cards = statsGrid.querySelectorAll(".stat-value");
      if (cards.length >= 2) {
        cards[1].setAttribute("data-stat", "requests");
        cards[1].textContent = "0";
      }
    }

    setGeneratorMode("password");
    genElements.lengthLabel.textContent = genElements.length.value + " characters";
    genElements.wordsLabel.textContent = genElements.words.value + " words";
    activateTab(location.hash.slice(1) || "analyzer");
    runAnalysis(false);

    // Show which engine is running, so nobody wonders whether data is sent.
    const badge = document.getElementById("engine-badge");
    if (badge) {
      badge.title = "In-browser engine (" + dataStats.common_passwords + " common passwords, " +
        dataStats.passphrase_words.toLocaleString() + " passphrase words loaded locally). " +
        "Network requests made: 0.";
    }
  })();
})();
