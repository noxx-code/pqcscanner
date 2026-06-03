/**
 * AegisGuard PQC Scanner — Dashboard Controller
 * Vanilla JS — No frameworks, no dependencies.
 */

(function () {
  "use strict";

  /* ================================================================
   *  Constants
   * ================================================================ */
  const API_BASE = "";  // same-origin
  const GRADE_COLORS = {
    "A+": "#10b981", A: "#10b981", B: "#22d3ee",
    C: "#f59e0b", D: "#f97316", F: "#ef4444",
  };

  /* ================================================================
   *  DOM references
   * ================================================================ */
  const $ = (id) => document.getElementById(id);

  const dom = {
    target:       $("scan-target"),
    port:         $("scan-port"),
    btnScan:      $("btn-scan"),
    btnBulk:      $("btn-bulk"),
    statusLabel:  $("status-label"),
    statusDetail: $("status-detail"),

    emptyState:   $("empty-state"),
    gradeCard:    $("grade-card"),
    pqcCard:      $("pqc-card"),
    trendCard:    $("trend-card"),
    findingsCard: $("findings-card"),
    policyCard:   $("policy-card"),
    probeCard:    $("probe-card"),
    actionsRow:   $("actions-row"),

    gradeLetter:  $("grade-letter"),
    gradeScore:   $("grade-score"),
    gradeBadge:   $("grade-badge"),
    gradeRing:    $("grade-ring-progress"),

    metaTLS:      $("meta-tls"),
    metaKemType:  $("meta-kem-type"),
    metaKemName:  $("meta-kem-name"),
    metaScanTime: $("meta-scan-time"),

    pqcBadge:     $("pqc-badge"),
    legendPqc:    $("legend-pqc"),
    legendPartial:$("legend-partial"),
    legendVuln:   $("legend-vuln"),

    findingsTabs: $("findings-tabs"),
    findingsList: $("findings-list"),
    countCritical:$("count-critical"),
    countHigh:    $("count-high"),
    countMedium:  $("count-medium"),
    countInfo:    $("count-info"),

    policyList:   $("policy-list"),
    probeGrid:    $("probe-grid"),

    btnCbom:      $("btn-cbom"),
    btnCert:      $("btn-cert"),
    btnRaw:       $("btn-raw"),

    overlay:      $("scan-overlay"),
    overlayText:  $("scan-overlay-text"),

    bulkBackdrop: $("bulk-backdrop"),
    bulkModal:    $("bulk-modal"),
    bulkTargets:  $("bulk-targets"),
    btnBulkCancel:$("btn-bulk-cancel"),
    btnBulkRun:   $("btn-bulk-run"),

    toasts:       $("toast-container"),
  };

  /* ================================================================
   *  State
   * ================================================================ */
  let lastResult = null;
  let currentFindings = { critical: [], high: [], medium: [], info: [] };
  let activeSeverity = "critical";

  /* ================================================================
   *  Utilities
   * ================================================================ */
  function toast(msg, type = "info") {
    const el = document.createElement("div");
    el.className = `toast toast--${type}`;
    el.textContent = msg;
    dom.toasts.appendChild(el);
    setTimeout(() => { el.style.opacity = "0"; setTimeout(() => el.remove(), 400); }, 4500);
  }

  function showOverlay(text) {
    dom.overlayText.textContent = text;
    dom.overlay.classList.add("scan-overlay--visible");
  }

  function hideOverlay() {
    dom.overlay.classList.remove("scan-overlay--visible");
  }

  function showCards() {
    dom.emptyState.classList.add("hidden");
    [dom.gradeCard, dom.pqcCard, dom.trendCard, dom.findingsCard,
     dom.policyCard, dom.probeCard, dom.actionsRow].forEach(
      (el) => el.classList.remove("hidden")
    );
  }

  async function apiFetch(path, opts = {}) {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `HTTP ${res.status}`);
    }
    return res;
  }

  /* ================================================================
   *  Scan
   * ================================================================ */
  async function runScan() {
    const target = dom.target.value.trim();
    if (!target) { toast("Please enter a domain", "error"); return; }

    const port = parseInt(dom.port.value, 10) || 443;
    dom.btnScan.disabled = true;
    showOverlay("Probing TLS handshake…");

    try {
      const res = await apiFetch("/scan", {
        method: "POST",
        body: JSON.stringify({ target, port, mode: "full" }),
      });
      lastResult = await res.json();
      renderDashboard(lastResult);
      toast(`Scan complete — Grade ${lastResult.grade}`, "success");
    } catch (err) {
      toast(`Scan failed: ${err.message}`, "error");
    } finally {
      hideOverlay();
      dom.btnScan.disabled = false;
    }
  }

  /* ================================================================
   *  Render
   * ================================================================ */
  function renderDashboard(d) {
    showCards();

    // -- Grade card --
    const color = GRADE_COLORS[d.grade] || "#64748b";
    dom.gradeLetter.textContent = d.grade;
    dom.gradeLetter.style.color = color;
    dom.gradeScore.textContent = `${d.score}/100`;

    const circ = 2 * Math.PI * 52;  // 326.73
    const offset = circ - (d.score / 100) * circ;
    dom.gradeRing.style.stroke = color;
    dom.gradeRing.style.strokeDashoffset = offset;

    const badgeCls = d.quantum_safe
      ? (d.kem_type === "hybrid" ? "card__badge--hybrid" : "card__badge--safe")
      : "card__badge--vuln";
    dom.gradeBadge.className = `card__badge ${badgeCls}`;
    dom.gradeBadge.textContent = d.quantum_safe
      ? (d.kem_type === "hybrid" ? "HYBRID" : "PQC SAFE")
      : "VULNERABLE";

    dom.metaTLS.textContent = `TLS ${d.tls_version}`;
    dom.metaKemType.textContent = d.kem_type.toUpperCase();
    dom.metaKemName.textContent = d.kem_name;
    dom.metaScanTime.textContent = `${d.scan_time_ms}ms`;

    // -- PQC donut card --
    renderDonut(d.pqc_pct, d.partial_pct, d.vuln_pct);
    dom.legendPqc.textContent = `${d.pqc_pct}%`;
    dom.legendPartial.textContent = `${d.partial_pct}%`;
    dom.legendVuln.textContent = `${d.vuln_pct}%`;

    const pqcLabel = d.pqc_label || "Unknown";
    const pqcBadgeCls = d.quantum_safe
      ? (d.kem_type === "hybrid" ? "card__badge--hybrid" : "card__badge--safe")
      : "card__badge--vuln";
    dom.pqcBadge.className = `card__badge ${pqcBadgeCls}`;
    dom.pqcBadge.textContent = pqcLabel;

    // -- Trend card --
    renderTrend(d.trend || []);

    // -- Findings --
    currentFindings.critical = d.critical_findings || [];
    currentFindings.high = d.high_findings || [];
    currentFindings.medium = d.medium_findings || [];
    currentFindings.info = d.info_findings || [];

    dom.countCritical.textContent = currentFindings.critical.length;
    dom.countHigh.textContent = currentFindings.high.length;
    dom.countMedium.textContent = currentFindings.medium.length;
    dom.countInfo.textContent = currentFindings.info.length;

    // Auto-select first non-empty tab
    if (currentFindings.critical.length) activeSeverity = "critical";
    else if (currentFindings.high.length) activeSeverity = "high";
    else if (currentFindings.medium.length) activeSeverity = "medium";
    else activeSeverity = "info";

    renderFindings();

    // -- Policy --
    renderPolicy(d.policy_compliance || {});

    // -- Probe --
    renderProbe(d.probe || {});

    // -- Actions --
    dom.btnCbom.disabled = false;
    dom.btnCert.disabled = !d.cert_eligible;
    dom.btnRaw.disabled = false;

    // Status bar
    dom.statusLabel.textContent = "Scan Complete";
    dom.statusDetail.textContent =
      `${d.raw_tls?.host || "—"}:${d.raw_tls?.port || "—"} · ${d.grade} · ${d.score}/100`;
  }

  /* ================================================================
   *  Donut chart (canvas)
   * ================================================================ */
  function renderDonut(pqc, partial, vuln) {
    const canvas = $("pqc-donut");
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    canvas.width = 120 * dpr;
    canvas.height = 120 * dpr;
    ctx.scale(dpr, dpr);
    canvas.style.width = "120px";
    canvas.style.height = "120px";

    const cx = 60, cy = 60, r = 46, lineWidth = 12;
    const total = pqc + partial + vuln || 1;
    const segments = [
      { pct: pqc / total,     color: "#10b981" },
      { pct: partial / total,  color: "#f59e0b" },
      { pct: vuln / total,     color: "#f43f5e" },
    ];

    ctx.clearRect(0, 0, 120, 120);

    // Background ring
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(255,255,255,0.06)";
    ctx.lineWidth = lineWidth;
    ctx.stroke();

    // Segments
    let startAngle = -Math.PI / 2;
    segments.forEach((seg) => {
      if (seg.pct <= 0) return;
      const sweep = seg.pct * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, startAngle, startAngle + sweep);
      ctx.strokeStyle = seg.color;
      ctx.lineWidth = lineWidth;
      ctx.lineCap = "round";
      ctx.stroke();
      startAngle += sweep + 0.04; // tiny gap
    });

    // Center label
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillStyle = "#f1f5f9";
    ctx.font = "bold 18px Inter, sans-serif";
    ctx.fillText(`${pqc}%`, cx, cy - 6);
    ctx.font = "11px Inter, sans-serif";
    ctx.fillStyle = "#94a3b8";
    ctx.fillText("PQC", cx, cy + 12);
  }

  /* ================================================================
   *  Trend line chart (canvas)
   * ================================================================ */
  function renderTrend(data) {
    const canvas = $("trend-canvas");
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.parentElement.clientWidth - 44;
    const h = 120;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";

    if (!data.length) return;
    ctx.clearRect(0, 0, w, h);

    const pad = { top: 10, right: 10, bottom: 24, left: 30 };
    const cw = w - pad.left - pad.right;
    const ch = h - pad.top - pad.bottom;
    const maxVal = 100;

    const pts = data.map((v, i) => ({
      x: pad.left + (i / (data.length - 1)) * cw,
      y: pad.top + (1 - v / maxVal) * ch,
    }));

    // Grid lines
    ctx.strokeStyle = "rgba(255,255,255,0.05)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (i / 4) * ch;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(w - pad.right, y);
      ctx.stroke();

      ctx.fillStyle = "#64748b";
      ctx.font = "10px Inter, sans-serif";
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      ctx.fillText(Math.round(100 - (i / 4) * 100), pad.left - 6, y);
    }

    // Day labels
    const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Today"];
    ctx.fillStyle = "#64748b";
    ctx.font = "10px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    pts.forEach((p, i) => {
      ctx.fillText(days[i] || `D${i + 1}`, p.x, h - pad.bottom + 6);
    });

    // Area fill
    const grad = ctx.createLinearGradient(0, pad.top, 0, h - pad.bottom);
    grad.addColorStop(0, "rgba(99,102,241,0.18)");
    grad.addColorStop(1, "rgba(99,102,241,0)");
    ctx.beginPath();
    ctx.moveTo(pts[0].x, h - pad.bottom);
    pts.forEach((p) => ctx.lineTo(p.x, p.y));
    ctx.lineTo(pts[pts.length - 1].x, h - pad.bottom);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    pts.forEach((p, i) => (i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y)));
    ctx.strokeStyle = "#6366f1";
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.stroke();

    // Dots
    pts.forEach((p, i) => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, i === pts.length - 1 ? 5 : 3, 0, Math.PI * 2);
      ctx.fillStyle = i === pts.length - 1 ? "#6366f1" : "#818cf8";
      ctx.fill();
      if (i === pts.length - 1) {
        ctx.strokeStyle = "rgba(99,102,241,0.3)";
        ctx.lineWidth = 6;
        ctx.stroke();
      }
    });
  }

  /* ================================================================
   *  Findings list
   * ================================================================ */
  function renderFindings() {
    // Active tab
    dom.findingsTabs.querySelectorAll(".findings-tab").forEach((t) => {
      t.classList.toggle("findings-tab--active", t.dataset.severity === activeSeverity);
    });

    const items = currentFindings[activeSeverity] || [];
    if (!items.length) {
      dom.findingsList.innerHTML =
        `<li class="finding-item"><span class="text-muted">No ${activeSeverity} findings</span></li>`;
      return;
    }

    dom.findingsList.innerHTML = items
      .map(
        (text) => `
        <li class="finding-item">
          <span class="finding-item__severity finding-item__severity--${activeSeverity}"></span>
          <span class="finding-item__text">${escapeHTML(text)}</span>
        </li>`
      )
      .join("");
  }

  function escapeHTML(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
  }

  /* ================================================================
   *  Policy compliance
   * ================================================================ */
  function renderPolicy(policy) {
    const labels = {
      key_exchange: "Key Exchange (PQC KEM)",
      digital_sig: "Digital Signature (PQC)",
      cipher_suite: "Cipher Suite",
      tls_protocol: "TLS Protocol",
      pqc_compliance: "Full PQC Compliance",
    };
    dom.policyList.innerHTML = Object.entries(policy)
      .map(([k, v]) => `
        <li class="policy-item">
          <span class="policy-item__label">${labels[k] || k}</span>
          <span class="policy-item__status policy-item__status--${v ? "pass" : "fail"}">
            ${v ? "✓ Pass" : "✗ Fail"}
          </span>
        </li>`)
      .join("");
  }

  /* ================================================================
   *  Probe / Certificate details
   * ================================================================ */
  function renderProbe(probe) {
    const fields = [
      ["IP Address", probe.ip],
      ["HSTS", probe.hsts ? "Enabled" : "Not Set"],
      ["Subject", probe.cert_subject],
      ["Issuer", probe.cert_issuer],
      ["Public Key", `${probe.cert_pubkey_alg} ${probe.cert_pubkey_bits}b`],
      ["Signature", probe.cert_sig_alg],
      ["Expires", probe.cert_not_after],
      ["Days Left", probe.cert_days_left],
      ["Expired", probe.cert_expired ? "Yes" : "No"],
      ["Self-Signed", probe.cert_self_signed ? "Yes" : "No"],
    ];
    dom.probeGrid.innerHTML = fields
      .map(([k, v]) => `
        <div class="probe-item">
          <span class="probe-item__key">${k}</span>
          <span class="probe-item__val" title="${escapeHTML(String(v ?? "—"))}">${escapeHTML(String(v ?? "—"))}</span>
        </div>`)
      .join("");
  }

  /* ================================================================
   *  CBOM / Certificate / Raw JSON actions
   * ================================================================ */
  async function exportCBOM() {
    if (!lastResult) return;
    const target = dom.target.value.trim();
    const port = parseInt(dom.port.value, 10) || 443;
    showOverlay("Generating CBOM…");
    try {
      const res = await fetch(`${API_BASE}/cbom`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, port, mode: "full" }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "Failed");
      const blob = await res.blob();
      downloadBlob(blob, `cbom_${target}_${port}.json`);
      toast("CBOM exported successfully", "success");
    } catch (err) {
      toast(`CBOM export failed: ${err.message}`, "error");
    } finally {
      hideOverlay();
    }
  }

  async function downloadCert() {
    if (!lastResult) return;
    const target = dom.target.value.trim();
    const port = parseInt(dom.port.value, 10) || 443;
    showOverlay("Generating PQC Certificate…");
    try {
      const res = await fetch(`${API_BASE}/certificate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, port, mode: "full" }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "Failed");
      const blob = await res.blob();
      downloadBlob(blob, `pqc_certificate_${target}.pdf`);
      toast("PQC Certificate downloaded", "success");
    } catch (err) {
      toast(`Certificate failed: ${err.message}`, "error");
    } finally {
      hideOverlay();
    }
  }

  function showRawJSON() {
    if (!lastResult) return;
    const w = window.open("", "_blank");
    w.document.write(
      `<pre style="background:#0a0e1a;color:#e2e8f0;padding:24px;font-family:monospace;font-size:13px;white-space:pre-wrap">${
        escapeHTML(JSON.stringify(lastResult, null, 2))
      }</pre>`
    );
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  /* ================================================================
   *  Bulk Scan
   * ================================================================ */
  function openBulkModal() {
    dom.bulkBackdrop.classList.add("modal-backdrop--visible");
    dom.bulkModal.classList.add("modal--visible");
    dom.bulkTargets.focus();
  }

  function closeBulkModal() {
    dom.bulkBackdrop.classList.remove("modal-backdrop--visible");
    dom.bulkModal.classList.remove("modal--visible");
  }

  async function runBulkScan() {
    const raw = dom.bulkTargets.value.trim();
    if (!raw) { toast("Enter at least one target", "error"); return; }

    const targets = raw.split("\n").map((l) => l.trim()).filter(Boolean);
    if (targets.length > 20) { toast("Maximum 20 targets allowed", "error"); return; }

    closeBulkModal();
    const port = parseInt(dom.port.value, 10) || 443;
    showOverlay(`Scanning ${targets.length} targets…`);

    try {
      const res = await apiFetch("/scan/bulk", {
        method: "POST",
        body: JSON.stringify({ targets, port, mode: "full" }),
      });
      const data = await res.json();
      toast(
        `Bulk scan done — ${data.pqc_safe} safe, ${data.pqc_vulnerable} vulnerable`,
        data.pqc_vulnerable === 0 ? "success" : "info"
      );

      // Render the first successful result on the dashboard
      const first = (data.results || []).find((r) => r.result);
      if (first) {
        lastResult = first.result;
        dom.target.value = first.target;
        renderDashboard(lastResult);
      }
    } catch (err) {
      toast(`Bulk scan failed: ${err.message}`, "error");
    } finally {
      hideOverlay();
    }
  }

  /* ================================================================
   *  Event binding
   * ================================================================ */
  dom.btnScan.addEventListener("click", runScan);
  dom.target.addEventListener("keydown", (e) => { if (e.key === "Enter") runScan(); });

  dom.btnBulk.addEventListener("click", openBulkModal);
  dom.btnBulkCancel.addEventListener("click", closeBulkModal);
  dom.bulkBackdrop.addEventListener("click", closeBulkModal);
  dom.btnBulkRun.addEventListener("click", runBulkScan);

  dom.btnCbom.addEventListener("click", exportCBOM);
  dom.btnCert.addEventListener("click", downloadCert);
  dom.btnRaw.addEventListener("click", showRawJSON);

  dom.findingsTabs.addEventListener("click", (e) => {
    const tab = e.target.closest(".findings-tab");
    if (!tab) return;
    activeSeverity = tab.dataset.severity;
    renderFindings();
  });

  // Health check on load
  (async () => {
    try {
      const res = await apiFetch("/health");
      const h = await res.json();
      dom.statusLabel.textContent = "Online";
      dom.statusDetail.textContent =
        `${h.scanner} v${h.version} — ${h.capabilities.length} capabilities ready`;
    } catch {
      dom.statusLabel.textContent = "Offline";
      dom.statusLabel.style.color = "#f43f5e";
    }
  })();

})();
