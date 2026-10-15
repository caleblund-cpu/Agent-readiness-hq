/* Agent Readiness HQ — site wiring (vanilla JS, no frameworks). */
(function () {
  "use strict";

  /* ================================================================
     CONFIG
     ----------------------------------------------------------------
     API_URL: where the audit function lives. Default "/api/audit"
        works automatically when the site + API are deployed together
        on Vercel (same project, same domain). Leave it alone unless
        you split them apart.
     SUBSCRIBE_URL: "/api/subscribe" forwards signups to Caleb's inbox
        via FormSubmit (no account, no API key — nothing to configure).
        NOTE: the live site now posts to FormSubmit directly from the
        browser instead (see FORMSUBMIT_URL below); the proxy is kept as
        a fallback.
     ================================================================ */
  var API_URL = "/api/audit";

  /* Email signup posts directly to FormSubmit from the visitor's browser
     (no server proxy — FormSubmit throttles shared server IPs, which broke
     the /api/subscribe proxy). The _autoresponse text below is the exact
     wording shown to Caleb on 2026-10-10. */
  var FORMSUBMIT_URL = "https://formsubmit.co/ajax/caleblund@gmail.com";
  var AUTORESPONSE_TEXT = "Thanks for your interest in Agent Readiness HQ! "
    + "We'll be in touch soon with your fix-it report and practical tips for "
    + "making your business easy for AI agents to find, understand, and buy "
    + "from. — Caleb, Agent Readiness HQ";

  var SITE_URL = "https://agentreadinesshq.com/";

  var auditForm = document.getElementById("audit-form");
  var urlInput = document.getElementById("site-url");
  var auditBtn = document.getElementById("audit-btn");
  var statusEl = document.getElementById("audit-status");
  var resultsEl = document.getElementById("audit-results");
  var emailCapture = document.getElementById("email-capture");
  var emailForm = document.getElementById("email-form");
  var emailNote = document.getElementById("email-note");

  var STATUS_ICON = { pass: "\u2713", partial: "~", fail: "\u2717" };

  function setStatus(msg) {
    statusEl.textContent = msg;
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function renderResults(report) {
    var pct = Math.max(0, Math.min(100, Number(report.score) || 0));
    var ringColor = pct >= 80 ? "#16a34a" : pct >= 60 ? "#d97706" : "#dc2626";
    var circ = (2 * Math.PI * 54).toFixed(1);
    var target = (2 * Math.PI * 54 * (1 - pct / 100)).toFixed(1);
    var html = "";
    html += '<div class="score-block">';
    html += '<div class="score-ring-wrap">';
    html += '<svg class="score-ring" viewBox="0 0 120 120" aria-hidden="true">';
    html += '<circle cx="60" cy="60" r="54" class="ring-bg"/>';
    html += '<circle cx="60" cy="60" r="54" class="ring-fg" stroke="' + ringColor + '"';
    html += ' style="--ring-c:' + circ + ';--ring-target:' + target + '"';
    html += ' stroke-dasharray="' + circ + '" stroke-dashoffset="' + circ + '"/>';
    html += "</svg>";
    html += '<div class="score-center"><div class="score-number">' + esc(report.score) + '</div>';
    html += '<div class="score-max">/ 100</div></div>';
    html += "</div>";
    html += '<div class="score-grade">Grade ' + esc(report.grade || "-") + "</div>";
    html += '<div class="score-url">' + esc(report.url) + "</div>";
    html += "</div>";

    html += '<ul class="result-checks">';
    (report.checks || []).forEach(function (c) {
      html += '<li class="check-' + esc(c.status) + '">';
      html += '<span class="check-icon">' + (STATUS_ICON[c.status] || "?") + "</span> ";
      html += "<strong>" + esc(c.name) + "</strong> ";
      html += '<span class="check-score">' + esc(c.score) + "/" + esc(c.weight) + "</span>";
      html += '<div class="check-detail">' + esc(c.detail) + "</div>";
      html += "</li>";
    });
    html += "</ul>";

    var fixes = (report.fixes || []).slice(0, 3);
    if (fixes.length) {
      html += '<div class="top-fixes"><h3>Top fixes</h3><ol>';
      fixes.forEach(function (f) { html += "<li>" + esc(f) + "</li>"; });
      html += "</ol></div>";
    }
    if ((report.errors || []).length) {
      html += '<p class="result-errors">Note: ' + esc(report.errors.join("; ")) + "</p>";
    }
    resultsEl.innerHTML = html;
    resultsEl.hidden = false;
  }

  auditForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var url = urlInput.value.trim();
    if (!url) return;
    auditBtn.disabled = true;
    auditBtn.textContent = "Auditing\u2026";
    resultsEl.hidden = true;
    setStatus("Running the 7-check audit on " + url + " \u2014 usually under 30 seconds.");

    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
      .then(function (resp) {
        return resp.json().then(function (body) {
          return { ok: resp.ok, body: body };
        });
      })
      .then(function (out) {
        if (!out.ok || out.body.error && !(out.body.checks || []).length) {
          throw new Error((out.body && out.body.error) || "audit failed");
        }
        setStatus("");
        renderResults(out.body);
        resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
      })
      .catch(function (err) {
        setStatus("Couldn't run the audit: " + err.message + ". Check the URL and try again.");
      })
      .finally(function () {
        auditBtn.disabled = false;
        auditBtn.textContent = "Run my free audit";
      });
  });

  emailForm.addEventListener("submit", function (e) {
    e.preventDefault();
    submitEmail(
      document.getElementById("email").value.trim(),
      "audit-page",
      emailNote,
      emailForm
    );
  });

  var newsletterForm = document.getElementById("newsletter-form");
  var newsletterNote = document.getElementById("newsletter-note");
  newsletterForm.addEventListener("submit", function (e) {
    e.preventDefault();
    submitEmail(
      document.getElementById("newsletter-email").value.trim(),
      "newsletter",
      newsletterNote,
      newsletterForm
    );
  });

  function submitEmail(email, source, noteEl, formEl) {
    if (!email) return;
    noteEl.textContent = "Joining…";
    // Form-encoded (not JSON) so the browser treats this as a simple
    // CORS request — no preflight, works everywhere.
    var params = new URLSearchParams();
    params.append("email", email);
    params.append("_subject", "New Agent Readiness HQ signup");
    params.append("message", "New signup from " + source + ": " + email);
    params.append("_template", "table");
    params.append("_autoresponse", AUTORESPONSE_TEXT);
    fetch(FORMSUBMIT_URL, { method: "POST", body: params })
      .then(function (resp) {
        return resp.json().catch(function () { return {}; });
      })
      .then(function (body) {
        if (!body || body.success !== "true") {
          throw new Error("signup failed");
        }
        noteEl.textContent = source === "newsletter"
          ? "You're on the list — talk soon."
          : "You're in — the full fix-it report is on its way.";
        formEl.reset();
      })
      .catch(function (err) {
        console.error("[Agent Readiness HQ] email submit failed:", err);
        noteEl.textContent = "Something went wrong saving your email — please try again.";
      });
  }
})();
