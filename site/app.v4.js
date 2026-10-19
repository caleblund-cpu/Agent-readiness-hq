/* Agent Readiness HQ - site wiring (vanilla JS, no frameworks). */
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
        via FormSubmit (no account, no API key - nothing to configure).
        NOTE: the live site now posts to FormSubmit directly from the
        browser instead (see FORMSUBMIT_URL below); the proxy is kept as
        a fallback.
     ================================================================ */
  var API_URL = "/api/audit";

  /* Email signup posts directly to FormSubmit from the visitor's browser
     (no server proxy - FormSubmit throttles shared server IPs, which broke
     the /api/subscribe proxy). The _autoresponse text below is the exact
     wording shown to Caleb on 2026-10-10. */
  var FORMSUBMIT_URL = "https://formsubmit.co/ajax/c171c3e0d3fb9d3525cb0945982c5d2b";
  var AUTORESPONSE_TEXT = "Thanks for your interest in Agent Readiness HQ! "
    + "We'll be in touch within one business day with a fix-it report "
    + "and details on our $149 report and $449 done-for-you cleanup. "
    + "Rachael, Agent Readiness HQ";

  var SITE_URL = "https://agentreadinesshq.com/";

  var auditForm = document.getElementById("audit-form");
  var urlInput = document.getElementById("site-url");
  var auditBtn = document.getElementById("audit-btn");
  var statusEl = document.getElementById("audit-status");
  var resultsEl = document.getElementById("audit-results");
  var emailCapture = document.getElementById("email-capture");
  var emailForm = document.getElementById("email-form");
  var emailNote = document.getElementById("email-note");

  /* Email capture guard: all listeners below are attached only when
     their forms exist, so missing forms don't throw. */

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

    /* Top fixes are hidden from the free audit - the specific fixes are
       what the $149 report sells. The free result shows the diagnosis
       (score + check breakdown); the prescription is paid. */
    if ((report.errors || []).length) {
      html += '<p class="result-errors">Note: ' + esc(report.errors.join("; ")) + "</p>";
    }
    html += '<p class="result-correction">See something we missed or got wrong? <a href="mailto:hello@agentreadinesshq.com?subject=Audit%20correction">Let us know.</a></p>';
    resultsEl.innerHTML = html;
    resultsEl.hidden = false;
  }

  auditForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var url = urlInput.value.trim();
    if (!url) return;
    var nameField = document.getElementById("scan-first-name");
    var emailField = document.getElementById("scan-email");
    var firstName = nameField ? nameField.value.trim() : "";
    var leadEmail = emailField ? emailField.value.trim() : "";
    if (!firstName || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(leadEmail)) {
      setStatus("Please add your first name and a valid email, and we'll email your results to you.");
      (!firstName ? nameField : emailField).focus();
      return;
    }
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
        captureScanLead(firstName, leadEmail, out.body);
        resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
      })
      .catch(function (err) {
        setStatus("Couldn't run the audit: " + err.message + ". Check the URL and try again.");
      })
      .finally(function () {
        auditBtn.disabled = false;
        auditBtn.textContent = "Run my free scan";
      });
  });

  /* Scan lead capture: after a successful free scan, send the visitor's
     first name, email, scanned site, and score to the business inbox via
     FormSubmit, with an autoresponse that emails them a copy of their
     result summary. Fire-and-forget: a capture failure never blocks or
     alters the on-page results. */
  function captureScanLead(firstName, email, report) {
    var score = report.score != null ? String(report.score) : "?";
    var grade = report.grade || "?";
    var site = report.url || "";
    var params = new URLSearchParams();
    params.append("name", firstName);
    params.append("email", email);
    params.append("website", site);
    params.append("score", score);
    params.append("grade", grade);
    params.append("_subject", "New free scan: " + site);
    params.append("message", firstName + " (" + email + ") ran a free scan on "
      + site + ": score " + score + "/100, grade " + grade + ".");
    params.append("_template", "table");
    params.append("_autoresponse", "Hi " + firstName + ", thanks for running "
      + "your free AI Readiness Scan with Agent Readiness HQ! " + site
      + " scored " + score + "/100 (grade " + grade + "). Your full results "
      + "are on the page where you ran the scan. If you'd like the detailed "
      + "report or a hand with the fixes, just reply to this email. Thanks, "
      + "Rachael Lund, Founder, Agent Readiness HQ");
    fetch(FORMSUBMIT_URL, { method: "POST", body: params })
      .catch(function (err) {
        console.error("[Agent Readiness HQ] scan lead capture failed:", err);
      });
  }

  /* Information packet form (homepage, under the scan results): posts
     the visitor's email to the business inbox via FormSubmit, labeled
     as an information packet request. The packet is then emailed from
     the inbox; FormSubmit's _autoresponse is deliberately NOT used
     (delivery through it is unreliable). The on-page confirmation also
     links straight to the hosted packet at /packet. */
  if (emailForm) emailForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var email = document.getElementById("email").value.trim();
    if (!email) return;
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      emailNote.textContent = "Please enter a valid email address.";
      return;
    }
    sendPacketRequest(email);
  });

  function sendPacketRequest(email) {
    emailNote.textContent = "Sending\u2026";
    var params = new URLSearchParams();
    params.append("email", email);
    params.append("request", "Information packet request");
    params.append("_subject", "Information packet request");
    params.append("message", "Please send the Agent Readiness HQ "
      + "information packet to " + email + ". Packet page: "
      + SITE_URL + "packet");
    params.append("_template", "table");
    fetch(FORMSUBMIT_URL, { method: "POST", body: params })
      .then(function (resp) {
        return resp.json().catch(function () { return {}; });
      })
      .then(function (body) {
        if (!body || body.success !== "true") throw new Error("send failed");
        emailNote.innerHTML = "Your packet is on its way. "
          + '<a href="/packet" style="color:#ffd9e2;text-decoration:underline">Can&rsquo;t wait? View the packet now</a>';
        emailForm.reset();
      })
      .catch(function (err) {
        console.error("[Agent Readiness HQ] packet request failed:", err);
        emailNote.textContent = "Something went wrong sending your request. Please try again.";
      });
  }

  var newsletterForm = document.getElementById("newsletter-form");
  var newsletterNote = document.getElementById("newsletter-note");
  if (newsletterForm) newsletterForm.addEventListener("submit", function (e) {
    e.preventDefault();
    submitEmail(
      document.getElementById("newsletter-email").value.trim(),
      "newsletter",
      newsletterNote,
      newsletterForm
    );
  });

  /* Contact form - no email address in the page source; messages go to
     Caleb's inbox via FormSubmit. Autoresponse text is the exact wording
     shown to Caleb on 2026-10-10. */
  var CONTACT_AUTORESPONSE = "Thanks for reaching out to Agent Readiness HQ! "
    + "We've got your message and will get back to you within one business "
    + "day, Rachael, Agent Readiness HQ";
  var contactForm = document.getElementById("contact-form");
  var contactNote = document.getElementById("contact-note");
  if (contactForm) contactForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var name = document.getElementById("contact-name").value.trim();
    var email = document.getElementById("contact-email").value.trim();
    var message = document.getElementById("contact-message").value.trim();
    if (!name || !email || !message) return;
    contactNote.textContent = "Sending…";
    var params = new URLSearchParams();
    params.append("name", name);
    params.append("email", email);
    params.append("_subject", "New contact message: Agent Readiness HQ");
    params.append("message", message);
    params.append("_template", "table");
    params.append("_autoresponse", CONTACT_AUTORESPONSE);
    fetch(FORMSUBMIT_URL, { method: "POST", body: params })
      .then(function (resp) {
        return resp.json().catch(function () { return {}; });
      })
      .then(function (body) {
        if (!body || body.success !== "true") throw new Error("send failed");
        contactNote.textContent = "Message sent. We'll get back to you within one business day.";
        contactForm.reset();
      })
      .catch(function (err) {
        console.error("[Agent Readiness HQ] contact submit failed:", err);
        contactNote.textContent = "Something went wrong sending your message. Please try again.";
      });
  });

  function submitEmail(email, source, noteEl, formEl) {
    if (!email) return;
    noteEl.textContent = "Joining…";
    // Form-encoded (not JSON) so the browser treats this as a simple
    // CORS request - no preflight, works everywhere.
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
          ? "You're on the list. Talk soon."
          : "Thanks. We'll send more info within one business day.";
        formEl.reset();
      })
      .catch(function (err) {
        console.error("[Agent Readiness HQ] email submit failed:", err);
        noteEl.textContent = "Something went wrong saving your email. Please try again.";
      });
  }
})();
