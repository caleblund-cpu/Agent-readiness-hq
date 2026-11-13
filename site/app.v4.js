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
  var UNLOCK_URL = "/api/unlock";

  /* Attribution capture (2026-11-12): the UTM parameters on the
     landing URL are read on first page load and kept in
     sessionStorage, so they survive the trip down to the scan
     section (and any in-site navigation in the same tab). The scan
     request rides them along with the page referrer, and the server
     stores them on the scan log record next to the completion, for
     comparison against ad traffic. Absent parameters stay empty. */
  var ATTRIBUTION = (function () {
    var keys = ["utm_source", "utm_medium", "utm_campaign"];
    var out = { referrer: document.referrer || "" };
    keys.forEach(function (k) { out[k] = ""; });
    try {
      var params = new URLSearchParams(window.location.search);
      keys.forEach(function (k) {
        var v = params.get(k);
        if (v) window.sessionStorage.setItem("arhq_" + k, v.slice(0, 120));
        out[k] = window.sessionStorage.getItem("arhq_" + k) || "";
      });
    } catch (err) {
      /* storage unavailable: attribution simply stays empty. */
    }
    return out;
  })();

  /* Email signup posts directly to FormSubmit from the visitor's browser
     (no server proxy - FormSubmit throttles shared server IPs, which broke
     the /api/subscribe proxy). The _autoresponse text below is the exact
     wording shown to Caleb on 2026-10-10. */
  var FORMSUBMIT_URL = "https://formsubmit.co/ajax/c171c3e0d3fb9d3525cb0945982c5d2b";
  var AUTORESPONSE_TEXT = "Thanks for your interest in Agent Readiness HQ! "
    + "We'll be in touch within one business day with a fix-it report "
    + "and details on our $149 report and $449 done-for-you cleanup. "
    + "Agent Readiness HQ";

  var SITE_URL = "https://agentreadinesshq.com/";

  /* Stripe checkout links for the results conversion box. Both are
     ACTIVE sandbox/test-mode payment links today (the same links the
     pricing-section buttons use); at Stripe live activation they swap
     to the live URLs. renderResults prefers the pair returned in the
     scan JSON (checkout_urls, whose single config spot is audit.py);
     these constants are the fallback if a response lacks them. */
  var CHECKOUT_URL_149 = "https://buy.stripe.com/5kQ14p9WhbAR4zd66e5AQ00";
  var CHECKOUT_URL_449 = "https://buy.stripe.com/5kQ14p8Sd9sJe9NeCK5AQ01";

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

  function renderResults(report, opts) {
    opts = opts || {};
    var locked = !!opts.locked;
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
    if (report.complete === false) {
      /* Scoring v5: an incomplete scan shows a prominent Incomplete
         result and NO letter grade (the API withholds the grade; a
         grade computed from unmeasured checks would mislead). The
         numeric ring is the partial score of the checks that could
         be measured, and it is labelled as such. */
      html += '<div class="score-grade score-incomplete">Incomplete scan</div>';
      html += '<div class="score-note">We could not read everything on this site, so no grade is issued. The number above is the partial score of the checks that could be measured.</div>';
    } else {
      html += '<div class="score-grade">Grade ' + esc(report.grade || "-") + "</div>";
      html += '<div class="score-note">Based on seven automated technical checks using our proprietary methodology. This assesses website accessibility and machine-readability, not business quality or whether AI recommends your business.</div>';
    }
    html += '<div class="score-url">' + esc(report.url) + "</div>";
    html += "</div>";

    /* Competitor comparison (2026-11-05): one slim line under the
       visitor's own score, scores only, nothing editorial. A failed
       competitor scan shows one plain note instead; the visitor's
       own results are never affected either way. */
    var comp = report.competitor || null;
    if (comp && comp.score != null) {
      var compName = comp.business_name || comp.url || "Competitor";
      html += '<div class="vs-strip"><span class="vs-you">You <strong>' + esc(report.score) + "</strong></span>";
      html += '<span class="vs-mid">vs</span>';
      html += '<span class="vs-them">' + esc(compName) + " <strong>" + esc(comp.score) + "</strong></span></div>";
      html += '<p class="vs-note">The competitor you asked us to scan, ' + esc(comp.url) + ". Their full results are at the bottom of this page.</p>";
    } else if (comp && comp.error) {
      html += '<p class="comp-error">We could not scan that competitor site, so no comparison is shown. Your results below are unaffected.</p>';
    }

    /* Conversion box (Caleb ruling 2026-10-22): immediately after the
       score, before the technical findings. Reassurance + the two
       options, buttons only (never whole-card links), each button
       linking straight to its Stripe checkout. Eligibility comes from
       the scan: A/unknown both buttons active; B both active (the
       platform caveat renders below the checks, per Caleb's later
       2026-10-22 ruling); C keeps the $449 card visible but muted
       and non-clickable. Both cards use the same clean style (the
       $449 card's featured rose treatment was removed by Caleb
       ruling 2026-10-22). No timing, fulfillment, authorization,
       or process copy inside the box. 2026-11-04 pause: the $449
       card stays visible with a Coming Soon label and no checkout
       link while implementation is in limited testing. */
    var pf = report.platform || {};
    var elig = pf.eligibility || "unknown";
    var urls = report.checkout_urls || {};
    var url149 = urls.audit_149 || CHECKOUT_URL_149;
    var url449 = urls.done_for_you_449 || CHECKOUT_URL_449;
    /* Ungated scan (2026-11-12): when the scan ran without a name +
       email, the summary response carries no detail, and everything
       from here down renders inside the gradual blur zone with the
       unlock card over it. The unlock POST returns the full report,
       which re-renders through this same function unlocked. A gated
       scan (name + email given) never enters the zone. */
    if (locked) {
      html += '<div class="fade-zone locked" id="fade-zone">';
      html += '<div class="fade-content">';
    }
    html += '<div class="conversion-box">';
    html += '<h3 class="conversion-headline">We\u2019ll help you fix your score.</h3>';
    html += '<p class="conversion-sub">Most of these issues sound more technical than they are. We turn your results into simple, plain-English fixes.</p>';
    html += '<div class="offer-cards">';
    html += '<div class="offer-card">';
    html += '<div class="offer-price">$149</div>';
    html += '<div class="offer-name">Show me how</div>';
    html += '<p class="offer-desc">Step-by-step instructions + ready-to-use content: copy, paste, publish.</p>';
    html += '<a class="btn offer-btn" href="' + esc(url149) + '">Show me how</a>';
    html += "</div>";
    if (elig === "C") {
      html += '<div class="offer-card offer-unavailable">';
      html += '<div class="offer-price">$449</div>';
      html += '<div class="offer-name">Do it for me</div>';
      html += '<p class="offer-desc">Not available on your website platform.</p>';
      html += "</div>";
    } else {
      html += '<div class="offer-card">';
      html += '<div class="offer-price">$449</div>';
      html += '<div class="offer-name">Do it for me</div>';
      html += '<p class="offer-desc">We make the approved improvements for you.</p>';
      html += '<span class="btn offer-btn" aria-disabled="true">Coming Soon</span>';
      html += "</div>";
    }
    html += "</div>";
    html += "</div>";

    /* Platform caveat (2026-10-22; placement re-ruled later the
       same day): for B/C, a collapsed plain-language warning BELOW
       the seven detailed checks - page order is score -> conversion
       box -> checks -> caveat. "See details" expands (native
       <details>) to the full technical disclosure, preserved
       verbatim (detected line, ceiling paragraph, offer paragraph).
       For an unidentified platform, the existing confirmation line
       stays as a small note under the conversion box. A: nothing. */
    var caveatHtml = "";
    if ((elig === "B" || elig === "C") && pf.short_line) {
      var dl = "";
      if (pf.detected) {
        dl += '<p class="platform-line"><strong>Website platform:</strong> ' + esc(pf.name) + " (detected automatically).</p>";
      }
      if (pf.ceiling_line) {
        dl += '<p class="platform-line">' + esc(pf.ceiling_line) + "</p>";
      }
      if (pf.offer_line) {
        dl += '<p class="platform-line">' + esc(pf.offer_line) + "</p>";
      }
      caveatHtml += '<details class="platform-caveat">';
      caveatHtml += "<summary>";
      caveatHtml += '<span class="caveat-title">\u26a0 Your website platform has a limitation</span>';
      caveatHtml += '<span class="caveat-line">' + esc(pf.short_line) + "</span>";
      caveatHtml += '<span class="caveat-more">See details <span class="caveat-chev">\u203a</span></span>';
      caveatHtml += "</summary>";
      caveatHtml += '<div class="caveat-body">' + dl + "</div>";
      caveatHtml += "</details>";
    } else if (elig === "unknown" && pf.confirm_line) {
      html += '<p class="platform-confirm-note">' + esc(pf.confirm_line) + "</p>";
    }

    html += '<ul class="result-checks">';
    (report.checks || []).forEach(function (c) {
      html += '<li class="check-' + esc(c.status) + '">';
      html += '<span class="check-icon">' + (STATUS_ICON[c.status] || "?") + "</span> ";
      html += "<strong>" + esc(c.name) + "</strong> ";
      html += '<span class="check-score">' + esc(c.score) + "/" + esc(c.weight) + "</span>";
      html += '<div class="check-detail">' + esc(c.detail) + "</div>";
      /* Plain-English layer (2026-10-20): what the check means, and
         — only when points were lost — that it is fixable, without
         saying how. Both strings come from the audit API so the page
         and the emailed copy always show identical wording. */
      if (c.meaning) {
        html += '<div class="check-meaning">' + esc(c.meaning) + "</div>";
      }
      if (c.note) {
        html += '<div class="check-meaning">' + esc(c.note) + "</div>";
      }
      if (c.fixable) {
        html += '<div class="check-fixable">' + esc(c.fixable) + "</div>";
      }
      /* Platform treatment (2026-10-21): when the customer's own
         platform is what blocks a fix, the line says so instead of
         calling the check fixable. Wording comes from the audit API,
         identical to the emailed copy. */
      if (c.platform_note) {
        html += '<div class="check-fixable check-platform">' + esc(c.platform_note) + "</div>";
      }
      html += "</li>";
    });
    html += "</ul>";
    html += caveatHtml;

    /* The platform disclosure renders as the collapsed caveat below
       the checks (2026-10-22), not as a separate bottom box; the
       expanded state carries the same verbatim lines the old bottom
       box used to show. */

    /* Top fixes are hidden from the free audit - the specific fixes are
       what the $149 report sells. The free result shows the diagnosis
       (score + check breakdown); the prescription is paid. */
    /* Competitor results (2026-11-05): a condensed block at the
       very bottom, ring plus check names and scores only, so the
       comparison never competes with the visitor's own results. */
    if (comp && comp.score != null) {
      var cpct = Math.max(0, Math.min(100, Number(comp.score) || 0));
      var cring = cpct >= 80 ? "#16a34a" : cpct >= 60 ? "#d97706" : "#dc2626";
      var ctarget = (2 * Math.PI * 54 * (1 - cpct / 100)).toFixed(1);
      html += '<div class="competitor-block">';
      html += '<h3 class="competitor-head">Competitor results: ' + esc(comp.business_name || comp.url || "Competitor") + "</h3>";
      html += '<div class="score-block">';
      html += '<div class="score-ring-wrap">';
      html += '<svg class="score-ring" viewBox="0 0 120 120" aria-hidden="true">';
      html += '<circle cx="60" cy="60" r="54" class="ring-bg"/>';
      html += '<circle cx="60" cy="60" r="54" class="ring-fg" stroke="' + cring + '"';
      html += ' style="--ring-c:' + circ + ';--ring-target:' + ctarget + '"';
      html += ' stroke-dasharray="' + circ + '" stroke-dashoffset="' + circ + '"/>';
      html += "</svg>";
      html += '<div class="score-center"><div class="score-number">' + esc(comp.score) + "</div>";
      html += '<div class="score-max">/ 100</div></div>';
      html += "</div>";
      if (comp.complete === false) {
        html += '<div class="score-grade score-incomplete">Incomplete scan</div>';
      } else {
        html += '<div class="score-grade">Grade ' + esc(comp.grade || "-") + "</div>";
      }
      html += '<div class="score-url">' + esc(comp.url) + "</div>";
      html += "</div>";
      html += '<ul class="result-checks">';
      (comp.checks || []).forEach(function (c) {
        html += '<li class="check-' + esc(c.status) + '">';
        html += '<span class="check-icon">' + (STATUS_ICON[c.status] || "?") + "</span> ";
        html += "<strong>" + esc(c.name) + "</strong> ";
        html += '<span class="check-score">' + esc(c.score) + "/" + esc(c.weight) + "</span>";
        html += "</li>";
      });
      html += "</ul>";
      html += "</div>";
    }

    if ((report.errors || []).length) {
      html += '<p class="result-errors">Note: ' + esc(report.errors.join("; ")) + "</p>";
    }
    html += '<p class="result-correction">See something we missed or got wrong? Email us at <a href="mailto:hello@agentreadinesshq.com?subject=Audit%20correction">hello@agentreadinesshq.com</a></p>';
    if (locked) {
      html += "</div>";
      html += '<div class="fade-veil">' + unlockCardHtml(report) + "</div>";
      html += "</div>";
    }
    if (opts.unlockedEmail) {
      html += '<p class="unlocked-note">Unlocked. Your full results are on this page, and a copy with your 10% code is on its way to ' + esc(opts.unlockedEmail) + ".</p>";
    }
    resultsEl.innerHTML = html;
    resultsEl.hidden = false;
    if (locked) wireUnlockForm(opts.token);
  }

  /* Unlock card (2026-11-12), copy approved by Caleb from the v3
     mockup. The competitor bullet appears only when a competitor
     scan actually ran. */
  function unlockCardHtml(report) {
    var comp = report.competitor || null;
    var html = '<div class="unlock-card">';
    html += "<h2>Unlock your full results</h2>";
    html += "<p>See every fix instantly.</p>";
    html += "<ul>";
    html += "<li>Every fix, check by check</li>";
    if (comp && comp.score != null) {
      html += "<li>Your competitor's full breakdown</li>";
    }
    html += "<li>10% off when you are ready to fix it</li>";
    html += "</ul>";
    html += '<form id="unlock-form">';
    html += '<input type="email" id="unlock-email" placeholder="you@yourbusiness.com" aria-label="Email address" required>';
    html += '<button class="btn" type="submit">Show me what to fix</button>';
    html += "</form>";
    html += '<p class="unlock-error" id="unlock-error" hidden></p>';
    html += '<div class="fine">Unlocks instantly on this page. Your copy and code go to your email.</div>';
    html += "</div>";
    return html;
  }

  function wireUnlockForm(token) {
    var form = document.getElementById("unlock-form");
    if (!form) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var emailInput = document.getElementById("unlock-email");
      var errEl = document.getElementById("unlock-error");
      var email = emailInput ? emailInput.value.trim() : "";
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        errEl.textContent = "Please enter a valid email address.";
        errEl.hidden = false;
        if (emailInput) emailInput.focus();
        return;
      }
      var btn = form.querySelector("button");
      btn.disabled = true;
      btn.textContent = "Unlocking\u2026";
      fetch(UNLOCK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token, email: email })
      })
        .then(function (resp) {
          return resp.json().then(function (body) {
            return { ok: resp.ok, body: body };
          });
        })
        .then(function (out) {
          if (!out.ok || !out.body || out.body.error) {
            throw new Error((out.body && out.body.error) || "unlock failed");
          }
          renderResults(out.body, { unlockedEmail: email });
          storeScanForIntake("", email, out.body);
          resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
        })
        .catch(function () {
          errEl.textContent = "Something went wrong unlocking your results. Please try again.";
          errEl.hidden = false;
          btn.disabled = false;
          btn.textContent = "Show me what to fix";
        });
    });
  }

  /* Competitor scan (2026-11-05): the optional Yes/No under the
     scan form. Yes reveals the competitor field; the submit handler
     reads it and rides it along with the scan request. Elements are
     optional, so pages without the question stay unaffected. */
  var compYes = document.getElementById("comp-yes");
  var compNo = document.getElementById("comp-no");
  var compField = document.getElementById("comp-field");
  function setCompetitor(on) {
    if (!compYes || !compNo || !compField) return;
    compYes.classList.toggle("on", on);
    compNo.classList.toggle("on", !on);
    compField.classList.toggle("show", on);
  }
  if (compYes && compNo) {
    compYes.addEventListener("click", function () { setCompetitor(true); });
    compNo.addEventListener("click", function () { setCompetitor(false); });
  }
  function competitorUrl() {
    var input = document.getElementById("competitor-url");
    if (!input || !compField || !compField.classList.contains("show")) return "";
    return input.value.trim();
  }

  auditForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var url = urlInput.value.trim();
    if (!url) return;
    var nameField = document.getElementById("scan-first-name");
    var emailField = document.getElementById("scan-email");
    var firstName = nameField ? nameField.value.trim() : "";
    var leadEmail = emailField ? emailField.value.trim() : "";
    /* Name + email are optional (2026-11-12): they ride along only
       when both are given and the email is valid, which keeps the
       gated behavior (full results at once, results copy emailed
       from hello@) exactly as before. Otherwise the scan runs
       ungated and the results arrive locked behind the unlock card. */
    var hasLead = !!firstName && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(leadEmail);
    auditBtn.disabled = true;
    auditBtn.textContent = "Auditing\u2026";
    resultsEl.hidden = true;
    setStatus("Running the 7-check audit on " + url + " \u2014 usually under 30 seconds.");

    var payload = { url: url, competitor_url: competitorUrl(),
                    utm_source: ATTRIBUTION.utm_source,
                    utm_medium: ATTRIBUTION.utm_medium,
                    utm_campaign: ATTRIBUTION.utm_campaign,
                    referrer: ATTRIBUTION.referrer };
    if (hasLead) {
      payload.first_name = firstName;
      payload.email = leadEmail;
    }
    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
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
        if (out.body.ungated && out.body.token) {
          renderResults(out.body, { locked: true, token: out.body.token });
        } else {
          renderResults(out.body);
          storeScanForIntake(firstName, leadEmail, out.body);
        }
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

  /* Scan lead capture is server-side now (2026-11-03): the audit
     function records the completed scan as a lead in hello@ in the
     same request that emails the visitor their results. The former
     browser-side FormSubmit post here was fire-and-forget and could
     fail silently after a successful scan, losing the lead. */

  /* Remember the scan on this device so the post-payment
     initial-details page (/intake-149.html) can pre-fill from
     it. Same-device memory only: it never leaves the
     browser except inside the personalized intake link the visitor
     opens themselves. Fire-and-forget. */
  function storeScanForIntake(firstName, email, report) {
    try {
      var data = {
        first_name: firstName,
        email: email,
        url: report.url || "",
        score: report.score,
        grade: report.grade || "",
        checks: (report.checks || []).map(function (c) {
          return { name: c.name, status: c.status, score: c.score, weight: c.weight };
        }),
        fetched_at: report.fetched_at || ""
      };
      window.localStorage.setItem("arhq_scan", JSON.stringify(data));
    } catch (err) {
      /* storage unavailable (private mode, quotas): the journey still
         works, the later pages just ask again. */
    }
  }

  /* Information packet form (homepage): the packet is also a public
     Information page; this form emails the PDF packet to the visitor
     via /api/packet (Oct 24 ruling, Option A). The endpoint sends the
     PDF from the business inbox and logs the request there as the
     lead record. No redirect: the visitor stays on the page. */
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
    fetch("/api/packet", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email })
    })
      .then(function (resp) {
        return resp.json().catch(function () { return {}; });
      })
      .then(function (body) {
        if (!body || body.ok !== true) throw new Error("send failed");
        emailNote.textContent = "Your packet is on its way to " + email
          + ". Check your inbox, and your spam folder just in case.";
        emailForm.reset();
      })
      .catch(function (err) {
        console.error("[Agent Readiness HQ] packet request failed:", err);
        emailNote.textContent = "Something went wrong sending your packet. Please try again, or email us at hello@agentreadinesshq.com.";
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
    + "day. Agent Readiness HQ";
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
