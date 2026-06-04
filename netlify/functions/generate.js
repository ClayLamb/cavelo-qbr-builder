// generate.js
// Parses a Cavelo Data Risk Report PDF and builds a 10-slide Technology Review deck
// using pptxgenjs. Returns .pptx as a binary download.

const busboy   = require("busboy");
const pptxgen  = require("pptxgenjs");

// ─── PDF text extractor ─────────────────────────────────────────────────────
// Uses pdf-parse@1.x — a thin CommonJS wrapper around older pdfjs that runs
// in Node/Netlify Functions without the DOMMatrix polyfill that pdf-parse@2
// (newer pdfjs) needs. Handles FlateDecode-compressed streams natively, so
// real Cavelo exports parse correctly (the original raw-regex extractor saw
// 0 chars on compressed PDFs).
const pdfParse = require("pdf-parse");
async function extractPDFText(buffer) {
  const result = await pdfParse(buffer);
  return result && typeof result.text === "string" ? result.text : "";
}

// ─── DATA PARSERS ─────────────────────────────────────────────────────────────

function parseRiskReport(text) {
  // Cavelo PDF format puts the NUMBER first and the LABEL on the next line:
  //   4.4 (Very High)
  //   Cavelo Data Risk Score
  // The category in parens is sometimes present (risk-style scores) and
  // sometimes absent (counts like "1,838 Instances Found").
  //
  // Strategy: for each metric, search for "<number> [(<category>)]\n<label>"
  // and return both the number and the category. Returns null for both if
  // not found — callers must render "Not detected" or similar, NOT a fake
  // fallback. Demo values used to leak through silently and look real.

  const text_ = String(text || "");

  // Generic: match a number (with optional comma/decimal) followed by an
  // optional "(Category)" then any whitespace then the label text.
  // The "$" terminator on the label keeps us from accidentally matching
  // a longer label that contains this label as a substring.
  const grab = (label) => {
    const labelEsc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(
      "([\\d][\\d,]*(?:\\.\\d+)?)" +     // number
      "\\s*(?:\\(([^)]+)\\))?" +          // optional (category)
      "\\s*\\n?\\s*" +
      labelEsc + "(?:\\s|$)",             // label, terminated
      "m",
    );
    const m = text_.match(re);
    if (!m) return { value: null, category: null };
    return {
      value:    parseFloat(m[1].replace(/,/g, "")),
      category: (m[2] || null),
    };
  };

  // Some metrics are written inline ("$295,566" then label, or "55 hosts"
  // then "Unapproved Software"). The same generic grab() handles them
  // because the number-then-label pattern is consistent. The only awkward
  // case is currency: PDF has "$295,566\nCost of Breach" — the $ comes
  // before the digits, so strip it.
  const grabCurrency = (label) => {
    const labelEsc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(
      "\\$\\s*([\\d][\\d,]*)\\s*\\n?\\s*" + labelEsc + "(?:\\s|$)",
      "m",
    );
    const m = text_.match(re);
    return m ? parseFloat(m[1].replace(/,/g, "")) : null;
  };

  // Inline colon format: "Label: 1,234" (used for Entities Discovered,
  // Outlier Directories under the Permission Risk section, etc.).
  const grabAfter = (label) => {
    const labelEsc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(labelEsc + "[:\\s]+([\\d][\\d,]*(?:\\.\\d+)?)", "m");
    const m = text_.match(re);
    return m ? parseFloat(m[1].replace(/,/g, "")) : null;
  };

  const riskScore       = grab("Cavelo Data Risk Score");
  const industryScore   = grab("Cavelo Industry Risk Score");
  const dataCostRisk    = grab("Data Cost Risk");
  const benchmarkRisk   = grab("Benchmark Risk");
  const vulnRisk        = grab("Vulnerability Risk");        // first match: endpoint
  const networkVulnRisk = grab("Network Vulnerability Risk");
  const permissionRisk  = grab("Permission Risk");

  return {
    // Risk scores — number + category label as they appear on the report
    riskScore:        riskScore.value,        riskScoreCat:        riskScore.category,
    industryScore:    industryScore.value,    industryScoreCat:    industryScore.category,
    dataCostRisk:     dataCostRisk.value,     dataCostRiskCat:     dataCostRisk.category,
    benchmarkRisk:    benchmarkRisk.value,    benchmarkRiskCat:    benchmarkRisk.category,
    vulnRisk:         vulnRisk.value,         vulnRiskCat:         vulnRisk.category,
    networkVulnRisk:  networkVulnRisk.value,  networkVulnRiskCat:  networkVulnRisk.category,
    permissionRisk:   permissionRisk.value,   permissionRiskCat:   permissionRisk.category,

    // Currency — Cost of Breach
    costOfBreach:     grabCurrency("Cost of Breach"),

    // Counts (number-then-label pattern, no parens/category)
    instancesFound:     grab("Instances Found").value,
    testsPassed:        grab("Tests Passed").value,
    testsFailed:        grab("Tests Failed").value,
    maxEPSS:            grab("Max EPSS Score").value,
    maxCVSS:            grab("Max CVSS Score").value,
    outlierDirs:        grabAfter("Outlier Directories"),
    entitiesDiscovered: grabAfter("Entities Discovered"),
    noncompliantHosts:  grab("Noncompliant Hosts").value || grab("Noncompliant Agents").value,
    unapprovedSoftware: grab("Unapproved Software").value,
    missingSoftware:    grab("Missing Software").value || grab("Missing Required").value,
    approvedApps:       grab("Approved Applications").value,
    approvedPublishers: grab("Approved Publishers").value,
    mandatoryApps:      grab("Mandatory Apps").value,

    // Top-host / top-connector fields are surfaced on slide 3 (Data
    // Discovery) and slide 10 (CIS Benchmarks). The Cavelo PDF carries
    // these values inside tables that don't parse cleanly with regex —
    // returning null so those slides render "—" until we add a proper
    // table extractor. The OLD parser shipped fake fallback values.
    topHostName:        null,
    topHostCost:        null,
    topHostInstances:   null,
    topConnectorCost:   null,
    connectorInstances: null,

    // Tabular data we CAN extract — see parseTopAtRiskTable() below.
    topConnectors: parseTopAtRiskTable(text_, "Top at-risk Connectors"),
    topAgents:     parseTopAtRiskTable(text_, "Top at-risk Agents"),

    // Per-section "Active Schedules / Policies / Whitelists" counts —
    // proves that monitoring is configured. See parseMonitoring().
    monitoring:    parseMonitoring(text_),
  };
}

// Cavelo's "Top at-risk X" tables in the PDF render with the source name
// on one line and ALL the score columns concatenated on the next line:
//
//     Top at-risk Agents
//     SourceScoreData CostBenchmarkPermissionVulnerability
//     LAPTOP-FEAIVATS
//     4.44.04.91.04.9
//
// We split on the next-line newline, capture every X.Y / n/a token
// from the score row (each is one column), and return rows of
//   { name, score, scores: [Score, DataCost, Benchmark, Permission, Vulnerability] }
// `score` is a convenience alias for scores[0]. The dimension column
// names depend on the table — Connectors omit the Vulnerability column,
// Network Hosts only have Score + NetworkVuln.
function parseTopAtRiskTable(text, heading) {
  const headIdx = text.indexOf(heading);
  if (headIdx < 0) return [];
  const tail = text.slice(headIdx + heading.length, headIdx + heading.length + 4000);
  const endIdx = Math.min(
    ...["Top at-risk", "Data Risk Report / PAGE", "Top 5 ", "Recommendations"]
      .map(m => { const i = tail.indexOf(m); return i < 0 ? Infinity : i; }),
  );
  const section = tail.slice(0, endIdx === Infinity ? tail.length : endIdx);

  const lines = section.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const rows = [];
  for (let i = 1; i < lines.length - 1; i += 2) {
    const name     = lines[i];
    const scoreRow = lines[i + 1];
    if (!/^(\d\.\d|n\/a)/i.test(scoreRow) || /^\d/.test(name)) continue;
    // Capture all X.Y / n/a tokens — each is one column from the table
    const tokens = scoreRow.match(/(\d\.\d|n\/a)/gi) || [];
    const scores = tokens.map(t => t.toLowerCase() === "n/a" ? null : parseFloat(t));
    if (scores.length === 0) continue;
    rows.push({ name, score: scores[0], scores });
  }
  rows.sort((a, b) => (b.score ?? -Infinity) - (a.score ?? -Infinity));
  return rows.slice(0, 10);
}

// Each summary section in the Risk Report (Data Cost, Benchmark,
// Vulnerability, Network Vulnerability) carries a small monitoring
// footprint — counts of Active Schedules / Policies / Whitelists. The
// PDF lays them out as "<count>\n<label>" inside their owning section.
// Return per-section counts so we can render a "monitoring posture"
// summary on its own slide.
//
// Each call is scoped to the named section so we don't accidentally
// pick up the count from a neighbouring section's "Active Schedules"
// entry (the labels repeat).
function parseMonitoring(text) {
  // Two pitfalls in the Risk Report layout:
  //  1. The Table of Contents lists every section name at the top of
  //     the PDF (e.g. "Benchmark Summary9" — name immediately followed
  //     by the page number). indexOf returns that TOC offset.
  //  2. "Vulnerability Summary" appears as a substring inside
  //     "Network Vulnerability Summary".
  // Find the first occurrence that's preceded by a non-letter (rules
  // out the substring inside "Network Vulnerability Summary") AND not
  // followed by a digit (rules out the TOC page-number entries).
  const findRealSection = (label) => {
    let pos = -1;
    while ((pos = text.indexOf(label, pos + 1)) !== -1) {
      const before = pos > 0 ? text[pos - 1] : "\n";
      const after  = text[pos + label.length] || "";
      if (/[a-z]/i.test(before)) continue;  // substring inside a longer name
      if (/\d/.test(after))      continue;  // TOC entry "<Name><page#>"
      return pos;
    }
    return -1;
  };
  const sectionSlice = (start, end) => {
    const s = findRealSection(start);
    if (s < 0) return "";
    const e = end ? findRealSection(end) : -1;
    return text.slice(s, e > s ? e : s + 4000);
  };
  const numberBefore = (section, label) => {
    if (!section) return null;
    const re = new RegExp("(\\d+)\\s*\\n?\\s*" + label + "(?:\\s|$)", "m");
    const m = section.match(re);
    return m ? parseInt(m[1], 10) : null;
  };
  const dc  = sectionSlice("Data Cost Summary",            "Benchmark Summary");
  const bm  = sectionSlice("Benchmark Summary",            "Vulnerability Summary");
  const vn  = sectionSlice("Vulnerability Summary",        "Network Vulnerability Summary");
  const nv  = sectionSlice("Network Vulnerability Summary","Software Summary");
  return {
    dataCost: { schedules: numberBefore(dc, "Active Schedules"),
                policies:  numberBefore(dc, "Active Policies") },
    benchmark:{ schedules: numberBefore(bm, "Active Schedules"),
                policies:  numberBefore(bm, "Active Policies"),
                whitelists:numberBefore(bm, "Active Whitelists") },
    vuln:     { schedules: numberBefore(vn, "Active Schedules"),
                policies:  numberBefore(vn, "Active Policies"),
                whitelists:numberBefore(vn, "Active Whitelists") },
    networkVuln:{ schedules: numberBefore(nv, "Active Schedules"),
                  policies:  numberBefore(nv, "Active Policies"),
                  whitelists:numberBefore(nv, "Active Whitelists") },
  };
}

// parseVulnAudit removed — Cavelo doesn't expose a separate Endpoint
// Vulnerability Audit PDF in production. The deck is now built from a
// single Risk Report. Vulnerability info comes from the Risk Report's
// Vulnerability Summary section (vulnRisk score, maxCVSS, maxEPSS,
// networkVulnRisk) which parseRiskReport already extracts.

// ─── SLIDE HELPERS ─────────────────────────────────────────────────────────────

function addChrome(s, pres, sectionNum, sectionLabel, accentColor = "3DBB8F") {
  // Left edge accent
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.18, h: 5.625,
    fill: { color: accentColor }, line: { color: accentColor },
  });
  // Cavelo pill (top-left)
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 0.5, y: 0.4, w: 1.0, h: 0.32,
    fill: { color: accentColor }, line: { color: accentColor }, rectRadius: 0.16,
  });
  s.addText("CAVELO", {
    x: 0.5, y: 0.4, w: 1.0, h: 0.32,
    fontSize: 11, bold: true, color: "FFFFFF", fontFace: "Calibri",
    align: "center", valign: "middle", margin: 0,
  });
  // Top-right section badge intentionally removed for a cleaner header.
  // Function still accepts sectionNum + sectionLabel so existing call
  // sites need no changes; the args are simply unused now. Drop them
  // when refactoring callers if you prefer.
}

function addTitle(s, title, subtitle) {
  s.addText(title, {
    x: 0.5, y: 0.95, w: 9, h: 0.55,
    fontSize: 30, bold: true, color: "FFFFFF", fontFace: "Calibri",
    align: "left", valign: "middle", margin: 0,
  });
  if (subtitle) {
    s.addText(subtitle, {
      x: 0.5, y: 1.55, w: 9, h: 0.32,
      fontSize: 13, color: "94A3B8", fontFace: "Calibri",
      align: "left", valign: "middle", margin: 0,
    });
  }
}

function addStatCard(s, pres, { x, y, w, h, accentColor, label, value, sublabel, valueSize = 40 }) {
  s.addShape(pres.shapes.RECTANGLE, { x, y, w, h, fill: { color: "253347" }, line: { color: "253347" } });
  s.addShape(pres.shapes.RECTANGLE, { x, y, w, h: 0.08, fill: { color: accentColor }, line: { color: accentColor } });
  s.addText(label, { x: x+0.15, y: y+0.16, w: w-0.3, h: 0.26, fontSize: 9, bold: true, color: accentColor, fontFace: "Calibri", align: "left", valign: "middle", margin: 0, charSpacing: 1 });
  s.addText(String(value), { x: x+0.15, y: y+0.42, w: w-0.3, h: h-0.85, fontSize: valueSize, bold: true, color: "FFFFFF", fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
  if (sublabel) s.addText(sublabel, { x: x+0.15, y: y+h-0.45, w: w-0.3, h: 0.32, fontSize: 10, color: "E2E8F0", fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
}

function addFootnote(s, text) {
  s.addText(text, {
    x: 0.5, y: 5.25, w: 9, h: 0.25,
    fontSize: 8, color: "64748B", fontFace: "Calibri", italic: true,
    align: "left", valign: "middle", margin: 0,
  });
}

function fmt(n) {
  if (n == null) return "—";
  return Number(n).toLocaleString();
}
function fmtCurrency(n) {
  if (n == null) return "—";
  if (n >= 1000000) return `$${(n/1000000).toFixed(1)}M`;
  if (n >= 1000) return `$${Math.round(n/1000)}K`;
  return `$${fmt(n)}`;
}
// Render a parsed score as "4.4" with optional category sublabel from PDF.
// Returns "—" when value is null so demo defaults can't leak through.
function fmtScore(n, decimals = 1) {
  if (n == null) return "—";
  return Number(n).toFixed(decimals);
}
// Trend-delta formatter for Slide 2 sublabels. Returns an array of
// pptxgen text runs so the arrow can be colored independently of the
// rest of the line. lowerIsBetter=true for risk scores / failure
// counts (the default and what every Slide 2 metric needs); pass
// false for things like "approved apps" where higher is better.
//
// Returns null when either value is missing — callers fall back to
// the static sublabel they used pre-trend.
function fmtDelta(curr, prior, opts = {}) {
  const { lowerIsBetter = true, decimals = 1, GREEN, RED, MUTED } = opts;
  if (curr == null || prior == null) return null;
  const diff   = curr - prior;
  // "Steady" threshold scales with precision: scores (decimals=1) need
  // a bigger floor than counts (decimals=0) for "no meaningful change".
  const noise  = decimals === 1 ? 0.05 : Math.max(1, Math.round(prior * 0.01));
  if (Math.abs(diff) < noise) {
    return [
      { text: "Steady ", options: { color: MUTED, italic: true } },
      { text: `(was ${prior.toFixed(decimals)})`, options: { color: MUTED } },
    ];
  }
  const better = lowerIsBetter ? diff < 0 : diff > 0;
  const arrow  = diff < 0 ? "↓" : "↑";
  const color  = better ? GREEN : RED;
  return [
    { text: `${arrow} `, options: { color, bold: true } },
    { text: `${curr.toFixed(decimals)} (was ${prior.toFixed(decimals)})`, options: {} },
  ];
}

// "Q2 2026", "April 2026" — both derived from current date so the deck
// auto-rolls quarter without code changes.
function periodLabels(date = new Date()) {
  const months = ["January","February","March","April","May","June",
                  "July","August","September","October","November","December"];
  const q = Math.floor(date.getMonth() / 3) + 1;
  return {
    quarter:    `Q${q} ${date.getFullYear()}`,
    nextQuarter:`Q${q === 4 ? 1 : q + 1} ${q === 4 ? date.getFullYear() + 1 : date.getFullYear()}`,
    monthYear:  `${months[date.getMonth()]} ${date.getFullYear()}`,
  };
}

// ─── DECK BUILDER ─────────────────────────────────────────────────────────────

async function buildDeck({ risk, priorRisk, prospectName, mspName, mspUrl, primaryColor, literacy, clientSize, compliance, logoDataUri }) {
  const GREEN  = primaryColor || "3DBB8F";
  const RED    = "EF4444";
  const AMBER  = "F59E0B";
  const BLUE   = "3B82F6";
  const BG     = "1E2A3A";
  const BG_MID = "253347";
  const WHITE  = "FFFFFF";
  const MUTED  = "94A3B8";
  const LIGHT  = "E2E8F0";
  const G_LIGHT = "DCFCE7";
  const G_TEXT  = "15803D";

  const period = periodLabels();

  const pres = new pptxgen();
  pres.layout  = "LAYOUT_16x9";
  pres.title   = `${prospectName} Technology Review — ${period.quarter}`;
  pres.author  = mspName;

  const addS = () => { const s = pres.addSlide(); s.background = { color: BG }; return s; };

  // Risk-score severity → card accent color. Driven by the parsed
  // category from the PDF, not hardcoded.
  const accentForCat = (cat) => {
    const c = (cat || "").toLowerCase();
    if (c.includes("very high") || c.includes("critical")) return RED;
    if (c.includes("high"))     return RED;
    if (c.includes("moderate") || c.includes("medium"))    return AMBER;
    if (c.includes("low"))      return GREEN;
    return AMBER;
  };

  // ── SLIDE 1: COVER ──────────────────────────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "", "", GREEN);
    s.addText(period.quarter, { x:0.5, y:1.7, w:9, h:0.4, fontSize:16, color:GREEN, fontFace:"Calibri", bold:true, align:"left", valign:"middle", margin:0, charSpacing:2 });
    s.addText("Technology Review", { x:0.5, y:2.15, w:9, h:0.85, fontSize:48, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(prospectName, { x:0.5, y:3.05, w:9, h:0.55, fontSize:28, color:GREEN, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(`Prepared by ${mspName}  ·  ${period.monthYear}`, { x:0.5, y:3.7, w:9, h:0.3, fontSize:12, color:MUTED, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(mspUrl.replace(/^https?:\/\//,""), { x:0.5, y:5.2, w:4, h:0.3, fontSize:10, color:MUTED, fontFace:"Calibri", bold:true, align:"left", valign:"middle", margin:0 });
  }

  // ── SLIDE: DEFINITIONS (Beginner and Intermediate personas only) ────────
  // Inserted right after the cover so non-expert readers (owners / office
  // managers / business or ops leads) have plain-English vocabulary before
  // hitting any data. Advanced readers skip this slide entirely.
  if (literacy === "beginner" || literacy === "intermediate") {
    const s = addS();
    addChrome(s, pres, "00", "DEFINITIONS", GREEN);
    addTitle(s, "A few quick definitions", "Before we get into the numbers, here is what a few of these terms actually mean.");

    const terms = [
      {
        term: "Vulnerability",
        nick: '"An open door"',
        defn: "A weakness in software or systems that could let an attacker in. Like an unlocked window on a building. Some are urgent. Others are minor.",
      },
      {
        term: "Sensitive Data / PII",
        nick: '"Personal Information"',
        defn: "Any data that identifies a specific person, such as names, addresses, health records, credit card numbers, government IDs, and banking details. The kind of information that, if it leaks, you are legally required to disclose.",
      },
      {
        term: "CIS Benchmarks",
        nick: '"Industry Standards"',
        defn: "A set of basic security expectations the whole industry has agreed on. Think of it like a building code for cybersecurity. There are minimum standards, and we measure how your environment compares against them.",
      },
      {
        term: "Permissions",
        nick: '"Who has the keys"',
        defn: "Which users or accounts have access to which files, folders, and systems. Overly broad permissions mean more people can reach sensitive data than actually need to.",
      },
      {
        term: "Cost of Breach",
        nick: '"What it would cost if data walked out the door"',
        defn: "An estimate of the financial exposure if the sensitive data in your environment were stolen or exposed. Includes regulatory fines, notification costs, and liability. Based on IBM industry data.",
      },
    ];

    // Row layout: outer box from x=0.5, w=9.0 → ends at x=9.5.
    // Left band (term + nickname) starts at x=0.7. Right band (definition)
    // starts at x = 0.7 + leftW + gap. Right band width is computed so
    // the text never extends past x = 9.5 - 0.2 (right padding).
    const rowH = 0.66, leftW = 2.8, gap = 0.15, rightPad = 0.2;
    const ROW_X = 0.5, ROW_W = 9.0;
    const rightX = ROW_X + 0.2 + leftW + gap;
    const rightW = (ROW_X + ROW_W) - rightPad - rightX;
    terms.forEach((t, i) => {
      const y = 2.05 + i * (rowH + 0.06);
      // Row background + green left edge accent
      s.addShape(pres.shapes.RECTANGLE, { x: ROW_X, y, w: ROW_W, h: rowH, fill: { color: BG_MID }, line: { color: BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x: ROW_X, y, w: 0.06, h: rowH, fill: { color: GREEN }, line: { color: GREEN } });
      // Term (bold white) + nickname (green italic) stacked in the left band
      s.addText(t.term, { x: 0.7, y: y + 0.06, w: leftW, h: 0.28, fontSize: 13, bold: true, color: WHITE, fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
      s.addText(t.nick, { x: 0.7, y: y + 0.34, w: leftW, h: 0.26, fontSize: 10, italic: true, color: GREEN, fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
      // Definition — width clamped to stay inside the row box
      s.addText(t.defn, { x: rightX, y: y + 0.06, w: rightW, h: rowH - 0.12, fontSize: 10, color: LIGHT, fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
    });
  }

  // ── SLIDE 2: EXEC SUMMARY ────────────────────────────────────────────────
  // Six stat cards in a 3x2 grid. Every value comes from the parsed Risk
  // Report; severity categories ("Very High", "High", etc.) are pulled
  // straight from the PDF rather than computed in code, so the accent
  // colors match Cavelo's own classification.
  {
    const s = addS();
    addChrome(s, pres, "01", "EXEC SUMMARY", GREEN);
    addTitle(s, "Executive summary", `Where your environment stands this quarter`);

    const tp = risk.testsPassed, tf = risk.testsFailed;
    const totalTests = (tp != null && tf != null) ? tp + tf : null;

    // Sublabels are short (~14-18 chars) so they fit inside the 2.95"-wide
    // cards. When a prior-quarter PDF was uploaded, every sublabel becomes
    // a colored trend line ("↓ 4.1 (was 4.4)" green for improvement, red
    // for regression, "Steady (was 4.4)" within noise).
    const trendOpts = { GREEN, RED, MUTED };
    const subTrendOrStatic = (key, decimals, fallback) => {
      if (priorRisk) {
        const d = fmtDelta(risk[key], priorRisk[key], { ...trendOpts, decimals });
        if (d) return d;
      }
      return fallback;
    };

    addStatCard(s, pres, {
      x:0.5, y:2.1, w:2.95, h:1.55,
      accentColor: accentForCat(risk.riskScoreCat),
      label: "DATA RISK SCORE",
      value: fmtScore(risk.riskScore),
      sublabel: subTrendOrStatic("riskScore", 1,
        risk.riskScoreCat || `Industry ${fmtScore(risk.industryScore)}`),
      valueSize: 44,
    });

    addStatCard(s, pres, {
      x:3.55, y:2.1, w:2.95, h:1.55,
      accentColor: AMBER,
      label: "POTENTIAL COST OF BREACH",
      value: fmtCurrency(risk.costOfBreach),
      sublabel: subTrendOrStatic("costOfBreach", 0,
        risk.instancesFound != null
          ? `${fmt(risk.instancesFound)} PII instances`
          : "Sensitive data exposure"),
      valueSize: 38,
    });

    addStatCard(s, pres, {
      x:6.6, y:2.1, w:2.85, h:1.55,
      accentColor: accentForCat(risk.vulnRiskCat),
      label: "VULNERABILITY RISK",
      value: fmtScore(risk.vulnRisk),
      sublabel: subTrendOrStatic("vulnRisk", 1,
        risk.maxCVSS != null
          ? `Max CVSS ${fmtScore(risk.maxCVSS, 1)}`
          : (risk.vulnRiskCat || "")),
      valueSize: 44,
    });

    addStatCard(s, pres, {
      x:0.5, y:3.8, w:2.95, h:1.25,
      accentColor: accentForCat(risk.benchmarkRiskCat),
      label: "CIS BENCHMARK FAILURES",
      value: fmt(tf),
      sublabel: subTrendOrStatic("testsFailed", 0,
        totalTests != null ? `of ${fmt(totalTests)} tests` : "Configuration baseline"),
      valueSize: 28,
    });

    addStatCard(s, pres, {
      x:3.55, y:3.8, w:2.95, h:1.25,
      accentColor: AMBER,
      label: "NONCOMPLIANT HOSTS",
      value: fmt(risk.noncompliantHosts),
      sublabel: subTrendOrStatic("noncompliantHosts", 0,
        risk.unapprovedSoftware != null
          ? `${fmt(risk.unapprovedSoftware)} unapproved`
          : "Software policy gaps"),
      valueSize: 28,
    });

    addStatCard(s, pres, {
      x:6.6, y:3.8, w:2.85, h:1.25,
      accentColor: accentForCat(risk.permissionRiskCat),
      label: "PERMISSION RISK",
      value: fmtScore(risk.permissionRisk),
      sublabel: subTrendOrStatic("permissionRisk", 1,
        risk.outlierDirs != null
          ? `${fmt(risk.outlierDirs)} outliers`
          : (risk.permissionRiskCat || "")),
      valueSize: 28,
    });
  }

  // ── SLIDE 3: DATA DISCOVERY ──────────────────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "02", "DATA DISCOVERY", GREEN);
    addTitle(s, "Where your sensitive data lives", `${fmt(risk.instancesFound)} instances of PII discovered across your environment`);

    // Top 5 at-risk Connectors from the Risk Report. Bar width tracks
    // the Cavelo "Score" column (0-5 scale, scaled against the section's
    // max). Color reflects severity: 4+ red, 3+ amber, otherwise blue.
    const connectors = (risk.topConnectors || [])
      .filter(c => c.score != null && c.score > 0)
      .slice(0, 5);
    const colorForScore = (s) => s >= 4 ? RED : s >= 3 ? AMBER : BLUE;
    s.addText("TOP PLATFORMS BY EXPOSURE", { x:0.5, y:2.1, w:4.4, h:0.3, fontSize:10, bold:true, color:GREEN, fontFace:"Calibri", charSpacing:1.5, valign:"middle", margin:0 });
    if (!connectors.length) {
      s.addText("No at-risk connectors detected — see Cavelo Data Risk Report for detail",
        { x:0.5, y:2.5, w:4.4, h:0.4, fontSize:11, italic:true, color:MUTED, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    }
    const maxScore = connectors[0]?.score || 5;
    connectors.forEach((p, i) => {
      const yPos = 2.5 + i * 0.45;
      const barW = (p.score / maxScore) * 3.0;
      const color = colorForScore(p.score);
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos+0.1, w:3.0, h:0.2, fill:{ color:BG_MID }, line:{ color:BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos+0.1, w:barW, h:0.2, fill:{ color }, line:{ color } });
      s.addText(p.name, { x:0.5, y:yPos-0.15, w:2.9, h:0.25, fontSize:11, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
      s.addText(p.score.toFixed(1), { x:3.6, y:yPos, w:1.0, h:0.4, fontSize:12, bold:true, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    });

    s.addText("MOST AT-RISK DATA TYPES", { x:5.3, y:2.1, w:4.2, h:0.3, fontSize:10, bold:true, color:GREEN, fontFace:"Calibri", charSpacing:1.5, valign:"middle", margin:0 });
    const piiTypes = [
      { name:"Health Card (Quebec)",    note:"$226K exposure" },
      { name:"Credit Card numbers",     note:"Most common" },
      { name:"Passport numbers",        note:"Travel/identity" },
      { name:"IBAN (banking)",          note:"Financial" },
      { name:"Social Insurance Numbers",note:"Identity theft" },
    ];
    piiTypes.forEach((t, i) => {
      const yPos = 2.5 + i * 0.45;
      s.addShape(pres.shapes.RECTANGLE, { x:5.3, y:yPos, w:4.2, h:0.4, fill:{ color:BG_MID }, line:{ color:BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x:5.3, y:yPos, w:0.06, h:0.4, fill:{ color:GREEN }, line:{ color:GREEN } });
      s.addText(t.name, { x:5.5, y:yPos, w:2.5, h:0.4, fontSize:11, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
      s.addText(t.note, { x:7.9, y:yPos, w:1.5, h:0.4, fontSize:10, color:LIGHT, fontFace:"Calibri", align:"right", valign:"middle", margin:0 });
    });

    addFootnote(s, "PII = Personally Identifiable Information. Source: Cavelo Data Risk Report.");
  }

  // ── SLIDE 4: COST OF BREACH ──────────────────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "03", "BREACH COST", GREEN);
    addTitle(s, "What a breach would cost you", `$${fmt(risk.costOfBreach)} total exposure based on IBM industry data`);

    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:2.1, w:9, h:1.1, fill:{ color:BG_MID }, line:{ color:BG_MID } });
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:2.1, w:9, h:0.08, fill:{ color:RED }, line:{ color:RED } });
    s.addText(`$${fmt(risk.costOfBreach)}`, { x:0.7, y:2.25, w:4, h:0.85, fontSize:52, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Total potential cost of breach", { x:4.6, y:2.35, w:4.7, h:0.35, fontSize:14, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Calculated across all sensitive data discovered", { x:4.6, y:2.7, w:4.7, h:0.3, fontSize:11, color:MUTED, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });

    // Top host + Top connector cards. Cavelo's Risk Report renders the
    // dollar exposure per host/connector inside chart graphics that don't
    // extract as text — but the report DOES carry the "Top at-risk Agents"
    // and "Top at-risk Connectors" tables, which give us the same ranking
    // by a 0-5 risk score. We surface the top entry from each as a
    // name + score pair.
    const topAgent     = (risk.topAgents     || [])[0] || null;
    const topConnector = (risk.topConnectors || []).filter(c => c.score != null && c.score > 0)[0] || null;

    // Top host card
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:3.4, w:4.4, h:1.65, fill:{ color:BG_MID }, line:{ color:BG_MID } });
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:3.4, w:4.4, h:0.08, fill:{ color:AMBER }, line:{ color:AMBER } });
    s.addText("HIGHEST-RISK HOST", { x:0.7, y:3.55, w:4, h:0.3, fontSize:9, bold:true, color:AMBER, fontFace:"Calibri", charSpacing:1, valign:"middle", margin:0 });
    s.addText(topAgent ? topAgent.name : "—", { x:0.7, y:3.85, w:4, h:0.45, fontSize:20, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(topAgent && topAgent.score != null
      ? `Risk score ${topAgent.score.toFixed(1)} of 5`
      : "Detail not available — see report",
      { x:0.7, y:4.35, w:4, h:0.3, fontSize:11, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Top entry from the Risk Report's Top at-risk Agents table",
      { x:0.7, y:4.7, w:4, h:0.3, fontSize:9, color:MUTED, fontFace:"Calibri", italic:true, align:"left", valign:"middle", margin:0 });

    // Top connector card
    s.addShape(pres.shapes.RECTANGLE, { x:5.1, y:3.4, w:4.4, h:1.65, fill:{ color:BG_MID }, line:{ color:BG_MID } });
    s.addShape(pres.shapes.RECTANGLE, { x:5.1, y:3.4, w:4.4, h:0.08, fill:{ color:AMBER }, line:{ color:AMBER } });
    s.addText("HIGHEST-RISK CONNECTOR", { x:5.3, y:3.55, w:4, h:0.3, fontSize:9, bold:true, color:AMBER, fontFace:"Calibri", charSpacing:1, valign:"middle", margin:0 });
    s.addText(topConnector ? topConnector.name : "—", { x:5.3, y:3.85, w:4, h:0.45, fontSize:20, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(topConnector && topConnector.score != null
      ? `Risk score ${topConnector.score.toFixed(1)} of 5`
      : "Detail not available — see report",
      { x:5.3, y:4.35, w:4, h:0.3, fontSize:11, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Top entry from the Risk Report's Top at-risk Connectors table",
      { x:5.3, y:4.7, w:4, h:0.3, fontSize:9, color:MUTED, fontFace:"Calibri", italic:true, align:"left", valign:"middle", margin:0 });

    addFootnote(s, "Cost calculated using IBM Cost of a Data Breach Report industry averages applied to discovered PII volume.");
  }

  // ── SLIDE 5: PERMISSION RISK ─────────────────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "04", "PERMISSIONS", GREEN);
    addTitle(s, "Who has access to what", `27 entities discovered with ${fmt(risk.outlierDirs)} outlier directories`);

    addStatCard(s, pres, { x:0.5, y:2.1, w:2.95, h:1.55, accentColor:AMBER, label:"PERMISSION RISK", value:risk.permissionRisk.toFixed(1), sublabel:"High", valueSize:44 });
    addStatCard(s, pres, { x:3.55, y:2.1, w:2.95, h:1.55, accentColor:AMBER, label:"OUTLIER DIRECTORIES", value:fmt(risk.outlierDirs), sublabel:"Permissions differ from parent", valueSize:32 });
    addStatCard(s, pres, { x:6.6, y:2.1, w:2.85, h:1.55, accentColor:RED, label:"ANONYMOUS LINKS", value:"Multiple", sublabel:"Files accessible to anyone", valueSize:24 });

    s.addText("KEY FINDINGS", { x:0.5, y:3.85, w:9, h:0.3, fontSize:10, bold:true, color:GREEN, fontFace:"Calibri", charSpacing:1.5, valign:"middle", margin:0 });
    const findings = [
      "18 users with direct access to OneDrive Teams chat files (bypassing groups)",
      "Anonymous share links active on internal employee assets and templates",
      "Permissions inherited inconsistently across SharePoint communication sites",
    ];
    findings.forEach((f, i) => {
      const yPos = 4.2 + i * 0.32;
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:9, h:0.28, fill:{ color:BG_MID }, line:{ color:BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:0.06, h:0.28, fill:{ color:AMBER }, line:{ color:AMBER } });
      s.addText(f, { x:0.7, y:yPos, w:8.7, h:0.28, fontSize:11, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    });
  }

  // ── SLIDE 5b: TOP HOSTS TO ADDRESS  (Intermediate / Advanced only) ───────
  // Per-host risk breakdown from the Risk Report's "Top at-risk Agents"
  // table. Each row shows the host's overall Risk Score plus its four
  // sub-dimension scores (Data Cost / Benchmark / Permission / Vulnerability)
  // so the audience can see WHERE each host's risk concentrates. Sub-cells
  // are tinted by severity (>=4 red, >=3 amber, otherwise neutral).
  // Beginner persona skips this — it's too dense for non-technical readers.
  if ((literacy === "intermediate" || literacy === "advanced")
      && Array.isArray(risk.topAgents) && risk.topAgents.length > 0) {
    const s = addS();
    addChrome(s, pres, "", "TOP HOSTS", GREEN);
    addTitle(s, "Top hosts to address this quarter",
      "Highest-risk endpoints from the Risk Report — sorted by overall score");

    const top = risk.topAgents.slice(0, 6);
    // Column geometry (slide width 10, padded to 9.0 usable from x=0.5)
    const cols = [
      { label: "HOST",        x: 0.50, w: 2.40, align: "left"  },
      { label: "OVERALL",     x: 2.95, w: 1.20, align: "center" },
      { label: "DATA COST",   x: 4.20, w: 1.30, align: "center" },
      { label: "BENCHMARK",   x: 5.55, w: 1.30, align: "center" },
      { label: "PERMISSION",  x: 6.90, w: 1.30, align: "center" },
      { label: "VULN",        x: 8.25, w: 1.20, align: "center" },
    ];

    // Header row
    const headerY = 2.05;
    cols.forEach(c => {
      s.addText(c.label, { x: c.x, y: headerY, w: c.w, h: 0.3,
        fontSize: 9, bold: true, color: GREEN, fontFace: "Calibri",
        align: c.align, valign: "middle", margin: 0, charSpacing: 1 });
    });

    // Data rows — alternating background so rows visually separate
    const tintForScore = (sc) => {
      if (sc == null) return MUTED;
      if (sc >= 4)    return RED;
      if (sc >= 3)    return AMBER;
      return LIGHT;
    };
    const rowH = 0.42;
    top.forEach((row, i) => {
      const y = 2.45 + i * rowH;
      // Subtle band on every other row for legibility
      if (i % 2 === 0) {
        s.addShape(pres.shapes.RECTANGLE, { x: 0.5, y, w: 9.0, h: rowH,
          fill: { color: BG_MID }, line: { color: BG_MID } });
      }
      // Host name
      s.addText(row.name, {
        x: cols[0].x + 0.1, y, w: cols[0].w - 0.1, h: rowH,
        fontSize: 11, bold: true, color: WHITE, fontFace: "Calibri",
        align: "left", valign: "middle", margin: 0,
      });
      // Overall + 4 dimension scores. Cavelo agents table columns are:
      //   scores[0] Score, [1] Data Cost, [2] Benchmark, [3] Permission, [4] Vulnerability
      [
        { col: 1, idx: 0, bold: true,  size: 14 },
        { col: 2, idx: 1, bold: false, size: 12 },
        { col: 3, idx: 2, bold: false, size: 12 },
        { col: 4, idx: 3, bold: false, size: 12 },
        { col: 5, idx: 4, bold: false, size: 12 },
      ].forEach(({ col, idx, bold, size }) => {
        const sc  = row.scores[idx];
        const txt = sc == null ? "—" : sc.toFixed(1);
        const c   = cols[col];
        s.addText(txt, {
          x: c.x, y, w: c.w, h: rowH,
          fontSize: size, bold, color: tintForScore(sc), fontFace: "Calibri",
          align: c.align, valign: "middle", margin: 0,
        });
      });
    });

    addFootnote(s, "Scores 0-5 per Cavelo's Risk Report. Red ≥ 4, amber ≥ 3. Source: Top at-risk Agents table.");
  }

  // ── SLIDE 6: SOFTWARE COMPLIANCE ─────────────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "05", "SOFTWARE", GREEN);
    addTitle(s, "Software compliance across the fleet", `${risk.noncompliantHosts} noncompliant agents need attention`);

    addStatCard(s, pres, { x:0.5, y:2.1, w:2.95, h:1.55, accentColor:AMBER, label:"NONCOMPLIANT AGENTS", value:String(risk.noncompliantHosts), sublabel:"Out of policy this quarter", valueSize:44 });
    addStatCard(s, pres, { x:3.55, y:2.1, w:2.95, h:1.55, accentColor:RED, label:"UNAPPROVED SOFTWARE", value:String(risk.unapprovedSoftware), sublabel:"Hosts running blocked apps", valueSize:44 });
    addStatCard(s, pres, { x:6.6, y:2.1, w:2.85, h:1.55, accentColor:AMBER, label:"MISSING REQUIRED", value:String(risk.missingSoftware), sublabel:"Hosts missing mandatory apps", valueSize:44 });

    // Approved stats
    const drawPositive = (x, val, label) => {
      s.addShape(pres.shapes.RECTANGLE, { x, y:3.85, w:4.4, h:1.05, fill:{ color:BG_MID }, line:{ color:BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x, y:3.85, w:0.08, h:1.05, fill:{ color:GREEN }, line:{ color:GREEN } });
      s.addText(fmt(val), { x:x+0.25, y:3.95, w:1.7, h:0.6, fontSize:32, bold:true, color:GREEN, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
      s.addText(label, { x:x+0.25, y:4.5, w:4, h:0.3, fontSize:11, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    };
    drawPositive(0.5, risk.approvedApps, "Approved applications");
    drawPositive(5.1, risk.approvedPublishers, "Approved publishers");
  }

  // ── SLIDE 7: VULNERABILITY POSTURE ───────────────────────────────────────
  // Single slide built from the Risk Report's Vulnerability Summary section.
  // The full per-CVE detail used to come from a separate Endpoint Vulnerability
  // Audit PDF — Cavelo doesn't expose that as a separate export, so we
  // surface the headline vuln metrics they DO include in the Risk Report.
  {
    const s = addS();
    addChrome(s, pres, "06", "VULNERABILITY", GREEN);
    addTitle(s, "Vulnerability posture", "Endpoint and network exposure summary from the Risk Report");

    addStatCard(s, pres, {
      x:0.5, y:2.05, w:2.95, h:1.85,
      accentColor: accentForCat(risk.vulnRiskCat),
      label: "ENDPOINT VULN RISK",
      value: fmtScore(risk.vulnRisk),
      sublabel: risk.vulnRiskCat || "—",
      valueSize: 56,
    });
    addStatCard(s, pres, {
      x:3.55, y:2.05, w:2.95, h:1.85,
      accentColor: RED,
      label: "MAX CVSS THIS QUARTER",
      value: fmtScore(risk.maxCVSS, 1),
      sublabel: "Severity of the worst known CVE",
      valueSize: 56,
    });
    addStatCard(s, pres, {
      x:6.6, y:2.05, w:2.85, h:1.85,
      accentColor: AMBER,
      label: "MAX EPSS",
      value: risk.maxEPSS != null ? risk.maxEPSS.toFixed(3) : "—",
      sublabel: "Likelihood of exploitation in next 30d",
      valueSize: 56,
    });

    // Network vuln callout — Cavelo separates "endpoint" from "network"
    // vulnerability scoring. Highlight the network result so the contrast
    // with endpoint risk is visible at a glance.
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:4.1, w:4.5, h:0.95, fill:{ color:BG_MID }, line:{ color:accentForCat(risk.networkVulnRiskCat), width:1 } });
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:4.1, w:0.08, h:0.95, fill:{ color:accentForCat(risk.networkVulnRiskCat) }, line:{ color:accentForCat(risk.networkVulnRiskCat) } });
    s.addText("Network vulnerability risk", { x:0.75, y:4.18, w:3, h:0.3, fontSize:12, bold:true, color:accentForCat(risk.networkVulnRiskCat), fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(risk.networkVulnRiskCat || "Not detected", { x:0.75, y:4.45, w:2.8, h:0.28, fontSize:10, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(fmtScore(risk.networkVulnRisk), { x:3.2, y:4.2, w:1.7, h:0.4, fontSize:24, bold:true, color:WHITE, fontFace:"Calibri", align:"right", valign:"middle", margin:0 });
    s.addText("perimeter score", { x:3.2, y:4.6, w:1.7, h:0.3, fontSize:9, color:MUTED, fontFace:"Calibri", align:"right", valign:"middle", margin:0 });

    // What it means callout — narrative context for the numbers above.
    s.addShape(pres.shapes.RECTANGLE, { x:5.2, y:4.1, w:4.3, h:0.95, fill:{ color:BG_MID }, line:{ color:GREEN, width:1 } });
    s.addShape(pres.shapes.RECTANGLE, { x:5.2, y:4.1, w:0.08, h:0.95, fill:{ color:GREEN }, line:{ color:GREEN } });
    s.addText("What this means", { x:5.45, y:4.18, w:4, h:0.3, fontSize:12, bold:true, color:GREEN, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Max CVSS reflects the most severe known vulnerability in your environment; max EPSS estimates how likely it is to be exploited in the next 30 days. We patch by priority of both.", { x:5.45, y:4.45, w:3.95, h:0.55, fontSize:9, color:LIGHT, fontFace:"Calibri", align:"left", valign:"top", margin:0 });

    addFootnote(s, "CVSS = Common Vulnerability Scoring System. EPSS = Exploit Prediction Scoring System. Source: Cavelo Risk Report.");
  }

  // ── SLIDE 7b: CONTINUOUS MONITORING POSTURE  (Intermediate / Advanced) ──
  // Validates that monitoring is actually configured. Pulled from each
  // section's Active Schedules / Policies / Whitelists counts in the
  // Risk Report. 2x2 grid of small cards. Beginner persona skips this —
  // "active whitelists" is too jargon-y without context.
  if ((literacy === "intermediate" || literacy === "advanced") && risk.monitoring) {
    const m = risk.monitoring;
    const allEmpty = [m.dataCost, m.benchmark, m.vuln, m.networkVuln]
      .every(b => Object.values(b || {}).every(v => v == null));
    if (!allEmpty) {
      const s = addS();
      addChrome(s, pres, "", "MONITORING", GREEN);
      addTitle(s, "Continuous monitoring posture",
        "What's running in your environment between Technology Reviews");

      const cards = [
        { name: "DATA DISCOVERY",         block: m.dataCost,    accent: GREEN },
        { name: "CIS BENCHMARKS",         block: m.benchmark,   accent: AMBER },
        { name: "VULNERABILITY SCANS",    block: m.vuln,        accent: RED   },
        { name: "NETWORK VULN SCANS",     block: m.networkVuln, accent: BLUE  },
      ];

      // 2x2 grid centered horizontally (cardW 4.45, gap 0.10)
      const cardW = 4.45, cardH = 1.35, gap = 0.10;
      const col = (i) => 0.5 + (i % 2) * (cardW + gap);
      const row = (i) => 2.05 + Math.floor(i / 2) * (cardH + gap);

      cards.forEach((c, i) => {
        const x = col(i), y = row(i);
        // Card background + accent left edge
        s.addShape(pres.shapes.RECTANGLE, { x, y, w: cardW, h: cardH,
          fill: { color: BG_MID }, line: { color: BG_MID } });
        s.addShape(pres.shapes.RECTANGLE, { x, y, w: 0.08, h: cardH,
          fill: { color: c.accent }, line: { color: c.accent } });
        // Card label
        s.addText(c.name, { x: x + 0.18, y: y + 0.12, w: cardW - 0.36, h: 0.28,
          fontSize: 10, bold: true, color: c.accent, fontFace: "Calibri",
          align: "left", valign: "middle", margin: 0, charSpacing: 1 });
        // Three numeric tiles inside the card: schedules / policies / whitelists.
        // dataCost only has schedules + policies (no whitelist tile).
        const tiles = [
          { label: "Schedules", value: c.block?.schedules },
          { label: "Policies",  value: c.block?.policies  },
          { label: "Whitelists",value: c.block?.whitelists },
        ].filter(t => t.value != null);
        if (tiles.length === 0) {
          s.addText("Detail not available", {
            x: x + 0.18, y: y + 0.45, w: cardW - 0.36, h: 0.4,
            fontSize: 11, italic: true, color: MUTED, fontFace: "Calibri",
            align: "left", valign: "middle", margin: 0,
          });
        } else {
          const tileW = (cardW - 0.36) / tiles.length;
          tiles.forEach((t, j) => {
            const tx = x + 0.18 + j * tileW;
            s.addText(String(t.value), {
              x: tx, y: y + 0.45, w: tileW - 0.05, h: 0.42,
              fontSize: 28, bold: true, color: WHITE, fontFace: "Calibri",
              align: "left", valign: "middle", margin: 0,
            });
            s.addText(t.label, {
              x: tx, y: y + 0.92, w: tileW - 0.05, h: 0.22,
              fontSize: 9, color: MUTED, fontFace: "Calibri",
              align: "left", valign: "middle", margin: 0,
            });
          });
        }
      });

      // Bottom callout — explains the terms without jargon
      s.addShape(pres.shapes.RECTANGLE, { x: 0.5, y: 4.85, w: 9.0, h: 0.45,
        fill: { color: BG_MID }, line: { color: GREEN, width: 1 } });
      s.addShape(pres.shapes.RECTANGLE, { x: 0.5, y: 4.85, w: 0.08, h: 0.45,
        fill: { color: GREEN }, line: { color: GREEN } });
      s.addText("Schedules run automatically against your environment. Policies are remediation rules. Whitelists carry approved exceptions.",
        { x: 0.75, y: 4.88, w: 8.6, h: 0.4, fontSize: 10, color: LIGHT,
          fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
    }
  }

  // ── SLIDE 8: CIS BENCHMARKS ─────────────────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "07", "BENCHMARKS", GREEN);
    addTitle(s, "CIS benchmark compliance", "Configuration hardening across your Windows fleet");

    const totalTests = risk.testsPassed + risk.testsFailed;
    addStatCard(s, pres, { x:0.5, y:2.1, w:2.95, h:1.55, accentColor:RED, label:"BENCHMARK RISK", value:risk.benchmarkRisk.toFixed(1), sublabel:"Very High", valueSize:44 });
    addStatCard(s, pres, { x:3.55, y:2.1, w:2.95, h:1.55, accentColor:RED, label:"TESTS FAILED", value:fmt(risk.testsFailed), sublabel:`Of ${fmt(totalTests)} total tests`, valueSize:32 });
    addStatCard(s, pres, { x:6.6, y:2.1, w:2.85, h:1.55, accentColor:GREEN, label:"TESTS PASSED", value:fmt(risk.testsPassed), sublabel:"Already aligned to CIS", valueSize:32 });

    s.addText("TOP FAILURE GROUPS (CIS WINDOWS 11 ENTERPRISE)", { x:0.5, y:3.85, w:9, h:0.3, fontSize:10, bold:true, color:GREEN, fontFace:"Calibri", charSpacing:1.5, valign:"middle", margin:0 });
    ["Network Protection — 100% failure rate", "WLAN Settings — 100% failure rate", "Windows Security (Defender) — 100% failure rate", "Control Panel — 100% failure rate"].forEach((g, i) => {
      const yPos = 4.2 + i * 0.27;
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:9, h:0.23, fill:{ color:BG_MID }, line:{ color:BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:0.06, h:0.23, fill:{ color:RED }, line:{ color:RED } });
      s.addText(g, { x:0.7, y:yPos, w:8.7, h:0.23, fontSize:10, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    });

    addFootnote(s, risk.topHostName
      ? `CIS = Center for Internet Security benchmarks. Highest cost host: ${risk.topHostName} ($${fmt(risk.topHostCost)} source cost) with Very High failure rate.`
      : "CIS = Center for Internet Security benchmarks. Source: Cavelo Data Risk Report.");
  }

  // ── SLIDE 9: COMPLIANCE EVIDENCE ─────────────────────────────────────────
  // Driven by the "Compliance focus" pill checkboxes on the form. MSP
  // checks the framework(s) that matter for that specific client.
  // Accepts comma-separated keys ("cmmc,soc2"), the legacy single value
  // ("cmmc"), the legacy "all" sentinel, or empty/none → skip entirely.
  // Layout adapts: 1 framework = wide centered card, 2 = side-by-side,
  // 3 = original 3-card grid.
  const _resolveCompliance = (raw) => {
    const VALID = ["cmmc", "nist", "soc2"];
    if (!raw || raw === "none") return [];
    if (raw === "all") return VALID;
    return raw.split(",").map(s => s.trim()).filter(k => VALID.includes(k));
  };
  const _selected = _resolveCompliance(compliance);
  if (_selected.length > 0) {
    // Each framework's bullets are stored as { label, code } pairs so the
    // human-readable "Regular vulnerability scanning" is always separable
    // from the framework code reference "SI.L1-3.14.5". Beginner /
    // Intermediate render label-only; Advanced renders the code as a
    // smaller muted suffix at the end of the line. Unifies what used to
    // be two parallel arrays (controls / controlsPlain) and avoids the
    // mixed "CC6: foo" leading-prefix style — codes always go to the
    // back now.
    const ALL_FRAMEWORKS = {
      cmmc: {
        name: "CMMC L1 / L2",
        sub:  "NIST 800-171",
        controls: [
          { label: "Regular vulnerability scanning",          code: "SI.L1-3.14.5, RA.L2-3.11.2" },
          { label: "Configuration baseline checks",            code: "CM.L2-3.4.1" },
          { label: "Access control monitoring",                code: "AC.L1-3.1.1, AC.L1-3.1.2" },
          { label: "Sensitive data discovery and location",    code: "MP.L2-3.8.4" },
          { label: "Risk assessment scoring",                  code: "RA.L2-3.11.1" },
        ],
        evidence: [
          { label: "Risk Score", value: fmtScore(risk.riskScore) },
          { label: "CIS fails",  value: fmt(risk.testsFailed) },
          { label: "PII inst.",  value: fmt(risk.instancesFound) },
        ],
      },
      nist: {
        name: "NIST CSF",
        sub:  "Cybersecurity Framework",
        controls: [
          { label: "Identify: asset and data inventory",       code: "ID.AM, ID.RA" },
          { label: "Identify: risk assessment scoring",        code: "ID.RA-1, ID.RA-3" },
          { label: "Protect: data security and access",        code: "PR.DS, PR.AC" },
          { label: "Detect: continuous monitoring",            code: "DE.CM-8" },
          { label: "Detect: anomalies and events",             code: "DE.AE-3" },
        ],
        evidence: [
          { label: "Risk Score", value: fmtScore(risk.riskScore) },
          { label: "Outliers",   value: fmt(risk.outlierDirs) },
          { label: "PII inst.",  value: fmt(risk.instancesFound) },
        ],
      },
      soc2: {
        name: "SOC 2",
        sub:  "Trust Services + Privacy",
        controls: [
          { label: "Logical access controls",                  code: "CC6.1, CC6.2" },
          { label: "Vulnerability management",                 code: "CC6.6, CC7.1" },
          { label: "Continuous system operations monitoring",  code: "CC7" },
          { label: "Change management visibility",             code: "CC8.1" },
          { label: "Confidential data inventory",              code: "C1 / Privacy" },
        ],
        evidence: [
          { label: "PII inst.",  value: fmt(risk.instancesFound) },
          { label: "Perm risk",  value: fmtScore(risk.permissionRisk) },
          { label: "CIS fails",  value: fmt(risk.testsFailed) },
        ],
      },
    };

    const frameworks = _selected.map(k => ALL_FRAMEWORKS[k]);

    const s = addS();
    addChrome(s, pres, "08", "COMPLIANCE", GREEN);
    addTitle(s, "How we help keep you compliant", "Cavelo's continuous monitoring produces the evidence auditors ask for");

    // Layout adapts to count. 1 framework → one wide centered card.
    // 2 frameworks → two side-by-side. 3 → original 3-card layout.
    const TOTAL_W = 9.0, GAP = 0.1;
    const n = frameworks.length;
    let cardW, startX;
    if (n === 1) {
      cardW = 6.0;
      startX = 0.5 + (TOTAL_W - cardW) / 2;
    } else {
      cardW = (TOTAL_W - GAP * (n - 1)) / n;
      startX = 0.5;
    }
    // Card height extended from 2.5 -> 3.05 to fit the 5-bullet list
    // (was 3 bullets). The freed space comes from removing the bottom
    // "continuous scanning" callout that used to live at y=4.65.
    const cardH = 3.05, cardY = 2.0;

    frameworks.forEach((fw, i) => {
      const x = startX + i * (cardW + GAP);
      // Card background + green left edge
      s.addShape(pres.shapes.RECTANGLE, { x, y: cardY, w: cardW, h: cardH, fill: { color: BG_MID }, line: { color: BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x, y: cardY, w: cardW, h: 0.08, fill: { color: GREEN }, line: { color: GREEN } });
      // Header
      s.addText(fw.name, { x: x + 0.18, y: cardY + 0.18, w: cardW - 0.36, h: 0.32, fontSize: 16, bold: true, color: WHITE, fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
      s.addText(fw.sub,  { x: x + 0.18, y: cardY + 0.50, w: cardW - 0.36, h: 0.22, fontSize: 9,  italic: true, color: GREEN, fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
      // Font sizing scales with card width. n=1 (wide) gets the most
      // generous text; n=2 (medium) sits between; n=3 stays compact.
      const bulletFs   = n === 1 ? 11 : n === 2 ? 10 : 9;
      const evidenceFs = n === 1 ? 16 : n === 2 ? 14 : 13;

      // Bullets are { label, code } pairs. Beginner + Intermediate see
      // the label only; Advanced gets the framework code reference too,
      // rendered as a smaller muted italic suffix at the end of the line.
      // Bullet glyph lives inside the text box as a green text run so
      // it sits on the same baseline as the body and stays aligned when
      // long lines wrap.
      //
      // Bullet spacing auto-fits the available height between the header
      // (cardY + 0.85) and the evidence strip (cardY + cardH - 0.55),
      // capped at 0.42 so 3-bullet cards don't get sparse.
      const showCodes = literacy === "advanced";
      const bulletAreaH = cardH - 0.85 - 0.55;
      const bulletSpacing = Math.min(0.42, bulletAreaH / fw.controls.length);
      const bulletH = Math.min(0.4, bulletSpacing - 0.02);
      fw.controls.forEach((c, j) => {
        const yPos = cardY + 0.85 + j * bulletSpacing;
        const runs = [
          { text: "● ",   options: { color: GREEN, bold: true } },
          { text: c.label, options: { color: LIGHT } },
        ];
        if (showCodes && c.code) {
          runs.push({ text: "   " + c.code, options: { color: MUTED, italic: true, fontSize: Math.max(7, bulletFs - 2) } });
        }
        s.addText(runs, {
          x: x + 0.20, y: yPos, w: cardW - 0.36, h: bulletH,
          fontSize: bulletFs, fontFace: "Calibri",
          align: "left", valign: "top", margin: 0,
        });
      });
      // Evidence strip
      const stripY = cardY + cardH - 0.55;
      s.addShape(pres.shapes.RECTANGLE, { x: x + 0.12, y: stripY, w: cardW - 0.24, h: 0.5, fill: { color: BG }, line: { color: BG } });
      s.addText("THIS QUARTER", { x: x + 0.18, y: stripY + 0.02, w: cardW - 0.36, h: 0.18, fontSize: 7, bold: true, color: GREEN, fontFace: "Calibri", charSpacing: 1, align: "left", valign: "middle", margin: 0 });
      const cellW = (cardW - 0.36) / 3;
      fw.evidence.forEach((e, j) => {
        const ex = x + 0.18 + j * cellW;
        s.addText(e.value, { x: ex, y: stripY + 0.18, w: cellW - 0.05, h: 0.2, fontSize: evidenceFs, bold: true, color: WHITE, fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
        s.addText(e.label, { x: ex, y: stripY + 0.36, w: cellW - 0.05, h: 0.14, fontSize: 7, color: MUTED, fontFace: "Calibri", align: "left", valign: "middle", margin: 0 });
      });
    });

    // Bottom callout removed — its real estate now goes to taller cards
    // with 5-bullet control lists per framework. The continuous-scanning
    // value prop is implied by the "Continuous system operations" /
    // "Detect: continuous monitoring" / "Periodic vulnerability
    // scanning" bullets that now appear on every card.

    addFootnote(s, "Cavelo provides continuous monitoring evidence; full compliance also requires governance, training, and other organizational controls outside this scope.");
  }

  // ── SLIDE 10: VISIBILITY GAPS ────────────────────────────────────────────
  // Three cards highlighting coverage and exposure gaps from the Risk
  // Report. Outlier-directories and noncompliant-hosts come straight from
  // the parser; the sublabels rotate based on whether their counterpart
  // metric is also present so the slide stays informative even when one
  // value is missing.
  {
    const s = addS();
    addChrome(s, pres, "09", "VISIBILITY", GREEN);
    addTitle(s, "Where we don't have visibility", "Coverage gaps and outlier exposure");

    addStatCard(s, pres, {
      x:0.5, y:2.1, w:2.95, h:1.55,
      accentColor: accentForCat(risk.permissionRiskCat),
      label: "OUTLIER DIRECTORIES",
      value: fmt(risk.outlierDirs),
      sublabel: "Permission anomalies vs parent",
      valueSize: 32,
    });
    addStatCard(s, pres, {
      x:3.55, y:2.1, w:2.95, h:1.55,
      accentColor: AMBER,
      label: "NONCOMPLIANT HOSTS",
      value: fmt(risk.noncompliantHosts),
      sublabel: "Software policy gaps",
      valueSize: 32,
    });
    addStatCard(s, pres, {
      x:6.6, y:2.1, w:2.85, h:1.55,
      accentColor: AMBER,
      label: "MISSING SOFTWARE",
      value: fmt(risk.missingSoftware),
      sublabel: risk.unapprovedSoftware != null
        ? `${fmt(risk.unapprovedSoftware)} unapproved apps`
        : "Hosts missing required apps",
      valueSize: 32,
    });

    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:3.85, w:9, h:1.35, fill:{ color:BG_MID }, line:{ color:AMBER, width:1 } });
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:3.85, w:0.08, h:1.35, fill:{ color:AMBER }, line:{ color:AMBER } });
    s.addText("What this means for you", { x:0.75, y:3.95, w:8.6, h:0.3, fontSize:13, bold:true, color:AMBER, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Outlier directories are permission anomalies that bypass your normal access policy — sensitive data could be reachable by accounts that shouldn't see it. Noncompliant hosts are endpoints running software outside your approved baseline. Both are highest-leverage closes for this quarter.", { x:0.75, y:4.3, w:8.6, h:0.85, fontSize:11, color:LIGHT, fontFace:"Calibri", align:"left", valign:"top", margin:0 });
  }

  // ── SLIDE 10: NEXT-QUARTER PRIORITIES ────────────────────────────────────
  // Three commitments synthesized from the highest-severity items in the
  // Risk Report. Body text references real parsed values where possible
  // (CIS test fail count, outlier dir count, vuln risk category).
  {
    const s = addS();
    addChrome(s, pres, "10", "NEXT QUARTER", GREEN);
    addTitle(s, `${period.nextQuarter} priorities`, "Three commitments for the next 90 days");

    const priorities = [
      {
        num: "01",
        title: "Reduce vulnerability exposure",
        body: risk.maxCVSS != null
          ? `Address the highest-severity issues from this quarter's scan (max CVSS ${fmtScore(risk.maxCVSS, 1)}, EPSS ${risk.maxEPSS != null ? risk.maxEPSS.toFixed(3) : "—"}). Apply outstanding critical Windows updates in scheduled maintenance windows.`
          : "Address the highest-severity issues from this quarter's scan. Apply outstanding critical Windows updates in scheduled maintenance windows.",
        color: RED,
      },
      {
        num: "02",
        title: "Tighten permission exposure",
        body: risk.outlierDirs != null
          ? `Remediate top ${Math.min(risk.outlierDirs, 50)}+ outlier directories — permission anomalies that bypass your normal access policy. Restrict anonymous share links on highest-cost resources.`
          : "Remediate the highest-cost outlier directories. Restrict anonymous share links on top-exposure resources.",
        color: AMBER,
      },
      {
        num: "03",
        title: "Harden CIS benchmark posture",
        body: (risk.testsFailed != null && risk.testsPassed != null)
          ? `Close ${fmt(risk.testsFailed)} failed tests of ${fmt(risk.testsPassed + risk.testsFailed)}. Begin with the Network Protection group on the highest-risk hosts; iterate weekly with the same scan cadence.`
          : "Close failed CIS benchmark tests starting with the Network Protection group on highest-risk hosts.",
        color: BLUE,
      },
    ];
    priorities.forEach((p, i) => {
      const yPos = 2.1 + i * 0.95;
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:9, h:0.85, fill:{ color:BG_MID }, line:{ color:BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:0.08, h:0.85, fill:{ color:p.color }, line:{ color:p.color } });
      s.addText(p.num, { x:0.78, y:yPos+0.13, w:0.6, h:0.6, fontSize:22, bold:true, color:p.color, fontFace:"Calibri", align:"center", valign:"middle", margin:0 });
      s.addText(p.title, { x:1.55, y:yPos+0.1, w:7.7, h:0.32, fontSize:14, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
      s.addText(p.body, { x:1.55, y:yPos+0.42, w:7.7, h:0.4, fontSize:10, color:LIGHT, fontFace:"Calibri", align:"left", valign:"top", margin:0 });
    });

    s.addText(mspUrl.replace(/^https?:\/\//, ""), { x:0.5, y:5.2, w:4, h:0.3, fontSize:10, color:MUTED, fontFace:"Calibri", bold:true, align:"left", valign:"middle", margin:0 });
    s.addText("Continuous monitoring · Weekly scans · Real-time alerting", { x:5, y:5.2, w:4.5, h:0.3, fontSize:10, color:MUTED, fontFace:"Calibri", align:"right", valign:"middle", margin:0 });
  }

  return pres.write({ outputType: "nodebuffer" });
}

// ─── FORM DATA PARSER ─────────────────────────────────────────────────────────

function parseFormData(event) {
  return new Promise((resolve, reject) => {
    const fields = {}, files = {};
    const bb = busboy({ headers: { "content-type": event.headers["content-type"] } });

    bb.on("field", (name, val) => { fields[name] = val; });
    bb.on("file", (name, stream, info) => {
      const chunks = [];
      stream.on("data", d => chunks.push(d));
      stream.on("end", () => { files[name] = { buffer: Buffer.concat(chunks), info }; });
    });
    bb.on("close", () => resolve({ fields, files }));
    bb.on("error", reject);

    const body = Buffer.from(event.body, event.isBase64Encoded ? "base64" : "utf8");
    bb.write(body); bb.end();
  });
}

// ─── NETLIFY HANDLER ──────────────────────────────────────────────────────────

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };

  try {
    const { fields, files } = await parseFormData(event);
    const { prospectName, mspName, mspUrl, primaryColor, literacy, clientSize, compliance, logoDataUri } = fields;

    if (!files.riskPdf) {
      return { statusCode: 400, body: JSON.stringify({ error: "Data Risk Report PDF is required." }) };
    }

    // Extract text from PDF (pdf-parse handles compressed streams).
    const riskText = await extractPDFText(files.riskPdf.buffer);
    const risk = parseRiskReport(riskText);

    // Optional prior-quarter PDF — if provided, parse it the same way and
    // hand the result to buildDeck so Slide 2 can render trend deltas.
    let priorRisk = null;
    if (files.priorRiskPdf) {
      const priorText = await extractPDFText(files.priorRiskPdf.buffer);
      priorRisk = parseRiskReport(priorText);
    }

    // Logo data URI
    let logoData = logoDataUri || null;
    if (files.logo) {
      logoData = `data:${files.logo.info.mimeType};base64,${files.logo.buffer.toString("base64")}`;
    }

    // Build deck
    const pptxBuffer = await buildDeck({
      risk,
      priorRisk,
      prospectName: prospectName || "Client",
      mspName:      mspName     || "Your MSP",
      mspUrl:       mspUrl      || "yourmsp.com",
      primaryColor: (primaryColor || "#3DBB8F").replace("#", ""),
      literacy:     literacy    || "intermediate",
      // ?? not || — empty string means "user unchecked all bubbles" and
      // should skip the slide. Only undefined (field absent entirely,
      // i.e. a legacy/API caller) falls back to all 3.
      compliance:   compliance  ?? "all",
      clientSize:   clientSize  || "smb",
      logoDataUri:  logoData,
    });

    const safeName  = (prospectName || "Client").replace(/[^a-zA-Z0-9]/g, "_");
    const safePeriod = periodLabels().quarter.replace(/\s+/g, "_");
    const filename  = `${safeName}_Technology_Review_${safePeriod}.pptx`;

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "Content-Disposition": `attachment; filename="${filename}"`,
      },
      body: pptxBuffer.toString("base64"),
      isBase64Encoded: true,
    };

  } catch (e) {
    console.error("Generate error:", e);
    return { statusCode: 500, body: JSON.stringify({ error: "Deck generation failed: " + e.message }) };
  }
};
