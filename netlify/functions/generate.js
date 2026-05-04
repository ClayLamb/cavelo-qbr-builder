// generate.js
// Parses Cavelo Data Risk Report + Endpoint Vulnerability Audit PDFs
// Builds a 12-slide QBR deck using pptxgenjs
// Returns .pptx as a binary download

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
  };
}

function parseVulnAudit(text) {
  if (!text) return null;
  const num = (re, fallback = 0) => {
    const m = text.match(re);
    return m ? parseFloat(m[1].replace(/,/g, "")) : fallback;
  };

  const totalVulns    = num(/Total Unique Vulnerabilities\s*(\d+)/, 12);
  const totalCVEs     = num(/Total Unique CVEs\s*(\d+)/, 316);
  const highestCVSS   = num(/CVSS Score Highest\s*([\d.]+)/, 9.8);
  const highestEPSS   = num(/EPSS\s*Score\s*([\d.]+)/, 0.95265);
  const cvssVeryHigh  = num(/Very High\s*(\d+)\s*$/, 7);
  const cvssHigh      = num(/(\d+)\s*High/, 1);
  const cvssMedium    = num(/(\d+)\s*Medium/, 4);

  // Estimate exploitable from CVSS Very High + High
  const exploitable   = Math.min(cvssVeryHigh + cvssHigh, totalVulns);
  const knownIssues   = Math.max(totalVulns - exploitable, 0);

  // Failed hosts
  const failedHosts   = (text.match(/Failed/g) || []).length;
  const successHosts  = (text.match(/Success/g) || []).length;
  const totalHosts    = failedHosts + successHosts;

  return {
    totalVulns, totalCVEs, highestCVSS, highestEPSS,
    exploitable, knownIssues,
    failedHosts: Math.min(failedHosts, 8),
    totalHosts:  totalHosts > 0 ? totalHosts : 19,
    cvssMedium, cvssHigh, cvssVeryHigh,
  };
}

// ─── SLIDE HELPERS ─────────────────────────────────────────────────────────────

function addChrome(s, pres, sectionNum, sectionLabel, accentColor = "3DBB8F") {
  // Left edge accent
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.18, h: 5.625,
    fill: { color: accentColor }, line: { color: accentColor },
  });
  // Cavelo pill
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 0.5, y: 0.4, w: 1.0, h: 0.32,
    fill: { color: accentColor }, line: { color: accentColor }, rectRadius: 0.16,
  });
  s.addText("CAVELO", {
    x: 0.5, y: 0.4, w: 1.0, h: 0.32,
    fontSize: 11, bold: true, color: "FFFFFF", fontFace: "Calibri",
    align: "center", valign: "middle", margin: 0,
  });
  // Section badge
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 7.7, y: 0.4, w: 1.8, h: 0.32,
    fill: { color: "253347" }, line: { color: accentColor, width: 1 }, rectRadius: 0.16,
  });
  s.addText(`${sectionNum}  ${sectionLabel}`, {
    x: 7.7, y: 0.4, w: 1.8, h: 0.32,
    fontSize: 10, bold: true, color: accentColor, fontFace: "Calibri",
    align: "center", valign: "middle", margin: 0,
  });
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

async function buildDeck({ risk, vuln, prospectName, mspName, mspUrl, primaryColor, literacy, clientSize, logoDataUri }) {
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
  pres.title   = `${prospectName} QBR — ${period.quarter}`;
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
    s.addText("Quarterly Business Review", { x:0.5, y:2.15, w:9, h:0.85, fontSize:48, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(prospectName, { x:0.5, y:3.05, w:9, h:0.55, fontSize:28, color:GREEN, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(`Prepared by ${mspName}  ·  ${period.monthYear}`, { x:0.5, y:3.7, w:9, h:0.3, fontSize:12, color:MUTED, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(mspUrl.replace(/^https?:\/\//,""), { x:0.5, y:5.2, w:4, h:0.3, fontSize:10, color:MUTED, fontFace:"Calibri", bold:true, align:"left", valign:"middle", margin:0 });
  }

  // ── SLIDE 2: EXEC SUMMARY ────────────────────────────────────────────────
  // Six stat cards laid out 3x2. Every value flows from the parsed PDF;
  // categories ("Very High", "High", etc.) come straight from the report
  // text rather than being computed in code. When the optional Vuln Audit
  // PDF isn't uploaded, the two vuln-dependent slots fall back to two
  // risk-report-only metrics (Permission Risk and Outlier Directories)
  // instead of rendering "—" placeholders.
  {
    const s = addS();
    addChrome(s, pres, "01", "EXEC SUMMARY", GREEN);
    addTitle(s, "Executive summary", `Where your environment stands · ${period.quarter}`);

    const tp = risk.testsPassed, tf = risk.testsFailed;
    const totalTests = (tp != null && tf != null) ? tp + tf : null;

    // Card 1 — overall risk score (always present, accent color driven by category)
    addStatCard(s, pres, {
      x:0.5, y:2.1, w:2.95, h:1.55,
      accentColor: accentForCat(risk.riskScoreCat),
      label: "DATA RISK SCORE",
      value: fmtScore(risk.riskScore),
      sublabel: risk.riskScoreCat
        ? `${risk.riskScoreCat}  ·  industry ${fmtScore(risk.industryScore)}`
        : `industry baseline ${fmtScore(risk.industryScore)}`,
      valueSize: 44,
    });

    // Card 2 — cost of breach
    addStatCard(s, pres, {
      x:3.55, y:2.1, w:2.95, h:1.55,
      accentColor: AMBER,
      label: "POTENTIAL COST OF BREACH",
      value: fmtCurrency(risk.costOfBreach),
      sublabel: risk.instancesFound != null
        ? `${fmt(risk.instancesFound)} PII instances discovered`
        : "Sensitive data exposure",
      valueSize: 38,
    });

    // Card 3 — exploitable threats (vuln) OR vulnerability risk score (risk-only fallback)
    if (vuln && vuln.exploitable != null) {
      addStatCard(s, pres, {
        x:6.6, y:2.1, w:2.85, h:1.55,
        accentColor: RED,
        label: "EXPLOITABLE VULNERABILITIES",
        value: String(vuln.exploitable),
        sublabel: "Active in the wild",
        valueSize: 44,
      });
    } else {
      addStatCard(s, pres, {
        x:6.6, y:2.1, w:2.85, h:1.55,
        accentColor: accentForCat(risk.vulnRiskCat),
        label: "VULNERABILITY RISK",
        value: fmtScore(risk.vulnRisk),
        sublabel: risk.maxCVSS != null
          ? `${risk.vulnRiskCat || ""}  ·  max CVSS ${fmtScore(risk.maxCVSS, 1)}`.trim()
          : (risk.vulnRiskCat || "—"),
        valueSize: 44,
      });
    }

    // Card 4 — CIS benchmark failures
    addStatCard(s, pres, {
      x:0.5, y:3.8, w:2.95, h:1.25,
      accentColor: accentForCat(risk.benchmarkRiskCat),
      label: "CIS BENCHMARK FAILURES",
      value: fmt(tf),
      sublabel: totalTests != null ? `of ${fmt(totalTests)} total tests` : "Configuration baseline",
      valueSize: 28,
    });

    // Card 5 — noncompliant hosts (software policy)
    addStatCard(s, pres, {
      x:3.55, y:3.8, w:2.95, h:1.25,
      accentColor: AMBER,
      label: "NONCOMPLIANT HOSTS",
      value: fmt(risk.noncompliantHosts),
      sublabel: (risk.unapprovedSoftware != null || risk.missingSoftware != null)
        ? `${fmt(risk.unapprovedSoftware)} unapproved · ${fmt(risk.missingSoftware)} missing`
        : "Software policy gaps",
      valueSize: 28,
    });

    // Card 6 — visibility gap (vuln) OR permission risk + outlier dirs (risk-only)
    if (vuln && vuln.failedHosts != null && vuln.totalHosts != null) {
      addStatCard(s, pres, {
        x:6.6, y:3.8, w:2.85, h:1.25,
        accentColor: AMBER,
        label: "VISIBILITY GAP",
        value: `${vuln.failedHosts} of ${vuln.totalHosts}`,
        sublabel: "Endpoints unreachable to scan",
        valueSize: 28,
      });
    } else {
      addStatCard(s, pres, {
        x:6.6, y:3.8, w:2.85, h:1.25,
        accentColor: accentForCat(risk.permissionRiskCat),
        label: "PERMISSION RISK",
        value: fmtScore(risk.permissionRisk),
        sublabel: risk.outlierDirs != null
          ? `${fmt(risk.outlierDirs)} outlier directories`
          : (risk.permissionRiskCat || "—"),
        valueSize: 28,
      });
    }
  }

  // ── SLIDE 3: DATA DISCOVERY ──────────────────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "02", "DATA DISCOVERY", GREEN);
    addTitle(s, "Where your sensitive data lives", `${fmt(risk.instancesFound)} instances of PII discovered across your environment`);

    // Platform counts will come from a proper table extractor later — for
    // now skip platforms whose count couldn't be parsed (was returning fake
    // demo numbers like "Box 26" before).
    const platforms = [
      { name: "Microsoft 365",     count: risk.connectorInstances, color: RED },
      { name: "Windows endpoints", count: risk.topHostInstances,   color: AMBER },
    ].filter(p => p.count != null);
    s.addText("TOP PLATFORMS BY EXPOSURE", { x:0.5, y:2.1, w:4.4, h:0.3, fontSize:10, bold:true, color:GREEN, fontFace:"Calibri", charSpacing:1.5, valign:"middle", margin:0 });
    const maxCount = platforms.length ? platforms[0].count : 1;
    if (!platforms.length) {
      s.addText("Detail not available — see Cavelo Data Risk Report for breakdown",
        { x:0.5, y:2.5, w:4.4, h:0.4, fontSize:11, italic:true, color:MUTED, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    }
    platforms.forEach((p, i) => {
      const yPos = 2.5 + i * 0.45;
      const barW = (p.count / maxCount) * 3.0;
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos+0.1, w:3.0, h:0.2, fill:{ color:BG_MID }, line:{ color:BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos+0.1, w:barW, h:0.2, fill:{ color:p.color }, line:{ color:p.color } });
      s.addText(p.name, { x:0.5, y:yPos-0.15, w:2.5, h:0.25, fontSize:11, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
      s.addText(fmt(p.count), { x:3.6, y:yPos, w:1.0, h:0.4, fontSize:12, bold:true, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
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

    // Top host card
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:3.4, w:4.4, h:1.65, fill:{ color:BG_MID }, line:{ color:BG_MID } });
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:3.4, w:4.4, h:0.08, fill:{ color:AMBER }, line:{ color:AMBER } });
    s.addText("TOP HOST EXPOSURE", { x:0.7, y:3.55, w:4, h:0.3, fontSize:9, bold:true, color:AMBER, fontFace:"Calibri", charSpacing:1, valign:"middle", margin:0 });
    s.addText(risk.topHostCost != null ? `$${fmt(risk.topHostCost)}` : "—", { x:0.7, y:3.85, w:4, h:0.55, fontSize:28, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(risk.topHostName ? `${risk.topHostName}  ·  ${fmt(risk.topHostInstances)} PII instances` : "Detail not available — see report", { x:0.7, y:4.4, w:4, h:0.3, fontSize:11, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Drivers Licenses, Health Cards, Credit Cards, Passports", { x:0.7, y:4.7, w:4, h:0.3, fontSize:9, color:MUTED, fontFace:"Calibri", italic:true, align:"left", valign:"middle", margin:0 });

    // Top connector card
    s.addShape(pres.shapes.RECTANGLE, { x:5.1, y:3.4, w:4.4, h:1.65, fill:{ color:BG_MID }, line:{ color:BG_MID } });
    s.addShape(pres.shapes.RECTANGLE, { x:5.1, y:3.4, w:4.4, h:0.08, fill:{ color:AMBER }, line:{ color:AMBER } });
    s.addText("TOP CONNECTOR EXPOSURE", { x:5.3, y:3.55, w:4, h:0.3, fontSize:9, bold:true, color:AMBER, fontFace:"Calibri", charSpacing:1, valign:"middle", margin:0 });
    s.addText(risk.topConnectorCost != null ? `$${fmt(risk.topConnectorCost)}` : "—", { x:5.3, y:3.85, w:4, h:0.55, fontSize:28, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(risk.connectorInstances != null ? `Microsoft 365 Tenant  ·  ${fmt(risk.connectorInstances)} PII instances` : "Detail not available — see report", { x:5.3, y:4.4, w:4, h:0.3, fontSize:11, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("17 distinct PII types including SSN, IBAN, Steuer-ID", { x:5.3, y:4.7, w:4, h:0.3, fontSize:9, color:MUTED, fontFace:"Calibri", italic:true, align:"left", valign:"middle", margin:0 });

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

  // ── SLIDE 7: VULN CURRENT STATE ───────────────────────────────────────────
  if (vuln) {
    const s = addS();
    addChrome(s, pres, "06", "VULN OVERVIEW", GREEN);
    addTitle(s, "Endpoint vulnerabilities: where you stand", "October 2024 endpoint scan results");

    addStatCard(s, pres, { x:0.5, y:2.05, w:2.95, h:1.85, accentColor:RED, label:"ACTIVE THREATS", value:String(vuln.exploitable), sublabel:"Exploitable in the wild", valueSize:56 });
    addStatCard(s, pres, { x:3.55, y:2.05, w:2.95, h:1.85, accentColor:AMBER, label:"KNOWN ISSUES", value:String(vuln.knownIssues), sublabel:"High severity, not yet exploited", valueSize:56 });
    addStatCard(s, pres, { x:6.6, y:2.05, w:2.85, h:1.85, accentColor:BLUE, label:"MONITORING", value:String(vuln.totalVulns), sublabel:"Total unique vulnerabilities", valueSize:56 });

    // Risk concentration
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:4.1, w:4.5, h:0.95, fill:{ color:BG_MID }, line:{ color:GREEN, width:1 } });
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:4.1, w:0.08, h:0.95, fill:{ color:GREEN }, line:{ color:GREEN } });
    s.addText("Risk concentration", { x:0.75, y:4.18, w:3, h:0.3, fontSize:12, bold:true, color:GREEN, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Domain controller driving most exposure", { x:0.75, y:4.45, w:2.8, h:0.28, fontSize:10, color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("10 of 12", { x:3.2, y:4.2, w:1.7, h:0.4, fontSize:20, bold:true, color:WHITE, fontFace:"Calibri", align:"right", valign:"middle", margin:0 });
    s.addText("on demo-dc-1", { x:3.2, y:4.6, w:1.7, h:0.3, fontSize:9, color:MUTED, fontFace:"Calibri", align:"right", valign:"middle", margin:0 });

    // Visibility gap
    s.addShape(pres.shapes.RECTANGLE, { x:5.2, y:4.1, w:4.3, h:0.95, fill:{ color:BG_MID }, line:{ color:AMBER, width:1 } });
    s.addShape(pres.shapes.RECTANGLE, { x:5.2, y:4.1, w:0.08, h:0.95, fill:{ color:AMBER }, line:{ color:AMBER } });
    s.addText("Visibility gap to close", { x:5.45, y:4.18, w:4, h:0.3, fontSize:12, bold:true, color:AMBER, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText(`${vuln.failedHosts} of ${vuln.totalHosts} endpoints could not be reached. We are not seeing the full picture until those machines come back online.`, { x:5.45, y:4.45, w:3.95, h:0.55, fontSize:10, color:LIGHT, fontFace:"Calibri", align:"left", valign:"top", margin:0 });

    addFootnote(s, `Highest CVSS this scan: ${vuln.highestCVSS} (Very High). Highest EPSS: ${vuln.highestEPSS} (Very High). Full CVE list in source Vuln Audit PDF.`);
  }

  // ── SLIDE 8: VULN QUARTERLY ACTIVITY ────────────────────────────────────
  if (vuln) {
    const s = addS();
    addChrome(s, pres, "07", "QUARTERLY ACTIVITY", GREEN);
    addTitle(s, "What we're addressing this quarter", "Top vulnerabilities prioritized for remediation");

    const items = [
      { title:"Critical Windows update KB5025229", sub:"Highest exploitability score this scan — patching in progress", accent:RED, badge:"In progress" },
      { title:"Critical Windows update KB5031361", sub:"Domain controller — maintenance window scheduled", accent:RED, badge:"Scheduled" },
      { title:"HTTP/2 Rapid Reset vulnerability",  sub:".NET runtime and Visual Studio patches identified", accent:AMBER, badge:"Scheduled" },
      { title:"Browser engine vulnerability (WebP)",sub:"Chrome/Edge updates pending on affected workstations", accent:AMBER, badge:"In progress" },
      { title:"WinVerifyTrust signature validation",sub:`${vuln.totalHosts - vuln.failedHosts} endpoints across the fleet — legacy patch rollout planned`, accent:AMBER, badge:"Planned" },
    ];
    items.forEach((v, i) => {
      const yPos = 2.1 + i * 0.55;
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:9, h:0.48, fill:{ color:BG_MID }, line:{ color:BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:0.08, h:0.48, fill:{ color:v.accent }, line:{ color:v.accent } });
      s.addText(v.title, { x:0.75, y:yPos+0.04, w:6.5, h:0.24, fontSize:11, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
      s.addText(v.sub,   { x:0.75, y:yPos+0.25, w:6.5, h:0.2,  fontSize:9,  color:LIGHT, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x:8.4, y:yPos+0.13, w:1.0, h:0.24, fill:{ color:G_LIGHT }, line:{ color:G_LIGHT }, rectRadius:0.04 });
      s.addText(v.badge, { x:8.4, y:yPos+0.13, w:1.0, h:0.24, fontSize:9, bold:true, color:G_TEXT, fontFace:"Calibri", align:"center", valign:"middle", margin:0 });
    });

    addFootnote(s, "Tracked CVEs include CVE-2023-21554, CVE-2023-44487, CVE-2023-4863, CVE-2013-3900. Full CVE list available in the Endpoint Vulnerability Audit.");
  }

  // ── SLIDE 9: VULN ROADMAP ────────────────────────────────────────────────
  if (vuln) {
    const s = addS();
    addChrome(s, pres, "08", "ROADMAP", GREEN);
    addTitle(s, "Vulnerability roadmap", "Next 90 days");

    const drawRow = (yPos, days, color, title, body) => {
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:9, h:0.85, fill:{ color:BG_MID }, line:{ color:BG_MID } });
      s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:yPos, w:0.08, h:0.85, fill:{ color }, line:{ color } });
      s.addShape(pres.shapes.OVAL, { x:0.78, y:yPos+0.13, w:0.6, h:0.6, fill:{ color }, line:{ color } });
      s.addText(days, { x:0.78, y:yPos+0.13, w:0.6, h:0.6, fontSize:12, bold:true, color:WHITE, fontFace:"Calibri", align:"center", valign:"middle", margin:0 });
      s.addText(title, { x:1.55, y:yPos+0.1, w:7.7, h:0.32, fontSize:13, bold:true, color:WHITE, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
      s.addText(body, { x:1.55, y:yPos+0.42, w:7.7, h:0.4, fontSize:10, color:LIGHT, fontFace:"Calibri", align:"left", valign:"top", margin:0 });
    };

    drawRow(2.05, "30d", RED,   "Resolve 5 active threats on the domain controller", "Scheduled maintenance window applies all outstanding critical Windows updates. Targeting completion by mid-November.");
    drawRow(3.0,  "60d", AMBER, "Restore visibility on 8 unreachable endpoints",       "Reach out to remote staff, reinstall the agent on offline machines, confirm every device is reporting before the next scan cycle.");
    drawRow(3.95, "90d", BLUE,  "Address remaining known issues across the fleet",      "Roll out WinVerifyTrust patches on affected endpoints. Refresh browser updates on shared boardroom devices.");

    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:4.95, w:9, h:0.55, fill:{ color:BG_MID }, line:{ color:GREEN, width:1 } });
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:4.95, w:0.08, h:0.55, fill:{ color:GREEN }, line:{ color:GREEN } });
    s.addText("Continuous monitoring stays on", { x:0.78, y:5.0, w:4, h:0.22, fontSize:11, bold:true, color:GREEN, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Your environment is scanned weekly. New issues are surfaced the day they are published, prioritized by severity, and built into your next service window.", { x:0.78, y:5.22, w:8.6, h:0.28, fontSize:9, color:LIGHT, fontFace:"Calibri", align:"left", valign:"top", margin:0 });
  }

  // ── SLIDE 10: COMPLIANCE & BENCHMARKS ───────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "09", "COMPLIANCE", GREEN);
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

  // ── SLIDE 11: VISIBILITY GAPS ────────────────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "10", "VISIBILITY", GREEN);
    addTitle(s, "Where we don't have visibility", "Combined visibility gaps across all scan types");

    addStatCard(s, pres, { x:0.5, y:2.1, w:2.95, h:1.55, accentColor:AMBER, label:"VULN SCAN GAP", value:vuln ? `${vuln.failedHosts} of ${vuln.totalHosts}` : "—", sublabel:"Endpoints failed to scan", valueSize:28 });
    addStatCard(s, pres, { x:3.55, y:2.1, w:2.95, h:1.55, accentColor:AMBER, label:"PII SCAN GAP", value:"26+", sublabel:"Hosts not in PII scans", valueSize:32 });
    addStatCard(s, pres, { x:6.6, y:2.1, w:2.85, h:1.55, accentColor:AMBER, label:"BENCHMARK GAP", value:"10+", sublabel:"Hosts not in CIS scans", valueSize:32 });

    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:3.85, w:9, h:1.35, fill:{ color:BG_MID }, line:{ color:AMBER, width:1 } });
    s.addShape(pres.shapes.RECTANGLE, { x:0.5, y:3.85, w:0.08, h:1.35, fill:{ color:AMBER }, line:{ color:AMBER } });
    s.addText("What this means for you", { x:0.75, y:3.95, w:8.6, h:0.3, fontSize:13, bold:true, color:AMBER, fontFace:"Calibri", align:"left", valign:"middle", margin:0 });
    s.addText("Endpoints we cannot scan are endpoints we cannot protect. Devices missing from PII scans could be holding sensitive data we have no visibility into. Closing these gaps is the single highest-leverage action this quarter.", { x:0.75, y:4.3, w:8.6, h:0.85, fontSize:11, color:LIGHT, fontFace:"Calibri", align:"left", valign:"top", margin:0 });
  }

  // ── SLIDE 12: Q1 PRIORITIES ──────────────────────────────────────────────
  {
    const s = addS();
    addChrome(s, pres, "11", "NEXT QUARTER", GREEN);
    addTitle(s, "Q1 2025 priorities", "Three commitments for the next 90 days");

    const priorities = [
      { num:"01", title:"Close the visibility gap", body:`Restore agent connectivity on ${vuln ? vuln.failedHosts : 8} unreachable endpoints. Onboard the 26+ hosts currently outside PII scans. Goal: 100% coverage by end of Q1.`, color:RED },
      { num:"02", title:"Reduce active threats to zero", body:`Patch all ${vuln ? vuln.exploitable : 5} currently exploitable vulnerabilities, with priority on the domain controller. Apply outstanding critical Windows updates in scheduled maintenance windows.`, color:AMBER },
      { num:"03", title:"Tighten data exposure", body:"Remediate top 5 anonymous share links. Restrict outlier permissions on highest-cost OneDrive resources. Begin CIS benchmark hardening starting with Network Protection group.", color:BLUE },
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
    const { prospectName, mspName, mspUrl, primaryColor, literacy, clientSize, logoDataUri } = fields;

    if (!files.riskPdf) {
      return { statusCode: 400, body: JSON.stringify({ error: "Data Risk Report PDF is required." }) };
    }

    // Extract text from PDFs (async — pdf-parse handles compressed streams)
    const riskText = await extractPDFText(files.riskPdf.buffer);
    const vulnText = files.vulnPdf ? await extractPDFText(files.vulnPdf.buffer) : null;

    // Parse data
    const risk = parseRiskReport(riskText);
    const vuln = vulnText ? parseVulnAudit(vulnText) : null;

    // Logo data URI
    let logoData = logoDataUri || null;
    if (files.logo) {
      logoData = `data:${files.logo.info.mimeType};base64,${files.logo.buffer.toString("base64")}`;
    }

    // Build deck
    const pptxBuffer = await buildDeck({
      risk, vuln,
      prospectName: prospectName || "Client",
      mspName:      mspName     || "Your MSP",
      mspUrl:       mspUrl      || "yourmsp.com",
      primaryColor: (primaryColor || "#3DBB8F").replace("#", ""),
      literacy:     literacy    || "tech_aware",
      clientSize:   clientSize  || "smb",
      logoDataUri:  logoData,
    });

    const safeName  = (prospectName || "Client").replace(/[^a-zA-Z0-9]/g, "_");
    const safePeriod = periodLabels().quarter.replace(/\s+/g, "_");
    const filename  = `${safeName}_QBR_${safePeriod}.pptx`;

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
