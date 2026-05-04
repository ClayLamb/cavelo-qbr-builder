# Cavelo QBR Deck Builder

Upload a Cavelo **Data Risk Report** PDF (required) and **Endpoint Vulnerability Audit** PDF (optional) — get a client-ready branded PowerPoint QBR deck in seconds.

Same architecture as [flash-deck-builder](https://github.com/ClayLamb/flash-deck-builder).

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/ClayLamb/cavelo-qbr-builder
cd cavelo-qbr-builder
npm install
```

### 2. Set environment variable

In Netlify → Site settings → Environment variables, add:

```
SITE_PASSWORD = your-access-code-here
```

For local dev, create `.env` in root:
```
SITE_PASSWORD=your-access-code-here
```

### 3. Deploy to Netlify

Connect the repo in Netlify:
- **Build command:** *(leave blank)*
- **Publish directory:** `.`
- **Functions directory:** `netlify/functions`

Or use Netlify CLI:
```bash
npm run dev    # local dev
```

---

## How it works

1. MSP logs in with access code
2. Saves their brand profile (logo, colors, contact info)
3. Uploads Cavelo PDF reports + enters client name + selects audience profile
4. Netlify function parses both PDFs, extracts key metrics, builds a 12-slide QBR deck
5. PowerPoint downloads instantly — nothing stored

---

## Deck structure (12 slides)

| # | Slide | Source |
|---|-------|--------|
| 01 | Cover | Form inputs |
| 02 | Executive Summary | Both reports |
| 03 | Data Discovery | Risk Report |
| 04 | Cost of Breach | Risk Report |
| 05 | Permission Risk | Risk Report |
| 06 | Software Compliance | Risk Report |
| 07 | Vuln Current State | Vuln Audit |
| 08 | Vuln Quarterly Activity | Vuln Audit |
| 09 | Vuln Roadmap | Vuln Audit |
| 10 | CIS Benchmarks | Risk Report |
| 11 | Visibility Gaps | Both reports |
| 12 | Q1 Priorities | Both reports |

Slides 07–09 are skipped automatically if no Vuln Audit PDF is uploaded (9-slide deck).

---

## Persona mapping

| Literacy selected | CVE visibility | Language |
|---|---|---|
| Non-technical | None | Plain English only |
| Business | None | Business framing |
| Tech-aware | Footnotes only | KB names + action framing |
| Technical | Visible | Full technical detail |
| Deep technical | Visible | Full CVSS/EPSS/CVE inline |

> **Note:** Full literacy-based rendering is v2. Current build uses the Tech-Aware template for all personas — persona field is captured and stored for the next iteration.
