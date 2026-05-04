# Cavelo QBR Deck Builder

Upload a Cavelo **Data Risk Report** PDF — get a client-ready branded PowerPoint QBR deck in seconds.

Same architecture as [flash-deck-builder](https://github.com/ClayLamb/flash-deck-builder).

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/ClayLamb/cavelo-qbr-builder
cd cavelo-qbr-builder
npm install
```

### 2. Deploy to Netlify

Connect the repo in Netlify:
- **Build command:** *(leave blank)*
- **Publish directory:** `.`
- **Functions directory:** `netlify/functions`

No environment variables required — the site is open by default. If you want a password gate, enable Netlify's site-level **Visitor access → Password protection** in the dashboard.

Or use Netlify CLI for local dev:
```bash
npm run dev
```

---

## How it works

1. MSP saves their brand profile (logo, colors, contact info)
2. Uploads a Cavelo Data Risk Report PDF + enters client name + selects audience profile
3. Netlify function parses the PDF, extracts key metrics, builds a 10-slide QBR deck
4. PowerPoint downloads instantly — nothing stored

---

## Deck structure (10 slides)

| # | Slide | Source |
|---|-------|--------|
| 01 | Cover | Form inputs + current quarter (auto) |
| 02 | Executive Summary | Risk Report — 6 stat cards |
| 03 | Data Discovery | Risk Report — top at-risk connectors |
| 04 | Cost of Breach | Risk Report — total + top exposure |
| 05 | Permission Risk | Risk Report |
| 06 | Software Compliance | Risk Report |
| 07 | Vulnerability Posture | Risk Report (Vulnerability Summary section) |
| 08 | CIS Benchmarks | Risk Report |
| 09 | Visibility Gaps | Risk Report |
| 10 | Next-Quarter Priorities | Risk Report |

All slides build from the same single PDF. Severity categories ("Very High", "High", "Moderate", "Low") are pulled from the report directly — they aren't classified by code, so card accent colors match Cavelo's own classification.

---

## Persona mapping

| Literacy selected | Language framing |
|---|---|
| Non-technical | Plain English only |
| Business | Business framing |
| Tech-aware | KB names + action framing |
| Technical | Full technical detail |
| Deep technical | Full CVSS/EPSS/CVE inline |

> **Note:** Full literacy-based rendering is v2. Current build uses the Tech-Aware template for all personas — the persona field is captured and stored for the next iteration.
