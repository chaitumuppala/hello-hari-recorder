# Indian Scam Call Detection

**Real-time, on-device scam detection for phone calls — in 11 Indian languages.**

[![Live Demo](https://img.shields.io/badge/🛡️_Live_Demo-HuggingFace_Spaces-yellow)](https://huggingface.co/spaces/chaitumuppala/indian-scam-detector)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-53_passing-brightgreen)]()
[![Languages](https://img.shields.io/badge/Languages-11-blue)]()
[![Scam Types](https://img.shields.io/badge/Scam_Types-13-red)]()

> **[Try the live demo →](https://huggingface.co/spaces/chaitumuppala/indian-scam-detector)**

<p align="center">
  <img src="docs/images/scam-detected.png" alt="Scam Detected — shield turns red with matched patterns" width="320" />
  &nbsp;&nbsp;&nbsp;
  <img src="docs/images/safe-listening.png" alt="Safe — green shield while listening" width="320" />
</p>

<!--
  📸 Add screenshots to docs/images/:
  - scam-detected.png  → red shield + pattern pills visible
  - safe-listening.png → green shield during safe conversation
  - (optional) debug-panel.png → expanded debug view with pipeline trace
-->

---

## The Problem

India loses an estimated **₹1.25 lakh crore annually** to phone scams. "Digital arrest" fraud, TRAI impersonation, courier threats, OTP theft, fake KYC, electricity disconnection threats — the scripts keep multiplying. The most vulnerable are the elderly, small-town workers, and first-time smartphone users. People have lost life savings. Some have taken their own lives.

Existing defenses — Truecaller, carrier spam filters, TRAI DND — work on **caller reputation**. They know *who* is calling. They fail against fresh SIM cards, VoIP spoofing, and social engineering.

**Nobody is analyzing *what is being said* on the call.**

---

## What This Does

A Progressive Web App that listens to a phone call (via speaker mode) and warns the user **in real time** if the conversation matches known scam patterns.

**No cloud. No uploads. Everything runs on-device.**

| Capability | Detail |
|-----------|--------|
| **Languages** | English, Hindi, Telugu, Tamil, Bengali, Marathi, Gujarati, Kannada, Malayalam, Punjabi, Odia |
| **Scam types** | 13 archetypes — digital arrest, TRAI/telecom, bank/OTP, KYC/Aadhaar, courier/customs, family emergency, tech support, investment/crypto, lottery/prize, insurance, electricity/utility, job/employment, loan/credit |
| **Detection** | 550+ exact-match phrases + keyword co-occurrence engine across 10 Indian scripts |
| **ASR** | Hybrid engine — faster-whisper (English) + AI4Bharat IndicConformer 600M (22 Indian languages) |
| **Privacy** | Local-first. No data leaves the device. User-initiated recording only. |

### Validated Results

| Language | Detection Rate | False Positives |
|----------|---------------|-----------------|
| English | **100%** | 0% |
| Hindi | **100%** | 0% |
| Telugu | **75%** | 0% |
| Tamil, Kannada, Malayalam, Bengali, Marathi, Gujarati, Punjabi, Odia | **95%** | 0% |

> Design philosophy: **Better to be wrong than miss a scam.** False positives are acceptable. False negatives are not.

---

## How It Works

```
User puts suspicious call on speaker
        │
        ▼
Browser captures audio (Web Audio API)
        │
        ▼ WebSocket stream (PCM 16kHz)
        │
Hybrid ASR Engine
├── English → faster-whisper (distil-small.en)
└── Indian langs → IndicConformer 600M (ONNX)
        │
        ▼
3-Layer Scam Detection
├── Layer 1: 550+ exact phrases (9 categories)
├── Layer 2: 13-archetype keyword co-occurrence (10 scripts)
└── Layer 3: Cross-language indicator bonuses
        │
        ▼
Real-time alert: 🛡️ SAFE → ⚠️ SUSPICIOUS → 🚨 SCAM DETECTED
```

The detection engine is ported from [hello-hari](https://github.com/anthropics-ai/hello-hari), a working Android app. The patterns are extracted from real scam call scripts reported by Indian users — not theoretical.

> **Deep dive:** [Detection Engine →](docs/detection-engine.md) · [Architecture →](docs/architecture.md)

---

## Why These Choices

| Decision | Why |
|----------|-----|
| **PWA, not native app** | Zero install. Works on any device with a browser. No app store gatekeeping. Cannot access call audio directly — user must use speaker mode. We frame this as a **privacy feature**: no background listening. |
| **Patterns + co-occurrence, not LLM** | Deterministic, fast, explainable, zero inference cost. Co-occurrence engine scales to new languages without hundreds of exact phrases. LLM planned as a complementary layer in Phase 2. |
| **ASR + text analysis, not audio classification** | Audio classification is the ideal approach — but requires labeled scam call recordings that don't exist publicly. This works now, with what we have. |
| **Local-only, no cloud** | Scam call audio contains sensitive information. Users will not trust a tool that uploads their conversations. |
| **Open source** | Scammers already know their own scripts. Open-sourcing helps defenders (community pattern updates) more than attackers. Detection uses keyword co-occurrence across 3 dimensions — changing a few words doesn't evade it. |

---

## The Vision

This is not the final product. It proves that **on-device, multilingual scam detection is feasible** — to open conversations with:

- **Government** (CERT-In, I4C, state cyber cells) — who have labeled scam call data for building audio classifiers
- **Telecoms** (Jio, Airtel, BSNL, Vi) — who can integrate detection at the network level
- **Researchers** (IITs, IIITs, ISI) — who can build better models with more data
- **Platforms** (Google, Apple) — who can expose call audio APIs for protection use cases

```
Phase 1 (NOW)    On-device ASR + pattern matching + co-occurrence
                 550+ patterns · 13 archetypes · 11 languages
                 Zero infrastructure · Zero cost · Zero data risk

Phase 2          Add on-device LLM (Phi-3-mini / Gemma-2B)
                 Catch paraphrased + novel scripts
                 Community pattern database

Phase 3          Audio classification model
                 Train on real scam data from partners
                 Language-agnostic · Sub-second · No ASR needed

Phase 4          Telecom integration
                 Detection at the carrier level
                 Before the call reaches the user
```

> **Full roadmap:** [Roadmap →](docs/roadmap.md)

---

## Get Started

```bash
# Backend (WSL2 / Linux)
cd backend && python3 -m venv venv-wsl && source venv-wsl/bin/activate
pip install -r requirements.txt
SCAM_ASR_ENGINE=hybrid SCAM_WHISPER_MODEL=distil-small.en \
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frontend && npm install && npm run dev

# Open http://localhost:5173
```

Or with Docker:

```bash
docker compose up --build    # → http://localhost:7860
```

> **Full setup guide:** [Setup →](docs/setup.md)

---

## Contribute

The most impactful contribution is **scam patterns**. If you've received a scam call in any Indian language, the exact phrases and keywords are valuable.

| What | How |
|------|-----|
| **Add patterns** | PR to `backend/app/detection/scam_detector.py` or `scam_archetypes.py` |
| **New archetype** | Add to `SCAM_ARCHETYPES` with context/threat/demand keywords |
| **Audio samples** | Scam call recordings (with consent) for future audio classifier training |
| **Test & report** | Run against real scam scripts, report catches vs. misses |

> **Contributor guide:** [Contributing →](docs/contributing.md)

---

## Documentation

| Document | Description |
|----------|-------------|
| [Detection Engine](docs/detection-engine.md) | 3-layer detection architecture, 13 archetypes, pattern categories, scoring |
| [Architecture](docs/architecture.md) | System design, hybrid ASR, WebSocket pipeline, tech stack, project structure |
| [Setup](docs/setup.md) | Local dev, Docker, environment variables, prerequisites |
| [Contributing](docs/contributing.md) | How to add patterns, archetypes, tests |
| [Roadmap](docs/roadmap.md) | Phase 2-4 vision, known limitations, alternative approaches, partnership asks |

---

## License

MIT — see [LICENSE](LICENSE).

---

**Built to protect. No data leaves your device.**