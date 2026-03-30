# Detection Engine

The scam detection engine uses a **3-layer architecture** to maximize recall across languages while minimizing false positives. Each layer is additive — scores accumulate, capped at 100.

---

## Layer 1: Exact Phrase Matching

**550+ hand-crafted phrases** across 9 categories, extracted from real scam call scripts reported by Indian users. Originally developed for the [hello-hari](https://github.com/anthropics-ai/hello-hari) Android app.

Each phrase carries a weighted score (20-100 points). When multiple phrases from the same category match, a 10% compounding boost is applied per additional hit.

### Categories

| Category | Patterns | Score Range | Languages | Example Phrases |
|----------|----------|-------------|-----------|-----------------|
| **Digital Arrest** | ~45 | 90-100 | EN, HI, TE | "you are under digital arrest", "warrant issued against you", "CBI officer speaking" |
| **TRAI / Telecom** | ~20 | 75-90 | EN, HI | "TRAI se bol raha hun", "SIM will be disconnected in 2 hours" |
| **Courier / Customs** | ~28 | 75-90 | EN, HI | "FedEx parcel seized", "drugs found in your package" |
| **Investment Fraud** | ~30 | 62-85 | EN, HI, TE | "guaranteed 10x returns", "crypto trading opportunity" |
| **Bank / OTP** | ~85 | 20-90 | EN, HI, TE + 8 scripts | "share your OTP", "account will be blocked", "KYC expired" |
| **Family Emergency** | ~26 | 75-95 | EN, HI | "your son has been arrested", "surgery money needed urgently" |
| **Hindi Advanced** | ~120 | 72-95 | HI (Devanagari + romanized) | "collector sahab ka order", "court hazir hona padega" |
| **Telugu Advanced** | ~50 | 65-90 | TE (script + romanized) | "మీ ఖాతా మూసివేయబడుతుంది", "warrant vachindi mee meeda" |
| **Hinglish** | ~50 | 70-95 | HI+EN code-switched | "aapka computer infected hai", "OTP share karo" |

### How Matching Works

```python
text = input.lower()
for phrase, points in patterns.items():
    if phrase in text:
        score += points
        # 10% boost per additional hit in same category
```

Matching is **case-insensitive substring search**. This is deliberately simple — deterministic, fast, and explainable. The trade-off (no fuzzy matching) is mitigated by Layer 2.

---

## Layer 2: Multi-Archetype Keyword Co-occurrence

**13 scam archetypes**, each defined by three keyword groups: **context**, **threat**, and **demand**. Each group contains keywords in **11 languages** (English + 10 Indian scripts). When words from 2 or more groups appear in the same text, the archetype fires.

This is the scalable layer. Adding a new language requires ~30 keywords per archetype, not 500+ exact phrases.

### Archetypes

| Archetype | Context | Threat | Demand |
|-----------|---------|--------|--------|
| **Bank / OTP** | bank, account, UPI, SBI, HDFC | blocked, suspended, frozen, unauthorized | OTP, PIN, transfer, verify |
| **Digital Arrest** | CBI, police, court, crime branch | arrest, warrant, jail, custody | fine, penalty, pay, settle |
| **TRAI / Telecom** | TRAI, SIM, mobile number, telecom | disconnect, cancel, suspend, deactivate | press 1, Aadhaar, verify, reactivate |
| **KYC / Aadhaar** | KYC, Aadhaar, PAN card, identity | expired, closed, deactivated, invalid | update, link, verify, submit |
| **Family Emergency** | son, daughter, family member, relative | accident, hospital, arrested, critical | money, transfer, urgently, immediately |
| **Tech Support** | computer, virus, Windows, software | infected, hacked, compromised, malware | TeamViewer, AnyDesk, remote access, install |
| **Courier / Customs** | parcel, FedEx, courier, customs, DHL | drugs, seized, illegal, contraband | fine, fee, clearance, pay |
| **Investment / Crypto** | stock market, crypto, trading, Bitcoin | loss, crash, opportunity, momentum | invest, deposit, guaranteed returns, transfer |
| **Lottery / Prize** | lottery, prize, winner, congratulations | tax, claim, expires, forfeited | fee, processing charge, bank details |
| **Insurance / Policy** | insurance, policy, LIC, premium | expired, lapsed, cancelled, void | premium, renewal, pay, bonus |
| **Electricity / Utility** | electricity, bill, meter, power | overdue, disconnect, 2 hours, penalty | pay now, app, link, online |
| **Job / Employment** | job, government, vacancy, selection | last date, limited seats, selected | registration fee, deposit, processing |
| **Loan / Credit** | loan, credit, pre-approved, EMI | rejected, CIBIL score, overdue | processing fee, advance, transfer |

### Scoring

| Match | Score | Reasoning |
|-------|-------|-----------|
| Context + Threat | 70% | Scam framing without explicit demand — could still be a warning |
| Context + Demand | 75% | Suspicious request in a scam context |
| Threat + Demand | 80% | Threat + action request — high confidence |
| Context + Threat + Demand | 95% | Full scam script — near certain |

### Keyword Matching

Keywords are matched with a **4-character minimum guard** to prevent short-word false positives. For keywords ≥ 4 characters, stemmed matching (substring containment) is used. For shorter keywords (OTP, PIN, SIM), exact word boundary matching is applied.

```python
def _match_keywords(text: str, keywords: set[str]) -> int:
    for kw in keywords:
        if len(kw) >= 4:
            if kw in text:  # stemmed containment
                hits += 1
        else:
            # exact word boundary for short keywords
            if re.search(rf'\b{re.escape(kw)}\b', text, re.IGNORECASE):
                hits += 1
```

### Languages

All 13 archetypes include keywords in:

| Script | Languages |
|--------|-----------|
| Devanagari | Hindi, Marathi |
| Telugu | Telugu |
| Tamil | Tamil |
| Bengali | Bengali |
| Gujarati | Gujarati |
| Kannada | Kannada |
| Malayalam | Malayalam |
| Gurmukhi | Punjabi |
| Odia | Odia |
| Latin | English, romanized Hindi/Telugu |

---

## Layer 3: Cross-language Indicator Bonuses

One-time score additions when specific indicator categories are detected anywhere in the text. These are language-agnostic boosters that reinforce the pattern/archetype scores.

| Indicator | Bonus | Keywords (sample) |
|-----------|-------|-------------------|
| **Urgency** | +15 | "immediately", "turant", "jaldi", "abhi", "तुरंत" |
| **Authority** | +20 | "police", "CBI", "court", "collector", "पुलिस", "కోర్ట్" |
| **Financial** | +25 | "OTP", "CVV", "UPI pin", "bank details", "खाता" |
| **Tech Support** | +12 | "TeamViewer", "AnyDesk", "virus detected", "remote access" |

---

## Real-time Pipeline

```
Audio chunk (5s PCM 16kHz)
        │
        ▼
   ASR transcription
        │
        ▼
   analyze_text()
   ├── Check all 9 pattern categories (Layer 1)
   ├── Check all 13 archetypes (Layer 2)
   ├── Check all 4 indicator groups (Layer 3)
   └── Sum scores, cap at 100
        │
        ▼
   WebSocket pipeline
   ├── Per-chunk score (this 5s)
   ├── Sliding window score (last 30s = 6 chunks)
   └── Session max score (sticky once ≥ 60%)
        │
        ▼
   Return highest of the three
```

### Sliding Window

The WebSocket handler maintains a **6-chunk sliding window** (30 seconds of context). Each new chunk is analyzed individually AND concatenated with the previous 5 chunks for a window-level analysis. This catches scam scripts that build context over time — e.g., "I'm calling from your bank" in chunk 1, "share your OTP" in chunk 4.

### Sticky Session Maximum

Once the session max score reaches **≥ 0.6 (60%)**, it never drops. Even if subsequent chunks are safe, the system remembers that a scam was detected. This prevents scammers from diluting detection by switching to benign conversation after the threat/demand phase.

---

## Adding New Detection

### New exact phrase

Add to the appropriate `*_PATTERNS` dict in `scam_detector.py`:

```python
DIGITAL_ARREST_PATTERNS["new scam phrase here"] = 85  # score 0-100
```

### New archetype

Add to `SCAM_ARCHETYPES` list in `scam_archetypes.py`:

```python
(
    "new_archetype_name",
    {"context_kw_1", "context_kw_2", ...},   # context keywords
    {"threat_kw_1", "threat_kw_2", ...},      # threat keywords
    {"demand_kw_1", "demand_kw_2", ...},      # demand keywords
),
```

Add keywords in as many Indian scripts as possible. Add a label in `ARCHETYPE_LABELS`.

### New language

Add keywords to each archetype's context/threat/demand sets in `scam_archetypes.py`. No code changes needed — the matching engine handles all Unicode scripts.
