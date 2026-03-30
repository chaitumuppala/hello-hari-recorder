# Contributing

The most impactful contributions are **scam patterns and keywords**. If you've received a scam call in any Indian language, the exact phrases used are valuable data.

---

## Add Exact Phrases (Layer 1)

File: `backend/app/detection/scam_detector.py`

Find the appropriate `*_PATTERNS` dictionary and add your phrase:

```python
# Example: adding to DIGITAL_ARREST_PATTERNS
"new scam phrase exactly as spoken": 85,  # score 0-100
```

**Guidelines:**
- Use lowercase
- Score range: 20 (weak indicator) to 100 (certain scam)
- Prefer phrases that are **unique to scam calls** — avoid common phrases that appear in legitimate conversations
- Include the language/script context in a code comment if adding non-English phrases

---

## Add Keywords to Archetypes (Layer 2)

File: `backend/app/detection/scam_archetypes.py`

Each archetype has three keyword sets: context, threat, demand. Add keywords to the appropriate set:

```python
# In the archetype tuple:
(
    "bank_otp",
    {"bank", "account", "your_new_context_word", ...},   # context
    {"blocked", "suspended", "your_new_threat_word", ...}, # threat
    {"OTP", "transfer", "your_new_demand_word", ...},      # demand
),
```

**Adding a new language script:**

Add keywords in the target script to each archetype's keyword sets. Example for adding Assamese:

```python
# Add Assamese equivalents to each set
"বেংক",        # bank (Assamese)
"একাউণ্ট",     # account (Assamese)
```

No code changes needed — the matching engine handles all Unicode scripts automatically.

---

## Add a New Archetype

If you've identified a scam type not covered by the existing 13:

1. Add to `SCAM_ARCHETYPES` list in `scam_archetypes.py`:

```python
(
    "your_archetype_name",
    {"context_keyword_1", "context_keyword_2", ...},
    {"threat_keyword_1", "threat_keyword_2", ...},
    {"demand_keyword_1", "demand_keyword_2", ...},
),
```

2. Add a label to `ARCHETYPE_LABELS`:

```python
"your_archetype_name": "Human-readable description of the scam type",
```

3. Add keywords in as many Indian scripts as possible

4. Add a test in `backend/tests/test_scam_detector.py`:

```python
def test_your_archetype_detection(self):
    result = analyze_text("sample text with context threat and demand keywords")
    self.assertGreaterEqual(result["risk_score"], 0.6)
```

---

## Add Tests

File: `backend/tests/test_scam_detector.py`

```bash
# Run all tests
cd backend
source venv-wsl/bin/activate
pytest tests/test_scam_detector.py -v
```

Test classes:
- `TestScamDetector` — exact phrase detection tests
- `TestArchetypeRegistry` — archetype structure validation
- `TestArchetypeDetection` — co-occurrence detection per archetype
- `TestEndToEndArchetypes` — full pipeline integration

---

## Audio Samples

If you have recordings of scam calls (with consent), these are critical for:
- Validating ASR transcription accuracy per language
- Building future audio classification models
- Testing end-to-end detection pipeline

Contact the maintainers to discuss how to share them securely.

---

## Code Contributions

### Dev Setup

See [Setup Guide](setup.md) for local development instructions.

### Code Style

- Python: Standard library conventions, type hints where helpful
- TypeScript: React 19 functional components, hooks
- No linter/formatter enforced yet — match existing code style

### PR Process

1. Fork the repo
2. Create a feature branch
3. Add/modify code + tests
4. Run `pytest tests/ -v` to ensure all tests pass
5. Open a PR with a description of what you changed and why
