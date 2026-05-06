# OSIF Detect — Multilingual Scam Call Detection SDK

Real-time phone scam detection across 12+ Indian languages.

## Quick Start

```python
from osif_detect import ScamDetector

# Load the intelligence file
detector = ScamDetector.from_json("patterns.json")

# Single-shot analysis
result = detector.analyze("this is from CBI, arrest warrant has been issued, transfer money immediately")
print(result.is_scam)       # True
print(result.risk_score)    # 0.95
print(result.explanation)   # "SCAM DETECTED (95%): Digital arrest / authority impersonation scam"

# Streaming session with narrative phase tracking
session = detector.create_session()
result1 = session.analyze_chunk("this is inspector sharma from cyber crime cell")
print(result1.narrative_phase)  # "HOOK"

result2 = session.analyze_chunk("drug trafficking case registered against you, arrest warrant issued")
print(result2.narrative_phase)  # "ESCALATE"

result3 = session.analyze_chunk("do not tell anyone about this, keep this confidential")
print(result3.narrative_phase)  # "ISOLATE"

result4 = session.analyze_chunk("transfer 50000 rupees as security deposit immediately")
print(result4.narrative_phase)  # "TRAP"
print(result4.is_scam)          # True
```

## Features

- 574+ scam phrases across 9 categories
- 13 archetype models with context/threat/demand triplets in 12 Indian scripts
- Narrative state machine: HOOK → ESCALATE → ISOLATE → TRAP
- 5 behavioral indicators (urgency, authority, financial risk, tech support, secrecy)
- Zero dependencies — loads from a single JSON file
- Works offline, on-device, no cloud required

## Install

```bash
pip install git+https://github.com/hello-hari/osif-detect.git
```

Or copy `osif_detect/` folder + `patterns.json` into your project.
