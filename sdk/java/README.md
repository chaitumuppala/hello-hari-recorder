# OSIF Detect — Java SDK

Standalone Java scam detection library for Android and server-side applications.

## Quick Start

```java
// Load from OSIF v2 JSON
InputStream is = context.getAssets().open("patterns.json");
ScamPatternEngine engine = ScamPatternEngine.load(is);

// Single-shot detection
ScamPatternEngine.Result result = engine.analyze("your account has been blocked share OTP");
System.out.println(result.isScam());      // true
System.out.println(result.getRiskScore()); // 85

// Session mode with narrative tracking
NarrativeTracker tracker = new NarrativeTracker();
tracker.loadFromJson(patternsJsonObject);

NarrativeTracker.NarrativeResult nr1 = tracker.advance("this is inspector sharma from cbi");
// nr1.phase = "HOOK"

NarrativeTracker.NarrativeResult nr2 = tracker.advance("drug trafficking case registered");
// nr2.phase = "ESCALATE"

NarrativeTracker.NarrativeResult nr3 = tracker.advance("don't tell anyone about this call");
// nr3.phase = "ISOLATE"

NarrativeTracker.NarrativeResult nr4 = tracker.advance("transfer 50000 as security deposit");
// nr4.phase = "TRAP"
```

## Files

- `ScamPatternEngine.java` — Full detection engine (extracted from hello-hari Android app)
- `NarrativeTracker.java` — Narrative state machine for phase tracking

## Integration

Copy both Java files into your Android project or Java backend. Load `patterns.json` (OSIF v2 format).

No external dependencies beyond `org.json` (included in Android SDK).
