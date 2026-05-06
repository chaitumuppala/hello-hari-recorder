"""OSIF Detect — Multilingual scam call detection SDK.

Detects phone scams across 12+ Indian languages using:
1. Exact phrase matching (574+ patterns, 9 categories)
2. Archetype co-occurrence engine (13 archetypes × 10 scripts)
3. Narrative state machine (HOOK → ESCALATE → ISOLATE → TRAP)
4. Behavioral indicator bonuses (urgency, authority, secrecy, etc.)

Usage:
    from osif_detect import ScamDetector

    detector = ScamDetector.from_json("patterns.json")
    result = detector.analyze("your account has been blocked share your OTP")
    print(result.is_scam, result.risk_score, result.narrative_phase)

    # Session mode (streaming chunks):
    session = detector.create_session()
    for chunk in transcript_chunks:
        result = session.analyze_chunk(chunk)
        print(result.narrative_phase)  # HOOK → ESCALATE → ISOLATE → TRAP
"""

from osif_detect.detector import ScamDetector, DetectionResult, DetectionSession

__version__ = "0.1.0"
__all__ = ["ScamDetector", "DetectionResult", "DetectionSession"]
