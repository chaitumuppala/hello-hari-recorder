"""Smoke test: narrative state machine across scam types + legitimate calls."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.detection.scam_detector import analyze_text
from app.detection.narrative_tracker import NarrativeTracker

scenarios = {
    "Digital Arrest": [
        "hello sir this is from cbi headquarters",
        "arrest warrant has been issued drug trafficking case",
        "do not inform anyone this is confidential",
        "transfer 50000 as security deposit immediately",
    ],
    "Bank OTP": [
        "calling from sbi bank regarding your account",
        "account has been compromised unauthorized transaction detected",
        "for verification share your card number",
        "give me the otp that you received share your cvv",
    ],
    "Family Emergency": [
        "hello beta i am in serious trouble",
        "accident hua hai hospital mein admit hai",
        "dont tell mom dad about this",
        "turant paisa chahiye send money immediately",
    ],
    "TRAI Scam": [
        "main trai se bol raha hun",
        "sim card band hone wala hai 22 complaints",
        "kisi ko mat batana confidential matter",
        "press 1 to avoid disconnection recharge karo",
    ],
    "Courier Scam": [
        "we are calling from fedex mumbai about your parcel",
        "drugs found in your package narcotic substances detected",
        "do not tell anyone keep this confidential",
        "pay customs clearance fee immediately transfer money",
    ],
    "Investment Fraud": [
        "congratulations you have been selected for exclusive offer",
        "guaranteed 10x returns limited time crypto investment",
        "only 100 slots remaining offer expires tonight",
        "pay processing fee to claim prize send money now",
    ],
    "Legit: Bank Call": [
        "hello this is customer care how can I help",
        "let me look up your account information",
        "your new card will be sent to your address",
        "thank you for calling have a good day",
    ],
    "Legit: Friend": [
        "hey how are you long time no see",
        "we should meet for coffee this weekend",
        "I will send you the address on whatsapp",
        "take care bye see you saturday",
    ],
    "Legit: Doctor": [
        "hello this is doctor sharma from apollo hospital",
        "your test reports are ready everything looks normal",
        "please continue the medication for two more weeks",
        "come for follow up next month take care",
    ],
}

print()
header = f"{'Scenario':<20} {'Final Phase':<10} {'PhScore':<8} {'Risk':<6} {'Scam':<5} {'Archetype':<20}"
print(header)
print("-" * len(header))

for name, chunks in scenarios.items():
    tracker = NarrativeTracker()
    for chunk in chunks:
        result = analyze_text(chunk)
        narrative = tracker.advance(chunk)
    phase = narrative.best_phase
    print(f"{name:<20} {phase:<10} {narrative.phase_score:<8} {result.risk_score:<6.2f} {str(result.is_scam):<5} {str(narrative.best_archetype):<20}")

print()
print("--- Per-chunk detail for Digital Arrest ---")
tracker = NarrativeTracker()
for i, chunk in enumerate(scenarios["Digital Arrest"], 1):
    result = analyze_text(chunk)
    narrative = tracker.advance(chunk)
    print(f"  Chunk {i}: {narrative.best_phase:<10} score={narrative.phase_score:3d}  risk={result.risk_score:.2f}  text={chunk[:55]}")
