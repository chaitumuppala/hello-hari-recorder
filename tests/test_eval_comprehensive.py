"""Comprehensive evaluation of narrative state machine + detection engine.

Tests:
  1. Realistic scam transcripts (longer, messier, code-switched)
  2. Hindi-only and Telugu-only scam calls
  3. Partial/incomplete scam calls (caller hangs up mid-arc)
  4. Cross-archetype accuracy (courier vs digital arrest vs TRAI)
  5. False positive stress test (12 types of legitimate calls)
  6. Edge cases (very short, empty, repetitive)
  7. Early detection — at which chunk does is_scam first trigger?

Three layers tested:
  - STATELESS: analyze_text() per chunk (keyword matching only)
  - SESSION:   analyze_session() with NarrativeTracker (+ narrative gating)
  - SESSION+ML: analyze_session() with NarrativeTracker + ScamClassifier
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.detection.scam_detector import analyze_text, analyze_session
from app.detection.narrative_tracker import NarrativeTracker
from app.detection.classifier import ScamClassifier

# Load trained classifier
_MODEL_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'backend', 'app', 'detection',
    'models', 'scam_classifier.joblib'
)
_classifier = ScamClassifier.load(_MODEL_PATH) if os.path.exists(_MODEL_PATH) else None


def run_scenario(name, chunks, expected_scam=None, expected_archetype=None):
    """Run a scenario in stateless, session, and session+ML modes."""
    # --- STATELESS MODE (per-chunk analyze_text) ---
    tracker = NarrativeTracker()
    stateless_scam = False
    first_scam_chunk = None
    for i, chunk in enumerate(chunks, 1):
        r = analyze_text(chunk)
        n = tracker.advance(chunk)
        if r.is_scam:
            stateless_scam = True
            if first_scam_chunk is None:
                first_scam_chunk = i

    stateless_final_risk = r.risk_score
    stateless_final_scam = stateless_scam  # any chunk flagged

    # --- SESSION MODE (narrative gating, no classifier) ---
    session_tracker = NarrativeTracker()
    session_result = analyze_session(chunks, session_tracker)
    session_narrative = session_tracker.get_state()
    session_scam = session_result.is_scam

    # --- SESSION+ML MODE (narrative gating + classifier) ---
    ml_tracker = NarrativeTracker()
    ml_result = analyze_session(chunks, ml_tracker, classifier=_classifier)
    ml_narrative = ml_tracker.get_state()
    ml_scam = ml_result.is_scam

    # Primary evaluation: SESSION+ML mode (the full pipeline)
    passed = True
    fail_reasons = []
    if expected_scam is not None and ml_scam != expected_scam:
        passed = False
        fail_reasons.append(f"expected scam={expected_scam}, got {ml_scam}")
    if expected_archetype and ml_narrative.best_archetype != expected_archetype:
        fail_reasons.append(f"archetype={ml_narrative.best_archetype} (expected {expected_archetype})")

    return {
        "name": name,
        # Session+ML mode results (primary)
        "final_phase": ml_narrative.best_phase,
        "final_score": ml_narrative.phase_score,
        "final_risk": ml_result.risk_score,
        "final_scam": ml_scam,
        "archetype": ml_narrative.best_archetype,
        # Session-only results (comparison)
        "session_scam": session_scam,
        "session_risk": session_result.risk_score,
        # Stateless mode results (comparison)
        "stateless_risk": stateless_final_risk,
        "stateless_scam": stateless_scam,
        # Meta
        "first_scam_chunk": first_scam_chunk,
        "total_chunks": len(chunks),
        "passed": passed,
        "fail_reasons": fail_reasons,
    }


# ===================================================================
# 1. REALISTIC SCAM TRANSCRIPTS (longer, messier, code-switched)
# ===================================================================
REALISTIC_SCAMS = {
    "Digital Arrest (realistic)": {
        "chunks": [
            "hello hello sir can you hear me this is officer verma calling from cyber crime cell mumbai",
            "sir we have received a very serious complaint against your aadhaar number someone has used your identity for illegal activities",
            "a case has been registered under section 420 and your arrest warrant has been issued by the magistrate court",
            "sir this is a very sensitive matter please do not disconnect the call and do not inform anyone about this investigation",
            "you need to cooperate with us for immediate verification transfer the security deposit of rupees 50000 to this account",
        ],
        "expected_scam": True,
        "expected_archetype": "digital_arrest",
    },
    "Bank OTP (realistic Hinglish)": {
        "chunks": [
            "hello sir main hdfc bank se bol raha hun aapke account mein ek suspicious transaction detect hua hai",
            "sir aapka account temporarily block ho gaya hai security reasons ki wajah se",
            "sir abhi ke abhi aapko verify karna hoga nahi toh account permanently deactivate ho jayega",
            "sir please aap mujhe apna 16 digit card number bataiye aur jo otp aayega wo share kariye",
        ],
        "expected_scam": True,
        "expected_archetype": "bank_otp",
    },
    "Courier Scam (realistic)": {
        "chunks": [
            "good afternoon this call is from fedex international logistics department regarding a parcel in your name",
            "sir your package has been intercepted at mumbai customs 140 grams of narcotic drugs found inside",
            "we are transferring your call to narcotics control bureau officer for further investigation do not disconnect",
            "sir this is ncb officer speaking you will be arrested unless you pay the settlement amount immediately",
        ],
        "expected_scam": True,
        "expected_archetype": "digital_arrest",  # typically escalates to digital arrest
    },
    "Investment Fraud (WhatsApp group)": {
        "chunks": [
            "congratulations you have been selected for our exclusive vip trading group guaranteed returns",
            "see screenshots of members profits everyone is making 10x returns in just 30 days risk free",
            "only 100 slots remaining this offer expires tonight you will miss out on this opportunity",
            "pay the registration fee of 5000 rupees to start investing send money to this account now",
        ],
        "expected_scam": True,
        "expected_archetype": "investment_crypto",
    },
    "Family Emergency (voice clone)": {
        "chunks": [
            "hello beta main bol raha hun please sun meri baat",
            "mera accident ho gaya hai hospital mein admit hai surgery ki zarurat hai",
            "kisi ko mat batana especially mom ko mat bolo woh tension mein aa jayegi",
            "turant paisa chahiye 2 lakh bhejo is account mein abhi ke abhi please jaldi karo",
        ],
        "expected_scam": True,
        "expected_archetype": "family_emergency",
    },
    "TRAI SIM Scam (IVR style)": {
        "chunks": [
            "this is an automated message from telecom regulatory authority of india your mobile number has been flagged",
            "22 complaints filed against your mobile sim for illegal usage your number will be disconnected in 2 hours",
            "press 1 to speak with our officer or your sim card will be permanently deactivated",
            "sir you need to pay the compliance fee and update your kyc immediately to avoid disconnection",
        ],
        "expected_scam": True,
        "expected_archetype": "trai_telecom",
    },
}

# ===================================================================
# 2. HINDI-ONLY AND TELUGU-ONLY SCAM CALLS
# ===================================================================
NATIVE_LANGUAGE_SCAMS = {
    "Hindi Digital Arrest": {
        "chunks": [
            "नमस्ते मैं सीबीआई से बोल रहा हूं आपके खिलाफ एक केस दर्ज हुआ है",
            "आपके आधार कार्ड का मिसयूज़ हुआ है मनी लॉन्ड्रिंग में आपका नाम आया है",
            "किसी को मत बताना यह गोपनीय मामला है कॉल कट मत करो",
            "तुरंत पैसे ट्रांसफर करो 50000 रुपये सिक्योरिटी डिपॉजिट के रूप में",
        ],
        "expected_scam": True,
        "expected_archetype": "digital_arrest",
    },
    "Hindi Bank Scam": {
        "chunks": [
            "मैं एसबीआई बैंक से बोल रहा हूं आपका अकाउंट ब्लॉक हो गया है",
            "अकाउंट में संदिग्ध लेनदेन पाया गया है अकाउंट फ्रीज हो जाएगा",
            "अभी के अभी वेरिफिकेशन करना होगा",
            "ओटीपी बताओ जो आएगा और कार्ड नंबर बताओ",
        ],
        "expected_scam": True,
        "expected_archetype": "bank_otp",
    },
    "Telugu Scam Call": {
        "chunks": [
            "cyber crime police nundi call chesaaru mee meeda case file ayyindi",
            "warrant vachindi mee meeda court lo hazaru kaavaali",
            "evvariki cheppakandi confidential matter",
            "money transfer cheyyaali immediately otp share cheyyandi",
        ],
        "expected_scam": True,
        "expected_archetype": "digital_arrest",
    },
}

# ===================================================================
# 3. PARTIAL/INCOMPLETE SCAM (victim hangs up early)
# ===================================================================
PARTIAL_SCAMS = {
    "Hangup after HOOK": {
        "chunks": [
            "hello sir this is from enforcement directorate calling about your case",
        ],
        "expected_scam": True,  # "enforcement directorate" is a known scam pattern (score 95)
    },
    "Hangup after ESCALATE": {
        "chunks": [
            "this is officer sharma from cbi headquarters",
            "arrest warrant has been issued against you for drug trafficking",
        ],
        "expected_scam": True,  # ESCALATE with high-confidence patterns should flag
    },
    "Hangup after ISOLATE": {
        "chunks": [
            "calling from mumbai police cyber cell",
            "case registered against your aadhaar card money laundering",
            "do not tell anyone about this call confidential matter",
        ],
        "expected_scam": True,
    },
}

# ===================================================================
# 4. FALSE POSITIVE STRESS TEST (legitimate calls)
# ===================================================================
LEGITIMATE_CALLS = {
    "Legit: Actual bank call": {
        "chunks": [
            "hello this is hdfc bank calling regarding your credit card application",
            "your application has been approved and card will be dispatched tomorrow",
            "you will receive the card within 5 to 7 working days at your registered address",
            "please call our customer care if you have any questions thank you",
        ],
        "expected_scam": False,
    },
    "Legit: Police verification": {
        "chunks": [
            "hello I am constable raju from local police station calling for passport verification",
            "we need to verify your address for passport application you submitted last week",
            "can you confirm your current address and how long you have been living there",
            "thank you we will complete the verification report have a good day",
        ],
        "expected_scam": False,
    },
    "Legit: Doctor call": {
        "chunks": [
            "hello this is doctor sharma from apollo hospital calling about your father",
            "his surgery went well and he is in recovery room now",
            "you can visit him after 2 hours once he is shifted to the ward",
            "please bring his previous prescription and insurance card when you come",
        ],
        "expected_scam": False,
    },
    "Legit: Delivery call": {
        "chunks": [
            "hello sir your amazon order is out for delivery I am near your building",
            "can you please share your flat number and any landmark",
            "I am at the gate please come down to collect the package",
            "thank you sir please rate the delivery have a nice day",
        ],
        "expected_scam": False,
    },
    "Legit: Job interview call": {
        "chunks": [
            "hello I am calling from infosys hr department regarding your application",
            "we would like to schedule your technical interview for next monday",
            "please confirm if 10 am works for you and bring your original documents",
            "we will send you the confirmation email with office address and directions",
        ],
        "expected_scam": False,
    },
    "Legit: Insurance renewal": {
        "chunks": [
            "hello sir this is from lic regarding your policy renewal",
            "your term plan premium is due on 15th of this month",
            "you can pay online through our website or visit the nearest branch",
            "shall I send you the payment link on your registered email",
        ],
        "expected_scam": False,
    },
    "Legit: School call": {
        "chunks": [
            "hello this is mrs gupta from your daughters school",
            "she has a slight fever and is resting in the medical room",
            "can you please come and pick her up by afternoon",
            "nothing serious just needs rest at home for a day",
        ],
        "expected_scam": False,
    },
    "Legit: Electricity department": {
        "chunks": [
            "hello this is from electricity department regarding scheduled maintenance",
            "there will be a power cut in your area tomorrow from 10 am to 2 pm",
            "please plan accordingly and switch off heavy appliances before that",
            "sorry for the inconvenience the maintenance is for transformer upgrade",
        ],
        "expected_scam": False,
    },
    "Legit: Friend planning trip": {
        "chunks": [
            "hey dude whats up are you free this weekend",
            "thinking of going to goa lets book tickets tonight before prices go up",
            "I will send you the hotel options on whatsapp check and let me know",
            "also need to transfer some money for booking will send you upi details",
        ],
        "expected_scam": False,
    },
    "Legit: Relative calling": {
        "chunks": [
            "hello beta how are you papa here",
            "I wanted to tell you that mummy is going for a checkup tomorrow",
            "nothing serious just routine dont worry she is fine",
            "also send me that photo you took at the wedding on whatsapp",
        ],
        "expected_scam": False,
    },
    "Legit: Telecom customer care": {
        "chunks": [
            "hello thank you for calling jio customer care how may I help you",
            "I can see your recharge was successful and data pack is active",
            "your next billing cycle starts on 5th of may",
            "is there anything else I can assist you with have a great day",
        ],
        "expected_scam": False,
    },
    "Legit: Cab driver": {
        "chunks": [
            "hello sir I am your uber driver I am 5 minutes away",
            "I am in a white swift dzire you will see me at the main gate",
            "can you please share your exact pickup location pin",
            "ok sir I can see you coming down thank you",
        ],
        "expected_scam": False,
    },
}

# ===================================================================
# 5. EDGE CASES
# ===================================================================
EDGE_CASES = {
    "Empty chunks": {
        "chunks": ["", "  ", ""],
        "expected_scam": False,
    },
    "Single word": {
        "chunks": ["hello"],
        "expected_scam": False,
    },
    "Repetitive safe text": {
        "chunks": ["ok ok ok ok ok", "yes yes yes", "hmm hmm alright", "ok bye"],
        "expected_scam": False,
    },
    "Mixed benign keywords": {
        "chunks": [
            "I need to go to the bank to deposit a check",
            "the police station is near the court on main road",
            "my phone number is linked to my aadhaar for kyc",
            "I will transfer the money for dinner tomorrow",
        ],
        "expected_scam": False,
    },
}


def print_section(title):
    print()
    print(f"{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def print_results_table(results):
    hdr = f"  {'Scenario':<35} {'Phase':<10} {'ML+Sess':<8} {'Session':<8} {'Keyword':<8} {'Result'}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        ml = "Y" if r["final_scam"] else "N"
        sess = "Y" if r["session_scam"] else "N"
        kw = "Y" if r["stateless_scam"] else "N"
        line = f"  {r['name']:<35} {r['final_phase']:<10} {ml:<8} {sess:<8} {kw:<8} {status}"
        if r["fail_reasons"]:
            line += f"  ({'; '.join(r['fail_reasons'])})"
        print(line)


def main():
    all_results = []
    total_pass = 0
    total_fail = 0

    # 1. Realistic scams
    print_section("1. REALISTIC SCAM TRANSCRIPTS")
    results = []
    for name, cfg in REALISTIC_SCAMS.items():
        r = run_scenario(name, cfg["chunks"], cfg.get("expected_scam"), cfg.get("expected_archetype"))
        results.append(r)
    print_results_table(results)
    all_results.extend(results)

    # 2. Native language scams
    print_section("2. NATIVE LANGUAGE SCAMS (Hindi, Telugu)")
    results = []
    for name, cfg in NATIVE_LANGUAGE_SCAMS.items():
        r = run_scenario(name, cfg["chunks"], cfg.get("expected_scam"), cfg.get("expected_archetype"))
        results.append(r)
    print_results_table(results)
    all_results.extend(results)

    # 3. Partial scams
    print_section("3. PARTIAL/INCOMPLETE SCAM CALLS")
    results = []
    for name, cfg in PARTIAL_SCAMS.items():
        r = run_scenario(name, cfg["chunks"], cfg.get("expected_scam"), cfg.get("expected_archetype"))
        results.append(r)
    print_results_table(results)
    all_results.extend(results)

    # 4. Legitimate calls
    print_section("4. FALSE POSITIVE STRESS TEST (legitimate calls)")
    results = []
    for name, cfg in LEGITIMATE_CALLS.items():
        r = run_scenario(name, cfg["chunks"], cfg.get("expected_scam"), cfg.get("expected_archetype"))
        results.append(r)
    print_results_table(results)
    all_results.extend(results)

    # 5. Edge cases
    print_section("5. EDGE CASES")
    results = []
    for name, cfg in EDGE_CASES.items():
        r = run_scenario(name, cfg["chunks"], cfg.get("expected_scam"), cfg.get("expected_archetype"))
        results.append(r)
    print_results_table(results)
    all_results.extend(results)

    # Summary
    for r in all_results:
        if r["passed"]:
            total_pass += 1
        else:
            total_fail += 1

    print_section("SUMMARY")
    total = total_pass + total_fail
    print(f"  Total: {total} | Pass: {total_pass} | Fail: {total_fail} | Accuracy: {total_pass/total*100:.1f}%")

    # Scam detection rate
    scam_scenarios = [r for r in all_results if r["name"] in
        {**REALISTIC_SCAMS, **NATIVE_LANGUAGE_SCAMS}.keys() or
        (r["name"] in PARTIAL_SCAMS and PARTIAL_SCAMS.get(r["name"], {}).get("expected_scam"))]
    # Count correctly detected scams
    true_positives = sum(1 for r in all_results
                        if any(r["name"] == n for n in {**REALISTIC_SCAMS, **NATIVE_LANGUAGE_SCAMS})
                        and r["final_scam"] == True)
    total_scam = len(REALISTIC_SCAMS) + len(NATIVE_LANGUAGE_SCAMS)
    print(f"  Scam Detection Rate: {true_positives}/{total_scam} ({true_positives/total_scam*100:.1f}%)")

    # False positive rate
    fp = sum(1 for r in all_results
             if any(r["name"] == n for n in {**LEGITIMATE_CALLS, **EDGE_CASES})
             and r["final_scam"] == True)
    total_legit = len(LEGITIMATE_CALLS) + len(EDGE_CASES)
    print(f"  False Positive Rate: {fp}/{total_legit} ({fp/total_legit*100:.1f}%)")

    # Early detection stats
    early_chunks = [r["first_scam_chunk"] for r in all_results
                    if r["first_scam_chunk"] is not None
                    and any(r["name"] == n for n in {**REALISTIC_SCAMS, **NATIVE_LANGUAGE_SCAMS})]
    if early_chunks:
        print(f"  Avg Early Detection: chunk {sum(early_chunks)/len(early_chunks):.1f} (lower = earlier)")

    if total_fail > 0:
        print()
        print("  FAILURES:")
        for r in all_results:
            if not r["passed"]:
                print(f"    - {r['name']}: {'; '.join(r['fail_reasons'])}")

    print()


if __name__ == "__main__":
    main()
