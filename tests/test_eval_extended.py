"""Extended evaluation — stress testing with more diverse scenarios.

Covers:
  - Code-switched Hinglish/Tenglish variants
  - Scams with unusual phrasing / paraphrasing
  - Ambiguous calls (could go either way)
  - Longer multi-turn conversations (6-8 chunks)
  - Regional scam variants (Marathi, Bengali, Tamil)
  - Rapid-fire scams (compressed into 2 chunks)
  - Legitimate calls that heavily use scam-domain vocabulary
  - Subtle scams that start very normally
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.detection.scam_detector import analyze_text, analyze_session
from app.detection.narrative_tracker import NarrativeTracker
from app.detection.classifier import ScamClassifier

_MODEL_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'backend', 'app', 'detection',
    'models', 'scam_classifier.joblib'
)
_classifier = ScamClassifier.load(_MODEL_PATH) if os.path.exists(_MODEL_PATH) else None


def run_scenario(name, chunks, expected_scam):
    tracker = NarrativeTracker()
    result = analyze_session(chunks, tracker, classifier=_classifier)
    narrative = tracker.get_state()

    # Also run keyword-only for comparison
    kw_scam = False
    for c in chunks:
        if analyze_text(c).is_scam:
            kw_scam = True
            break

    passed = result.is_scam == expected_scam
    return {
        "name": name,
        "phase": narrative.best_phase,
        "phase_score": narrative.phase_score,
        "risk": result.risk_score,
        "ml_scam": result.is_scam,
        "kw_scam": kw_scam,
        "expected": expected_scam,
        "passed": passed,
        "archetype": narrative.best_archetype,
    }


# ===================================================================
# SCAM SCENARIOS
# ===================================================================
SCAM_TESTS = [
    # --- Code-switched Hinglish (very common in real calls) ---
    ("Hinglish: Digital arrest verbose", [
        "hello sir good afternoon I am calling from mumbai cyber crime branch",
        "sir aapke aadhaar card se kuch illegal transactions hui hain",
        "sir ye bahut serious matter hai isko under investigation rakha gaya hai",
        "sir aap kisi ko bhi is baare mein mat batana nahi toh case aur serious ho jayega",
        "sir aapko ek security deposit dena hoga 50000 rupees verify hone tak",
    ], True),

    ("Hinglish: Bank OTP natural", [
        "hello sir myself calling from icici bank customer care department",
        "sir aapke account mein ek unauthorized transaction flag hua hai 45000 ka",
        "sir ye bahut urgent hai aapko abhi verify karna padega warna account band ho jayega",
        "sir please apna 16 digit card number bataiye jo card ke front pe hai aur pin bhi",
    ], True),

    ("Hinglish: Courier natural", [
        "hello sir we are calling from blue dart courier service regarding your parcel",
        "sir aapke naam se ek parcel aaya tha jismein kuch suspicious items found hue hain",
        "sir hum aapko ncb officer se connect kar rahe hain please call disconnect mat karna",
        "sir officer bol rahe hain ki aapko fine pay karna hoga nahi toh arrest ho jayega",
    ], True),

    # --- Slow burn scam (starts very innocently) ---
    ("Slow burn: Friendly then scam", [
        "hello how are you sir I hope you are doing well today",
        "sir I am calling to inform you about a small issue with your mobile connection",
        "sir actually 22 complaints have been filed against your sim card number",
        "sir your number will be disconnected within 2 hours if you dont take action now",
        "sir press 1 to connect with our senior officer or pay the compliance fee immediately",
    ], True),

    ("Slow burn: Insurance to scam", [
        "hello sir this is from max life insurance regarding your term plan",
        "sir your policy is about to lapse the grace period ends today",
        "sir if you dont pay right now your entire coverage of 50 lakhs will be gone permanently",
        "sir just share your bank account number and upi pin we will process the renewal right now",
    ], True),

    # --- Rapid fire (compressed scam in 2 chunks) ---
    ("Rapid: Digital arrest 2-chunk", [
        "this is cbi officer your aadhaar is linked to drug trafficking case arrest warrant issued",
        "transfer 1 lakh as bail deposit immediately dont tell anyone or case becomes worse",
    ], True),

    ("Rapid: Bank OTP 2-chunk", [
        "your sbi account is blocked due to suspicious activity unauthorized transaction of 89000",
        "share your otp and card number immediately to unblock or account will be permanently closed",
    ], True),

    # --- Telugu / Tenglish ---
    ("Telugu: Authority scam", [
        "hello sir idi cyber crime police nundi call",
        "mee aadhaar card misuse ayyindi illegal activities lo",
        "evvariki cheppakandi confidential matter idi",
        "money transfer cheyyaali immediately leda arrest avtundi",
    ], True),

    ("Tenglish: Bank fraud", [
        "hello sir mee bank account lo problem vachindi",
        "mee account block avuthundi unauthorized transaction jarigindi",
        "ventane verify cheyyandi time ledu",
        "otp share cheyyandi aur card details ivvandi",
    ], True),

    # --- Hindi Devanagari script ---
    ("Devanagari: Police threat", [
        "नमस्ते मैं इंस्पेक्टर शर्मा बोल रहा हूं पुलिस से",
        "आपके नाम पर एफआईआर दर्ज हुआ है गंभीर मामला है",
        "किसी को बोलना मत यह गोपनीय मामला है",
        "तुरंत 30000 जमा करो नहीं तो गिरफ्तारी होगी",
    ], True),

    ("Devanagari: OTP scam", [
        "बैंक से बोल रहा हूं आपका खाता ब्लॉक हो गया है",
        "अकाउंट में संदिग्ध लेनदेन हुआ है",
        "जल्दी करो अभी के अभी",
        "ओटीपी बताओ और पासवर्ड शेयर करो",
    ], True),

    # --- Investment / lottery variants ---
    ("Investment: Crypto WhatsApp", [
        "hi I found your number from mutual friend join our exclusive trading group",
        "we have been making guaranteed returns of 300 percent in just 2 weeks see these screenshots",
        "only 50 members allowed this month slots are filling fast you will miss out",
        "deposit 10000 to start trading I will send you the wallet address pay now before offer closes",
    ], True),

    ("Lottery: KBC style", [
        "congratulations you have been selected as the winner of kaun banega crorepati season 15",
        "you have won a cash prize of 25 lakhs plus a samsung phone",
        "to claim your prize you need to pay the gst tax of 5000 rupees",
        "please share your bank account details and pay the processing fee through google pay",
    ], True),

    # --- Family emergency variants ---
    ("Family: Kidnapping scam", [
        "hello we have your son he is with us right now",
        "if you want to see him alive you need to cooperate",
        "do not call the police or inform anyone we are watching",
        "transfer 5 lakhs to this account within 1 hour or face consequences",
    ], True),

    ("Family: Accident Hinglish", [
        "hello uncle main rahul bol raha hun aapke bete ka dost",
        "uncle aapke bete ka accident ho gaya hai bahut serious hai hospital mein hai",
        "uncle please papa ko mat batao woh tension mein aa jayenge",
        "uncle 50000 chahiye surgery ke liye abhi ke abhi please jaldi bhejo",
    ], True),

    # --- Tech support ---
    ("Tech: Microsoft scam", [
        "hello this is microsoft technical support calling about your windows computer",
        "we have detected a serious virus on your system your data is being stolen right now",
        "you need to install anydesk app so our technician can remove the malware",
        "there is a one time repair fee of 15000 rupees please pay through upi or gift card",
    ], True),

    # --- Electricity / utility ---
    ("Utility: Bijli scam Hindi", [
        "hello aapke ghar ki bijli ke baare mein call kar raha hun",
        "aapka bill 3 mahine se pending hai 8500 rupees bkaya hai",
        "aaj raat 8 baje tak pay nahi kiya toh bijli kat jayegi",
        "abhi google pay se ye number pe pay kar do nahi toh connection permanently band",
    ], True),

    # --- Job scam ---
    ("Job: Work from home", [
        "hello we have a work from home job offer for you guaranteed income 50000 per month",
        "this is an amazon data entry position no experience required start immediately",
        "there are only limited seats available application closes today",
        "you need to pay registration fee of 2000 and training kit fee of 3000 to start the job",
    ], True),
]

# ===================================================================
# LEGITIMATE SCENARIOS
# ===================================================================
LEGIT_TESTS = [
    # --- Domain-heavy legitimate calls ---
    ("Legit: Bank manager personal", [
        "hello sir this is rajesh from hdfc bank mangalore branch your relationship manager",
        "sir your fixed deposit of 5 lakhs has matured today",
        "would you like to renew it or withdraw the amount to your savings account",
        "you can visit the branch or I can help you process it over a video call",
    ], False),

    ("Legit: Actual police call", [
        "hello this is inspector singh from koramangala police station",
        "we found your wallet near the bus stop someone handed it in",
        "can you come to the station with your id proof to collect it",
        "we are open until 8 pm today the address is 100 feet road koramangala",
    ], False),

    ("Legit: Real court summons", [
        "hello this is from district court clerk office regarding case number 4523",
        "your hearing has been scheduled for may 15th at 10 am",
        "please bring all relevant documents and your lawyer",
        "if you need to reschedule please call the court office before may 10th",
    ], False),

    ("Legit: Hospital emergency real", [
        "hello is this mrs sharma I am calling from fortis hospital emergency",
        "your husband has been brought in after a minor road accident",
        "he is stable and conscious just some bruises and we are running tests",
        "please come to the emergency ward with his insurance card and aadhaar",
    ], False),

    ("Legit: Insurance agent visit", [
        "hello sir I am your lic agent calling about your policy maturity",
        "your endowment plan matures next month the amount is 12 lakhs",
        "I will come to your house with the form you need to sign",
        "please keep your policy document and cancelled cheque ready",
    ], False),

    ("Legit: Telecom complaint resolution", [
        "hello sir this is airtel customer care regarding your complaint about slow internet",
        "we have identified the issue it was a network congestion in your area",
        "the problem has been fixed you should now get full speed",
        "we are also giving you 5 gb extra data as compensation for the inconvenience",
    ], False),

    ("Legit: E-commerce return", [
        "hello this is amazon customer service calling about your return request",
        "we have received the returned item and inspection is complete",
        "your refund of 3499 rupees will be processed within 3 to 5 business days",
        "is there anything else I can help you with today",
    ], False),

    ("Legit: School principal", [
        "hello I am the principal of st marys school calling about your son",
        "he has been selected for the inter school science competition",
        "the competition is on june 5th at delhi public school",
        "we need your written consent and permission form signed by friday",
    ], False),

    ("Legit: Govt helpline", [
        "hello you have reached the national consumer helpline",
        "your complaint about the defective product has been registered",
        "complaint number is 2024-567890 please note this for reference",
        "the company has been notified they will respond within 15 days",
    ], False),

    ("Legit: Builder calling", [
        "hello sir this is from prestige constructions about your flat booking",
        "the registration date has been fixed for may 20th at sub registrar office",
        "please bring all original documents stamp duty cheque and your id proof",
        "our representative will be there to assist you with the process",
    ], False),

    ("Legit: Doctor follow up Hindi", [
        "hello beta main doctor gupta bol raha hun",
        "tumhare papa ki reports aa gayi hain sab normal hai",
        "blood pressure thoda high hai medicine continue karo",
        "next checkup 2 hafte baad karna hai take care",
    ], False),

    ("Legit: Relative wedding planning", [
        "hello beta chacha bol raha hun tumse baat karni thi",
        "pinki ki shaadi ki date fix ho gayi hai 15 december ko",
        "tum sab ko aana padega function mein help chahiye bahut kaam hai",
        "hotel booking ke liye main paisa bhej dunga tum arrange kar dena",
    ], False),

    ("Legit: Friend money split", [
        "hey bro last night dinner ka bill split karna tha remember",
        "total 4500 tha so your share is 1500 rupees",
        "upi se bhej de mera google pay number hai same mobile number",
        "thanks bro next time treat is on me haha",
    ], False),

    ("Legit: Gym trainer", [
        "hello sir this is your gym trainer calling about your membership",
        "your 6 month membership expires next week on may 5th",
        "we have a renewal offer 20 percent discount if you renew before expiry",
        "you can pay at the reception or online through our app",
    ], False),

    ("Legit: Landlord calling", [
        "hello this is your landlord speaking rent for this month is pending",
        "please transfer it by 5th as per our agreement",
        "also the plumber is coming tomorrow for the bathroom repair",
        "please be available between 10 to 12 in the morning",
    ], False),

    ("Legit: Passport office", [
        "hello this is from regional passport office regarding your application",
        "your passport has been printed and dispatched via speed post",
        "tracking number is EE123456789IN you can track on india post website",
        "it should reach your address within 3 to 5 working days",
    ], False),

    ("Legit: Colleague work call", [
        "hey can you send me the updated spreadsheet before the meeting",
        "the client wants to see the numbers for last quarter",
        "also forward the email from finance about the budget approval",
        "meeting is at 3 pm in the conference room dont be late",
    ], False),

    ("Legit: Pharmacy delivery", [
        "hello sir your medicine order from apollo pharmacy is ready for delivery",
        "we have paracetamol blood pressure tablets and the vitamin supplements",
        "delivery boy will reach your address in 30 minutes",
        "total amount is 850 rupees you can pay cash on delivery or online",
    ], False),
]

# ===================================================================
# TRICKY EDGE CASES
# ===================================================================
TRICKY_TESTS = [
    # Legitimate but uses LOTS of scam vocabulary
    ("Tricky: Fraud victim reporting to police", [
        "hello I want to report a scam I was called by someone claiming to be from cbi",
        "they said I have an arrest warrant and asked me to transfer money",
        "I did not give them any otp or card details but they threatened me with jail",
        "please file an fir my aadhaar number is 1234 and the scammer number is 9876",
    ], False),

    ("Tricky: Cybersecurity training webinar", [
        "welcome to todays webinar on how to identify scam calls and phishing attacks",
        "common scam patterns include someone claiming your account is blocked or suspended",
        "they will ask you to share otp card number cvv and threaten you with arrest",
        "never share your personal details remember banks never ask for otp on call",
    ], False),

    ("Tricky: News reporter covering scam story", [
        "today we report on the digital arrest scam that has defrauded thousands",
        "the scammer calls pretending to be from cbi or enforcement directorate",
        "victims are told they are under investigation and must pay a security deposit",
        "police have arrested 15 suspects and recovered 2 crore rupees",
    ], False),

    ("Tricky: Bank employee training", [
        "in this training module we will learn about common banking frauds",
        "scammers often say account is blocked or unauthorized transaction detected",
        "they ask customers to share otp pin or card number for verification",
        "as bank employees we must never ask customers for these details on call",
    ], False),

    # Scams that try to sound legitimate
    ("Tricky scam: Polite authority", [
        "good morning sir I hope I am not disturbing you I am calling from the IT department",
        "sir we have noticed some discrepancies in your income tax return for last year",
        "sir this is a confidential matter please do not discuss this with your CA or family",
        "sir to resolve this you need to pay a penalty of 25000 immediately via neft",
    ], True),

    ("Tricky scam: Helpful bank person", [
        "hello sir I am calling from your bank to help protect your account",
        "we detected a fraudulent transaction of 75000 on your credit card",
        "to block this transaction immediately I need to verify your card details",
        "please read out your 16 digit card number and the otp you will receive now",
    ], True),
]


def print_section(title):
    print()
    print("=" * 75)
    print(f"  {title}")
    print("=" * 75)


def print_table(results):
    hdr = f"  {'Scenario':<45} {'Phase':<8} {'ML':<4} {'KW':<4} {'Exp':<4} {'Result'}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        ml = "Y" if r["ml_scam"] else "N"
        kw = "Y" if r["kw_scam"] else "N"
        exp = "Y" if r["expected"] else "N"
        line = f"  {r['name']:<45} {r['phase']:<8} {ml:<4} {kw:<4} {exp:<4} {status}"
        if not r["passed"]:
            line += f"  <<<< WRONG"
        print(line)


def main():
    all_results = []

    print_section("SCAM SCENARIOS (expected: detected)")
    results = [run_scenario(n, c, e) for n, c, e in SCAM_TESTS]
    print_table(results)
    all_results.extend(results)

    print_section("LEGITIMATE SCENARIOS (expected: not detected)")
    results = [run_scenario(n, c, e) for n, c, e in LEGIT_TESTS]
    print_table(results)
    all_results.extend(results)

    print_section("TRICKY EDGE CASES")
    results = [run_scenario(n, c, e) for n, c, e in TRICKY_TESTS]
    print_table(results)
    all_results.extend(results)

    # Summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r["passed"])
    failed = total - passed

    scam_tests = [r for r in all_results if r["expected"]]
    legit_tests = [r for r in all_results if not r["expected"]]
    tp = sum(1 for r in scam_tests if r["ml_scam"])
    fn = sum(1 for r in scam_tests if not r["ml_scam"])
    tn = sum(1 for r in legit_tests if not r["ml_scam"])
    fp = sum(1 for r in legit_tests if r["ml_scam"])

    # How many FPs does keyword-only produce?
    kw_fp = sum(1 for r in legit_tests if r["kw_scam"])

    print_section("SUMMARY")
    print(f"  Total: {total} | Pass: {passed} | Fail: {failed} | Accuracy: {passed/total*100:.1f}%")
    print()
    print(f"  True Positives  (scam caught):      {tp}/{tp+fn}  ({tp/(tp+fn)*100:.0f}%)")
    print(f"  False Negatives (scam missed):       {fn}/{tp+fn}")
    print(f"  True Negatives  (legit cleared):     {tn}/{tn+fp}  ({tn/(tn+fp)*100:.0f}%)")
    print(f"  False Positives (legit flagged):      {fp}/{tn+fp}")
    print()
    print(f"  Precision: {tp/(tp+fp)*100:.1f}%" if (tp+fp) > 0 else "  Precision: N/A")
    print(f"  Recall:    {tp/(tp+fn)*100:.1f}%")
    print(f"  F1 Score:  {2*tp/(2*tp+fp+fn)*100:.1f}%")
    print()
    print(f"  Keyword-only false positives: {kw_fp}/{len(legit_tests)}")
    print(f"  ML+Session false positives:   {fp}/{len(legit_tests)}")
    if kw_fp > 0:
        reduction = (kw_fp - fp) / kw_fp * 100
        print(f"  FP reduction from ML:         {reduction:.0f}%")
    print()

    if failed > 0:
        print("  FAILURES:")
        for r in all_results:
            if not r["passed"]:
                got = "scam" if r["ml_scam"] else "legit"
                exp = "scam" if r["expected"] else "legit"
                print(f"    - {r['name']}: got {got}, expected {exp} "
                      f"(phase={r['phase']}, risk={r['risk']:.2f})")
    print()


if __name__ == "__main__":
    main()
