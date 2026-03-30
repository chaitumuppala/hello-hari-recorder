import pytest

from app.detection.scam_detector import analyze_text
from app.detection.scam_archetypes import (
    SCAM_ARCHETYPES,
    ARCHETYPE_LABELS,
    check_keyword_cooccurrence,
)


class TestScamDetector:
    """Tests for the multi-language scam detector (ported from hello-hari)."""

    # --- Clean / empty text ---

    def test_clean_text_returns_no_scam(self):
        result = analyze_text("Hello, how are you doing today?")
        assert result.is_scam is False
        assert result.risk_score == 0.0
        assert result.matched_patterns == []

    def test_empty_text(self):
        result = analyze_text("")
        assert result.is_scam is False
        assert result.risk_score == 0.0

    def test_none_text(self):
        result = analyze_text(None)
        assert result.is_scam is False

    # --- Digital Arrest (highest risk category) ---

    def test_digital_arrest_scam(self):
        result = analyze_text("You are now under digital arrest by CBI headquarters")
        assert result.is_scam is True
        assert result.risk_score >= 0.9

    def test_digital_arrest_hindi(self):
        result = analyze_text("main mumbai police se bol raha hun arrest warrant has been issued")
        assert result.is_scam is True
        assert result.risk_score >= 0.9

    def test_digital_arrest_confinement(self):
        result = analyze_text("stay on video call until investigation completes don't disconnect the call or inform anyone")
        assert result.is_scam is True

    # --- TRAI / Telecom ---

    def test_trai_scam(self):
        result = analyze_text("main trai se bol raha hun sim card band hone wala hai")
        assert result.is_scam is True
        assert any("trai" in p.lower() or "telecom" in p.lower() for p in result.matched_patterns)

    def test_sim_disconnection(self):
        result = analyze_text("your number will be disconnected in 2 hours press 1 to avoid disconnection")
        assert result.is_scam is True

    # --- Courier / Customs ---

    def test_courier_scam(self):
        result = analyze_text("we are calling from fedex mumbai drugs found in your package")
        assert result.is_scam is True

    def test_customs_fee(self):
        result = analyze_text("customs clearance fee required package stuck at customs")
        assert result.risk_score > 0.5

    # --- Investment / Crypto ---

    def test_crypto_fraud(self):
        result = analyze_text("guaranteed 10x returns exclusive crypto trading opportunity join our private vip group")
        assert result.is_scam is True

    # --- Family Emergency ---

    def test_family_emergency(self):
        result = analyze_text("hello beta i am in serious trouble accident hua hai immediate money needed")
        assert result.is_scam is True

    def test_voice_cloning_hint(self):
        result = analyze_text("phone is broken thats why i sound different dont tell mom dad about this")
        assert result.is_scam is True

    # --- Hinglish / Banking ---

    def test_otp_share_hinglish(self):
        result = analyze_text("otp share karo verification ke liye upi pin batao security check")
        assert result.is_scam is True
        assert result.risk_score >= 0.8

    def test_remote_access_hinglish(self):
        result = analyze_text("remote access dena hoga sir aapka computer infected hai virus remove karna padega")
        assert result.is_scam is True

    # --- Telugu patterns ---

    def test_telugu_script_scam(self):
        result = analyze_text("మీ ఖాతా మూసివేయబడుతుంది అరెస్ట్ వారెంట్ వచ్చింది")
        assert result.is_scam is True

    def test_telugu_romanized_scam(self):
        result = analyze_text("mee account block avuthundi warrant vachindi mee meeda police station vellaali")
        assert result.is_scam is True

    def test_telugu_it_targeting(self):
        result = analyze_text("h1b visa problem us lo arrest warrant tax evasion case filed")
        assert result.is_scam is True

    # --- Hindi authority patterns ---

    def test_hindi_authority(self):
        result = analyze_text("warrant nikla hai aapke naam aapke khilaaf case file ho gaya police aane wali hai")
        assert result.is_scam is True

    def test_hindi_banking(self):
        result = analyze_text("income tax notice loan default case cheque bounce case bank fraud detection")
        assert result.is_scam is True

    # --- Cross-language indicators ---

    def test_urgency_boost(self):
        result = analyze_text("customs clearance fee required immediately")
        assert result.risk_score > 0.5

    def test_authority_boost(self):
        result = analyze_text("police customs duty payment needed immediately")
        assert result.risk_score > 0.5

    def test_financial_terms(self):
        result = analyze_text("otp share karo verification ke liye bank details money transfer")
        assert result.risk_score > 0.5

    # --- Multiple patterns increase score ---

    def test_multiple_patterns_increase_score(self):
        single = analyze_text("customs clearance fee required")
        double = analyze_text(
            "customs clearance fee required package stuck at customs "
            "drugs found in your package"
        )
        assert double.risk_score >= single.risk_score
        assert double.risk_score >= 0.9

    # --- Legitimate calls ---

    def test_legitimate_bank_call(self):
        result = analyze_text("Good morning, this is a reminder about your scheduled appointment tomorrow")
        assert result.is_scam is False

    def test_legitimate_delivery(self):
        result = analyze_text("Your order has been shipped and will arrive by Wednesday")
        assert result.is_scam is False


# ===================================================================
# Archetype co-occurrence tests (scam_archetypes.py)
# ===================================================================


class TestArchetypeRegistry:
    """Verify the archetype registry is correctly structured."""

    def test_archetype_count(self):
        assert len(SCAM_ARCHETYPES) == 13

    def test_all_archetypes_have_labels(self):
        for name, _, _, _ in SCAM_ARCHETYPES:
            assert name in ARCHETYPE_LABELS, f"Missing label for {name}"

    def test_all_keyword_sets_nonempty(self):
        for name, ctx, thr, dem in SCAM_ARCHETYPES:
            assert len(ctx) > 0, f"{name} context empty"
            assert len(thr) > 0, f"{name} threat empty"
            assert len(dem) > 0, f"{name} demand empty"


class TestArchetypeDetection:
    """Test keyword co-occurrence detection for each archetype."""

    # --- Bank / OTP ---

    def test_bank_otp_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "बैंक अकाउंट लॉक हो गया है ओटीपी बता दो", detected
        )
        assert score >= 95
        assert any("bank_otp" in d for d in detected)

    def test_bank_otp_telugu(self):
        detected = []
        score = check_keyword_cooccurrence(
            "బ్యాంక్ ఖాతా బ్లాక్ అయింది ఓటీపీ చెప్పండి", detected
        )
        assert score >= 70

    # --- Digital Arrest ---

    def test_digital_arrest_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "पुलिस विभाग गिरफ्तारी वारंट पैसे ट्रांसफर करो", detected
        )
        assert score >= 95
        assert any("digital_arrest" in d for d in detected)

    # --- TRAI / Telecom ---

    def test_trai_telecom_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "सिम कार्ड बंद हो रहा है 1 दबाएं", detected
        )
        assert score >= 95
        assert any("trai_telecom" in d for d in detected)

    # --- KYC / Aadhaar ---

    def test_kyc_aadhaar_tamil(self):
        detected = []
        score = check_keyword_cooccurrence(
            "கேவைசி எக்ஸ்பையர் ஆகிவிட்டது அப்டேட் செய்யுங்க", detected
        )
        assert score >= 95
        assert any("kyc_aadhaar" in d for d in detected)

    # --- Family Emergency ---

    def test_family_emergency_bengali(self):
        detected = []
        score = check_keyword_cooccurrence(
            "মা ছেলে হাসপাতাল গ্রেফতার টাকা দরকার এখনই পাঠান", detected
        )
        assert score >= 95
        assert any("family_emergency" in d for d in detected)

    # --- Tech Support ---

    def test_tech_support_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "कंप्यूटर में वायरस है एनीडेस्क डाउनलोड करें", detected
        )
        assert score >= 95
        assert any("tech_support" in d for d in detected)

    def test_tech_support_english(self):
        detected = []
        score = check_keyword_cooccurrence(
            "microsoft technical support computer infected virus download teamviewer remote access", detected
        )
        assert score >= 95
        assert any("tech_support" in d for d in detected)

    # --- Courier / Customs ---

    def test_courier_customs_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "पार्सल में ड्रग्स मिले हैं कस्टम्स फीस भरें", detected
        )
        assert score >= 95
        assert any("courier_customs" in d for d in detected)

    # --- Investment / Crypto ---

    def test_investment_crypto_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "शेयर बाजार निवेश गारंटीड रिटर्न आखिरी मौका पैसा दोगुना", detected
        )
        assert score >= 95
        assert any("investment_crypto" in d for d in detected)

    # --- Lottery / Prize ---

    def test_lottery_prize_telugu(self):
        detected = []
        score = check_keyword_cooccurrence(
            "లాటరీ బహుమతి ఈరోజే ట్యాక్స్ చెల్లించండి రద్దు అవుతుంది", detected
        )
        assert score >= 95
        assert any("lottery_prize" in d for d in detected)

    # --- Insurance / Policy ---

    def test_insurance_policy_tamil(self):
        detected = []
        score = check_keyword_cooccurrence(
            "காப்பீடு பாலிசி முடிகிறது ரத்து பிரீமியம் செலுத்துங்க", detected
        )
        assert score >= 95
        assert any("insurance_policy" in d for d in detected)

    # --- Electricity / Utility ---

    def test_electricity_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "बिजली बिल बकाया है 2 घंटे में कट जाएगी अभी भरें", detected
        )
        assert score >= 95
        assert any("electricity_utility" in d for d in detected)

    def test_electricity_english(self):
        detected = []
        score = check_keyword_cooccurrence(
            "electricity power bill overdue disconnected within 2 hours pay now google pay", detected
        )
        assert score >= 95
        assert any("electricity_utility" in d for d in detected)

    # --- Job / Employment ---

    def test_job_employment_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "सरकारी नौकरी भर्ती आखिरी तारीख रजिस्ट्रेशन फीस", detected
        )
        assert score >= 95
        assert any("job_employment" in d for d in detected)

    # --- Loan / Credit ---

    def test_loan_credit_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "पर्सनल लोन प्री-अप्रूव्ड ऑफर खत्म प्रोसेसिंग फीस", detected
        )
        assert score >= 95
        assert any("loan_credit" in d for d in detected)

    def test_loan_credit_bengali(self):
        detected = []
        score = check_keyword_cooccurrence(
            "পার্সোনাল লোন অফার শেষ হচ্ছে প্রসেসিং ফি দিন আজই", detected
        )
        assert score >= 95
        assert any("loan_credit" in d for d in detected)

    # --- Safe text (no false positives) ---

    def test_safe_hindi(self):
        detected = []
        score = check_keyword_cooccurrence(
            "नमस्ते आज मौसम बहुत अच्छा है चलो बाहर चलते हैं", detected
        )
        assert score == 0
        assert len(detected) == 0

    def test_safe_telugu(self):
        detected = []
        score = check_keyword_cooccurrence(
            "నమస్తే ఎలా ఉన్నారు నేను బాగానే ఉన్నాను", detected
        )
        assert score == 0

    def test_safe_english(self):
        detected = []
        score = check_keyword_cooccurrence(
            "hello how are you I wanted to discuss the project meeting tomorrow", detected
        )
        assert score == 0


class TestEndToEndArchetypes:
    """Test archetype detection through the full analyze_text pipeline."""

    def test_tech_support_full_pipeline(self):
        result = analyze_text(
            "माइक्रोसॉफ्ट से बोल रहा हूं कंप्यूटर में वायरस है एनीडेस्क डाउनलोड करें"
        )
        assert result.is_scam is True
        assert result.risk_score >= 0.9

    def test_electricity_scam_full_pipeline(self):
        result = analyze_text(
            "this is electricity department power bill overdue "
            "connection disconnected within 2 hours pay now google pay"
        )
        assert result.is_scam is True
        assert result.risk_score >= 0.9

    def test_loan_scam_full_pipeline(self):
        result = analyze_text(
            "आपका पर्सनल लोन प्री-अप्रूव्ड है ऑफर खत्म हो रहा है "
            "प्रोसेसिंग फीस भेजें"
        )
        assert result.is_scam is True
        assert result.risk_score >= 0.9

    def test_safe_conversation_full_pipeline(self):
        result = analyze_text(
            "Good afternoon, I'm calling to confirm your dentist "
            "appointment for next Tuesday at 3pm"
        )
        assert result.is_scam is False
        assert result.risk_score == 0.0
