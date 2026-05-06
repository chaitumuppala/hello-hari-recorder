"""Multi-language scam detection engine.

Ported from the proven hello-hari Android app (MultiLanguageScamDetector.java).
Two detection layers:
1. Exact phrase matching across 574+ English patterns in 9 categories.
2. Multi-archetype keyword co-occurrence engine (13 archetypes × 10 Indian
   language scripts + English) — see scam_archetypes.py.

Scoring: per-pattern weighted points, 10% boost per extra hit in same category,
cross-language urgency/authority/financial/tech-support indicator bonuses.
Capped at 100.
"""

import logging

from app.detection.scam_archetypes import ARCHETYPE_LABELS, check_keyword_cooccurrence
from app.detection.narrative_tracker import NarrativeTracker
from app.models.schemas import ScamAnalysis

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern dictionaries: phrase -> risk points (0-100)
# Matching is case-insensitive substring (.contains equivalent).
# ---------------------------------------------------------------------------

# === DIGITAL ARREST SCAMS (HIGHEST RISK) ===
DIGITAL_ARREST_PATTERNS: dict[str, int] = {
    # Authority establishment
    "this is from mumbai police cyber cell": 95,
    "main mumbai police se bol raha hun": 95,
    "i am calling from cbi headquarters": 98,
    "this is from enforcement directorate": 95,
    "main ncb officer hun": 98,
    "we are from supreme court of india": 100,
    "arrest warrant has been issued": 98,
    "you are under investigation": 90,
    "cyber crime cell speaking": 95,
    "narcotics control bureau": 98,
    "income tax department raid": 92,
    "customs enforcement calling": 90,
    "delhi police headquarters": 95,
    "central bureau investigation": 98,
    # Digital confinement
    "you are now under digital arrest": 100,
    "stay on video call until investigation completes": 100,
    "don't disconnect the call or inform anyone": 100,
    "don't involve family lawyer in this matter": 100,
    "this is confidential government matter": 95,
    "case will become serious if you disconnect": 98,
    "you cannot leave until cleared": 100,
    "maintain video call throughout": 100,
    "digital custody until verification": 100,
    "remote arrest proceedings": 100,
    # Accusations
    "your aadhaar card has been used for illegal activities": 90,
    "parcel containing drugs found in your name": 95,
    "22 complaints filed against your mobile sim": 90,
    "aapke naam se human trafficking ka case": 98,
    "your bank account is being used for money laundering": 95,
    "anti national activities linked to your number": 98,
    "terror charges will be filed": 100,
    "drug trafficking case registered": 95,
    "drug trafficking case has been registered": 95,
    "case has been registered under your aadhaar": 92,
    "case registered under your aadhaar": 92,
    "i am calling from cbi": 95,
    "this is from cbi headquarters": 95,
    "cbi headquarters": 90,
    "fake passport found with your details": 95,
    "hawala transaction detected": 90,
    "suspicious international transfers": 88,
    "cybercrime unit has evidence": 92,
    "narcotics found in courier": 95,
    "illegal weapons shipment": 98,
    "human organ trafficking": 100,
    "child trafficking allegations": 100,
    "terrorism funding detected": 100,
    "fake currency circulation": 95,
    # Secrecy / isolation demands (hallmark of scams — real police never say this)
    "dont tell anyone about this call": 90,
    "don't tell anyone about this call": 90,
    "do not tell anyone": 85,
    "do not inform your family": 90,
    "do not inform anyone": 88,
    "keep this between us": 85,
    "keep this confidential": 80,
    "this is a confidential matter": 78,
    "do not discuss this with anyone": 88,
    "if you tell anyone case will be worse": 92,
    "if you inform anyone you will be arrested": 95,
    "do not contact a lawyer": 95,
    "no need to tell family": 85,
    "kisi ko mat batana": 88,
    "kisi ko bhi mat batao": 88,
    "family ko mat bolo": 85,
    "ghar mein kisi ko mat batao": 88,
    # Threat escalation — arrest/jail/FIR
    "fir will be filed against you": 90,
    "fir file ho jayegi": 90,
    "we will file an fir": 88,
    "non bailable fir": 95,
    "you will be arrested": 92,
    "you will be arrested within 24 hours": 95,
    "arrested within 2 hours": 95,
    "police will come to your house": 88,
    "we will send police to your house": 88,
    "jail mein jayenge": 85,
    "jail mein daal denge": 88,
    "jail ho jayegi": 85,
    "you will go to jail": 85,
    "prison sentence": 82,
    # Aadhaar / PAN misuse
    "your aadhaar has been misused": 85,
    "aadhaar card misuse": 85,
    "your pan card has been misused": 85,
    "someone used your aadhaar": 82,
    "someone used your pan": 82,
    "share your pan number": 78,
    "tell me your aadhaar number": 80,
    "share your aadhaar number": 80,
}

# === TRAI & TELECOM AUTHORITY SCAMS ===
TRAI_PATTERNS: dict[str, int] = {
    "main trai se bol raha hun": 85,
    "sim card band hone wala hai": 85,
    "this is from telecom regulatory authority": 85,
    "your number will be disconnected in 2 hours": 90,
    "22 complaints registered against your sim": 85,
    "mobile connection has illegal usage": 80,
    "immediate action required on your number": 85,
    "trai compliance violation": 80,
    "sim deactivation process started": 85,
    "telecom fraud detected on your number": 85,
    "press 1 to avoid disconnection": 90,
    "your mobile services will be suspended": 85,
    "department of telecommunications calling": 85,
    "sim card kyc verification failed": 80,
    "illegal call forwarding detected": 82,
    "international roaming misuse": 78,
    "bulk sms violation": 75,
    "telecom license cancellation": 88,
    "sim card cloning detected": 90,
    "sim card has been cloned": 90,
    "your sim has been cloned": 88,
    "someone is using your number": 78,
    "your number is being used by someone": 78,
    "unauthorized network access": 82,
}

# === FEDEX / COURIER / CUSTOMS SCAMS ===
COURIER_PATTERNS: dict[str, int] = {
    "we are calling from fedex mumbai": 80,
    "your parcel has been confiscated": 85,
    "drugs found in your package": 90,
    "140 grams of narcotic drugs found": 90,
    "parcel contained illegal items": 85,
    "customs clearance fee required": 75,
    "package stuck at customs": 75,
    "custom commission duty and tax": 80,
    "parcel from thailand intercepted": 85,
    "five passports three credit cards found": 90,
    "mdma synthetic narcotics detected": 90,
    "international package security alert": 80,
    "customs duty payment needed immediately": 80,
    "courier company legal notice": 75,
    "dhl package seizure notice": 80,
    "blue dart security department": 78,
    "speed post suspicious package": 75,
    "first flight courier verification": 76,
    "aramex package investigation": 78,
    "gati courier fraud department": 75,
    "dtdc package confiscation": 76,
    "professional courier security": 78,
    "international express detention": 82,
    "air cargo security alert": 85,
    "postal department investigation": 80,
    "package contains contraband": 88,
    "narcotic substances detected": 90,
    "illegal wildlife products": 85,
    "counterfeit currency found": 88,
    "prohibited pharmaceutical items": 82,
}

# === INVESTMENT & CRYPTOCURRENCY FRAUD ===
INVESTMENT_PATTERNS: dict[str, int] = {
    "exclusive crypto trading opportunity": 70,
    "guaranteed 10x returns": 85,
    "join our private vip group": 75,
    "double your bitcoin in 30 days": 85,
    "government approved digital currency": 80,
    "see screenshots of members profits": 75,
    "offer expires tonight invest now": 80,
    "only 100 slots remaining": 80,
    "professor has been arrested pay to unlock": 85,
    "withdraw restrictions after 24 hours": 80,
    "limited time crypto investment": 75,
    "insider trading tips available": 85,
    "binary options guaranteed profit": 80,
    "forex trading robot": 75,
    "stock market sure shot tips": 75,
    "rbi approved cryptocurrency": 82,
    "sebi registered investment scheme": 78,
    "mutual fund guaranteed returns": 75,
    "ipo early bird offer": 72,
    "share market inside information": 85,
    "commodity trading signals": 70,
    "gold investment scheme": 68,
    "real estate fixed returns": 70,
    "startup equity investment": 75,
    "peer to peer lending": 72,
    "cryptocurrency mining pool": 75,
    "defi staking rewards": 78,
    "nft investment opportunity": 65,
    "metaverse land purchase": 62,
    "blockchain technology investment": 70,
    # Lottery / prize / reward scams
    "you have won a prize": 82,
    "you have won a lottery": 85,
    "you are the lucky winner": 85,
    "congratulations you have been selected": 82,
    "congratulations you are selected": 82,
    "congratulations you won": 85,
    "lucky draw winner": 82,
    "lucky draw prize": 82,
    "won a cash prize": 85,
    "claim your prize": 85,
    "claim your reward": 85,
    "claim your gift": 80,
    "collect your prize money": 85,
    "prize money of": 80,
    "reward amount of": 78,
    "kaun banega crorepati": 88,
    "kbc lottery": 90,
    "kbc winner": 88,
    "jio lottery winner": 85,
    "airtel lucky draw": 85,
    "whatsapp lottery": 88,
    "facebook lottery": 85,
    "google lottery winner": 88,
    "you are selected for a cash prize": 85,
    "pay tax to receive prize": 90,
    "processing fee to claim prize": 90,
    "pay to claim your reward": 88,
}

# === ENGLISH BANK / OTP / ACCOUNT SCAMS ===
BANK_OTP_PATTERNS: dict[str, int] = {
    # Bank impersonation — context setters, not standalone triggers.
    # These are legitimate when real banks call. They become scam
    # signals only when combined with threats/OTP requests in the window.
    "calling from hdfc bank": 35,
    "calling from sbi bank": 35,
    "calling from icici bank": 35,
    "calling from axis bank": 35,
    "calling from kotak bank": 35,
    "calling from yes bank": 35,
    "calling from pnb bank": 35,
    "calling from bank of baroda": 35,
    "calling from canara bank": 35,
    "calling from union bank": 35,
    "calling from idbi bank": 35,
    "calling from indusind bank": 35,
    "calling from federal bank": 35,
    "this is from your bank": 30,
    "from the bank": 20,
    "bank security department": 40,
    "bank fraud department": 40,
    "bank verification team": 38,
    # Account threats
    "your account is deactivated": 85,
    "your account has been deactivated": 85,
    "your account will be deactivated": 85,
    "account is deactivated": 82,
    "account has been deactivated": 82,
    "account will be deactivated": 82,
    "your account is blocked": 85,
    "your account has been blocked": 85,
    "your account will be blocked": 85,
    "account is blocked": 82,
    "account has been blocked": 82,
    "your account is suspended": 85,
    "your account has been suspended": 85,
    "account is suspended": 82,
    "account has been compromised": 85,
    "suspicious activity on your account": 82,
    "suspicious transaction on your account": 82,
    "unauthorized transaction detected": 85,
    "unauthorized access to your account": 85,
    "your account is at risk": 80,
    "your account is frozen": 82,
    "account is frozen": 80,
    "problem with your account": 55,
    "issue with your account": 55,
    "account will be closed": 80,
    "account will be permanently closed": 88,
    # OTP/credential requests (English phrasing)
    "share the otp": 90,
    "share your otp": 90,
    "share an otp": 90,
    "tell me the otp": 90,
    "give me the otp": 90,
    "provide the otp": 90,
    "read the otp": 88,
    "otp that you will receive": 90,
    "otp you received": 88,
    "otp sent to your": 85,
    "verification code": 78,
    "share your pin": 90,
    "tell me your pin": 90,
    "enter your pin": 82,
    "share your password": 90,
    "share your card number": 90,
    "tell me your card number": 90,
    "give me your card number": 90,
    "what is your card number": 88,
    "provide your card number": 88,
    "read out your card number": 90,
    "card number please": 82,
    "your card details": 80,
    "give me your card details": 88,
    "tell me your card details": 88,
    "share your card details": 88,
    "need your card details": 85,
    "provide your card details": 85,
    "credit card number": 82,
    "credit card information": 82,
    "debit card number": 82,
    "debit card information": 82,
    "16 digit number on your card": 90,
    "16 digit card number": 88,
    "number on front of your card": 85,
    "three digit number on the back": 88,
    "last four digits of your card": 78,
    "cvv number": 85,
    "cvv on the back": 88,
    "what is your cvv": 90,
    "tell me your cvv": 90,
    "share your cvv": 90,
    "expiry date of your card": 80,
    "card expiry date": 78,
    "when does your card expire": 78,
    "card details for verification": 88,
    "bank details for verification": 85,
    "account number for verification": 85,
    # Unblock/fix promises — moderate signals (legitimate banks don't
    # promise to "unblock" over the phone with just an OTP)
    "we can unblock it": 55,
    "we will unblock your account": 58,
    "unblock your account": 55,
    "reactivate your account": 52,
    "restore your account": 52,
    "fix your account": 45,
    "resolve this issue": 30,
    "verify your identity": 35,
    "for security purposes": 30,
    "for verification purposes": 32,
    "all you need to do is": 40,
    "just need to verify": 38,
    "confirm your details": 38,
    # KYC scam (English)
    "kyc verification required": 80,
    "kyc has expired": 82,
    "update your kyc": 78,
    "complete your kyc": 78,
    "kyc not completed": 75,
    "link your aadhaar": 72,
    "link your pan card": 72,
    "aadhaar verification": 70,
    # Payment / fine / fee demands
    "pay the fine": 75,
    "pay the penalty": 75,
    "pay the penalty amount": 78,
    "pay a fine of": 78,
    "pay the settlement amount": 80,
    "settlement amount": 72,
    "pay compensation amount": 78,
    "pay processing fee": 75,
    "pay the processing charges": 75,
    "refundable security deposit": 78,
    "security deposit required": 75,
    "registration fee required": 72,
    "pay registration fee": 72,
    "pay the charges": 70,
    "pay to release": 80,
    "pay to unlock": 80,
    "send money immediately": 82,
    "transfer money now": 80,
    "transfer money immediately": 82,
    "do a upi transfer": 75,
    "upi transfer karo": 78,
    "go to nearest atm": 72,
    "go to the atm": 70,
    "withdraw cash and deposit": 80,
    "deposit money in this account": 80,
    "send money to this account": 82,
    "transfer to this account number": 80,
    "pay through google pay": 72,
    "send through phonepe": 72,
    "pay via paytm": 72,
}

# === FAMILY EMERGENCY & VOICE CLONING SCAMS ===
FAMILY_EMERGENCY_PATTERNS: dict[str, int] = {
    "hello beta i am in serious trouble": 95,
    "ive been in an accident dont tell anyone": 95,
    "stuck in dubai canada abroad arrested": 90,
    "phone is broken thats why i sound different": 95,
    "dont tell mom dad about this": 85,
    "police station mein hun urgent help": 90,
    "accident hua hai immediate money needed": 90,
    "kidnappers have me send ransom": 95,
    "medical emergency surgery required": 85,
    "bail money needed right now": 90,
    "aapko kuch ho gaya hai": 90,
    "hospital mein admit hai": 90,
    "turant paisa chahiye": 85,
    "dadi nani main aapka pota hun": 90,
    "bache ko kuch ho gaya hai": 95,
    "accident mein serious condition": 90,
    "operation ki zarurat hai": 85,
    "blood ki emergency hai": 85,
    "police case mein fansa hai": 90,
    "college ragging mein problem": 80,
    "dost ke saath mushkil mein": 75,
    "paise ki bahut zarurat hai": 80,
    "mama chacha emergency": 85,
    "bua ki tabiyat kharab": 82,
    "nana nani hospital": 88,
    "cousin brother accident": 85,
    "family member arrested": 92,
    "relative needs urgent surgery": 88,
    "grandmother heart attack": 90,
    "uncle needs immediate help": 85,
}

# === HINDI ADVANCED PATTERNS (Romanized + Devanagari) ===
HINDI_ADVANCED_PATTERNS: dict[str, int] = {
    # Respectful manipulation
    "sarkar ki taraf se": 85,
    "aapko court mein hazir hona hoga": 90,
    "ye ek legal matter hai": 85,
    "immediate action lena padega": 80,
    "aapke khilaaf case file ho gaya": 90,
    "warrant nikla hai aapke naam": 95,
    "police aane wali hai": 90,
    "ghar ki talashi hogi": 85,
    "account freeze ho jayega": 85,
    "property attach kar denge": 85,
    # Authority terms
    "collector sahab se baat karo": 85,
    "sp sahab ka order hai": 90,
    "judge sahab ne kaha hai": 95,
    "commissioner ka call hai": 90,
    "magistrate ka summon": 90,
    "thana incharge se milna hoga": 85,
    "sarkari kaam hai urgent": 80,
    "government ka faisla": 85,
    "mantri ji ka order": 88,
    "secretary sahab ka message": 85,
    "dm sahab se baat": 87,
    "ias officer calling": 85,
    "ips officer urgent": 88,
    "tehsildar ka notice": 82,
    "patwari se verification": 75,
    "election commission notice": 85,
    "returning officer message": 80,
    # Banking / Financial Hindi
    "bank manager urgent call": 75,
    "loan default case": 85,
    "emi bounce notice": 80,
    "credit card block": 78,
    "account overdraft": 76,
    "cheque bounce case": 85,
    "loan recovery agent": 82,
    "bank fraud detection": 85,
    "suspicious transaction": 80,
    "kyc verification pending": 75,
    "aadhar link mandatory": 72,
    "pan card verification": 70,
    "income tax notice": 85,
    "gst registration issue": 78,
    "service tax pending": 75,
    "property tax notice": 72,
    "electricity bill default": 68,
    "gas connection problem": 65,
    "water bill pending": 62,
    "telephone bill issue": 65,
    # --- Hindi Devanagari patterns (match IndicConformer output) ---
    # Bank calling
    "बैंक से कॉल कर रहे हैं": 35,
    "बैंक से बोल रहा हूं": 35,
    "बैंक से बात कर रहे हैं": 35,
    # Account threats
    "अकाउंट लॉक हो गया है": 82,
    "अकाउंट ब्लॉक हो गया है": 82,
    "अकाउंट बंद हो गया है": 82,
    "अकाउंट बंद हो जाएगा": 82,
    "अकाउंट फ्रीज हो गया": 82,
    "अकाउंट सस्पेंड हो गया": 82,
    "अकाउंट में प्रॉब्लम": 55,
    "अकाउंट में समस्या": 55,
    "खाता बंद हो जाएगा": 82,
    "खाता बंद हो गया": 82,
    "खाता ब्लॉक": 80,
    "खाता फ्रीज": 80,
    "अकाउंट डिएक्टिवेट": 85,
    # OTP / credential requests (Devanagari — IndicConformer spaces the letters)
    "ओ टी पी बता": 90,
    "ओटीपी बता": 90,
    "ओ टी पी शेयर": 90,
    "ओटीपी शेयर": 90,
    "ओ टी पी दे": 90,
    "ओ टी पी भेज": 88,
    "ओ टी पी आएगा": 85,
    "ओटीपी आएगा": 85,
    "पिन बताओ": 90,
    "पिन बता दो": 90,
    "पिन शेयर करो": 90,
    "पासवर्ड बताओ": 90,
    "पासवर्ड बता दो": 90,
    "कार्ड नंबर बताओ": 88,
    "सीवीवी बताओ": 88,
    # Verification / KYC Hindi
    "केवाईसी वेरिफिकेशन": 78,
    "केवाईसी अपडेट करो": 78,
    "आधार लिंक करो": 72,
    "आधार वेरिफिकेशन": 70,
    "पैन कार्ड वेरिफिकेशन": 70,
    # Urgency Hindi Devanagari
    "तुरंत कार्रवाई करें": 80,
    "जल्दी करो": 40,
    "अभी के अभी": 40,
    # Legal / authority Hindi
    "पुलिस केस दर्ज": 88,
    "गिरफ्तारी वारंट": 95,
    "कोर्ट में पेश होना": 90,
    "कानूनी कार्रवाई": 85,
    "एफआईआर दर्ज": 88,
}

# === TELUGU ADVANCED PATTERNS (Script + Romanized) ===
TELUGU_ADVANCED_PATTERNS: dict[str, int] = {
    # Telugu script
    "మీ ఖాతా మూసివేయబడుతుంది": 85,
    "వెంటనే verify చేయండి": 80,
    "పోలీసులు రావడానికి సిద్ధమవుతున్నారు": 90,
    "అరెస్ట్ వారెంట్ వచ్చింది": 95,
    "చట్టపరమైన చర్య తీసుకుంటాం": 85,
    "బ్యాంక్ ఖాతా బ్లాక్ అవుతుంది": 85,
    "న్యాయస్థానంలో హాజరు కావాలి": 90,
    "సైబర్ క్రైమ్ కేసు రిజిస్టర్ అయింది": 90,
    "ఆధార్ కార్డ్ misuse అయింది": 82,
    "పాన్ కార్డ్ duplicate దొరికింది": 85,
    # Romanized Telugu
    "mee account block avuthundi": 85,
    "police station vellaali": 90,
    "legal case file ayyindi": 85,
    "court lo hazaru kaavaali": 90,
    "warrant vachindi mee meeda": 95,
    "cyber crime police raabothunnaru": 90,
    "bank nundi call chesaaru": 75,
    "money transfer cheyyaali": 80,
    "otp share cheyyandi": 85,
    "verification ki details": 75,
    # IT professional targeting
    "software company case": 80,
    "h1b visa problem": 85,
    "us lo arrest warrant": 90,
    "green card application reject": 80,
    "offshore account freeze": 85,
    "tax evasion case filed": 85,
    "foreign remittance issue": 80,
    "rbi foreign exchange violation": 85,
    "it returns filing problem": 78,
    "form 16 discrepancy": 75,
    "tds certificate issue": 72,
    "pf account problem": 70,
    "esi registration issue": 68,
    "visa interview call": 82,
    "embassy verification": 85,
    "consulate urgent message": 80,
    "immigration department": 88,
    "homeland security": 90,
    "customs declaration": 75,
    "airport security alert": 85,
    # Regional Telugu authority
    "collector garu message": 85,
    "sp garu urgent call": 88,
    "mla garu office": 75,
    "mp garu secretary": 78,
    "cm office nundi": 90,
    "governor office call": 85,
    "ias officer message": 82,
    "ips officer urgent": 85,
    "mandal officer call": 75,
    "village secretary": 68,
    "vro office urgent": 70,
    "vra verification": 65,
    "college fees issue": 70,
    "hostel fee pending": 68,
    "scholarship problem": 72,
    "fee reimbursement": 70,
}

# === MIXED LANGUAGE (HINGLISH) PATTERNS ===
HINGLISH_PATTERNS: dict[str, int] = {
    "sir aapka computer infected hai": 75,
    "aapko refund mil sakta hai": 75,
    "verification ke liye details chahiye": 80,
    "customer care se call kar rahe": 70,
    "aapka account hack ho gaya": 80,
    "virus remove karna padega": 75,
    "technical support ki zarurat": 70,
    "microsoft se official call": 75,
    "windows license expire ho gaya": 70,
    "security breach detect hua": 80,
    "firewall update karna hai": 70,
    "remote access dena hoga": 85,
    "otp share karo verification ke liye": 85,
    "upi pin batao security check": 90,
    "net banking password confirm karo": 95,
    "credit card details verify": 88,
    "debit card block ho gaya": 82,
    "internet banking suspended": 85,
    "mobile banking issue": 78,
    "paytm account problem": 75,
    "phonepe verification": 72,
    "google pay security": 75,
    "bhim app update": 68,
    "upi transaction failed": 70,
    "digital wallet freeze": 80,
    "crypto wallet hack": 85,
    "trading account issue": 82,
    "demat account problem": 78,
    "mutual fund redemption": 72,
    "insurance claim pending": 75,
    # Platform / e-commerce impersonation
    "this is amazon customer service": 72,
    "calling from amazon": 68,
    "amazon order problem": 65,
    "amazon refund pending": 70,
    "amazon prime membership": 62,
    "flipkart calling": 68,
    "flipkart order issue": 65,
    "flipkart refund": 65,
    "calling from flipkart": 68,
    "meesho order problem": 65,
    "swiggy delivery issue": 60,
    "zomato order problem": 60,
    "zomato refund": 60,
    "ola customer care": 62,
    "uber support calling": 62,
    # Hindi utility threats
    "bijli kat jayegi": 78,
    "bijli connection band": 75,
    "bijli ka bill pending": 72,
    "light kat jayegi": 75,
    "electricity bill overdue": 72,
    "gas connection band ho jayega": 75,
    "gas supply disconnect": 72,
    "pani ka connection band": 70,
    "water supply disconnect": 70,
    # Unclaimed / maturity scams
    "unclaimed insurance amount": 75,
    "unclaimed money in your name": 78,
    "policy maturity amount": 72,
    "bonus amount pending": 70,
    # Job scam patterns
    "work from home job offer": 68,
    "work from home guaranteed income": 75,
    "data entry job guaranteed": 72,
    "online job guaranteed salary": 75,
    "pay for training material": 72,
    "pay for training kit": 72,
    "pay to start the job": 78,
    "job registration fee": 72,
    # Part-time / earn-from-home scams
    "earn from home": 70,
    "earn daily from home": 75,
    "simple typing work": 72,
    "guaranteed salary": 75,
    "guaranteed income": 75,
    "no experience required start": 72,
    "send security deposit for": 80,
    "pay security deposit for": 80,
    "training material and id card": 75,
    "verified company": 60,
    "many people already earning": 68,
}

# ---------------------------------------------------------------------------
# Cross-language indicator sets (bonus points if found)
# ---------------------------------------------------------------------------

URGENCY_WORDS: set[str] = {
    # English
    "immediately", "urgent", "quickly", "emergency",
    "right now", "within minutes", "before midnight",
    "today only", "limited time", "last chance", "expires soon",
    "deadline", "time sensitive", "critical", "asap",
    "without delay", "right away", "this instant", "at once",
    # Hindi
    "turant", "jaldi", "abhi", "foran", "tatkal",
    "zaruri", "aaj hi", "do ghante mein",
    "der mat karo", "time nahi hai", "jaldi karo",
    "abhi ke abhi", "is waqt", "isi samay", "turant se",
    # Telugu
    "వెంటనే", "త్వరగా", "ఇప్పుడే", "అత్యవసరం",
    "immediatelyga", "jaldiga", "emergency lo",
    "time ledu", "twaraga cheyyandi", "ventane cheyandi",
    # Mixed
    "urgent hai", "immediate action",
    "emergency mein", "turant karo", "emergency call", "urgent matter",
}

AUTHORITY_WORDS: set[str] = {
    # Law enforcement
    "police", "cbi", "ncb", "enforcement directorate",
    "income tax", "customs", "rbi", "sebi", "trai", "court",
    "judge", "magistrate", "collector", "commissioner",
    "inspector", "superintendent", "constable",
    "sub inspector", "circle officer",
    # Hindi
    "पुलिस", "न्यायाधीश", "कलेक्टर", "आयुक्त",
    "थाना", "कोर्ट", "सरकार", "अफसर",
    "मजिस्ट्रेट", "न्यायालय", "पुलिस अधीक्षक",
    # Telugu
    "పోలీసు", "న్యాయమూర్తి", "కలెక్టర్", "కమిషనర్",
    "ప్రభుత్వం", "అధికారి", "కోర్టు", "న్యాయస్థానం",
    # Romanized
    "police waala", "officer sahab", "sarkar", "government",
    "adhikari", "crime branch", "special branch",
    "vigilance", "anti corruption", "enforcement",
}

FINANCIAL_RISK_TERMS: set[str] = {
    # Direct money requests
    "money transfer", "bank details", "account number",
    "ifsc code", "upi pin", "otp", "cvv", "atm pin",
    "net banking password", "debit card number", "credit card details",
    "card number", "card details", "card information",
    "expiry date", "security code", "mpin", "transaction password",
    # Hindi financial
    "paisa bhejo", "account details do", "pin batao",
    "otp share karo", "bank se paise", "transfer karo",
    "paise ki zarurat", "amount send", "rupaye bhejo",
    # Banking apps
    "phonepe", "paytm", "google pay", "bhim upi",
    "amazon pay", "mobikwik", "freecharge", "airtel money",
    # Crypto
    "bitcoin", "crypto", "wallet address", "private key",
    "metamask", "binance", "coinbase", "usdt",
    "ethereum", "blockchain",
    # Investment
    "guaranteed returns", "double money", "risk free",
    "insider information", "sure shot profit", "limited offer",
    "high returns", "quick money", "easy profit",
}

TECH_SUPPORT_TERMS: set[str] = {
    "microsoft", "windows", "virus", "malware",
    "firewall", "hacker", "ip address",
    "remote access", "teamviewer", "anydesk", "chrome",
    "computer slow", "pop up", "browser",
    "license expired", "technical support", "customer care",
    "antivirus", "trojan", "spyware", "ransomware",
    "phishing", "suspicious activity", "unauthorized access",
    "system compromise", "data breach", "identity theft",
}

SECRECY_ISOLATION_TERMS: set[str] = {
    # English
    "dont tell anyone", "don't tell anyone", "do not tell anyone",
    "keep this between us", "keep this confidential",
    "do not inform", "do not discuss",
    "confidential matter", "secret matter",
    "do not contact a lawyer", "no need to tell",
    "tell nobody", "inform nobody",
    # Hindi
    "kisi ko mat batana", "kisi ko mat bolo",
    "kisi ko bhi mat batao", "family ko mat bolo",
    "ghar mein kisi ko mat", "ye secret rakhna",
    "किसी को मत बताना", "किसी को बोलना मत",
    "परिवार को मत बताओ", "गोपनीय रखना",
    # Telugu
    "ఎవరికీ చెప్పకు", "ఎవరికీ చెప్పకండి",
    "secret ga unchandi", "evvariki cheppakandi",
}

# All categories for iteration
PATTERN_CATEGORIES: list[tuple[str, dict[str, int]]] = [
    ("DIGITAL_ARREST", DIGITAL_ARREST_PATTERNS),
    ("TRAI_SCAM", TRAI_PATTERNS),
    ("COURIER_SCAM", COURIER_PATTERNS),
    ("INVESTMENT_FRAUD", INVESTMENT_PATTERNS),
    ("BANK_OTP", BANK_OTP_PATTERNS),
    ("FAMILY_EMERGENCY", FAMILY_EMERGENCY_PATTERNS),
    ("HINDI_SCAM", HINDI_ADVANCED_PATTERNS),
    ("TELUGU_SCAM", TELUGU_ADVANCED_PATTERNS),
    ("HINGLISH_SCAM", HINGLISH_PATTERNS),
]

CATEGORY_LABELS: dict[str, str] = {
    "DIGITAL_ARREST": "Digital arrest / authority impersonation scam",
    "TRAI_SCAM": "TRAI / telecom authority scam",
    "COURIER_SCAM": "FedEx / courier / customs scam",
    "INVESTMENT_FRAUD": "Investment / cryptocurrency fraud",
    "BANK_OTP": "Bank impersonation / OTP theft",
    "FAMILY_EMERGENCY": "Family emergency / voice cloning scam",
    "HINDI_SCAM": "Hindi authority / banking scam",
    "TELUGU_SCAM": "Telugu targeted scam",
    "HINGLISH_SCAM": "Hinglish tech-support / banking scam",
    "KEYWORD_COOCCUR": "Suspicious keyword combination detected",
    "URGENCY": "Artificial urgency detected",
    "AUTHORITY": "Authority impersonation language",
    "FINANCIAL_RISK": "Financial credential request",
    "TECH_SUPPORT": "Tech-support scam language",
    "SECRECY": "Secrecy / isolation demand",
    **{f"KEYWORD_COOCCUR:{k}": v for k, v in ARCHETYPE_LABELS.items()},
}


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _check_patterns(
    text: str,
    patterns: dict[str, int],
    detected: list[str],
    category: str,
) -> int:
    """Check text against a pattern dict. Returns aggregated score."""
    score = 0
    count = 0
    for phrase, points in patterns.items():
        if phrase in text:
            score += points
            count += 1
            detected.append(f"[{category}] {phrase} (+{points})")
    # 10 % boost per additional hit in same category
    if count > 1:
        score = int(score * (1.0 + (count - 1) * 0.1))
    return score


def _check_indicator_set(
    text: str,
    indicators: set[str],
    detected: list[str],
    category: str,
    bonus: int,
) -> int:
    """Return a one-time bonus if any indicator is found."""
    for word in indicators:
        if word in text:
            detected.append(f"[{category}] {word} (+{bonus})")
            return bonus
    return 0




def analyze_text(text: str) -> ScamAnalysis:
    """Analyze transcribed text for scam patterns.

    Two detection layers:
    1. Exact phrase matching (574+ patterns, 9 English categories).
    2. Keyword co-occurrence (13 archetypes × 10 Indian scripts + English).
    Plus cross-language urgency/authority/financial/tech-support/secrecy indicator bonuses.
    """
    if not text or not text.strip():
        return ScamAnalysis(
            is_scam=False,
            risk_score=0.0,
            matched_patterns=[],
            explanation="No text to analyze.",
        )

    lower = text.lower()
    total_score = 0
    detected: list[str] = []
    category_scores: dict[str, int] = {}

    # Check every pattern category
    for cat_name, cat_patterns in PATTERN_CATEGORIES:
        cat_score = _check_patterns(lower, cat_patterns, detected, cat_name)
        if cat_score:
            category_scores[cat_name] = cat_score
            total_score += cat_score

    # Keyword co-occurrence detector (for code-switched speech)
    cooccur_score = check_keyword_cooccurrence(lower, detected)
    if cooccur_score:
        category_scores["KEYWORD_COOCCUR"] = cooccur_score
        total_score += cooccur_score

    # Cross-language indicator bonuses (each counted at most once)
    total_score += _check_indicator_set(
        lower, URGENCY_WORDS, detected, "URGENCY", 15
    )
    total_score += _check_indicator_set(
        lower, AUTHORITY_WORDS, detected, "AUTHORITY", 20
    )
    total_score += _check_indicator_set(
        lower, FINANCIAL_RISK_TERMS, detected, "FINANCIAL_RISK", 25
    )
    total_score += _check_indicator_set(
        lower, TECH_SUPPORT_TERMS, detected, "TECH_SUPPORT", 12
    )
    total_score += _check_indicator_set(
        lower, SECRECY_ISOLATION_TERMS, detected, "SECRECY", 20
    )

    # Cap at 100
    total_score = min(100, total_score)

    if total_score == 0:
        logger.info("SCAM_DEBUG | input=%r | score=0 | NO_MATCH", text[:120])
        return ScamAnalysis(
            is_scam=False,
            risk_score=0.0,
            matched_patterns=[],
            explanation="No scam patterns detected.",
        )

    # Normalise to 0.0-1.0
    risk_score = round(total_score / 100.0, 2)
    is_scam = risk_score >= 0.6

    # Build human-readable pattern list (deduplicate by category label)
    matched_labels: list[str] = []
    for cat in category_scores:
        label = CATEGORY_LABELS.get(cat, cat)
        if label not in matched_labels:
            matched_labels.append(label)
    # Add archetype-specific labels from keyword co-occurrence
    for d in detected:
        if d.startswith("[KEYWORD_COOCCUR:"):
            tag = d.split("]")[0][1:]  # e.g. "KEYWORD_COOCCUR:bank_otp"
            label = CATEGORY_LABELS.get(tag, "")
            if label and label not in matched_labels:
                matched_labels.append(label)
    # Add indicator labels if they fired
    for tag in ("URGENCY", "AUTHORITY", "FINANCIAL_RISK", "TECH_SUPPORT", "SECRECY"):
        if any(f"[{tag}]" in d for d in detected):
            label = CATEGORY_LABELS[tag]
            if label not in matched_labels:
                matched_labels.append(label)

    if is_scam:
        if total_score > 90:
            level = "CRITICAL THREAT"
        elif total_score > 70:
            level = "HIGH RISK"
        else:
            level = "SCAM DETECTED"
        explanation = (
            f"{level} ({total_score}%): Detected {len(detected)} "
            f"scam indicator(s) — {', '.join(matched_labels[:3])}"
        )
    else:
        explanation = (
            f"LOW RISK ({total_score}%): Some suspicious patterns — "
            f"{', '.join(matched_labels[:2])}"
        )

    logger.info(
        "SCAM_DEBUG | input=%r | score=%d | is_scam=%s | hits=%d | categories=%s",
        text[:120], total_score, is_scam, len(detected),
        ", ".join(matched_labels),
    )
    for d in detected:
        logger.debug("  PATTERN_HIT | %s", d)

    return ScamAnalysis(
        is_scam=is_scam,
        risk_score=risk_score,
        matched_patterns=matched_labels,
        explanation=explanation,
        debug_details=detected,
    )


def analyze_session(
    chunks: list[str],
    tracker: NarrativeTracker | None = None,
    classifier: "ScamClassifier | None" = None,
) -> ScamAnalysis:
    """Analyze a sequence of transcript chunks with narrative tracking.

    Uses per-chunk analysis (not concatenation) to avoid false co-occurrence
    matches from unrelated words across chunks.  The narrative phase acts as
    a confidence gate: a high risk score alone isn't enough — the call must
    also progress through the manipulation arc (HOOK→ESCALATE→ISOLATE→TRAP).

    When a classifier is provided, it acts as a secondary confidence layer
    that can suppress false positives from keyword coincidences.

    Args:
        chunks: List of transcript chunks in chronological order.
        tracker: Optional pre-existing NarrativeTracker instance (for
                 ongoing WebSocket sessions). If None, creates a new one.
        classifier: Optional trained ScamClassifier for intent-based
                    false positive suppression.

    Returns:
        ScamAnalysis with both pattern scores and narrative phase info.
    """
    if tracker is None:
        tracker = NarrativeTracker()

    # Analyze each chunk individually; keep the highest-risk result
    best_result = None
    all_patterns = []
    all_debug = []
    for chunk in chunks:
        tracker.advance(chunk)
        r = analyze_text(chunk)
        if best_result is None or r.risk_score > best_result.risk_score:
            best_result = r
        all_patterns.extend(r.matched_patterns)
        all_debug.extend(r.debug_details)

    if best_result is None:
        best_result = ScamAnalysis(
            is_scam=False, risk_score=0.0, matched_patterns=[],
            explanation="No text to analyze",
        )

    # De-duplicate patterns
    seen = set()
    unique_patterns = []
    for p in all_patterns:
        if p not in seen:
            seen.add(p)
            unique_patterns.append(p)
    best_result.matched_patterns = unique_patterns
    best_result.debug_details = all_debug

    # Overlay narrative state
    narrative = tracker.get_state()
    best_result.narrative_phase = narrative.best_phase
    best_result.narrative_archetype = narrative.best_archetype
    best_result.narrative_phase_label = narrative.phase_label
    best_result.narrative_phase_score = narrative.phase_score

    # --- Classifier-based confidence layer ---
    # When available, the ML classifier provides a second opinion on each
    # chunk.  We use the MEAN confidence across chunks (not max) because
    # legitimate calls have consistently low scores while scam calls have
    # at least some high-confidence chunks that pull the mean up.
    classifier_scam_score = None
    if classifier is not None:
        scam_confidences = []
        for chunk in chunks:
            if chunk.strip():
                cr = classifier.predict(chunk)
                scam_confidences.append(cr.confidence)
        if scam_confidences:
            classifier_scam_score = sum(scam_confidences) / len(scam_confidences)
            best_result.debug_details.append(
                f"[CLASSIFIER] mean_confidence={classifier_scam_score:.2f} "
                f"max={max(scam_confidences):.2f}"
            )

    # Final scam decision: require BOTH a risk threshold AND narrative
    # progression.  Thresholds are tiered: higher narrative confidence
    # allows lower risk thresholds (the manipulation arc confirms intent).
    #
    # KEY INSIGHT: Legitimate calls routinely reach ESCALATE because
    # common words ("bank", "account", "police", "insurance") match
    # archetype context/threat keywords.  Only ISOLATE and TRAP phases
    # indicate actual manipulation tactics (secrecy demands, credential
    # requests), so those get lower thresholds.
    if narrative.phase_score >= 95:  # TRAP — full manipulation arc
        best_result.is_scam = best_result.risk_score >= 0.3
    elif narrative.phase_score >= 65:  # ISOLATE — secrecy/isolation demands
        best_result.is_scam = best_result.risk_score >= 0.5
    elif narrative.phase_score >= 40:  # ESCALATE — common in legit calls too
        best_result.is_scam = best_result.risk_score >= 0.9
    else:  # HOOK or IDLE
        best_result.is_scam = best_result.risk_score >= 0.95

    # Classifier override: if the keyword engine flagged scam but the ML
    # classifier is confident it's legitimate, suppress the alert.
    # This specifically fixes false positives like "credit card application
    # approved" where domain vocabulary triggers keyword co-occurrence.
    #
    # GUARD: Only override when the classifier is actually confident
    # (mean < 0.45).  At 0.45-0.50 the classifier is uncertain (e.g.,
    # on Devanagari/native script text it hasn't been trained on) and
    # should not suppress real scams.
    if (classifier_scam_score is not None
            and best_result.is_scam
            and classifier_scam_score < 0.45):
        best_result.is_scam = False
        best_result.debug_details.append(
            f"[CLASSIFIER_OVERRIDE] suppressed: classifier_conf={classifier_scam_score:.2f}"
        )

    if best_result.is_scam and narrative.best_phase in ("ISOLATE", "TRAP"):
        best_result.explanation = (
            f"NARRATIVE ALERT ({narrative.best_phase}): "
            f"{narrative.phase_label} | {best_result.explanation}"
        )

    return best_result
