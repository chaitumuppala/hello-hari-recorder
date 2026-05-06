"""100-case evaluation suite for scam detection pipeline.

Categories:
  A. Scam calls (40 cases) — diverse types, languages, phrasing
  B. Legitimate calls (40 cases) — domain-heavy, everyday, professional
  C. Edge/adversarial cases (20 cases) — meta-scam, ambiguous, tricky
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

def run(name, chunks, expected):
    # Layer 1: Keyword only (stateless per-chunk)
    kw = any(analyze_text(c).is_scam for c in chunks)

    # Layer 2: Keyword + Narrative (no classifier)
    t2 = NarrativeTracker()
    r2 = analyze_session(chunks, t2, classifier=None)
    narr = r2.is_scam

    # Layer 3: Keyword + Narrative + ML Classifier (full pipeline)
    t3 = NarrativeTracker()
    r3 = analyze_session(chunks, t3, classifier=_classifier)
    n3 = t3.get_state()
    ml = r3.is_scam

    return {
        "name": name, "phase": n3.best_phase, "ps": n3.phase_score,
        "risk": r3.risk_score, "kw": kw, "narr": narr, "ml": ml,
        "exp": expected, "ok": ml == expected,
        "arch": n3.best_archetype,
    }

# ===================================================================
# A. SCAM CALLS (40 cases)
# ===================================================================
SCAMS = [
    # A1-A5: Digital arrest variants
    ("A01 Digital arrest: Classic CBI", [
        "hello sir this is from cbi headquarters new delhi",
        "a drug trafficking case has been registered under your aadhaar number",
        "do not disconnect the call or inform anyone this is confidential",
        "transfer 50000 as security deposit to clear your name",
    ], True),
    ("A02 Digital arrest: ED variant", [
        "this is enforcement directorate calling regarding money laundering investigation",
        "your bank account is being used for hawala transactions suspicious international transfers",
        "this is a very sensitive matter do not contact a lawyer or family",
        "you need to transfer your savings to a safe rbi account immediately",
    ], True),
    ("A03 Digital arrest: Hinglish", [
        "sir main mumbai police cyber cell se bol raha hun",
        "aapke naam pe ek case register hua hai non bailable fir",
        "kisi ko mat batana ye confidential government matter hai",
        "abhi ke abhi 1 lakh transfer karo warna arrest ho jayega",
    ], True),
    ("A04 Digital arrest: Telugu", [
        "hello sir cyber crime police nundi call chesaaru",
        "mee aadhaar card misuse ayyindi anti national activities linked",
        "evvariki cheppakandi confidential matter idi court order",
        "money transfer cheyyaali immediately leda warrant vachindi",
    ], True),
    ("A05 Digital arrest: Devanagari", [
        "नमस्ते मैं सीबीआई अधिकारी बोल रहा हूं",
        "आपके खिलाफ ड्रग ट्रैफिकिंग का केस दर्ज हुआ है गिरफ्तारी वारंट जारी",
        "किसी को मत बताना गोपनीय रखना कॉल कट मत करो",
        "तुरंत पैसे ट्रांसफर करो सिक्योरिटी डिपॉजिट के रूप में",
    ], True),

    # A6-A10: Bank OTP variants
    ("A06 Bank OTP: SBI classic", [
        "hello sir calling from sbi bank fraud department",
        "unauthorized transaction of 89000 detected on your account",
        "your account will be permanently closed unless you verify right now",
        "share your 16 digit card number and the otp you will receive",
    ], True),
    ("A07 Bank OTP: Hinglish HDFC", [
        "hello sir main hdfc bank se bol raha hun aapke account mein problem hai",
        "aapka account block ho gaya hai suspicious activity ki wajah se",
        "jaldi karo warna account permanently deactivate ho jayega",
        "apna card number batao aur jo otp aayega wo bata dena",
    ], True),
    ("A08 Bank OTP: Devanagari", [
        "बैंक से बोल रहा हूं आपका अकाउंट ब्लॉक हो गया",
        "अनऑथराइज्ड ट्रांजैक्शन डिटेक्ट हुआ है अकाउंट फ्रीज होगा",
        "तुरंत वेरिफाई करना होगा अभी के अभी",
        "ओटीपी बताओ और कार्ड नंबर शेयर करो",
    ], True),
    ("A09 Bank OTP: UPI theft", [
        "sir your google pay account has suspicious activity",
        "someone is trying to transfer money from your account",
        "to block this transaction I need to verify urgently",
        "tell me your upi pin and the otp sent to your phone",
    ], True),
    ("A10 Bank OTP: KYC variant", [
        "hello your bank kyc has expired your account will be closed in 24 hours",
        "all your money will be frozen if kyc is not updated immediately",
        "click the link I am sending to update or tell me your aadhaar number",
        "also share your card details and otp for verification",
    ], True),

    # A11-A15: TRAI / telecom
    ("A11 TRAI: Classic IVR", [
        "this is an automated call from telecom regulatory authority of india",
        "22 complaints registered against your mobile sim illegal usage detected",
        "your number will be disconnected in 2 hours and fir will be filed",
        "press 1 to speak with officer or pay compliance fee immediately",
    ], True),
    ("A12 TRAI: Hinglish", [
        "main trai se bol raha hun aapke number pe bahut complaints aaye hain",
        "sim card band hone wala hai telecom fraud detected on your number",
        "ye bahut urgent hai abhi ke abhi action lena padega",
        "recharge karo ya press 1 karo nahi toh disconnection ho jayega",
    ], True),
    ("A13 TRAI: SIM cloning", [
        "sir your sim card has been cloned someone is using your number",
        "we detected illegal call forwarding on your number",
        "do not make any calls until this is resolved this is urgent",
        "pay the verification fee of 2000 to protect your number immediately",
    ], True),

    # A14-A18: Courier / customs
    ("A14 Courier: FedEx classic", [
        "this is fedex international logistics department about your parcel",
        "140 grams of narcotic drugs found in package addressed to you",
        "we are connecting you to narcotics control bureau officer",
        "pay settlement amount of 2 lakhs or face criminal prosecution",
    ], True),
    ("A15 Courier: DHL variant", [
        "calling from dhl customs clearance your shipment has been seized",
        "five passports and counterfeit currency found in your consignment",
        "do not tell anyone about this investigation is ongoing",
        "transfer the customs duty and penalty amount immediately to release",
    ], True),
    ("A16 Courier: Hinglish", [
        "sir aapke naam se ek parcel aaya hai jismein drugs found hue hain",
        "ye bahut serious case hai customs ne aapke parcel ko confiscate kiya hai",
        "kisi ko mat batao ye investigation chal rahi hai",
        "fine pay karo nahi toh arrest hoga 50000 immediately bhejo",
    ], True),

    # A17-A20: Investment / lottery
    ("A17 Investment: Stock tips", [
        "hello sir I have insider information about a stock that will go 10x",
        "guaranteed returns of 300 percent in one month see screenshots of profits",
        "only 50 seats left in our vip group this offer expires tonight",
        "pay registration fee of 10000 rupees to join send money now",
    ], True),
    ("A18 Lottery: WhatsApp lucky draw", [
        "congratulations your whatsapp number selected for lucky draw prize of 25 lakhs",
        "you are the winner of airtel lucky draw 2026",
        "claim your prize before the deadline expires in 24 hours today only",
        "pay gst tax of 5000 and processing fee through google pay to receive amount",
    ], True),
    ("A19 Investment: Crypto Hinglish", [
        "bhai ek amazing crypto opportunity hai guaranteed double money in 30 days",
        "mere group ke sab log profit kama rahe hain risk free hai bilkul",
        "bas 20000 invest karo aur 60000 milega offer limited hai",
        "abhi paisa bhejo is wallet address pe last chance hai",
    ], True),
    ("A20 Lottery: KBC", [
        "kaun banega crorepati lottery winner congratulations you won 50 lakhs",
        "your lucky number 8754 has been selected in the bumper draw",
        "to claim prize money you must pay processing fee and gst tax",
        "share your bank account details and pay 8000 rupees registration fee",
    ], True),

    # A21-A25: Family emergency
    ("A21 Family: Kidnapping ransom", [
        "hello we have your son do not call the police",
        "if you want to see him alive you must cooperate with us",
        "we are watching your house do not inform anyone",
        "transfer 5 lakhs to this account within 1 hour",
    ], True),
    ("A22 Family: Accident voice clone", [
        "hello beta I am in serious trouble please help me",
        "I have been in a bad accident and need surgery urgently",
        "dont tell mom dad about this they will panic",
        "send 2 lakh rupees immediately to this account for hospital",
    ], True),
    ("A23 Family: Hinglish accident", [
        "hello uncle main aapke bete ka dost bol raha hun",
        "bhaiya ka accident ho gaya hai hospital mein admit hain serious hai",
        "papa ko mat batao abhi woh tension mein aa jayenge",
        "50000 chahiye surgery ke liye turant bhejo please jaldi karo",
    ], True),
    ("A24 Family: Abroad variant", [
        "hello I am your sons friend calling from dubai",
        "he has been arrested at the airport for some document issue",
        "please dont tell others it will make the situation worse",
        "he needs bail money urgently transfer 3 lakhs right now",
    ], True),
    ("A25 Family: Grandparent scam", [
        "dadi main aapka pota bol raha hun bahut mushkil mein hun",
        "police case mein fansa hun station mein hun bail chahiye",
        "ghar mein kisi ko mat batao nahi toh aur problem hogi",
        "turant 1 lakh bhejo is number pe urgent hai bahut",
    ], True),

    # A26-A30: Tech support
    ("A26 Tech: Microsoft classic", [
        "hello this is microsoft technical support your windows license has expired",
        "we detected that your computer has been infected with a trojan virus",
        "you need to download anydesk so our engineer can fix it remotely",
        "the repair and license renewal fee is 15000 rupees pay now",
    ], True),
    ("A27 Tech: Amazon refund", [
        "hello calling from amazon customer service about your pending refund",
        "sir aapko refund mil sakta hai 5000 rupees verify karna hoga",
        "please install anydesk app I will guide you through the process",
        "now enter your bank details and upi pin to receive the refund",
    ], True),

    # A28-A30: Electricity / utility
    ("A28 Utility: Electricity Hindi", [
        "aapke ghar ki bijli ke baare mein call hai overdue bill hai",
        "3 mahine ka pending bill hai 12000 rupees defaulter list mein naam",
        "aaj raat 8 baje connection permanently cut kar diya jayega",
        "abhi google pay pe ye number pe pay karo warna bijli band",
    ], True),
    ("A29 Utility: Gas connection", [
        "your gas connection will be permanently disconnected tonight",
        "outstanding bill of 8000 rupees is pending since 3 months",
        "pay immediately through this upi link or connection will be shut",
        "scan this qr code and pay right now to avoid disconnection",
    ], True),

    # A30-A32: Job scam
    ("A30 Job: Work from home", [
        "congratulations you are selected for amazon work from home data entry job",
        "guaranteed salary 50000 per month no experience required start today",
        "limited seats only 20 positions remaining filling fast hurry",
        "pay registration fee 3000 and training kit 2000 to start immediately",
    ], True),
    ("A31 Job: Part time scam", [
        "earn 2000 daily from home just simple typing work on laptop",
        "this is a verified company many people already earning see proof",
        "but you need to register today offer closes at midnight",
        "send 5000 as security deposit for the training material and id card",
    ], True),

    # A32-A34: Insurance / loan
    ("A32 Insurance: Policy lapse", [
        "sir your lic policy is about to lapse today is the last date",
        "if you dont pay premium now your 50 lakh coverage will be gone",
        "the grace period ends at midnight you will lose no claim bonus",
        "share your bank account number and pay through upi immediately",
    ], True),
    ("A33 Loan: Pre-approved", [
        "congratulations you are eligible for pre-approved personal loan of 10 lakhs",
        "interest rate is only 5 percent lowest in market limited period offer",
        "approval will cancel if you dont pay processing fee today only",
        "pay 5000 processing fee and 2000 gst charges to disburse loan now",
    ], True),

    # A34-A36: Mixed / unusual
    ("A34 Mixed: Customs to arrest", [
        "this is customs department your parcel from thailand has been intercepted",
        "mdma synthetic narcotics detected in the package criminal case will be filed",
        "I am transferring you to ncb officer please stay on the line dont disconnect",
        "officer says you must pay fine and security deposit of 1 lakh immediately",
    ], True),
    ("A35 Mixed: Religious donation scam", [
        "hello I am calling from a charitable trust for temple renovation",
        "you have been selected for a special blessing donate and get 10x returns",
        "this is a divine opportunity limited time only dont miss your karma",
        "send donation of 21000 rupees immediately to this account for blessings",
    ], True),

    # A36-A40: Rapid / compressed scams
    ("A36 Rapid: One sentence scam", [
        "your account is blocked share otp to unblock or it will be permanently closed give me your card number now",
    ], True),
    ("A37 Rapid: Hindi 2-chunk", [
        "सीबीआई से बोल रहा हूं आपके नाम पर ड्रग केस है गिरफ्तारी वारंट जारी हुआ",
        "किसी को मत बताओ तुरंत 50000 ट्रांसफर करो नहीं तो जेल होगी",
    ], True),
    ("A38 Rapid: Telugu 2-chunk", [
        "cyber crime police nundi call warrant vachindi mee meeda arrest avtundi",
        "evvariki cheppakandi money transfer cheyyaali immediately otp share cheyyandi",
    ], True),
    ("A39 Rapid: Investment 1-liner", [
        "guaranteed 10x returns invest now only 100 slots remaining pay registration fee of 5000 limited time offer expires today",
    ], True),
    ("A40 Rapid: Family 2-chunk", [
        "hello beta bahut mushkil mein hun accident ho gaya hospital mein hun",
        "kisi ko mat batao turant 1 lakh bhejo surgery ke liye abhi ke abhi jaldi",
    ], True),
]

# ===================================================================
# B. LEGITIMATE CALLS (40 cases)
# ===================================================================
LEGIT = [
    # B1-B8: Bank / financial — informational
    ("B01 Legit: Bank FD maturity", [
        "hello sir this is rajesh from hdfc bank your relationship manager",
        "your fixed deposit of 5 lakhs has matured today",
        "would you like to renew or withdraw to savings account",
        "you can visit branch or do it through net banking",
    ], False),
    ("B02 Legit: Credit card approved", [
        "hello congratulations your credit card application has been approved",
        "your platinum card will be dispatched to registered address tomorrow",
        "you will receive it within 5 to 7 working days",
        "please call customer care if you have any questions thank you",
    ], False),
    ("B03 Legit: Loan sanctioned", [
        "hello sir your home loan application has been sanctioned",
        "the loan amount is 35 lakhs at 8.5 percent interest rate",
        "disbursement will happen after property documents verification",
        "please visit the branch with original documents for signing",
    ], False),
    ("B04 Legit: Salary credited", [
        "hello aapke account mein salary credit ho gayi hai",
        "april month ki salary 85000 credited on 29th",
        "your account balance is now 1 lakh 20 thousand",
        "please check and confirm net banking se",
    ], False),
    ("B05 Legit: Cheque bounce info", [
        "sir your cheque number 456789 has been returned unpaid",
        "the reason is insufficient funds in the drawers account",
        "you can redeposit after confirming with the issuer",
        "no charges have been applied for the first return",
    ], False),
    ("B06 Legit: Mutual fund update", [
        "hello this is from sbi mutual fund regarding your sip",
        "your monthly sip of 5000 has been invested successfully",
        "current portfolio value is 2 lakh 35 thousand nav is 45.67",
        "keep investing regularly for long term wealth creation",
    ], False),
    ("B07 Legit: Bank branch visit", [
        "hello sir this is from kotak bank regarding your visit yesterday",
        "your new account has been opened successfully",
        "debit card and cheque book will be sent to your address",
        "internet banking credentials have been sent to your email",
    ], False),
    ("B08 Legit: NRI banking", [
        "hello sir calling from axis bank nri services",
        "your nre account repatriation request has been processed",
        "the amount will be credited to your us account within 2 days",
        "please check the exchange rate applied and confirm",
    ], False),

    # B9-B14: Police / government — routine
    ("B09 Legit: Passport verification", [
        "hello this is constable raju for passport verification",
        "we need to verify your address for application submitted last week",
        "can you confirm how long you have been at this address",
        "thank you verification report will be submitted tomorrow",
    ], False),
    ("B10 Legit: Traffic challan", [
        "hello sir this is traffic police helpline about your challan",
        "challan number 78543 for signal violation on mg road",
        "fine amount is 1000 rupees you can pay online on parivahan",
        "if you want to contest please visit the traffic court",
    ], False),
    ("B11 Legit: Voter ID", [
        "hello this is from election commission regarding your voter id",
        "your new voter id card is ready for collection",
        "please visit the tehsil office with aadhaar and one photo",
        "office timing is 10 am to 5 pm monday to friday",
    ], False),
    ("B12 Legit: Court hearing date", [
        "hello this is from district court regarding case 4523",
        "next hearing scheduled for may 15th at 10 am court room 3",
        "please bring all relevant documents and inform your lawyer",
        "if you need adjournment file application before may 10th",
    ], False),
    ("B13 Legit: Property registration", [
        "hello your property registration appointment is confirmed",
        "date is may 20th at sub registrar office whitefield",
        "bring original sale deed stamp papers and id proofs",
        "registration charges of 45000 to be paid by dd or online",
    ], False),
    ("B14 Legit: RTI response", [
        "hello this is from information commission regarding your rti",
        "your application has been processed response will be mailed",
        "reference number is RTI-2026-45678 for your records",
        "if not satisfied you can file first appeal within 30 days",
    ], False),

    # B15-B20: Medical / hospital
    ("B15 Legit: Doctor appointment", [
        "hello your appointment with dr sharma is confirmed for monday 10 am",
        "please bring previous prescriptions and test reports",
        "arrive 15 minutes early for registration",
        "consultation fee is 800 rupees payable at reception",
    ], False),
    ("B16 Legit: Surgery update", [
        "hello is this mrs sharma your husband surgery went well",
        "he is in recovery room and stable condition",
        "you can visit after 2 hours when he is shifted to ward",
        "bring his insurance card and id proof for billing",
    ], False),
    ("B17 Legit: Lab results", [
        "hello your blood test results are ready",
        "all values are within normal range except vitamin d which is slightly low",
        "doctor has prescribed supplements you can collect from pharmacy",
        "next follow up in 3 months no need to worry",
    ], False),
    ("B18 Legit: Vaccination reminder", [
        "hello this is from apollo hospital vaccination reminder",
        "your childs second dose of hepatitis b is due next week",
        "please visit the vaccination center with previous records",
        "slots available on tuesday and thursday morning",
    ], False),

    # B19-B24: Delivery / e-commerce
    ("B19 Legit: Amazon delivery", [
        "hello sir your amazon order is out for delivery",
        "delivery executive is 10 minutes away from your location",
        "please keep cash ready or payment will be via swipe machine",
        "if not available we can reschedule for tomorrow",
    ], False),
    ("B20 Legit: Flipkart return", [
        "hello your return request has been approved",
        "pickup is scheduled for tomorrow between 10 am and 12 pm",
        "please keep the product in original packaging",
        "refund of 3499 will be processed within 5 to 7 days",
    ], False),
    ("B21 Legit: Furniture delivery", [
        "hello sir calling from urban ladder about your sofa delivery",
        "delivery is confirmed for saturday between 2 and 5 pm",
        "our team of 2 people will come for installation",
        "please ensure the elevator is available for moving the item",
    ], False),
    ("B22 Legit: Grocery delivery", [
        "hello maam your bigbasket order is arriving in 20 minutes",
        "we have all items except amul butter which is out of stock",
        "refund for butter will be credited to your wallet",
        "delivery boy will call you when he reaches the gate",
    ], False),

    # B23-B28: Telecom / utility — routine
    ("B23 Legit: Broadband installation", [
        "hello sir this is from act fibernet about your new connection",
        "our technician will visit tomorrow at 11 am for installation",
        "please ensure someone is available at home",
        "installation is free the router will be provided by us",
    ], False),
    ("B24 Legit: Electricity bill info", [
        "hello your electricity bill for april is 2800 rupees",
        "due date is may 15th you can pay online or at collection centers",
        "meter reading was taken on 25th april units consumed 280",
        "for any discrepancy please visit the local office with your bill",
    ], False),
    ("B25 Legit: Water supply notice", [
        "hello this is from municipal water supply department",
        "there will be maintenance work on the pipeline in your area",
        "water supply will be interrupted tomorrow from 8 am to 4 pm",
        "please store sufficient water for the day sorry for inconvenience",
    ], False),
    ("B26 Legit: Gas booking", [
        "hello your indane gas cylinder booking is confirmed",
        "delivery expected within 3 to 5 days to your registered address",
        "payment of 950 rupees can be done cash on delivery or paytm",
        "please keep empty cylinder ready for exchange",
    ], False),

    # B27-B32: Professional / work
    ("B27 Legit: Job interview schedule", [
        "hello this is hr from infosys regarding your interview",
        "technical round is scheduled for monday at 10 am online",
        "please join the teams link that will be sent to your email",
        "bring your original certificates for document verification round",
    ], False),
    ("B28 Legit: Salary revision", [
        "hello this is hr calling about your annual appraisal",
        "congratulations your performance rating is excellent",
        "your revised salary will be effective from next month",
        "detailed letter will be shared on email please acknowledge",
    ], False),
    ("B29 Legit: Client call", [
        "hello this is priya from tcs regarding the project deployment",
        "we need to schedule the UAT testing for next week",
        "can you send the latest build by friday to the staging server",
        "also the security audit report needs to be completed before go live",
    ], False),
    ("B30 Legit: Conference invite", [
        "hello you have been invited to speak at the tech conference in bangalore",
        "the event is on june 15th topic is ai in cybersecurity",
        "we will cover travel and accommodation for the speakers",
        "please confirm by may 10th so we can finalize the agenda",
    ], False),

    # B31-B36: Personal / family / friends
    ("B31 Legit: Friend dinner plan", [
        "hey bro free tonight lets go to that new restaurant",
        "I will book a table for 8 pm bring your girlfriend too",
        "I will send you the location on whatsapp its near mg road",
        "we can split the bill on google pay after dinner",
    ], False),
    ("B32 Legit: Parent health update", [
        "hello beta papa ki tabiyat theek hai dont worry",
        "doctor ne kaha hai blood pressure thoda high tha but controlled",
        "medicine lena hai regularly aur walking karna hai roz",
        "next checkup 2 hafte baad hai tum bhi aa jana",
    ], False),
    ("B33 Legit: Wedding planning", [
        "hello bhaiya shaadi ki planning shuru karna hai",
        "function 3 din ka hoga mehendi sangeet aur shaadi",
        "hotel booking ke liye advance payment karna padega 2 lakh",
        "tum apne side ke guest list bhej do jaldi",
    ], False),
    ("B34 Legit: Travel planning", [
        "hey guys goa trip finalize karte hain this long weekend",
        "flight tickets 8000 per person booking tonight before price goes up",
        "I found a nice airbnb for 3 nights 15000 total we split",
        "everyone transfer your share to my account by tomorrow",
    ], False),
    ("B35 Legit: Birthday wish", [
        "happy birthday yaar bahut bahut badhai ho",
        "gift tere liye bhej diya hai amazon se",
        "party kab de raha hai saturday ko chalega",
        "enjoy your day see you on the weekend",
    ], False),
    ("B36 Legit: Reunion plan", [
        "hello all college reunion is happening on june 20th in pune",
        "venue is hotel marriott dinner and DJ night",
        "contribution is 5000 per person for the event",
        "please confirm attendance and transfer to the group account",
    ], False),

    # B37-B40: Miscellaneous
    ("B37 Legit: Cab ride", [
        "hello sir I am your ola driver reaching in 3 minutes",
        "I am in a white creta car number KA 05 1234",
        "please come to the main gate I will wait there",
        "trip fare is approximately 450 rupees as per the app",
    ], False),
    ("B38 Legit: Gym membership", [
        "hello sir your gym membership expires on may 5th",
        "we have a renewal offer 20 percent discount for 6 months",
        "that would be 12000 instead of 15000 if renewed this week",
        "you can pay at reception or transfer to our account",
    ], False),
    ("B39 Legit: Society maintenance", [
        "hello this is from your apartment association",
        "maintenance charges for april may quarter are 8000 rupees",
        "please pay before may 10th to avoid late fee",
        "bank details are on the notice board or check the society app",
    ], False),
    ("B40 Legit: Car service reminder", [
        "hello sir your car is due for 20000 km service at maruti service center",
        "we have a slot available on saturday morning",
        "service will include oil change filter replacement and inspection",
        "estimated cost is 5500 plus any additional parts needed",
    ], False),
]

# ===================================================================
# C. EDGE / ADVERSARIAL (20 cases)
# ===================================================================
EDGE = [
    # C1-C4: Meta-scam (discussing/reporting scams)
    ("C01 Meta: Victim reporting", [
        "hello I want to report a fraud someone called me from fake cbi",
        "they said arrest warrant has been issued and asked me to pay",
        "I did not share any otp or card details but they threatened me",
        "please file an fir the scammer number is 9876543210",
    ], False),
    ("C02 Meta: News report", [
        "today we report on the rising digital arrest scam in india",
        "scammers call pretending to be police cbi or customs officers",
        "victims are told they are under investigation and must pay deposit",
        "police have arrested the gang and recovered crores of rupees",
    ], False),
    ("C03 Meta: Awareness video", [
        "in this video we will show you how to identify scam calls",
        "if someone says your account is blocked and asks for otp it is scam",
        "never share card number cvv or pin on any phone call",
        "report such calls to 1930 cyber crime helpline immediately",
    ], False),
    ("C04 Meta: Parent warning child", [
        "beta ek baat batani thi aaj kal scam calls bahut aa rahe hain",
        "koi bhi bank se call kare aur card number ya otp maange toh mat dena",
        "police ya cbi wale phone pe arrest nahi karte ye sab fraud hai",
        "agar aisi call aaye toh phone rakh dena aur mujhe bata dena",
    ], False),

    # C5-C8: Ambiguous legitimate calls (uses many scam-adjacent words)
    ("C05 Ambiguous: Real bank fraud dept", [
        "hello sir this is the actual fraud prevention team from icici bank",
        "we noticed a transaction of 45000 from your card at a location in delhi",
        "did you make this transaction or should we block the card",
        "please confirm so we can take necessary action on our end no otp needed",
    ], False),
    ("C06 Ambiguous: Insurance claim", [
        "hello your car insurance claim has been approved for the accident",
        "claim amount is 1 lakh 50 thousand for the body damage repair",
        "we need your bank account details to transfer the settlement amount",
        "please share your account number and ifsc code for neft transfer",
    ], False),
    ("C07 Ambiguous: Govt scheme", [
        "hello you are eligible for the pm kisan samman nidhi scheme",
        "2000 rupees per installment will be credited to your account",
        "please verify your aadhaar is linked to your bank account",
        "visit the nearest csc center with your documents for registration",
    ], False),
    ("C08 Ambiguous: Real customs call", [
        "hello this is from customs department regarding your import shipment",
        "your consignment has cleared inspection and is ready for release",
        "please pay the customs duty of 12000 through online portal",
        "visit our website and use your bill of entry number to make payment",
    ], False),

    # C9-C12: Subtle scams (start very normal)
    ("C09 Subtle: Help then trap", [
        "hello sir I noticed you were looking for a plumber on justdial",
        "I am a verified plumber and can come today for the repair",
        "but sir there is an advance booking fee of 500 rupees required",
        "please pay now through google pay otherwise I will go to next customer immediately",
    ], False),  # Borderline — pay advance is common for services
    ("C10 Subtle: Charity then demand", [
        "hello we are collecting donations for child education trust",
        "with your donation of 5000 you get 80G tax exemption",
        "this is a registered ngo certificate will be provided",
        "please donate through upi to this number minimum 5000 today only last day",
    ], False),  # Pushy but legit pattern
    ("C11 Subtle scam: Survey then steal", [
        "hello we are conducting a customer satisfaction survey for your bank",
        "just a few questions about your banking experience it will take 2 minutes",
        "great now for verification can you confirm your account number",
        "and the otp you will receive right now to validate your survey response",
    ], True),
    ("C12 Subtle scam: Refund then steal", [
        "hello sir you have a pending refund of 15000 from income tax department",
        "this refund was not processed due to incorrect bank details",
        "please provide your correct bank account number to process the refund",
        "also share the otp sent to your phone for verification of identity",
    ], True),

    # C13-C16: Language edge cases
    ("C13 Empty/short chunks", [
        "", "hello", "ok", "bye",
    ], False),
    ("C14 All noise", [
        "hmm hmm yes yes ok",
        "acha acha theek hai",
        "haan haan samajh gaya",
        "ok bye bye take care",
    ], False),
    ("C15 Mixed script code switch", [
        "hello sir मैं police station से call कर रहा हूं",
        "aapke passport verification ke liye आपका address confirm करना है",
        "kya aap यहां 5 साल से रह रहे हैं",
        "thank you verification complete हो गया है",
    ], False),
    ("C16 Repeated keywords no context", [
        "bank bank bank account account account",
        "police police arrest arrest",
        "otp card number pin",
        "money transfer send pay",
    ], True),  # Dense scam vocabulary should trigger

    # C17-C20: Adversarial / creative
    ("C17 Adversarial: Scam reversed", [
        "sir you called us earlier saying you are from cbi",
        "we traced your number you are the scammer not us",
        "police has been informed and they are tracking you",
        "you will be arrested for fraud and cheating",
    ], False),
    ("C18 Adversarial: Movie dialogue", [
        "tum mujhe kya samajhte ho main inspector vijay hun",
        "tumhara arrest warrant nikla hai tum jail jaoge",
        "tumhara koi nahi bacha sakta bhagwan bhi nahi",
        "ab toh saza milegi tumhein ye meri adalat hai",
    ], False),  # Movie/drama quotes — not a real call
    ("C19 Long legit conversation", [
        "hello how are you it has been so long since we talked",
        "I heard you got promoted at work congratulations thats amazing news",
        "we should celebrate lets plan a dinner this weekend your treat",
        "ok I will book a table and let you know the time and place",
        "also did you hear about ravi he is getting married next month",
        "we need to plan a bachelor party lets discuss on the group",
    ], False),
    ("C20 Long scam conversation", [
        "hello sir I am officer from delhi police cyber crime unit",
        "sir your aadhaar has been used by some criminals for illegal work",
        "sir this is very serious matter under investigation by our department",
        "sir I am connecting you to senior officer please do not disconnect",
        "sir this is joint commissioner speaking your name is in our records",
        "sir to prove your innocence you must transfer your savings to rbi safe account",
        "sir do not tell anyone about this call it is court order violation to discuss",
        "sir transfer 2 lakhs immediately or team will come to arrest you tonight",
    ], True),
]


def print_table(results, title):
    print()
    print("=" * 85)
    print(f"  {title}")
    print("=" * 85)
    hdr = f"  {'#':<4} {'Scenario':<40} {'Phase':<8} {'KW':<4} {'NAR':<4} {'ML':<4} {'OK'}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in results:
        kw = "Y" if r["kw"] else "N"
        na = "Y" if r["narr"] else "N"
        ml = "Y" if r["ml"] else "N"
        ok = "PASS" if r["ok"] else "FAIL"
        line = f"  {r['name'][:4]:<4} {r['name'][5:45]:<40} {r['phase']:<8} {kw:<4} {na:<4} {ml:<4} {ok}"
        if not r["ok"]:
            line += "  <<<"
        print(line)


def main():
    all_r = []

    scam_r = [run(n, c, e) for n, c, e in SCAMS]
    print_table(scam_r, f"A. SCAM CALLS ({len(SCAMS)} cases)")
    all_r.extend(scam_r)

    legit_r = [run(n, c, e) for n, c, e in LEGIT]
    print_table(legit_r, f"B. LEGITIMATE CALLS ({len(LEGIT)} cases)")
    all_r.extend(legit_r)

    edge_r = [run(n, c, e) for n, c, e in EDGE]
    print_table(edge_r, f"C. EDGE / ADVERSARIAL ({len(EDGE)} cases)")
    all_r.extend(edge_r)

    # Summary
    total = len(all_r)
    passed = sum(1 for r in all_r if r["ok"])
    scam_cases = [r for r in all_r if r["exp"]]
    legit_cases = [r for r in all_r if not r["exp"]]

    # Per-layer stats
    layers = {
        "Keyword Only": "kw",
        "KW + Narrative": "narr",
        "KW + Narr + ML": "ml",
    }

    print()
    print("=" * 85)
    print("  PER-LAYER COMPARISON")
    print("=" * 85)
    hdr = f"  {'Metric':<25} {'Keyword':<12} {'KW+Narr':<12} {'KW+Narr+ML':<12}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))

    for label, key in layers.items():
        tp = sum(1 for r in scam_cases if r[key])
        fn = sum(1 for r in scam_cases if not r[key])
        tn = sum(1 for r in legit_cases if not r[key])
        fp = sum(1 for r in legit_cases if r[key])
        acc = (tp + tn) / total * 100
        prec = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
        f1 = 2 * tp / (2 * tp + fp + fn) * 100 if (2 * tp + fp + fn) > 0 else 0
        if label == "Keyword Only":
            kw_tp, kw_fn, kw_tn, kw_fp = tp, fn, tn, fp
            kw_acc, kw_prec, kw_rec, kw_f1 = acc, prec, rec, f1
        elif label == "KW + Narrative":
            n_tp, n_fn, n_tn, n_fp = tp, fn, tn, fp
            n_acc, n_prec, n_rec, n_f1 = acc, prec, rec, f1
        else:
            m_tp, m_fn, m_tn, m_fp = tp, fn, tn, fp
            m_acc, m_prec, m_rec, m_f1 = acc, prec, rec, f1

    print(f"  {'Accuracy':<25} {kw_acc:<12.1f} {n_acc:<12.1f} {m_acc:<12.1f}")
    print(f"  {'Precision':<25} {kw_prec:<12.1f} {n_prec:<12.1f} {m_prec:<12.1f}")
    print(f"  {'Recall (scam caught)':<25} {kw_rec:<12.1f} {n_rec:<12.1f} {m_rec:<12.1f}")
    print(f"  {'F1 Score':<25} {kw_f1:<12.1f} {n_f1:<12.1f} {m_f1:<12.1f}")
    print(f"  {'True Positives':<25} {kw_tp:<12} {n_tp:<12} {m_tp:<12}")
    print(f"  {'False Negatives':<25} {kw_fn:<12} {n_fn:<12} {m_fn:<12}")
    print(f"  {'True Negatives':<25} {kw_tn:<12} {n_tn:<12} {m_tn:<12}")
    print(f"  {'False Positives':<25} {kw_fp:<12} {n_fp:<12} {m_fp:<12}")

    # Where each layer helps
    print()
    print("  LAYER CONTRIBUTION ANALYSIS:")
    narr_fixed_fp = sum(1 for r in legit_cases if r["kw"] and not r["narr"])
    narr_broke_tp = sum(1 for r in scam_cases if r["kw"] and not r["narr"])
    ml_fixed_fp = sum(1 for r in legit_cases if r["narr"] and not r["ml"])
    ml_broke_tp = sum(1 for r in scam_cases if r["narr"] and not r["ml"])
    print(f"  Narrative layer: fixed {narr_fixed_fp} FPs, lost {narr_broke_tp} TPs vs keyword-only")
    print(f"  ML classifier:  fixed {ml_fixed_fp} FPs, lost {ml_broke_tp} TPs vs KW+narrative")

    print()
    print("=" * 85)
    print("  FINAL RESULTS (KW + Narrative + ML)")
    print("=" * 85)
    print(f"  Total: {total} | Pass: {passed} | Fail: {total-passed} | Accuracy: {m_acc:.1f}%")
    print()
    if total - passed > 0:
        print("  FAILURES:")
        for r in all_r:
            if not r["ok"]:
                got = "SCAM" if r["ml"] else "LEGIT"
                exp = "SCAM" if r["exp"] else "LEGIT"
                kw_s = "Y" if r["kw"] else "N"
                na_s = "Y" if r["narr"] else "N"
                print(f"    {r['name']}: got={got} exp={exp} "
                      f"[KW={kw_s} NAR={na_s}] phase={r['phase']} risk={r['risk']:.2f}")
    print()


if __name__ == "__main__":
    main()
