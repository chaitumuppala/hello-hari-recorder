"""Training data for scam vs legitimate text classifier.

Each entry is (text, label) where label=1 is scam and label=0 is legitimate.
The key challenge: same domain vocabulary appears in both classes.
The classifier must learn that INTENT matters, not just keyword presence.

Sources:
  - Positive (scam): derived from patterns.json phrases + realistic expansions
  - Negative (legit): realistic Indian call center / bank / police / daily life
"""

TRAINING_DATA: list[tuple[str, int]] = [
    # ================================================================
    # SCAM: Bank / OTP theft — requesting credentials
    # ================================================================
    ("give me your credit card number", 1),
    ("share your otp that you received", 1),
    ("tell me your cvv number", 1),
    ("please share your card details for verification", 1),
    ("what is your card number", 1),
    ("read out your card number", 1),
    ("share your pin number", 1),
    ("give me the otp you received on your phone", 1),
    ("tell me the three digit number on the back of your card", 1),
    ("provide your card number and expiry date", 1),
    ("share your password for verification", 1),
    ("otp share karo verification ke liye", 1),
    ("apna card number batao", 1),
    ("cvv batao jo card ke peeche hai", 1),
    ("otp bata do jo abhi aaya hai", 1),
    ("pin batao apna", 1),
    ("kya hai aapka card number", 1),
    ("16 digit number on your card batao", 1),
    ("card details share karo", 1),
    ("credit card information de do", 1),
    ("upi pin batao security check ke liye", 1),
    ("net banking password confirm karo", 1),
    ("your account is blocked share otp to unblock", 1),
    ("account deactivate ho jayega otp do", 1),
    ("verify karne ke liye card number chahiye", 1),
    ("otp share cheyyandi verification ki", 1),
    ("mee card number cheppandi", 1),
    ("cvv number cheppandi", 1),

    # SCAM: Bank — account threats
    ("your account has been blocked due to suspicious activity", 1),
    ("account will be permanently closed if you dont verify", 1),
    ("unauthorized transaction detected on your account", 1),
    ("your account is suspended contact us immediately", 1),
    ("account freeze ho jayega agar verify nahi kiya", 1),
    ("aapka account hack ho gaya hai", 1),
    ("suspicious transaction on your account detected", 1),
    ("your account is at risk of being closed", 1),
    ("account has been compromised by hackers", 1),
    ("aapka debit card block ho gaya hai", 1),

    # SCAM: Digital arrest — authority impersonation
    ("this is from cbi headquarters we have a case against you", 1),
    ("arrest warrant has been issued in your name", 1),
    ("you are now under digital arrest", 1),
    ("drug trafficking case registered against your aadhaar", 1),
    ("narcotics found in courier with your name", 1),
    ("fir will be filed against you", 1),
    ("you will be arrested within 24 hours", 1),
    ("cyber crime cell speaking you are under investigation", 1),
    ("enforcement directorate has evidence against you", 1),
    ("central bureau investigation calling", 1),
    ("main cbi se bol raha hun aapke khilaaf case hai", 1),
    ("warrant nikla hai aapke naam", 1),
    ("jail ho jayegi agar cooperate nahi kiya", 1),
    ("aapke naam se human trafficking ka case", 1),
    ("police will come to your house", 1),
    ("we will send police to your location", 1),

    # SCAM: Secrecy demands
    ("do not tell anyone about this call", 1),
    ("dont inform your family about this matter", 1),
    ("keep this confidential between us", 1),
    ("if you tell anyone case will be worse", 1),
    ("kisi ko mat batana ye secret hai", 1),
    ("family ko mat bolo police aa jayegi", 1),
    ("do not contact a lawyer", 1),
    ("ghar mein kisi ko mat batao", 1),
    ("evvariki cheppakandi confidential matter", 1),

    # SCAM: Money demands
    ("transfer 50000 rupees as security deposit", 1),
    ("send money immediately to this account", 1),
    ("pay the fine amount through upi", 1),
    ("deposit money in this account to avoid arrest", 1),
    ("transfer money now or you will be arrested", 1),
    ("pay processing fee to claim your prize", 1),
    ("registration fee required send 5000 rupees", 1),
    ("turant paisa bhejo is account mein", 1),
    ("abhi ke abhi paise transfer karo", 1),
    ("pay to release your parcel from customs", 1),

    # SCAM: TRAI / telecom
    ("your sim card will be disconnected in 2 hours", 1),
    ("press 1 to avoid disconnection of your number", 1),
    ("main trai se bol raha hun sim band hone wala hai", 1),
    ("22 complaints registered against your sim card", 1),
    ("telecom fraud detected on your number", 1),
    ("sim deactivation process started press 1", 1),

    # SCAM: Courier / customs
    ("drugs found in your package at customs", 1),
    ("parcel containing illegal items intercepted", 1),
    ("narcotic substances detected in your courier", 1),
    ("pay customs clearance fee or face criminal charges", 1),
    ("we are calling from fedex your parcel has contraband", 1),

    # SCAM: Investment / lottery fraud
    ("congratulations you have won a cash prize of 10 lakhs", 1),
    ("guaranteed 10x returns on your investment", 1),
    ("pay tax to receive your prize money", 1),
    ("you are the lucky winner of our draw", 1),
    ("join our vip trading group for sure shot profits", 1),
    ("kbc lottery winner you have been selected", 1),
    ("only 100 slots remaining invest now", 1),
    ("double your bitcoin in 30 days guaranteed", 1),

    # SCAM: Family emergency
    ("hello beta i am in serious trouble send money", 1),
    ("accident hua hai hospital mein turant paisa chahiye", 1),
    ("bail money needed right now dont tell anyone", 1),
    ("i have been kidnapped send ransom money", 1),
    ("relative needs urgent surgery send money immediately", 1),
    ("phone is broken thats why i sound different please help", 1),
    # Family emergency — abroad / arrest variants
    ("your son has been arrested at airport send bail money", 1),
    ("he has been detained at airport for document issue send money", 1),
    ("your son is in trouble abroad needs money urgently", 1),
    ("he is stuck in dubai arrested please transfer 3 lakhs", 1),
    ("calling from abroad your relative arrested need bail money now", 1),
    ("please dont tell others just send the money quickly", 1),
    ("he was caught at immigration needs money for lawyer", 1),
    ("your brother is in jail in canada send bail amount", 1),
    ("friend calling from foreign country your son arrested transfer money", 1),
    ("dont tell family it will make situation worse send bail", 1),

    # SCAM: Tech support
    ("your computer has been infected install anydesk", 1),
    ("download teamviewer so we can fix your virus", 1),
    ("give remote access to fix the security breach", 1),
    ("pay repair fee to remove malware from your system", 1),
    ("sir aapka computer infected hai remote access dena hoga", 1),
    ("windows license expire ho gaya pay to renew", 1),

    # SCAM: KYC / Aadhaar
    ("complete your kyc or account will be closed", 1),
    ("kyc has expired update immediately or face penalty", 1),
    ("click this link to update your aadhaar kyc", 1),
    ("share your aadhaar number for verification", 1),
    ("aadhar link mandatory karo warna account band", 1),

    # SCAM: Insurance
    ("your policy will lapse pay premium immediately", 1),
    ("coverage will be lost if you dont pay now", 1),
    ("grace period ending today pay or policy cancelled", 1),

    # SCAM: Electricity / utility
    ("electricity will be disconnected tonight pay now", 1),
    ("bijli kat jayegi 2 ghante mein bill bharo", 1),
    ("scan this qr code to pay your overdue bill", 1),

    # SCAM: Job
    ("pay registration fee to start your guaranteed job", 1),
    ("training kit fee required before joining", 1),
    ("send 5000 as security deposit for data entry job", 1),
    # Job scam — part time / work from home variants
    ("earn 2000 daily from home simple typing work guaranteed", 1),
    ("verified company many people already earning see proof", 1),
    ("register today offer closes at midnight limited seats", 1),
    ("send security deposit for training material and id card", 1),
    ("work from home guaranteed income 50000 per month no experience", 1),
    ("online job offer pay registration fee to start earning", 1),
    ("earn money from mobile phone just 2 hours daily work", 1),
    ("amazon data entry job from home pay 3000 to register", 1),
    ("simple copy paste work earn 1500 daily guaranteed payment", 1),
    ("join our team pay security deposit start earning tomorrow", 1),
    ("this is genuine company not fraud pay small fee to start", 1),

    # SCAM: Loan
    ("pre approved loan processing fee required", 1),
    ("pay advance emi to get loan disbursed today", 1),
    ("loan approval will cancel if you dont pay fee now", 1),

    # ================================================================
    # LEGITIMATE: Bank / financial — informational, not requesting
    # ================================================================
    ("your credit card application has been approved", 0),
    ("your new credit card will be dispatched tomorrow", 0),
    ("credit card statement for this month is available online", 0),
    ("your debit card has been renewed successfully", 0),
    ("card will be delivered to your registered address", 0),
    ("your fixed deposit has matured please visit branch", 0),
    ("emi for your home loan has been debited successfully", 0),
    ("interest rate on your savings account has been revised", 0),
    ("your cheque has been cleared and amount credited", 0),
    ("new bank branch opening near your area", 0),
    ("your account balance is sufficient for the transaction", 0),
    ("we have processed your refund it will reflect in 3 days", 0),
    ("your loan application is under review", 0),
    ("congratulations your home loan has been sanctioned", 0),
    ("your neft transfer has been processed successfully", 0),
    ("thank you for banking with us have a good day", 0),
    ("your credit score has improved this quarter", 0),
    ("atm near your location is temporarily under maintenance", 0),
    ("aapka account mein salary credit ho gayi hai", 0),
    ("aapki fd mature ho gayi hai branch mein aayiye", 0),
    ("bank ki nayi branch aapke area mein khul rahi hai", 0),

    # LEGITIMATE: Police / government — routine interaction
    ("this is constable raju calling for passport verification", 0),
    ("we need to verify your address for passport application", 0),
    ("please come to the police station to collect your fir copy", 0),
    ("traffic challan has been generated for your vehicle", 0),
    ("your driving license renewal is due next month", 0),
    ("voter id card is ready for collection at tehsil office", 0),
    ("property registration documents are ready for pickup", 0),
    ("court hearing has been scheduled for next tuesday", 0),
    ("your passport application status is under processing", 0),
    ("thank you we will complete the verification report", 0),
    ("police verification for your new tenant is done", 0),
    ("your complaint has been registered fir number is 2345", 0),
    ("the investigation is progressing we will update you", 0),
    ("aapka passport verification complete ho gaya hai", 0),
    ("challan ka payment online bhi kar sakte hain", 0),
    ("court ki next date 15 may ko hai", 0),

    # LEGITIMATE: Doctor / hospital
    ("your father surgery went well he is recovering", 0),
    ("test reports are ready everything looks normal", 0),
    ("please continue the medication for two more weeks", 0),
    ("your appointment with dr sharma is confirmed for monday", 0),
    ("hospital visiting hours are from 10 am to 6 pm", 0),
    ("blood test results show all values are within normal range", 0),
    ("your insurance claim for hospitalization has been approved", 0),
    ("please bring previous prescription when you visit", 0),
    ("mri report is ready you can collect from reception", 0),
    ("papa ki surgery successful rahi hai tension mat lo", 0),

    # LEGITIMATE: Delivery / e-commerce
    ("your amazon order is out for delivery", 0),
    ("flipkart order has been shipped tracking id is shared", 0),
    ("delivery boy is at your gate please collect parcel", 0),
    ("your package has been delivered at the reception", 0),
    ("return pickup scheduled for tomorrow between 10 to 12", 0),
    ("refund has been processed will reflect in 5 to 7 days", 0),
    ("your order has been cancelled as per your request", 0),
    ("product is out of stock we will notify when available", 0),
    ("aapka order deliver ho gaya hai rate kariye", 0),

    # LEGITIMATE: Insurance — informational
    ("your policy renewal is due on 15th of this month", 0),
    ("premium payment received thank you", 0),
    ("your term plan coverage has been increased as requested", 0),
    ("lic policy maturity amount will be credited next week", 0),
    ("health insurance card has been dispatched to your address", 0),
    ("claim settlement amount has been transferred to your account", 0),
    ("your vehicle insurance is valid until december 2026", 0),
    ("nominee details have been updated in your policy", 0),
    ("aapki policy ka premium 15 tarikh ko due hai", 0),
    ("insurance renewal online bhi kar sakte hain website par", 0),

    # LEGITIMATE: Telecom — customer service
    ("thank you for calling jio customer care", 0),
    ("your recharge was successful data pack is active", 0),
    ("next billing cycle starts on 5th of may", 0),
    ("your broadband connection has been activated", 0),
    ("sim card replacement request has been processed", 0),
    ("your number has been successfully ported", 0),
    ("network maintenance scheduled in your area tomorrow", 0),
    ("your complaint about slow internet has been resolved", 0),
    ("aapka recharge successful ho gaya hai", 0),
    ("internet speed issue resolve ho gaya hai", 0),

    # LEGITIMATE: Job / recruitment — professional
    ("we would like to schedule your interview for monday", 0),
    ("your application for software engineer has been shortlisted", 0),
    ("please bring original documents for verification", 0),
    ("offer letter has been sent to your email", 0),
    ("joining date is 1st june please report to hr", 0),
    ("your salary has been credited for this month", 0),
    ("performance review meeting is scheduled for friday", 0),
    ("congratulations on your promotion effective next month", 0),
    ("training session starts next week please register", 0),
    ("aapka interview monday ko 10 baje hai", 0),

    # LEGITIMATE: School / education
    ("your daughter has a slight fever please pick her up", 0),
    ("parent teacher meeting is on saturday at 10 am", 0),
    ("exam results have been published check the website", 0),
    ("school fees for next quarter are due by 30th", 0),
    ("annual day function is on 15th december you are invited", 0),
    ("your son scored well in mathematics congratulations", 0),
    ("field trip permission form needs to be signed", 0),

    # LEGITIMATE: Electricity / utility — informational
    ("scheduled power cut tomorrow from 10 am to 2 pm", 0),
    ("your electricity bill for this month is 2500 rupees", 0),
    ("meter reading has been taken for this month", 0),
    ("new electricity connection application has been approved", 0),
    ("transformer upgrade work in your area this weekend", 0),
    ("gas cylinder booking confirmed delivery in 3 days", 0),
    ("water supply will be interrupted for maintenance work", 0),
    ("bijli ka bill online jama kar sakte hain", 0),

    # LEGITIMATE: Friends / family — casual conversation
    ("hey how are you lets meet for coffee this weekend", 0),
    ("I will send you the restaurant address on whatsapp", 0),
    ("happy birthday wishing you all the best", 0),
    ("did you see the match yesterday it was amazing", 0),
    ("can you pick up groceries on your way home", 0),
    ("planning a trip to goa this long weekend", 0),
    ("need to transfer money for booking will send upi", 0),
    ("bhai aaj raat dinner pe chal sakte hain kya", 0),
    ("photo bhej de jo kal wedding mein li thi", 0),
    ("mummy ki tabiyat theek hai routine checkup tha", 0),

    # LEGITIMATE: Cab / ride
    ("hello sir I am your uber driver 5 minutes away", 0),
    ("your ola ride has been confirmed driver en route", 0),
    ("please share your pickup location", 0),
    ("trip has ended total fare is 350 rupees", 0),
    ("driver is waiting at the gate", 0),

    # LEGITIMATE: Restaurant / food delivery
    ("your zomato order is being prepared", 0),
    ("swiggy delivery in 30 minutes", 0),
    ("table reservation confirmed for 8 pm", 0),
    ("your food order has been dispatched", 0),

    # LEGITIMATE: Real estate / housing
    ("flat registration documents are ready for signing", 0),
    ("society maintenance bill for this quarter is 5000", 0),
    ("property tax payment receipt has been generated", 0),
    ("building construction work update for your flat", 0),

    # LEGITIMATE: Using same domain words innocently
    ("I need to go to the bank to deposit a cheque", 0),
    ("the police station is near the court on main road", 0),
    ("my aadhaar card needs to be updated with new address", 0),
    ("I will transfer money for the dinner we shared", 0),
    ("customs clearance for our import shipment is done", 0),
    ("my credit card bill is due I will pay online", 0),
    ("called the bank to check my account balance", 0),
    ("insurance agent came for policy renewal discussion", 0),
    ("phone pe se paise transfer kar diye hain", 0),
    ("bank mein gaya tha fixed deposit karvane", 0),
    ("police verification ho gayi passport ke liye", 0),
    ("aadhaar update centre bahut bheeda tha aaj", 0),
    ("court mein case ki hearing thi aaj", 0),
    ("otp aaya tha amazon order confirm karne ke liye", 0),

    # LEGITIMATE: Meta-scam text (describing/discussing scams, not scamming)
    ("today we report on the digital arrest scam that has defrauded thousands", 0),
    ("common scam patterns include someone claiming your account is blocked", 0),
    ("they will ask you to share otp card number and threaten with arrest", 0),
    ("never share your personal details banks never ask for otp on call", 0),
    ("the scammer calls pretending to be from cbi or police", 0),
    ("victims are told they are under investigation and must pay deposit", 0),
    ("police have arrested 15 suspects involved in the scam ring", 0),
    ("I want to report a scam someone called claiming to be from bank", 0),
    ("they said my account is blocked and asked me to share card details", 0),
    ("I did not give them any otp or password but they threatened me", 0),
    ("cyber crime helpline number is 1930 for reporting fraud", 0),
    ("awareness campaign about phone scams launched by government", 0),
    ("how to identify scam calls a guide for senior citizens", 0),
    ("in this training we will learn to spot phishing and vishing attacks", 0),
    ("as bank employees we must never ask customers for otp on call", 0),
    ("scammers use fear tactics like arrest warrants and account blocking", 0),
    ("if someone asks you to transfer money urgently it is likely a scam", 0),
    ("the digital arrest scam cost indians over 1 billion dollars last year", 0),
    ("rbi advisory says never share card cvv or otp with anyone on phone", 0),
    ("police recovered 2 crore rupees from the scam call center", 0),

    # LEGITIMATE: Bank operations (using card/account words innocently)
    ("your new debit card has been activated successfully", 0),
    ("credit card annual fee of 500 has been waived for this year", 0),
    ("your account has been upgraded to premium savings", 0),
    ("fixed deposit interest rate revised to 7.5 percent", 0),
    ("your credit card reward points balance is 25000", 0),
    ("video call kyc is now available for account opening", 0),
    ("your mutual fund sip has been set up successfully", 0),
    ("bank account statement has been sent to your email", 0),
    ("your neft transfer of 50000 to ramesh has been completed", 0),
    ("cheque book request received will be delivered in a week", 0),

    # LEGITIMATE: E-commerce / refund (using process/refund words)
    ("your refund of 3499 rupees has been processed to your bank account", 0),
    ("replacement item has been shipped will arrive in 2 days", 0),
    ("your return request has been approved pickup scheduled tomorrow", 0),
    ("order cancelled successfully refund will be processed in 5 days", 0),
    ("exchange request accepted new size will be delivered by friday", 0),

    # LEGITIMATE: Traffic / vehicle — uses fine/pay vocabulary
    ("traffic challan for signal violation fine amount 1000 rupees", 0),
    ("your challan can be paid online on parivahan portal", 0),
    ("speeding challan generated for your vehicle on highway", 0),
    ("vehicle insurance renewal due next month please renew online", 0),
    ("driving license renewal application has been processed", 0),
    ("your vehicle fitness certificate is ready for collection", 0),
    ("challan payment received of 500 rupees receipt number 4567", 0),
    ("parking fine of 200 rupees issued at mg road pay online", 0),

    # LEGITIMATE: Society / housing — uses pay/maintenance vocabulary
    ("society maintenance charges for this quarter are 8000 rupees", 0),
    ("please pay maintenance before 10th to avoid late fee", 0),
    ("apartment association meeting scheduled for sunday", 0),
    ("parking slot allotment for new residents on first come basis", 0),
    ("water tank cleaning scheduled for saturday please store water", 0),
    ("lift maintenance work tomorrow lift will be unavailable", 0),
    ("society annual general meeting agenda has been shared", 0),
    ("new security guard has been appointed from next week", 0),

    # LEGITIMATE: Bank FD / investment — uses maturity/video call vocabulary
    ("your fixed deposit has matured you can renew or withdraw", 0),
    ("fd maturity amount of 5 lakhs credited to savings account", 0),
    ("video call kyc is now available for new account opening", 0),
    ("you can complete kyc through video call no branch visit needed", 0),
    ("mutual fund sip of 5000 invested successfully this month", 0),
    ("ppf account annual interest credited for this year", 0),
    ("recurring deposit matured total amount 1 lakh 20 thousand", 0),

    # LEGITIMATE: Victim reporting / discussing scams (more examples)
    ("I want to file a complaint someone tried to scam me on phone", 0),
    ("they asked me to transfer money saying arrest warrant I refused", 0),
    ("fake cbi officer called me demanding security deposit I hung up", 0),
    ("someone claiming from bank asked my card number I did not share", 0),
    ("reporting fraud attempt caller asked for otp saying account blocked", 0),
    ("my neighbor got scammed they took 50000 as security deposit", 0),
    ("please warn others about this scam they pretend to be police", 0),
    ("uncle ko scam call aaya tha cbi wala ban ke paise maang rahe the", 0),

    # LEGITIMATE: Parent/elder warning about scams
    ("beta phone pe koi otp maange toh kabhi mat dena", 0),
    ("agar koi police ya cbi se call kare toh phone rakh dena fraud hai", 0),
    ("bank wale kabhi phone pe card number nahi maangte ye yaad rakhna", 0),
    ("mummy ko bhi batao ki scam calls se savdhan rahe", 0),
    ("koi bhi account block bolke otp maange toh wo scam hai", 0),
    ("papa ko samjhao ki arrest warrant phone pe nahi aata", 0),

    # LEGITIMATE: Real customs / official communication
    ("customs duty for your import consignment has been calculated", 0),
    ("please pay duty online through icegate portal", 0),
    ("your shipment has cleared customs inspection successfully", 0),
    ("import license application is under review", 0),
    ("bill of entry has been filed for your cargo", 0),

    # LEGITIMATE: Mixed script legitimate (Hindi-English)
    ("hello sir main police station se call kar raha hun passport verification ke liye", 0),
    ("aapka address confirm karna hai kya aap yahan 5 saal se hain", 0),
    ("verification complete ho gaya hai thank you for your cooperation", 0),
    ("sir court ki next hearing 15 may ko hai please apne vakeel ko inform karein", 0),
]
