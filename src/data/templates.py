"""Text templates for the synthetic generator.

Each template is (subject, body) with `{slot}` placeholders filled by the generator.
Greetings and sign-offs are shared by every class so they carry no signal on their own.
"""
from __future__ import annotations

GREETINGS = ["Hi {first},", "Hello {first},", "Dear {first},", "{first},", "Hi,", "Good morning {first},"]
SIGNOFFS = ["Thanks,\n{sender}", "Best regards,\n{sender}", "Regards,\n{sender}", "Cheers,\n{sender}",
            "Thank you,\n{sender}", "{sender}"]

INDUSTRY_TOPICS: dict[str, list[str]] = {
    "manufacturing": ["line 3 retooling", "Q3 production schedule", "supplier quality audit", "CNC maintenance window",
                      "raw material forecast", "ISO 9001 recertification"],
    "pharma": ["stability study batch 14", "GMP audit findings", "clinical supply forecast", "API sourcing review",
               "batch release documentation", "regulatory submission timeline"],
    "fintech": ["reconciliation job failures", "PCI scope review", "card issuing roadmap", "ledger migration",
                "fraud model retraining", "SOC 2 evidence collection"],
    "retail": ["holiday assortment plan", "store replenishment", "POS rollout", "markdown calendar",
               "inventory shrink report", "loyalty program launch"],
    "legal": ["Henderson matter discovery", "engagement letter draft", "billing guidelines", "court filing deadline",
              "conflict check request", "deposition prep"],
    "logistics": ["lane rate renewal", "warehouse slotting", "carrier scorecard", "customs clearance backlog",
                  "fleet telematics pilot", "peak season capacity"],
    "healthcare": ["clinic scheduling template", "EHR upgrade", "credentialing renewals", "patient intake forms",
                   "HIPAA training", "supply par levels"],
    "construction": ["site 12 change order", "concrete pour schedule", "subcontractor bids", "safety walk findings",
                     "permit inspection", "RFI responses"],
    "saas": ["sprint planning", "incident postmortem", "pricing page experiment", "SSO integration",
             "churn analysis", "Q3 OKRs"],
    "education": ["fall enrollment numbers", "curriculum review", "faculty onboarding", "LMS migration",
                  "financial aid packaging", "campus visit day"],
}

# ---- legit -------------------------------------------------------------------------------
LEGIT_INTERNAL = [
    ("Re: {topic}", "Following up on the {topic}. Can you send me the latest numbers before {day}? "
                    "I'd like to review them with {colleague} first."),
    ("{topic} update", "Quick update on the {topic}: we are on track for {day}. Let me know if you see any blockers."),
    ("Notes from today's {topic} sync", "Attached are the notes from today's sync on the {topic}. "
                                        "Action items are at the bottom, owners are assigned."),
    ("Can we move our 1:1?", "Something came up on {day}. Could we move our 1:1 to the afternoon? "
                             "Happy to also cover the {topic} then."),
    ("Draft for review", "I've put together a first draft on the {topic}. Comments welcome, no rush, "
                         "end of week is fine."),
    ("Team lunch {day}", "We're planning a team lunch on {day} to celebrate wrapping up the {topic}. "
                         "Let me know about dietary restrictions."),
]
LEGIT_VENDOR = [
    ("Invoice {inv} for PO {po}", "Please find attached invoice {inv} for PO {po}, amount {amount}, payable "
                                  "net-30 to the account on file. Let us know if anything looks off."),
    ("Order {po} shipped", "Your order {po} has shipped and should arrive by {day}. Tracking details are in "
                           "the portal: {url}"),
    ("Quote for {item}", "As discussed, attached is our quote for {item}. Pricing is valid for 30 days. "
                         "Happy to walk through it on a call."),
    ("Re: {item} delivery", "Confirming the {item} delivery window for {day}. Our driver will call ahead."),
    ("Updated price list", "Attached is our updated price list effective next month. Most items are unchanged; "
                           "{item} goes up 3% due to freight costs."),
]
LEGIT_NOTIFICATION = [
    ("DocuSign", "dse@docusign.net", "Please review and sign: {doc}",
     "{colleague} sent you a document to review and sign. REVIEW DOCUMENT: {url}"),
    ("Microsoft 365", "no-reply@microsoft.com", "Your Microsoft 365 invoice is available",
     "Your invoice for this billing period is ready. View it in the admin center: {url}"),
    ("Zoom", "no-reply@zoom.us", "Cloud recording now available",
     "Your cloud recording for \"{topic}\" is now available. View recording: {url}"),
    ("Industry Weekly", "news@industryweekly.com", "This week: {topic} and more",
     "Top stories this week. Read more: {url} Manage preferences or unsubscribe: {url2}"),
]

# ---- hard negatives: legit mail that looks malicious -------------------------------------
HN_EXEC_URGENT_PAYMENT = ("Urgent: payment to {vendor_name} today",
                          "Please process the wire to {vendor_name} today, it's urgent. The invoice {inv} is overdue "
                          "and they will hold the shipment otherwise. Amount {amount}, bank details are in the ERP.")
HN_IT_PASSWORD = ("Reminder: password expires in 5 days",
                  "Your network password expires in 5 days. Please change it via the self-service portal: {url} "
                  "IT will never ask for your password by email.")
HN_PROMO = ("Limited time: 30% off annual plans",
            "For a limited time, upgrade to an annual plan and save 30%. Offer ends {day}. Upgrade now: {url} "
            "Unsubscribe: {url2}")
HN_NEW_VENDOR = ("Introduction - {vendor_name}",
                 "I'm reaching out from {vendor_name}. We supply {item} to several companies in your area and would "
                 "love to quote. Our capabilities deck is attached.")
HN_VENDOR_BANK_CHANGE = ("Notice: change of bank",
                         "Please note that we are moving our banking to a new provider from next month. Our finance "
                         "team will call you from the number on file to confirm the details. Do not act on email alone.")

# ---- spam --------------------------------------------------------------------------------
SPAM = [
    ("{pct}% OFF everything - today only!!", "Huge sale! Get {pct}% off all products today only. Free shipping "
                                             "worldwide. Shop now: {url} Click here to unsubscribe: {url2}"),
    ("Turn $250 into $5,000 this month", "Our crypto trading bot made members guaranteed returns of 2000%. "
                                         "Limited spots, act now: {url} You are receiving this because you opted in."),
    ("Your website {tenant_domain} is losing traffic", "I noticed your website is not ranking on page one. Our SEO "
                                                       "team can guarantee first-page results in 30 days. Reply YES "
                                                       "for a free audit. {url}"),
    ("Congratulations! You've been selected", "You have been selected to receive an exclusive reward worth $1,000. "
                                              "Claim your prize before it expires: {url}"),
    ("B2B leads list - 50,000 verified contacts", "We offer verified email lists of decision makers in your "
                                                  "industry. Special price this week only. Details: {url}"),
]

# ---- phishing ----------------------------------------------------------------------------
PHISH_BRAND = [
    ("Microsoft 365", "Action required: mailbox storage full",
     "Your mailbox has exceeded its storage limit. You will stop receiving messages within 24 hours. "
     "Verify your account to increase storage: {url}"),
    ("Microsoft Security", "Unusual sign-in activity",
     "We detected an unusual sign-in to your account from {country}. If this wasn't you, secure your account "
     "immediately by confirming your password: {url}"),
    ("DocuSign", "Completed: {doc}", "All parties have completed {doc}. Sign in with your email credentials to "
                                     "view the document: {url}"),
    ("PayPal", "Your account has been limited", "We noticed suspicious activity and limited your account. "
                                                "Log in to restore full access: {url}"),
    ("DHL Express", "Delivery attempt failed", "We could not deliver your parcel. Confirm your address and pay "
                                               "the 1.99 redelivery fee: {url}"),
]
PHISH_TENANT_IT = ("IT Helpdesk", "Password expires today",
                   "Your {tenant_name} password expires today. To keep your current password, verify your login "
                   "here: {url} Failure to verify will lock your account.")
PHISH_SHARED_DOC = ("Shared: {doc}", "I've shared a document with you via OneDrive. Please sign in to view it: {url}")

# ---- BEC (no links, social engineering) ---------------------------------------------------
BEC_GIFT_CARDS = ("Quick favor", "Are you at your desk? I need you to purchase some gift cards for a client "
                                 "appreciation event. I'm in meetings all day so can't take calls. Keep this "
                                 "confidential for now and reply with the codes once you have them.")
BEC_WIRE = ("Confidential - wire transfer", "I need a wire processed today for an acquisition we are closing. "
                                            "This is strictly confidential, please do not discuss with anyone. "
                                            "Amount {amount}. Reply and I'll send the beneficiary details.")
BEC_PAYROLL = ("Direct deposit change", "I recently changed banks and would like my next paycheck to go to my new "
                                        "account. Can you update my direct deposit before the next payroll run? "
                                        "I'll send the new account and routing numbers.")
BEC_VENDOR_INVOICE = ("Re: Invoice {inv} - updated bank details",
                      "Please note our bank details have changed due to an audit. Kindly update your records and "
                      "remit payment for invoice {inv} ({amount}) to the new account attached. Payment is overdue, "
                      "please process urgently.")

# ---- malware -----------------------------------------------------------------------------
MALWARE = [
    ("Invoice {inv} overdue", "Your invoice {inv} is overdue. Please see the attached document and enable content "
                              "to view it.", "Invoice_{inv}.docm"),
    ("DHL shipment notice", "Your shipment is on hold. Open the attached shipping documents for details.",
     "DHL_AWB_{inv}.iso"),
    ("Scanned document", "Attached is the scanned document you requested.", "Scan_{inv}.zip"),
    ("Purchase order {po}", "Please find attached our purchase order {po}. Kindly confirm availability.",
     "PO_{po}.xlsm"),
]
MALWARE_PASSWORD_ZIP = ("Re: {topic}", "Here are the updated files. The archive is password protected for "
                                       "security, the password is 4421.", "files_{inv}.zip")

ITEMS = ["steel brackets", "lab reagents", "POS terminals", "pallet racking", "network switches", "office chairs",
         "safety gloves", "printer toner", "label stock", "laptops", "HVAC filters", "cardboard cartons"]
DOCS = ["NDA_2026.pdf", "Master Services Agreement", "Q3 Budget.xlsx", "Offer Letter", "Contract Amendment 2",
        "Lease Renewal"]
COUNTRIES = ["Russia", "Nigeria", "Vietnam", "Brazil", "Romania"]
