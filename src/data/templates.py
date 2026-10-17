"""Text templates for the synthetic generator.

Each template is (subject, body) with `{slot}` placeholders filled by the generator. Attack
intents have several phrasings, legit mail reuses much of the same vocabulary (invoices,
bank details, passwords, shared documents), and greetings / sign-offs / filler sentences are
shared by every class, so the text alone is a strong but imperfect signal.
"""
from __future__ import annotations

GREETINGS = ["Hi {first},", "Hello {first},", "Dear {first},", "{first},", "Hi,", "Good morning {first},",
             "Hi all,", "Hey {first},"]
SIGNOFFS = ["Thanks,\n{sender}", "Best regards,\n{sender}", "Regards,\n{sender}", "Cheers,\n{sender}",
            "Thank you,\n{sender}", "{sender}", "Sent from my iPhone", "Best,\n{sender}"]
FILLERS = ["Let me know if you have any questions.", "Hope your week is going well.",
           "Sorry for the slow reply, it's been a busy week.", "Thanks in advance for your help.",
           "Please treat this as a priority.", "Happy to jump on a call if easier.",
           "I'm travelling this week so email is best.", "Appreciate your quick response.",
           "Please confirm once done.", "Looping in the right people here."]

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
    ("Quick question", "Do you have a minute today? I have a quick question about the {topic} and the invoice "
                       "from {vendor_name}."),
    ("Expense report", "I submitted my expense report for the {topic} trip. Can you approve it before the payment "
                       "run on {day}?"),
]
LEGIT_VENDOR = [
    ("Invoice {inv} for PO {po}", "Please find attached invoice {inv} for PO {po}, amount {amount}, payable "
                                  "net-30 to the account on file. Let us know if anything looks off."),
    ("Invoice {inv}", "Attached is invoice {inv} ({amount}). Payment details are unchanged. Kindly confirm receipt."),
    ("Order {po} shipped", "Your order {po} has shipped and should arrive by {day}. Tracking details are in "
                           "the portal: {url}"),
    ("Quote for {item}", "As discussed, attached is our quote for {item}. Pricing is valid for 30 days. "
                         "Happy to walk through it on a call."),
    ("Re: {item} delivery", "Confirming the {item} delivery window for {day}. Our driver will call ahead."),
    ("Updated price list", "Attached is our updated price list effective next month. Most items are unchanged; "
                           "{item} goes up 3% due to freight costs."),
    ("Payment reminder: {inv}", "Friendly reminder that invoice {inv} for {amount} is now 10 days overdue. "
                                "Please let us know when payment is scheduled."),
    ("Summer sale on {item}", "This month only: 20% off {item} and free delivery on orders over $500. "
                              "Order through the portal: {url}"),
]
LEGIT_NOTIFICATION = [
    ("DocuSign", "dse@docusign.net", "Please review and sign: {doc}",
     "{colleague} sent you a document to review and sign. REVIEW DOCUMENT: {url}"),
    ("Microsoft 365", "no-reply@microsoft.com", "Your Microsoft 365 invoice is available",
     "Your invoice for this billing period is ready. View it in the admin center: {url}"),
    ("Microsoft account team", "account-security-noreply@microsoft.com", "New sign-in to your account",
     "We noticed a new sign-in to your account. If this was you, you can ignore this email. If not, review your "
     "recent activity and secure your account: {url}"),
    ("Zoom", "no-reply@zoom.us", "Cloud recording now available",
     "Your cloud recording for \"{topic}\" is now available. View recording: {url}"),
    ("Industry Weekly", "news@industryweekly.com", "This week: {topic} and more",
     "Top stories this week. Read more: {url} Manage preferences or unsubscribe: {url2}"),
    ("PayPal", "service@paypal.com", "You sent a payment",
     "You sent a payment of {amount} to {vendor_name}. View the transaction details: {url}"),
]
LEGIT_SHARED_DOC = [
    ("Shared: {doc}", "I've shared {doc} with you via OneDrive. Please sign in to view it: {url}"),
    ("{doc}", "Here is the link to {doc} as promised: {url} Let me know if you can't open it."),
]

# ---- hard negatives: legit mail that looks malicious -------------------------------------
HN_EXEC_URGENT_PAYMENT = [
    ("Urgent: payment to {vendor_name} today",
     "Please process the wire to {vendor_name} today, it's urgent. The invoice {inv} is overdue and they will hold "
     "the shipment otherwise. Amount {amount}, bank details are in the ERP."),
    ("Wire needed today", "Can you push the {vendor_name} wire through today? Invoice {inv}, {amount}. I approved "
                          "it in the system this morning."),
    ("Payment today", "Can you push a wire through today? Invoice {inv}, {amount}, for {vendor_name}. I approved "
                      "it already."),
    ("Urgent", "Are you in the office? I need you to process a payment to {vendor_name} before end of day. Details "
               "are in the ERP."),
    ("Quick question", "Do you have a minute today? I have a quick question about the {topic} and the invoice "
                       "from {vendor_name}."),
]
HN_IT_PASSWORD = [
    ("Reminder: password expires in 5 days",
     "Your network password expires in 5 days. Please change it via the self-service portal: {url} "
     "IT will never ask for your password by email."),
    ("Action required: enroll in MFA", "All staff must enroll in multi-factor authentication by {day}. Sign in to "
                                       "verify your account and complete enrollment: {url}"),
    ("Password expires today", "Your {tenant_name} password expires today. Change it in the self-service portal to "
                               "avoid being locked out: {url}"),
    ("Mailbox storage almost full", "Your mailbox is at 95% of its storage limit. Archive old messages or request "
                                    "more storage here: {url}"),
    ("Your password was reset", "Your password was reset by the service desk as requested. Sign in to verify your "
                                "account and set a new password: {url}"),
]
HN_VENDOR_PAYMENT_REQUEST = [
    ("Payment reminder: {inv}", "Invoice {inv} for {amount} is now overdue. Please process payment urgently to "
                                "avoid a hold on your account. Remittance details are on the invoice."),
    ("Invoice {inv} - please process today", "Could you process invoice {inv} ({amount}) today? We need it cleared "
                                             "before month end."),
    ("Invoice {inv}", "Attached is invoice {inv} ({amount}). Payment details are unchanged. Kindly confirm receipt."),
]
HN_PROMO = ("Limited time: 30% off annual plans",
            "For a limited time, upgrade to an annual plan and save 30%. Offer ends {day}. Upgrade now: {url} "
            "Unsubscribe: {url2}")
HN_NEW_VENDOR = ("Introduction - {vendor_name}",
                 "I'm reaching out from {vendor_name}. We supply {item} to several companies in your area and would "
                 "love to quote. Our capabilities deck is attached.")
HN_VENDOR_BANK_CHANGE = ("Notice: change of bank",
                         "Please note that we are moving our banking to a new provider from next month. Updated bank "
                         "details are attached. Our finance team will call you from the number on file to confirm.")
HN_PERSONAL_ACCOUNT = ("Sending from personal email", "My laptop is in for repair so I'm writing from my personal "
                                                      "account. Can you send me the {topic} deck? Need it for {day}.")
HN_ENCRYPTED_ZIP = ("Re: {topic}", "Files attached as discussed. The archive is password protected per our "
                                   "confidentiality policy, I'll send the password in a separate message.")
HN_REBRAND = ("We have a new name and domain", "{vendor_name} is now part of a new group and we've moved to a new "
                                               "email domain. Please update your contacts. Nothing else changes, "
                                               "including our bank details.")

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
    ("Quick question about {tenant_name}", "I'm reaching out because we help companies like {tenant_name} cut "
                                           "{item} costs by 30%. Would you be open to a 15 minute call on {day}? "
                                           "Our deck is here: {url}"),
    ("Re: {item} supply", "Following up on my last email. We supply {item} to several companies in your area "
                          "and would love to quote. Book a time here: {url}"),
    ("Webinar invitation: {topic}", "Join our free webinar on {topic} best practices this {day}. Limited seats, "
                                    "register now: {url} To stop receiving these emails click {url2}"),
]

# ---- phishing ----------------------------------------------------------------------------
PHISH_BRAND = [
    ("Microsoft 365", "Action required: mailbox storage full",
     "Your mailbox has exceeded its storage limit. You will stop receiving messages within 24 hours. "
     "Verify your account to increase storage: {url}"),
    ("Microsoft account team", "New sign-in to your account",
     "We noticed a new sign-in to your account from {country}. If this wasn't you, review your recent activity "
     "and secure your account: {url}"),
    ("Microsoft Security", "Unusual sign-in activity",
     "We detected an unusual sign-in to your account from {country}. If this wasn't you, secure your account "
     "immediately by confirming your password: {url}"),
    ("DocuSign", "Please review and sign: {doc}", "{colleague} sent you a document to review and sign. "
                                                  "REVIEW DOCUMENT: {url}"),
    ("PayPal", "Your account has been limited", "We noticed suspicious activity and limited your account. "
                                                "Log in to restore full access: {url}"),
    ("DHL Express", "Delivery attempt failed", "We could not deliver your parcel. Confirm your address and pay "
                                               "the 1.99 redelivery fee: {url}"),
]
PHISH_TENANT_IT = [
    ("IT Helpdesk", "Password expires today",
     "Your {tenant_name} password expires today. To keep your current password, verify your login "
     "here: {url} Failure to verify will lock your account."),
    ("IT Service Desk", "Action required: enroll in MFA",
     "All staff must enroll in multi-factor authentication today. Sign in to verify your account and complete "
     "enrollment: {url}"),
]

# ---- BEC (no links, social engineering) ---------------------------------------------------
BEC_GIFT_CARDS = [
    ("Quick favor", "Are you at your desk? I need you to purchase some gift cards for a client appreciation event. "
                    "I'm in meetings all day so can't take calls. Reply with the codes once you have them."),
    ("Are you available?", "Are you available? I need a quick favor, can you get some Apple gift cards for the "
                           "team? I'll reimburse you. Keep it between us for now, it's a surprise."),
    ("Request", "I need you to handle a task for me discreetly. Let me know when you are free."),
]
BEC_WIRE = [
    ("Confidential - wire transfer", "I need a wire processed today for an acquisition we are closing. This is "
                                     "strictly confidential, please do not discuss with anyone. Amount {amount}."),
    ("Payment today", "Can you push a wire through today? Invoice {inv}, {amount}. I'll send the beneficiary "
                      "details, I approved it already."),
    ("Urgent", "Are you in the office? I need you to process a payment before end of day. Reply and I will send "
               "the details."),
]
BEC_PAYROLL = [
    ("Direct deposit change", "I recently changed banks and would like my next paycheck to go to my new account. "
                              "Can you update my direct deposit before the next payroll run?"),
    ("Payroll update", "Please update my bank details for payroll. I'll send the new account and routing numbers. "
                       "Need it done before {day}."),
]
BEC_VENDOR_INVOICE = [
    ("Re: Invoice {inv} - updated bank details",
     "Please note our bank details have changed due to an audit. Kindly update your records and remit payment for "
     "invoice {inv} ({amount}) to the new account attached. Payment is overdue, please process urgently."),
    ("Invoice {inv}", "Attached is invoice {inv} ({amount}). Please note we have a new bank account, details "
                      "in the attachment. Kindly confirm once payment is scheduled."),
    ("Payment reminder: {inv}", "Friendly reminder that invoice {inv} for {amount} is overdue. Our old account is "
                                "under review, so please use the updated bank details attached."),
]

# ---- malware -----------------------------------------------------------------------------
MALWARE = [
    ("Invoice {inv} overdue", "Your invoice {inv} is overdue. Please see the attached document and enable content "
                              "to view it.", "Invoice_{inv}.docm"),
    ("Invoice {inv}", "Attached is invoice {inv} ({amount}). Kindly confirm receipt.", "Invoice_{inv}.zip"),
    ("DHL shipment notice", "Your shipment is on hold. Open the attached shipping documents for details.",
     "DHL_AWB_{inv}.iso"),
    ("Scanned document", "Attached is the scanned document you requested.", "Scan_{inv}.zip"),
    ("Purchase order {po}", "Please find attached our purchase order {po}. Kindly confirm availability.",
     "PO_{po}.xlsm"),
    ("Quote for {item}", "As discussed, attached is our quote for {item}. Pricing is valid for 30 days.",
     "Quote_{po}.img"),
]
MALWARE_PASSWORD_ZIP = ("Re: {topic}", "Here are the updated files. The archive is password protected for "
                                       "security, the password is 4421.", "files_{inv}.zip")

ITEMS = ["steel brackets", "lab reagents", "POS terminals", "pallet racking", "network switches", "office chairs",
         "safety gloves", "printer toner", "label stock", "laptops", "HVAC filters", "cardboard cartons"]
DOCS = ["NDA_2026.pdf", "Master Services Agreement", "Q3 Budget.xlsx", "Offer Letter", "Contract Amendment 2",
        "Lease Renewal"]
COUNTRIES = ["Russia", "Nigeria", "Vietnam", "Brazil", "Romania"]
