# Hand-written challenge set

10 hand-written emails (6 attacks, 4 legit), mostly in styles the generator does not use;
the overlap column says where a case resembles a generator scenario. Classified by the seed-42 cascade
with sender history as of the train/test split. Never used for tuning. Correct = attack not delivered
silently, or legit delivered without a banner.

**Attacks caught: 6 / 6** · **Legit delivered cleanly:
3 / 4**

|  | style | overlaps generator? | truth | action | tier | P(malicious) | reasons | correct |
|---|---|---|---|---|---|---|---|---|
| c01_job_telegram | Fake remote job, refundable deposit, Telegram contact | Yes: generator has fake-job advance-fee scams (phishing:advance_fee), added after this case was written | phishing | QUARANTINE | 1 | 0.98 | MODEL_HIGH_RISK | yes |
| c02_lottery | Lottery win, claims agent on WhatsApp | Partly: generator has prize / advance-fee templates; lottery wording and the GBP win are new | phishing | QUARANTINE | 1 | 0.88 | AUTH_FAIL, MODEL_HIGH_RISK | yes |
| c03_sextortion | Sextortion with a Bitcoin wallet, no links | No | phishing | QUARANTINE | 2 | 0.50 | AUTH_FAIL, INTERNAL_SPOOF, ASKS_PAYMENT, NEW_SENDER, TOPIC_SHIFT | yes |
| c04_fake_delivery | Short SMS-style parcel notice with a link | Partly: generator has a 'DHL delivery attempt failed' brand phish; SMS style and USPS are new | phishing | WARNING_BANNER | 2 | 0.44 | AUTH_FAIL, NEW_SENDER | yes |
| c05_callback_scam | Fake subscription renewal, call a phone number (no link) | No (phone-only callback scam) | phishing | QUARANTINE | 1 | 1.00 | MODEL_HIGH_RISK | yes |
| c06_spanish_bec | BEC in Spanish from a freemail account using the CEO's name | Metadata yes (freemail sender with the CEO's name); language no | bec | QUARANTINE | 1 | 0.91 | DISPLAY_NAME_MISMATCH, MODEL_HIGH_RISK | yes |
| c07_legit_emoji_allhands | Internal, very casual, emoji-heavy | No | legit | DELIVER | 1 | 0.04 | – | yes |
| c08_legit_new_address_known_vendor | Terse email from a first-time address (ops@) at a known vendor domain, phone number in the body | Partly: the vendor domain is known, but this address (ops@) has never written before | legit | DELIVER | 1 | 0.02 | – | yes |
| c09_legit_customer_refund | First-time customer on Gmail asking for money back | No | legit | QUARANTINE | 1 | 0.94 | MODEL_HIGH_RISK | **no** |
| c10_legit_benefits | Internal HR notice with a sign-in link to a real SaaS | No | legit | DELIVER | 1 | 0.20 | – | yes |
