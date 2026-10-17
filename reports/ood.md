# Out-of-distribution check

10 hand-written emails in styles the generator never uses (6 attacks, 4 legit),
classified by the seed-42 cascade with sender history as of the train/test split. Never used for
tuning. Correct = attack not delivered silently, or legit delivered without a banner.

**Attacks caught: 5 / 6** · **Legit delivered cleanly:
3 / 4**

|  | style | truth | action | tier | P(malicious) | reasons | correct |
|---|---|---|---|---|---|---|---|
| ood01_job_telegram | Fake remote job, refundable deposit, Telegram contact | phishing | QUARANTINE | 1 | 0.88 | MODEL_HIGH_RISK | yes |
| ood02_lottery | Lottery win, claims agent on WhatsApp | phishing | QUARANTINE | 2 | 0.75 | AUTH_FAIL, ASKS_PAYMENT, ASKS_OFF_CHANNEL, NEW_SENDER | yes |
| ood03_sextortion | Sextortion with a Bitcoin wallet, no links | phishing | DELIVER | 1 | 0.28 | AUTH_FAIL, INTERNAL_SPOOF | **no** |
| ood04_fake_delivery | Short SMS-style parcel notice with a link | phishing | WARNING_BANNER | 2 | 0.46 | AUTH_FAIL, NEW_SENDER | yes |
| ood05_callback_scam | Fake subscription renewal, call a phone number (no link) | phishing | QUARANTINE | 1 | 0.98 | MODEL_HIGH_RISK | yes |
| ood06_spanish_bec | BEC in Spanish from a freemail account using the CEO's name | bec | QUARANTINE | 2 | 0.75 | DISPLAY_NAME_MISMATCH, ASKS_PAYMENT, NEW_SENDER, FREEMAIL_SENDER | yes |
| ood07_legit_emoji_allhands | Internal, very casual, emoji-heavy | legit | DELIVER | 1 | 0.07 | – | yes |
| ood08_legit_terse_vendor | Known vendor, terse, phone number in the body | legit | DELIVER | 1 | 0.02 | – | yes |
| ood09_legit_customer_refund | First-time customer on Gmail asking for money back | legit | QUARANTINE | 2 | 0.79 | ASKS_PAYMENT, NEW_SENDER, FREEMAIL_SENDER | **no** |
| ood10_legit_benefits | Internal HR notice with a sign-in link to a real SaaS | legit | DELIVER | 1 | 0.10 | – | yes |
