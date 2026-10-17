# Design notes

The trade-offs behind bec-guard, in the order they matter. Headline numbers are mean ± std over 5
seeds (`make multiseed`: each seed regenerates the data and retrains); single-run numbers are seed 42
(`make eval`) and say so.

## 1. A cascade, not one big model

The budget is $0.30 per mailbox per month: $0.002 per email at the specified 5 inbound emails per
mailbox per day, and only $0.00008 per email in a 120/day stress test. The provider waits at most 5 s.
A cascade spends money only where it is needed: rules and a small LightGBM decide ~99% of mail in
~10 ms, and only the gray zone (1%) gets the extra intent check. The same structure is what would make
an embedding model or an LLM affordable later: plug it into Tier 2 and it sees 1% of traffic, not 100%.
At the base volume the whole pipeline costs $0.0084 ± 0.0007/mailbox/month (~3% of budget); in seed
42 that leaves ~$0.11 to spend per gray-zone email.

Cost of the choice: three places to tune instead of one. Tier 2 adds a modest amount over LightGBM
alone (+2.3 points BEC recall, +13.7 points hard-positive recall, for ~6 more legit banners per run)
because Tier 1 is already confident on this data.

## 2. Rules explain; they rarely decide

Each rule's precision was measured on the training period. Only two were precise enough to quarantine
alone (lookalike domain, young domain sending in bulk), and even those only fire as blocks for
**first-time senders**: legit sister companies have lookalike domains (lookalike precision rises from
0.90 to 0.97 with this gate, seed 42). `INTERNAL_SPOOF` (own domain, DMARC fail) looks like a block rule but had
0.45 precision: the classic cause is a legit SaaS tool sending as the company without DMARC alignment.
All other rules add reason codes and leave the decision to the model. Missing signals (a service
timeout) never fire a rule: the system fails open, like the provider. No rule looks at the subject
line: subject signals are cheap for attackers to vary and common in legit mail, so they only feed the
model.

## 3. Point-in-time features and a time-based split

Every relationship feature (first-time sender, prior exchanges, 24 h domain volume, topic shift) is
computed by walking the stream in time order, so an email never sees later mail. History includes the
tenant's **sent-mail log**: "have these two people corresponded?" is answered from what the mailbox
actually sent, never from the quoted thread inside the incoming email, which an attacker can forge. A random split would
leak campaign siblings and future history into training; the last 12 days are the test set instead.
The first 7 days only build history, because every sender looks new at the start of the stream.
Hyperparameters and the gray zone were chosen on the last 7 training days, never on test.

## 4. The text model reads language, not identity

TF-IDF + logistic regression gives a `text_score` that LightGBM uses as one feature, out-of-fold on
training rows so the stacked model is not fed an overfit score. Three fixes came from reading the
model's top terms rather than its metrics:

- **URLs are masked** (attacker domain names leaked the label; link features judge URLs).
- **Sender display names and the recipient's name are masked.** The first model's strongest attack
  terms were "Inc", "Ltd" and attackers' signature names; its strongest legit term was "IT Service Desk".
- **Bigrams stay inside a sentence**, so "...owners are assigned. Cheers" no longer creates a token
  that only exists because of how templates were stitched together.
- **Reply prefixes are stripped.** After fake replies were added, "fw", "fwd" and "re payment" became
  top attack terms, because legit mail never forwarded. Legit forwards were added to the data and the
  prefix is now judged only by the history-based `fake_reply` feature.

TF-IDF is fast, free and explainable, but matches words, not meaning; plain-wording attacks are left
to the metadata features (text-only PR-AUC 0.895 ± 0.016 vs 0.996 ± 0.001 for the full model). A
fourth leak, a literal "budget review" topic used only by fake replies, was a generator artifact and
was removed; one remains visible on purpose ("brightcart", a tenant name that attack templates use).

## 4a. Missing values are neutral

Some features have nothing to measure: topic shift for a sender with no earlier mail, link age for an
email without links, any lookup that timed out. Left as NaN, LightGBM learned a direction for
"missing", and because missing history mostly means a new sender (mostly attackers in training), a
missing topic shift pushed +0.175 toward attack on average. The model now receives the training
median for any missing value (`feature_fill.json`, saved with the model): that push is +0.004, and the
"new sender" signal is carried only by the explicit `first_time_sender` feature. Missing link age moved
from +0.010 to −0.047 (now slightly toward legit, since most link-free mail is legit). Rules still see
the raw NaN, so a timeout never fires a rule.

## 4b. Subject-line features

Six subject features (fake reply, subject–body similarity, subject keywords, capitals, "!", emojis)
went in as model features only. On this data they add little (PR-AUC 0.995 → 0.996, legit flagged
3.0 → 1.8 per run, hard-positive recall unchanged at 53%). The
interesting one, `fake_reply`, is redundant here because every fake reply comes from a new attacker
address that `first_time_sender` already catches; its value is against a hijacked account that fakes a
reply, which the data does not yet contain. Kept because they are cheap, explainable, and cover a real
attacker trick.

## 5. Gray zone and Tier 2

Tier 2 asks two questions: does the email ask for money, gift cards, credentials or an off-channel
contact, and does the relationship look off (new sender, topic shift, reply-to or display-name
mismatch, new freemail sender)? The first question has two parts: a TF-IDF intent classifier trained on
weak pattern labels, and a deterministic keyword layer (currency amounts in any format, pay / fee /
deposit / transfer, phone numbers, WhatsApp / Telegram) that overrides it. The layer exists because a
tester's job scam ("pay 5000 dollar as resignation fee at <phone>") scored 0.02 for payment: a
bag-of-words model can't know phrasings it never saw, while "a currency amount plus a phone number from
a stranger" needs no training data. The fix was made generally (keyword layer, plus advance-fee and
fake-job scams in the generator), not for that one email. Both → quarantine, one → banner,
neither → deliver. One exception: an **established correspondent** (has exchanged mail with this
mailbox, or has sent the company at least 3 earlier emails) is bannered, never quarantined, by Tier 2.
Tier 2 signals are soft, and before this rule real vendors' payment requests were being quarantined
for "asks for payment + topic shift". A banner is the right action for uncertainty: the user still
gets a real invoice, but with a warning. The price is that a hijacked vendor account can at most be
bannered by Tier 2.

Gray-zone lower bound, chosen on the validation window of seed 42 (last 7 training days, 1,204 emails,
914 legit, 22 hard positives), with the established-correspondent rule and the keyword layer in place:

| Lower bound | Recall | Hard-positive recall | Legit flagged | Legit quarantined |
|---|---|---|---|---|
| **0.30 (chosen)** | 99.0% | 86% | 4 | 0 |
| 0.20 | 99.0% | 86% | 11 | 0 |
| 0.10 | 99.7% | 95% | 27 | 0 |
| 0.05 | 100.0% | 100% | 76 | 2 |

Before the established-correspondent rule, widening quarantined real vendors' payment requests (2, 3,
10 and 18 legit emails across these bounds on an earlier data draw). Now it mostly costs banners, so
the choice is a **banner budget: at most 1% of legit mail** (≤9 here). 0.3 is the only bound inside
it; 0.1 would be a reasonable choice for a customer who accepts ~3% bannered mail.

## 6. Labels, classes and noise

LightGBM is multiclass (legit / spam / phishing / BEC / malware) because the action depends on the
class: spam goes to the spam folder, everything else is quarantined. It trains on labels with 2% noise
(user reports are wrong sometimes); all metrics use the true labels. Of the settings tried,
regularisation (`min_child_samples=40`, `reg_lambda=5`, 150 trees) gave the best validation PR-AUC.

## 7. Attachments: async scan, tiered cost

The virus scan is slow (median ~2.5 s, long tail), so the cascade never waits for it: it starts on
arrival and pulls infected mail after delivery. Scanning every attachment in a sandbox fits the base
case ($0.04/mailbox/month at 5 emails/day) but costs **$1.00 in the 120/day stress test**, over
budget. Static AV on every file plus a sandbox only for risky types (archives, macro documents,
executables) on mail that was not already quarantined brings the stress test to **$0.20** (base case
$0.008).
The mock scanner flags unknown macro documents only by hash, because finance teams send legit
`.xlsm` files every day; encrypted archives cannot be scanned at all (see Limitations in the README).

## 8. Synthetic data, built to be hard

The first trained model scored a perfect 1.000 PR-AUC, which meant the data was too easy, not that
the model was good. The generator now shares filler sentences across classes, writes legit mail that
sounds risky (CFO urgent wires, vendor payment chasers, IT password notices), makes 50–60% of
phishing/BEC/malware campaigns copy ordinary business wording, and makes some hard positives
word-for-word copies of legit mail (hijacked accounts, phishing on real SharePoint). Campaigns are
spread evenly in time so every class reaches the test split.

## 9. What was deliberately left out

- **FastAPI service and Docker:** the cascade is a plain Python object; wrapping it adds code but
  nothing to evaluate.
- **External LLM backends:** cost, latency and data-handling terms for customer mail; listed as a
  gray-zone-only future tier.
- **Embedding model (ONNX):** a stronger text signal, but a download, a runtime and more latency for a
  demo whose text-only result is already deliberately limited. Future work.
- **Bootstrap confidence intervals and a notebook:** replaced by a 5-seed rerun of the whole pipeline,
  which captures what actually varies here (which campaigns and hijacked accounts land in the test
  period). Single runs moved BEC recall between 89% and 99%; the headline is 94.7 ± 4.0%. Rule
  severities, hyperparameters and the gray zone were tuned on seed 42 only, so the other seeds are a
  fair check of them.

## 10. An out-of-distribution check, kept separate

Every number above comes from the same generator that produced the training data, so it measures
how well the system learned the generator. `data/ood/emails.json` holds 10 hand-written emails in
styles the generator never uses (job scam via Telegram, lottery, sextortion, SMS-style parcel notice,
callback scam, Spanish BEC, and four unusual legit emails). They were written before any fix was
evaluated on them and are never used for tuning; the README reports them separately. Before the keyword
layer and the advance-fee data: 2 of 6 attacks caught. After: 5.0 ± 0.7 of 6 over 5 seeds, with 3 of 4
legit delivered cleanly every time. The two consistent failures (self-spoofed sextortion delivered; a
new customer's refund request quarantined) are documented with proposed fixes rather than patched,
because patching them would turn the check into training data.
