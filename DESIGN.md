# Design notes

The trade-offs behind bec-guard, in the order they matter. Headline numbers are mean ± std over 5
seeds (`make multiseed`: each seed regenerates the data and retrains); single-run numbers are seed 42
(`make eval`) and say so. Model-selection numbers come from `make validate`
([reports/validation.md](reports/validation.md)).

## 1. A cascade, not one big model

The budget is $0.30 per mailbox per month: $0.002 per email at the specified 5 inbound emails per
mailbox per day, and only $0.00008 per email in a 120/day projection. The provider waits at most 5 s.
A cascade spends money only where it is needed: rules and a small LightGBM decide ~99% of mail, and
only the gray zone (~1%) gets the extra intent check. The same structure is what would make an
embedding model or an LLM affordable later: plug it into Tier 2 and it sees 1% of traffic, not 100%.

Cost of the choice: three places to tune instead of one. Over LightGBM alone the cascade adds +2.0
points BEC recall (blocked or bannered) and +4.5 points hard-positive recall for ~4 more legit banners
per run. The intent check's own contribution is narrower: with the same rules and thresholds,
bannering every gray-zone email detects exactly as much, and the intent check turns banners into
quarantines for attacks (BEC blocked 88.4% → 91.8%) without flagging more legit mail.

## 2. The 5-second deadline, enforced

The whole decision (lookups, rules, text model, LightGBM, intent check) runs in a worker, and
`classify` waits for it with a hard timeout set by `sync_deadline_ms`. If the deadline passes,
`classify` returns DELIVER at the deadline (fail open, as the provider would do), whatever is still
running; the late result is discarded and the async virus scan can still pull the email. An earlier
version only checked the deadline after model inference returned, so a slow model could still hold the
response. Inside the worker, WHOIS, IP and URL lookups run concurrently, each with its own timeout
(50–80 ms); whatever has not answered by the deadline counts as missing. Latency is measured once, as
wall time, with the mock lookups really sleeping their simulated latency. A Tier 0 block returns before
the text model and LightGBM run. Tests cover lookups slower than the deadline (DELIVER after ~100 ms),
a model that takes 1 s (DELIVER at a 200 ms deadline), and 40 links (82 lookups, ~1.6 s sequentially)
finishing well inside the deadline. Over 5
seeds: p99 42.8 ± 4.5 ms and zero fail-open verdicts.

## 3. Rules explain; they rarely decide

Each rule's precision was measured on the training period. Only two were precise enough to quarantine
alone (lookalike domain, young domain sending in bulk), and even those only fire as blocks for
senders who are **not established** (section 4): legit sister companies have lookalike domains
(lookalike precision rises from
0.90 to 0.97 with this gate, seed 42). `INTERNAL_SPOOF` (own domain, DMARC fail) looks like a block rule
but had 0.45 precision: the classic cause is a legit SaaS tool sending as the company without DMARC
alignment. All other rules add reason codes and leave the decision to the model. Missing signals (a
service timeout) never fire a rule. No rule looks at the subject line: subject signals are cheap for
attackers to vary and common in legit mail, so they only feed the model.

## 4. Point-in-time features, trust and a time-based split

Every relationship feature (untrusted sender, prior exchanges, 24 h domain volume, topic shift) is
computed by walking the stream in time order, so an email never sees later mail. History includes the
tenant's **sent-mail log**: "have these two people corresponded?" is answered from what the mailbox
actually sent, never from the quoted thread inside the incoming email, which an attacker can forge.

**Trust is separate from history, must be earned, and has one definition.** A sender is *established*
only if this mailbox has written to them, or at least `established_min_msgs` (3) of their earlier
emails were **delivered** without a banner and passed DMARC; a message that itself fails DMARC is never
established. `FeatureExtractor.is_established` is the only implementation, and every tier calls it:
Tier 0 block rules act only on senders who are not established, the model feature `untrusted_sender`
is its negation, and Tier 2 treats non-established senders as new and never quarantines an
established one. Earlier versions used different definitions on different paths (Tier 0 used the raw
received count, Tier 2 treated one clean delivery as enough, and DMARC-failing deliveries still
incremented the counter), so a repeated quarantined lookalike lost its Tier 0 block and a stranger
could gain trust cheaply. Quarantined, spam-foldered and bannered mail still counts for volume and
topic history but never earns trust. In the offline replay, mail from before the test period has no
verdicts, so mail whose observed label is legit stands in for "delivered and not reported"; inside the
test period only the cascade's own DELIVER verdicts earn trust. Regression tests cover: a quarantined
lookalike sending again (still blocked at Tier 0), a quarantined stranger's repeated payment request
(still quarantine-eligible), one clean delivery followed by a payment request (still new), three
DMARC-failing deliveries (still not established), and a DMARC-failing copy of an established colleague
(quarantined, not bannered).

A random split would leak campaign siblings and future history into training; the last 12 days are the
test set instead. The first 7 days are excluded from **LightGBM** training only, because every sender
looks new there; the text and intent models do train on them.

## 5. The text model reads language, not identity

TF-IDF + logistic regression gives a `text_score` that LightGBM uses as one feature, out-of-fold on
training rows so the stacked model is not fed an overfit score. Several fixes came from reading the
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
to the metadata features (text-only PR-AUC 0.895 ± 0.016 vs 0.994 ± 0.004 for the full model). A
literal "budget review" topic used only by fake replies was a generator artifact and was removed; one
artifact remains visible on purpose ("brightcart", a tenant name that attack templates use).

## 6. Missing values get a typical value

Some features have nothing to measure: topic shift for a sender with no earlier mail, link age for an
email without links, any lookup that timed out. Left as NaN, LightGBM learned a direction for
"missing", and because missing history mostly means a new sender (mostly attackers in training), a
missing topic shift pushed +0.175 toward attack on average. The model now receives the training
median for any missing value (`feature_fill.json`, saved with the model). That supplies a typical
value, **not a guaranteed neutral contribution**: in seed 42 a missing topic shift still pushes +0.039
and a missing link age −0.079 on average, because the model can still combine the filled value with
other features. "New sender" is carried by the explicit `untrusted_sender` feature. Rules see the raw
NaN, so a timeout never fires a rule.

## 7. Subject-line features

Six subject features (fake reply, subject–body similarity, subject keywords, capitals, "!", emojis)
went in as model features only. On this data they have no measurable effect (PR-AUC 0.994 with or
without, legit flagged 3.2 per run either way, hard-positive recall 59.8 → 59.2%, inside the noise). The interesting one,
`fake_reply`, is redundant here because every fake reply comes from a new attacker address that
`untrusted_sender` already catches; its value is against a hijacked account that fakes a reply,
which the data does not yet contain. Kept because they are cheap, explainable, and cover a real
attacker trick.

## 8. Gray zone and Tier 2

Tier 2 asks two questions: does the email ask for money, gift cards, credentials or an off-channel
contact, and does the relationship look off (untrusted sender, topic shift, reply-to or display-name
mismatch, untrusted freemail sender)? The first question has two parts: a TF-IDF intent classifier
trained on weak pattern labels, and a deterministic keyword layer (currency amounts in any format,
pay / fee / deposit / transfer, phone numbers, WhatsApp / Telegram) that overrides it. The layer exists
because a tester's job scam ("pay 5000 dollar as resignation fee at <phone>") scored 0.02 for payment:
a bag-of-words model can't know phrasings it never saw, while "a currency amount plus a phone number
from a stranger" needs no training data. Both → quarantine, one → banner, neither → deliver, except
that an **established** sender (section 4) is bannered, never quarantined, by Tier 2: its signals are
soft, and a real vendor's payment request must still reach the user. The price is that a hijacked
vendor account can at most be bannered by Tier 2.

## 9. Model selection is a script

`make validate` fits everything (TF-IDF vocabulary, text model, intent model, missing-value medians,
LightGBM) on data before the validation window, the last 7 training days of seed 42 (1,204 emails, 907
legit by observed label, 22 hard positives). It scores with the observed (noisy) labels, which is all a
deployment has. It then checks its choices against `configs/default.yaml` and refits on the full
training period. If they differ, it stops and says what to change.

LightGBM settings (fixed: learning rate 0.05, subsample 0.8, colsample 0.8):

| Trees | Leaves | min_child_samples | reg_lambda | Validation PR-AUC |
|---|---|---|---|---|
| 300 | 15 | 20 | 0.0 | 0.9546 |
| **150** | **15** | **20** | **0.0** | **0.9604 (chosen)** |
| 300 | 7 | 40 | 0.0 | 0.9577 |
| 300 | 15 | 40 | 5.0 | 0.9540 |
| 150 | 15 | 40 | 5.0 | 0.9520 |

An earlier version of this file said a regularised model (`min_child_samples=40`, `reg_lambda=5`) had
won; that came from an ad-hoc comparison on an older data draw and does not reproduce, so the config
now uses the script's choice. The spread across settings (0.952–0.960) is small, so the choice matters
little.

Gray-zone lower bound (upper bound 0.8), with the trust rules and keyword layer in place. The rule is
a **banner budget**: catch the most hard positives while flagging at most 1% of legit mail (≤9 here);
if no bound fits, use the most conservative one.

| Lower bound | Sent to Tier 2 | Recall | Hard-positive recall | Legit flagged | Legit quarantined / spam-foldered |
|---|---|---|---|---|---|
| **0.30 (chosen)** | 0.7% | 94.3% | 82% | 10 | 6 |
| 0.20 | 0.7% | 94.3% | 82% | 11 | 6 |
| 0.10 | 1.7% | 94.9% | 91% | 18 | 7 |
| 0.05 | 3.1% | 94.9% | 91% | 31 | 7 |

With the shared trust definition, no bound meets the budget: 0.3 flags 10 of 907 legit validation
emails (1.1%), so the script falls back to it and says so. "Legit" here is by observed label, so it
includes a few mislabelled attacks; the quarantined ones come from Tier 0 and confident Tier 1
decisions, not from the gray zone. 0.1 would be a reasonable choice for a customer who accepts ~2%
flagged mail in exchange for catching more hijacked-account attacks. Rule
severities were chosen earlier from per-rule training-period precision (section 3) and are not part of
the sweep.

## 10. Labels, classes and noise

LightGBM is multiclass (legit / spam / phishing / BEC / malware) because the action depends on the
class: spam goes to the spam folder, everything else is quarantined. A Tier 0 block never runs the
model, so its class comes from the evidence (attachment → malware, link → phishing, bulk from a young
domain → spam, otherwise BEC). Training uses labels with 2% noise (user reports are wrong sometimes);
all metrics use the true labels.

## 11. Attachments and cost

The virus scan is slow (median ~2.5 s, long tail), so the cascade never waits for it: it starts on
arrival and pulls infected mail after delivery. The mock scanner flags unknown macro documents only by
hash, because finance teams send legit `.xlsm` files every day; encrypted archives cannot be scanned at
all.

The cost model is an **estimated variable cost under stated deployment assumptions**. As implemented
(every lookup paid, every attachment through the single scanner at sandbox prices) it is $0.115 ±
0.003 per mailbox per month at the specified 5 emails/day (38% of budget), and $2.77 at a 120/day
projection (over 9× the budget). The proposed, not implemented, savings are a lookup cache, an
attachment hash cache, a cheap static AV scan on every file, and the sandbox only for risky file types
on mail that was not already quarantined. With them the base case is $0.008 (3%) and the projection
$0.20 (67%). The synthetic data has ~0.56 emails per mailbox per day, so both volumes reuse the
per-email rates observed in the replay.

## 12. Synthetic data, built to be hard

The first trained model scored a perfect 1.000 PR-AUC, which meant the data was too easy, not that
the model was good. The generator now shares filler sentences across classes, writes legit mail that
sounds risky (CFO urgent wires, vendor payment chasers, IT password notices), makes 50–60% of
phishing/BEC/malware campaigns copy ordinary business wording, and makes some hard positives
word-for-word copies of legit mail (hijacked accounts, phishing on real SharePoint). Campaigns are
spread evenly in time so every class reaches the test split.

## 13. A hand-written challenge set, kept separate

Every number above comes from the same generator that produced the training data, so it measures
how well the system learned the generator. `data/challenge/emails.json` holds 10 hand-written emails,
mostly in styles the generator does not use (sextortion, a callback scam, Spanish BEC, an SMS-style
parcel notice, and four unusual legit emails). Some overlap generator scenarios, noted per case: the
job scam and lottery resemble the advance-fee scams added later, the parcel notice resembles a brand
phish, and the "vendor" email is a first-time address at a known vendor domain. It is therefore called
a challenge set, not an out-of-distribution test. The emails were written before any fix was evaluated
on them and are never used for tuning. Before the keyword layer and the advance-fee data: 2 of 6
attacks caught (seed 42). Now: 5.0 ± 0.7 of 6 over 5 seeds, with 3 of 4 legit delivered cleanly every
time. One fix was prompted by a case in this set (DMARC-failing mail inherits no trust, section 4),
because it exposed a real spoofing hole rather than a scoring miss. The two consistent failures
(self-spoofed sextortion delivered in 4 of 5 seeds; a new customer's refund request quarantined) are
documented with proposed fixes rather than patched.

## 14. What was deliberately left out

- **FastAPI service and Docker:** the cascade is a plain Python object; wrapping it adds code but
  nothing to evaluate.
- **External LLM backends:** cost, latency and data-handling terms for customer mail; listed as a
  gray-zone-only future tier.
- **Embedding model (ONNX):** a stronger text signal, but a download, a runtime and more latency for a
  demo whose text-only result is already deliberately limited. Future work.
- **Bootstrap confidence intervals and a notebook:** replaced by a 5-seed rerun of the whole pipeline,
  which captures what actually varies here (which campaigns and hijacked accounts land in the test
  period). Single runs moved BEC recall (blocked or bannered) between 89% and 97%; the headline is
  94.4 ± 3.0%. Hyperparameters and the gray zone were selected on seed 42 only, so the other seeds are a
  fair check of them.

## 15. Reference tables

Detail moved out of the README. Single-run tables are seed 42 (`make eval`); the full reports are
[reports/eval_report.md](reports/eval_report.md), [reports/challenge.md](reports/challenge.md),
[reports/validation.md](reports/validation.md) and [reports/multiseed.md](reports/multiseed.md).

### Per-class results (seed 42, full cascade after the async scan)

| Class | Precision | Recall | F1 | Support | PR-AUC (LightGBM) |
|---|---|---|---|---|---|
| legit | 99.2% | 99.4% | 99.3% | 1574 | 0.999 |
| spam | 97.5% | 100.0% | 98.7% | 115 | 1.000 |
| phishing | 100.0% | 95.2% | 97.5% | 104 | 0.999 |
| **BEC** | **94.3%** | **89.2%** | **91.7%** | 74 | 0.961 |
| malware | 93.2% | 97.2% | 95.2% | 71 | 0.996 |

Classic BEC patterns (CEO gift cards, wire requests from lookalike and freemail domains, payroll
diversion, direct spoofing, vendor-invoice fraud) were detected 65 of 67 times. Most BEC misses came
from **compromised real vendor accounts**: 6 of 7 delivered, 1 bannered.

**Hard cases.** Hard positives: 44.4% detected (compromised partner accounts 3/5, compromised vendor
1/7, password-protected zips 4/6). Hard negatives: 247 in test, 2 quarantined (legit
password-protected archives), 7 bannered (4 real vendor payment requests, 3 legit archives).

**What drives the model (SHAP, top 10):** text_score, risky_attachments, sender_domain_age_days,
payment_kw, min_url_domain_age_days, subject_body_sim, topic_shift, lookalike_score, ip_score,
domain_volume_24h.
Chart: [reports/shap_top_features.png](reports/shap_top_features.png).

### Subject-line features

| Feature | What it measures |
|---|---|
| `fake_reply` | Subject starts with RE:/FW:/Fwd: but this mailbox and sender have never exchanged mail (history store, not the quoted thread) |
| `subject_body_sim` | TF-IDF cosine similarity between subject and body |
| `subject_kw` | Urgency / money words in the subject (separate from the body keyword counts) |
| `subject_caps_ratio`, `subject_exclaims`, `subject_emojis` | Style: share of capital letters, "!" count, emoji count |

### Top TF-IDF terms (seed 42)

| # | Toward attack | Toward legit |
|---|---|---|
| 1 | purchase | unchanged |
| 2 | your | are unchanged |
| 3 | purchase order | payment details |
| 4 | document | hi |
| 5 | last email | tuesday |
| 6 | book time | payment |
| 7 | book | details are |
| 8 | time here | from |
| 9 | last | on the |
| 10 | on my | available |
| 11 | my last | delivery |
| 12 | here url | on |
| 13 | here | are |
| 14 | account | the |
| 15 | brightcart | capabilities deck |

Sensible: "click here" links ("here url"), spam follow-ups ("my last email", "book time"), malware lures
("purchase order", "document"), credential lures ("account"), and on the legit side "payment details are
unchanged" from genuine vendor mail. "payment" leans legit because real payment chasers far outnumber
fraudulent ones, which is exactly why text alone can't catch BEC. Not sensible, and left visible on
purpose: "brightcart" is one tenant's company name (spam and phishing templates name the company),
"capabilities deck" comes from one hard-negative template, and "tuesday", "hi" and function words
reflect template style. Three earlier versions of this list exposed leaks that were fixed: sender
names and company suffixes ("Ltd", "IT Service Desk"), reply prefixes ("fw", "fwd") once fake replies
were added, and a literal "budget review" topic that only fake replies used.

### Hand-written challenge set, case by case (seed 42)

| Email | Truth | Action | Tier | Why |
|---|---|---|---|---|
| Fake remote job, deposit via Telegram | phishing | QUARANTINE | 1 | model confident (0.98) |
| Lottery win, agent on WhatsApp | phishing | QUARANTINE | 1 | model confident (0.88), auth failure |
| Sextortion, Bitcoin wallet, spoofs the recipient's own address | phishing | QUARANTINE | 2 | money request + no trust (DMARC fails, so the spoofed address inherits none) |
| SMS-style parcel notice with a link | phishing | WARNING_BANNER | 2 | new sender, auth failure |
| Callback scam, phone number only | phishing | QUARANTINE | 1 | model confident (1.00) |
| BEC in Spanish from Gmail with the CEO's name | BEC | QUARANTINE | 1 | model confident (0.91), display-name mismatch |
| Emoji-heavy internal note | legit | DELIVER | 1 | |
| Terse email from a new address at a known vendor domain | legit | DELIVER | 1 | |
| First-time customer on Gmail asking for a refund | legit | **QUARANTINE** | 1 | model confident (0.94): "new freemail sender + money request" is the scam pattern |
| HR sign-in reminder with a Workday link | legit | DELIVER | 1 | |

### Estimated variable cost

| $/mailbox/month | Base, as implemented | Base, with proposed savings | Projection (120/day), as implemented | Projection, with proposed savings |
|---|---|---|---|---|
| **5 seeds** | **0.115 ± 0.003 (38%)** | 0.008 ± 0.001 (3%) | 2.77 ± 0.07 (923%) | 0.200 ± 0.014 (67%) |
| Seed 42: compute | 0.0000 | 0.0000 | 0.0006 | 0.0006 |
| Seed 42: reputation / WHOIS lookups | 0.0396 | 0.0040 | 0.9503 | 0.0950 |
| Seed 42: attachment scanning | 0.0791 | 0.0047 | 1.8985 | 0.1129 |
| Seed 42: total | 0.1187 (40%) | 0.0087 (3%) | 2.8493 (950%) | 0.2085 (69%) |

Assumptions (all in `configs/default.yaml`; measured values come from the eval run):

| Assumption | Value | Source |
|---|---|---|
| Inbound emails per mailbox per day (base) | 5 | The assignment's specification (30 mailboxes per customer). |
| Inbound emails per mailbox per day (projection) | 120 | A heavy business inbox. Radicati reports 122 emails *sent and received* per business user per day ([2015 report](https://www.radicati.com/wp/wp-content/uploads/2015/02/Email-Statistics-Report-2015-2019-Executive-Summary.pdf)) and ~78 *received* ([2012 survey](https://www.radicati.com/?p=8785)), so 120 inbound is pessimistic. |
| Synthetic rate | ~0.56/day | Measured: 10,000 emails / 300 mailboxes / 60 days. Not used for cost; per-email rates are. |
| Compute price | $0.04 per vCPU-hour | AWS c7g.large (2 vCPU, on-demand, us-east-1) lists at $0.0725/hour ≈ $0.036/vCPU-hour per third-party trackers ([DoIT](https://www.doit.com/compute/spot/us-east-1/c7g.large), [Holori](https://calculator.holori.com/aws/ec2/c7g.large/us-east-1)); rounded up. |
| CPU per email | ~4.6 ms | Measured (process CPU time of the sync path). |
| Overhead on measured compute | 3× | Assumption: MIME parsing, queueing and retries are not in the measured time. |
| Lookups per email | 2.6 | Measured: IP + sender WHOIS + URL reputation and WHOIS per unique link. |
| Price per lookup | $0.0001 | Assumption: blend of self-hosted feeds and commercial reputation APIs; prices vary widely. |
| Lookup cache hit rate (proposed) | 90% | Assumption: senders, IPs and link domains repeat heavily within hours. |
| Attachments per email | 0.26 | Measured on the synthetic test set (likely higher than real mail). |
| Scanner / sandbox price | $0.002 per file | Assumption: order of magnitude for a commercial sandbox. |
| Static AV scan (proposed) | $0.00005 per file | Assumption: self-hosted signature scanner, CPU cost only. |
| Sandbox submissions (proposed) | 0.025 per email | Measured: archives, macro documents and executables on mail not already quarantined. |
| Attachment hash cache hit rate (proposed) | 50% | Assumption: the same files (invoices, decks, campaign payloads) reach many mailboxes. |
