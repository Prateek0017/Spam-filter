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

Cost of the choice: three places to tune instead of one. Over LightGBM alone the cascade adds +1.7
points BEC recall (blocked or bannered) and +5.1 points hard-positive recall for ~4 more legit banners
per run. The intent check's own contribution is narrower: with the same rules and thresholds,
bannering every gray-zone email detects exactly as much, and the intent check turns banners into
quarantines for attacks (BEC blocked 88.1% → 91.5%) without flagging more legit mail.

## 2. The 5-second deadline, enforced

WHOIS, IP and URL lookups run concurrently, each with its own timeout (50–80 ms), under one shared
deadline taken from `sync_deadline_ms`. Whatever has not answered by then counts as missing. If the
deadline expires, the verdict is DELIVER (fail open, as the provider would do) and is evaluated as
such; the async virus scan can still pull the email afterwards. Latency is measured once, as wall time
of the whole synchronous path, with the mock lookups really sleeping their simulated latency (the
earlier version added a simulated lookup time on top of measured compute). A Tier 0 block returns
before the text model and LightGBM run. Tests cover lookups slower than the deadline (DELIVER after
~100 ms) and 40 links (82 lookups, ~1.6 s sequentially) finishing well inside the deadline. Over 5
seeds: p99 41.3 ± 3.4 ms and zero fail-open verdicts.

## 3. Rules explain; they rarely decide

Each rule's precision was measured on the training period. Only two were precise enough to quarantine
alone (lookalike domain, young domain sending in bulk), and even those only fire as blocks for
**first-time senders**: legit sister companies have lookalike domains (lookalike precision rises from
0.90 to 0.97 with this gate, seed 42). `INTERNAL_SPOOF` (own domain, DMARC fail) looks like a block rule
but had 0.45 precision: the classic cause is a legit SaaS tool sending as the company without DMARC
alignment. All other rules add reason codes and leave the decision to the model. Missing signals (a
service timeout) never fire a rule. No rule looks at the subject line: subject signals are cheap for
attackers to vary and common in legit mail, so they only feed the model.

## 4. Point-in-time features, trust and a time-based split

Every relationship feature (first-time sender, prior exchanges, 24 h domain volume, topic shift) is
computed by walking the stream in time order, so an email never sees later mail. History includes the
tenant's **sent-mail log**: "have these two people corresponded?" is answered from what the mailbox
actually sent, never from the quoted thread inside the incoming email, which an attacker can forge.

**Trust is separate from history and must be earned.** A sender is *established* only if this mailbox
has written to them, or at least `established_min_msgs` (3) of their earlier emails were **delivered**
without a banner. Quarantined, spam-foldered and bannered mail still counts for volume and topic
history but never earns trust; the earlier version let one unsolicited email make a sender
"established". Mail failing DMARC inherits no trust, because its From address may be spoofed (the
challenge set's self-spoofed sextortion exposed this: a spoofed colleague was being treated as
established). In the offline replay, mail from before the test period has no verdicts, so mail whose
observed label is legit stands in for "delivered and not reported"; inside the test period only the
cascade's own DELIVER verdicts earn trust. Regression tests cover a stranger's payment request that is
quarantined and then sent again (still quarantine-eligible) and a DMARC-failing copy of an established
colleague (quarantined, not bannered).

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
value, **not a guaranteed neutral contribution**: in seed 42 a missing topic shift still pushes +0.036
and a missing link age −0.067 on average, because the model can still combine the filled value with
other features. "New sender" is carried by the explicit `first_time_sender` feature. Rules see the raw
NaN, so a timeout never fires a rule.

## 7. Subject-line features

Six subject features (fake reply, subject–body similarity, subject keywords, capitals, "!", emojis)
went in as model features only. On this data they add little (PR-AUC 0.993 → 0.994, legit flagged
4.2 → 3.0 per run, hard-positive recall 59.8 → 60.3%, inside the noise). The interesting one,
`fake_reply`, is redundant here because every fake reply comes from a new attacker address that
`first_time_sender` already catches; its value is against a hijacked account that fakes a reply,
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
| 300 | 15 | 20 | 0.0 | 0.9562 |
| **150** | **15** | **20** | **0.0** | **0.9585 (chosen)** |
| 300 | 7 | 40 | 0.0 | 0.9579 |
| 300 | 15 | 40 | 5.0 | 0.9560 |
| 150 | 15 | 40 | 5.0 | 0.9564 |

An earlier version of this file said a regularised model (`min_child_samples=40`, `reg_lambda=5`) had
won; that came from an ad-hoc comparison on an older data draw and does not reproduce, so the config
now uses the script's choice. The spread across settings (0.956–0.959) is small, so the choice matters
little.

Gray-zone lower bound (upper bound 0.8), with the trust rules and keyword layer in place. The rule is
a **banner budget**: catch the most hard positives while flagging at most 1% of legit mail (≤9 here).

| Lower bound | Sent to Tier 2 | Recall | Hard-positive recall | Legit flagged | Legit quarantined / spam-foldered |
|---|---|---|---|---|---|
| **0.30 (chosen)** | 0.3% | 93.9% | 77% | 8 | 7 |
| 0.20 | 0.7% | 94.3% | 82% | 12 | 7 |
| 0.10 | 2.0% | 94.9% | 91% | 22 | 8 |
| 0.05 | 3.3% | 95.3% | 95% | 33 | 8 |

"Legit" here is by observed label, so it includes a few mislabelled attacks; the quarantined ones come
from Tier 0 and confident Tier 1 decisions, not from the gray zone. 0.1 would be a reasonable choice for
a customer who accepts ~2.4% flagged mail in exchange for catching most hijacked-account attacks. Rule
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
  period). Single runs moved BEC recall (blocked or bannered) between 88% and 97%; the headline is
  93.8 ± 3.5%. Hyperparameters and the gray zone were selected on seed 42 only, so the other seeds are a
  fair check of them.
