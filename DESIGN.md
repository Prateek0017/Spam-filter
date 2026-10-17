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
At the base volume the whole pipeline costs $0.0086 ± 0.0005/mailbox/month (~3% of budget); in seed
42 that leaves ~$0.28 to spend per gray-zone email.

Cost of the choice: three places to tune instead of one, and Tier 2 currently adds little over
LightGBM alone (+1.8 points BEC recall, +6.7 points hard-positive recall, for ~2.4 legit banners per
run) because Tier 1 is already confident on this data.

## 2. Rules explain; they rarely decide

Each rule's precision was measured on the training period. Only two were precise enough to quarantine
alone (lookalike domain, young domain sending in bulk), and even those only fire as blocks for
**first-time senders**: legit sister companies have lookalike domains (lookalike precision rises from
0.91 to 0.97 with this gate). `INTERNAL_SPOOF` (own domain, DMARC fail) looks like a block rule but had
0.36 precision: the classic cause is a legit SaaS tool sending as the company without DMARC alignment.
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
to the metadata features (text-only PR-AUC 0.880 ± 0.019 vs 0.994 ± 0.004 for the full model).

## 4b. Subject-line features

Six subject features (fake reply, subject–body similarity, subject keywords, capitals, "!", emojis)
went in as model features only. On this data they are neutral (PR-AUC 0.994 ± 0.004 with or without,
hard-positive recall 42.9 → 43.5%, well inside the noise). The
interesting one, `fake_reply`, is redundant here because every fake reply comes from a new attacker
address that `first_time_sender` already catches; its value is against a hijacked account that fakes a
reply, which the data does not yet contain. Kept because they are cheap, explainable, and cover a real
attacker trick.

## 5. Gray zone and Tier 2

Tier 2 asks two questions: does the email ask for money, gift cards or credentials (TF-IDF intent
classifier trained on weak pattern labels), and does the relationship look off (new sender, topic
shift, reply-to or display-name mismatch, new freemail sender)? Both → quarantine, one → banner,
neither → deliver. One exception: an **established correspondent** (has exchanged mail with this
mailbox, or has sent the company at least 3 earlier emails) is bannered, never quarantined, by Tier 2.
Tier 2 signals are soft, and before this rule real vendors' payment requests were being quarantined
for "asks for payment + topic shift". A banner is the right action for uncertainty: the user still
gets a real invoice, but with a warning. The price is that a hijacked vendor account can at most be
bannered by Tier 2.

Gray-zone lower bound, chosen on the validation window of seed 42 (last 7 training days, 1,234 emails,
945 legit, 24 hard positives), with the established-correspondent rule in place:

| Lower bound | Sent to Tier 2 | Recall | Hard-positive recall | Legit flagged | Legit quarantined |
|---|---|---|---|---|---|
| **0.30 (chosen)** | 0.6% | 95.2% | 46% | 3 | 0 |
| 0.20 | 1.4% | 95.8% | 54% | 10 | 0 |
| 0.10 | 3.3% | 97.2% | 67% | 26 | 0 |
| 0.05 | 9.4% | 99.7% | 96% | 71 | 0 |

Before the rule, the same sweep quarantined 2, 3, 10 and 18 legit emails. Now widening only costs
banners, so the choice is a **banner budget: at most 1% of legit mail** (≤9 here). 0.3 is the only
bound inside it; 0.1 would be a reasonable choice for a customer who accepts ~3% bannered mail in
exchange for catching two thirds of hijacked-account attacks.

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
  period). Single runs moved BEC recall between 85% and 94%; the headline is 90.0 ± 3.7%. Rule
  severities, hyperparameters and the gray zone were tuned on seed 42 only, so the other seeds are a
  fair check of them.
