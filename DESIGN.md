# Design notes

The trade-offs behind bec-guard, in the order they matter. Numbers are from `make eval` unless noted.

## 1. A cascade, not one big model

The budget is about $0.00008 per email and the provider waits at most 5 s. A cascade spends money
only where it is needed: rules and a small LightGBM decide ~99% of mail in ~10 ms, and only the gray
zone (1%) gets the extra intent check. The same structure is what would make an embedding model or an
LLM affordable later: plug it into Tier 2 and it sees 1% of traffic, not 100%.

Cost of the choice: three places to tune instead of one, and Tier 2 currently adds little (one more
hard positive for three flagged legit emails) because Tier 1 is already confident on this data.

## 2. Rules explain; they rarely decide

Each rule's precision was measured on the training period. Only two were precise enough to quarantine
alone (lookalike domain, young domain sending in bulk), and even those only fire as blocks for
**first-time senders**: legit sister companies have lookalike domains (lookalike precision rises from
0.92 to 0.97 with this gate). `INTERNAL_SPOOF` (own domain, DMARC fail) looks like a block rule but had
0.33 precision: the classic cause is a legit SaaS tool sending as the company without DMARC alignment.
All other rules add reason codes and leave the decision to the model. Missing signals (a service
timeout) never fire a rule: the system fails open, like the provider.

## 3. Point-in-time features and a time-based split

Every relationship feature (first-time sender, prior exchanges, 24 h domain volume, topic shift) is
computed by walking the stream in time order, so an email never sees later mail. A random split would
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

TF-IDF is fast, free and explainable, but matches words, not meaning; plain-wording attacks are left
to the metadata features (text-only PR-AUC 0.860 vs 0.993 for the full model).

## 5. Gray zone and Tier 2

Tier 2 asks two questions: does the email ask for money, gift cards or credentials (TF-IDF intent
classifier trained on weak pattern labels), and does the relationship look off (new sender, topic
shift, reply-to or display-name mismatch, new freemail sender)? Both → quarantine, one → banner,
neither → deliver. A banner is the right action for uncertainty: the user still gets a real invoice,
but with a warning.

Gray-zone lower bound, chosen on the validation window (last 7 training days, 1,192 emails, 27 hard
positives):

| Lower bound | Sent to Tier 2 | Recall | Hard-positive recall | Legit flagged |
|---|---|---|---|---|
| **0.30 (chosen)** | 1.9% | 96.6% | 78% | 3 |
| 0.20 | 2.3% | 96.6% | 78% | 8 |
| 0.10 | 4.4% | 96.6% | 78% | 27 |
| 0.05 | 11.2% | 97.0% | 81% | 74 |

## 6. Labels, classes and noise

LightGBM is multiclass (legit / spam / phishing / BEC / malware) because the action depends on the
class: spam goes to the spam folder, everything else is quarantined. It trains on labels with 2% noise
(user reports are wrong sometimes); all metrics use the true labels. Of the settings tried,
regularisation (`min_child_samples=40`, `reg_lambda=5`, 150 trees) gave the best validation PR-AUC.

## 7. Attachments: async scan, tiered cost

The virus scan is slow (median ~2.5 s, long tail), so the cascade never waits for it: it starts on
arrival and pulls infected mail after delivery. Scanning every attachment in a sandbox cost
**$1.00/mailbox/month**. Static AV on every file plus a sandbox only for risky types (archives, macro
documents, executables) on mail that was not already quarantined brings the total to **$0.20**.
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
- **Bootstrap confidence intervals and a notebook:** kept the repo small; with 69 BEC test emails, a
  one-email change moves BEC recall by ~1.4 points, which is worth saying instead of computing.
