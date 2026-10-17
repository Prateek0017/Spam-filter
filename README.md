# bec-guard

A tiered spam / phishing / BEC (business email compromise) filter for a multi-tenant B2B email
platform. Cheap rules and a gradient-boosted model handle almost all mail in ~10 ms; only gray-zone
emails get a second look; a slow attachment scan runs in the background. Everything runs locally,
no API keys, on reproducible synthetic data.

**Cost: $0.009 per mailbox per month (~3% of the $0.30 budget)** at the specified 5 inbound emails
per mailbox per day; still within budget ($0.21, ~69%) in a 120 emails/day stress test.

## Key result

Mean ± standard deviation over **5 seeds**: each seed regenerates the synthetic data and retrains every
model, then evaluates on its own held-out last 12 days (~1,970 emails, ~380 malicious, ~70 BEC; true
labels). "Detected" means any action other than DELIVER; models were trained on labels with 2% noise.
Legit flagged is a count per run (~1,590 legit test emails each).

| Approach | PR-AUC | Precision | Recall | BEC recall | Hard-positive recall | Legit flagged |
|---|---|---|---|---|---|---|
| Rules only (Tier 0 block) | 0.605 ± 0.022 | 99.2 ± 1.2% | 11.7 ± 1.2% | 27.7 ± 4.6% | 0.0 ± 0.0% | 0.4 ± 0.5 |
| Text only (TF-IDF + LR) | 0.880 ± 0.019 | 56.6 ± 2.1% | 87.7 ± 3.4% | 87.3 ± 5.5% | 75.9 ± 11.7% | 257.6 ± 23.7 |
| Metadata only (no text or subject features) | 0.981 ± 0.007 | 96.0 ± 1.4% | 91.7 ± 1.6% | 73.1 ± 7.6% | 26.2 ± 12.4% | 14.8 ± 5.5 |
| Full model (LightGBM, no subject features) | 0.994 ± 0.004 | 99.9 ± 0.3% | 95.5 ± 1.3% | 88.5 ± 4.6% | 42.9 ± 8.6% | 0.4 ± 0.9 |
| Full model + subject features | **0.994 ± 0.004** | 100.0 ± 0.0% | 95.6 ± 1.1% | 88.2 ± 5.2% | 43.5 ± 7.4% | 0.0 ± 0.0 |
| **Full cascade** (rules → model → intent check) | – | 99.3 ± 0.5% | 95.8 ± 1.0% | **90.0 ± 3.7%** | **50.2 ± 7.8%** | 2.4 ± 1.7 |

Per-seed values: [reports/multiseed.md](reports/multiseed.md) (`make multiseed`, ~1.5 minutes).

- **Text alone is not enough.** It finds most attacks only by also flagging ~258 legit emails per run
  (16% of legit mail), because legit invoices, payment chasers and IT notices use the same words.
- **Relationship + infrastructure features carry BEC.** Who is writing (first-time sender, prior
  exchanges, lookalike or freemail domain, display-name and reply-to tricks) is what separates a real
  CFO's urgent wire request from a fake one. Combining them with the text score gives the best of both.
- **The cascade adds a little on top of the model:** +1.8 points BEC recall and +6.7 points
  hard-positive recall, paid for with ~2.4 warning banners on legit mail per run. The intent check
  never quarantines an established correspondent; it banners them instead.
- **Subject-line features are neutral here** (PR-AUC 0.994 with or without). See
  [Subject-line features](#subject-line-features) for why.
- **Hijacked real accounts remain hard.** Compromised-vendor BEC is the main miss; see
  [Limitations](#limitations).
- **Why five seeds:** each run has only ~70 BEC and ~25 hard-positive test emails, so one email moves
  BEC recall by ~1.4 points and hard-positive recall by ~4. Single runs moved BEC recall between 85%
  and 94%; the standard deviations above are the honest error bars.

The detailed sections below (per-class results, hard cases, SHAP, latency, cost table, demo) come from
a **single run, seed 42**; the full report is [reports/eval_report.md](reports/eval_report.md).

## Quickstart

```bash
make setup               # Python 3.11 venv via uv (macOS: run `brew install libomp` once first)
make data train eval     # ~10k synthetic emails -> models/ -> reports/   (~30 seconds)
make demo                # Streamlit app on http://localhost:8501
```

`make test` runs the test suite; `make multiseed` reruns everything over 5 seeds. **macOS:** LightGBM
needs the OpenMP runtime; without `brew install libomp`, importing it fails with
`Library not loaded: @rpath/libomp.dylib`.

## The problem and the constraints

A B2B email provider must classify every inbound email into **DELIVER**, **WARNING_BANNER**,
**SPAM_FOLDER** or **QUARANTINE**, with reason codes the customer's admin can read.

- **Budget: $0.30 per mailbox per month.** At the specified 5 inbound emails per mailbox per day
  (30 mailboxes per customer) that is 150 emails, so **$0.002 per email** for compute, reputation
  lookups and attachment scanning together. The design must also survive a heavy inbox: at 120/day
  the budget shrinks to $0.00008 per email, where a hosted LLM call on every email is out of reach.
- **Latency: the provider gives up after 5 s** and delivers anyway (fail open). Target p99 < 2 s.
- **BEC is the expensive failure.** It has no malicious link or file to detect; the signal is
  *who* is asking *what*, compared with how this sender normally behaves.
- **Multi-tenant.** Every tenant has its own executives, vendors and correspondents, so "normal"
  must be learned per tenant from point-in-time history.

## Architecture

```mermaid
flowchart LR
    A[Inbound email] --> S["Signals: auth, WHOIS age, IP and URL reputation,<br/>sender history, topic shift, keywords, subject line"]
    A -. attachments .-> V[(Virus scan<br/>async, median ~2.5 s)]
    S --> R{Tier 0<br/>rules}
    R -- "block rule + first-time sender" --> Q[QUARANTINE]
    R -- otherwise --> M[Tier 1<br/>text score + LightGBM]
    M -- "P < 0.3" --> D[DELIVER]
    M -- "P ≥ 0.8" --> X[SPAM_FOLDER or<br/>QUARANTINE by class]
    M -- "0.3 ≤ P < 0.8" --> I{"Tier 2 intent check:<br/>asks for money, gift cards or login?<br/>relationship looks off?"}
    I -- "both, unknown sender" --> Q
    I -- "both, established sender" --> B
    I -- one --> B[WARNING_BANNER]
    I -- neither --> D
    V -- "infected, after delivery" --> P[Pull from mailbox]
```

| Tier | What it does | Share of test mail (seed 42) |
|---|---|---|
| 0: rules | 7 reason-coded rules. Two can quarantine alone (lookalike domain, young domain sending in bulk), and only for first-time senders. None looks at the subject. | 2.3% |
| 1: model | TF-IDF text score + 30 other features in a LightGBM classifier (5 classes). | 97.0% |
| 2: intent check | Gray-zone scores only: what the email asks for plus whether the relationship looks off. Never quarantines an established correspondent. | 0.7% |
| async | Attachment scan; never delays delivery, pulls infected mail afterwards. | 0.25 attachments per email |

## How it works

**Synthetic data** (`src/data/`). 10 tenants (one per industry) × 30 mailboxes, 60 days, 10,000 emails:
78% legit, 8% spam, 6% phishing, 4% BEC, 4% malware. Attacks arrive as campaigns (bulk spam across
tenants, targeted BEC). It includes hard negatives (real CFO urgent wires, vendor payment chasers, IT
password notices, staff writing from personal Gmail, a third-party tool failing DMARC) and hard
positives (hijacked vendor and partner accounts, credential pages on real SharePoint, password-protected
zips), 2% label noise, and threat intel for the mocked WHOIS / IP / URL / AV services. A **sent-mail
log** records the tenant's real replies, so "have these two people actually corresponded?" can be
answered from history. Fully seeded.

**Rules** (`src/rules/engine.py`): auth failure, internal-domain spoof, employee display name from
outside, lookalike domain (rapidfuzz vs the tenant's domain, its vendors and major brands), young
domain + high volume, blocklisted IP, reply-to mismatch. Each returns a reason code. Rules whose
precision on the training period was not near-perfect only add reasons; they never decide alone.

**Point-in-time features** (`src/features/extract.py`). 31 features computed by walking inbound mail
and the sent-mail log in time order: each email only sees history from earlier messages (sender's
prior messages to this tenant, prior exchanges with this mailbox in either direction, domain volume
in the last 24 h, topic shift vs the sender's past mail). The quoted thread inside an email is never
trusted, because attackers forge it. A test checks that adding future emails never changes past
features. The split is by time (last 12 days are test); the first 7 days only build history.

### Subject-line features

Six features, used by the model only (no rule acts on the subject):

| Feature | What it measures |
|---|---|
| `fake_reply` | Subject starts with RE:/FW:/Fwd: but this mailbox and sender have never exchanged mail (history store, not the quoted thread) |
| `subject_body_sim` | TF-IDF cosine similarity between subject and body |
| `subject_kw` | Urgency / money words in the subject (separate from the body keyword counts) |
| `subject_caps_ratio`, `subject_exclaims`, `subject_emojis` | Style: share of capital letters, "!" count, emoji count |

The generator gives real threads a reply prefix (backed by the sent-mail log), makes 30–40% of
phishing and BEC campaigns fake a reply (half with a forged quoted thread), has colleagues forward
vendor mail, and puts emojis and capitals in some spam and in a few legit newsletters and promos.

Why they add little here: `subject_body_sim` and `subject_caps_ratio` rank 7th and 9th by SHAP, but
`fake_reply` adds almost nothing because every fake reply in this data comes from a brand-new attacker
address, which `first_time_sender` already flags; it would matter for a hijacked account faking a reply.
The style features mainly fire on spam, which is already caught 100%.

### The text approach

- **Tier 1: TF-IDF + logistic regression → `text_score`.** Unigrams and bigrams (never crossing a
  sentence boundary) over subject + body, with URLs, reply prefixes, the sender's display name and the
  recipient's name removed so the model reads *what is said*, not *who signed it*. Its P(malicious) is
  one feature of LightGBM. On training rows the score is **out-of-fold** (5-fold), so LightGBM never
  learns from a score that has already seen that row's label.
- **Tier 2: TF-IDF intent classifier + topic-shift cosine.** A one-vs-rest logistic regression
  predicts four request intents (payment, gift card, credential, urgency), trained on weak labels from
  simple patterns. Topic shift is 1 − cosine similarity between this email's TF-IDF vector and the
  centroid of the sender's earlier emails to this tenant.
- **Why this and not embeddings or an LLM:** it is fast (~1 ms per email on CPU), free (no GPU, no
  API calls, nothing leaves the tenant boundary) and explainable (every weight maps to a word or
  phrase you can read, below).
- **Limitation:** it matches words, not meaning. A paraphrase it has not seen ("handle this discreetly
  for me") or an attacker copying a real vendor's wording passes as normal; that is why the metadata
  and relationship features exist, and why embeddings are listed under future work.

### What the text model learned

Top 15 TF-IDF terms by logistic-regression weight (from `make eval`):

| # | Toward attack | Toward legit |
|---|---|---|
| 1 | here | through it |
| 2 | purchase | it on |
| 3 | here url | walk through |
| 4 | url | to walk |
| 5 | book | available |
| 6 | on my | payment |
| 7 | book time | unchanged |
| 8 | last | are unchanged |
| 9 | my last | from |
| 10 | last email | are |
| 11 | time here | on the |
| 12 | url please | introduction |
| 13 | your | out from |
| 14 | document | our capabilities |
| 15 | purchase order | capabilities |

Sensible: "click here" links ("here url", "url please"), spam follow-ups ("my last email", "book time"),
malware lures ("purchase order", "document"), and on the legit side "payment details are unchanged" and
"walk through" from genuine vendor mail. "payment" leans legit because real payment chasers far
outnumber fraudulent ones, which is exactly why text alone can't catch BEC. Not sensible: "introduction"
and "our capabilities" come from one hard-negative template (a new vendor introducing itself), and
function words ("from", "are", "on the") mostly reflect that legit mail is longer. Two earlier versions
of this list exposed leaks that were then fixed: sender names and company suffixes ("Ltd", "Inc",
"IT Service Desk"), and reply prefixes ("fw", "fwd", "re payment") once fake replies were added.

## Results (single run, seed 42)

**Per class** (full cascade, final output after the async scan):

| Class | Precision | Recall | F1 | Support | PR-AUC (LightGBM) |
|---|---|---|---|---|---|
| legit | 99.1% | 99.9% | 99.5% | 1518 | 0.999 |
| spam | 93.6% | 100.0% | 96.7% | 132 | 1.000 |
| phishing | 98.8% | 85.9% | 91.9% | 99 | 0.967 |
| **BEC** | **98.4%** | **88.7%** | **93.3%** | 71 | 0.979 |
| malware | 100.0% | 100.0% | 100.0% | 67 | 1.000 |

Spam precision is lower because 6 phishing emails were routed to the spam folder instead of
quarantine. Classic BEC patterns (CEO gift cards, wire requests from lookalike and freemail domains,
payroll diversion, direct spoofing, vendor-invoice fraud) were caught 61 of 62 times. Almost all BEC
misses came from **compromised real vendor accounts**: 7 of 9 delivered, 2 bannered.

**Hard cases.** Hard positives: 47.8% detected (compromised partner accounts 6/11, compromised vendor
2/9, password-protected zips 3/3). Hard negatives: 210 in test, none quarantined, 1 bannered.

**Latency** (synchronous path: measured compute plus simulated parallel lookups):
p50 **10.3 ms**, p95 **25.2 ms**, p99 **33.6 ms** (p99 over 5 seeds: 30.1 ± 2.9 ms), well under the
2 s target and the 5 s deadline. Model compute itself is ~1 ms; the slowest external lookup dominates.

**What drives the model (SHAP, top 10):** text_score, sender_domain_age_days, min_url_domain_age_days,
payment_kw, topic_shift, risky_attachments, subject_body_sim, lookalike_score, subject_caps_ratio,
ip_score. Chart: [reports/shap_top_features.png](reports/shap_top_features.png).

### Cost vs the $0.30/mailbox/month budget

**Base case: $0.0083 per mailbox per month (2.8% of budget)** at the specified 5 inbound emails per
mailbox per day; $0.0086 ± 0.0005 over 5 seeds. The stress test at 120/day costs $0.20 (67%; $0.21 ±
0.01 over 5 seeds) and still fits. Table for seed 42:

| Item | Base (5/day) $/mailbox/month | Share of budget | Stress test (120/day) $/mailbox/month | Share of budget |
|---|---|---|---|---|
| Compute (features, rules, models) | 0.0000 | 0.0% | 0.0001 | 0.0% |
| Reputation / WHOIS lookups | 0.0041 | 1.4% | 0.0991 | 33.0% |
| Static AV scan (every attachment) | 0.0009 | 0.3% | 0.0222 | 7.4% |
| Sandbox (risky file types, not already quarantined) | 0.0033 | 1.1% | 0.0782 | 26.1% |
| **Total** | **0.0083** | **2.8%** | **0.1996** | **66.5%** |

**Headroom for a smarter Tier 2:** the base case leaves $0.29/mailbox/month, and only ~1 email per
mailbox per month reaches the gray zone (0.7%), so Tier 2 could spend up to **~$0.28 per gray-zone
email** on embeddings or an LLM call and still fit the budget.

Assumptions (all in `configs/default.yaml`; measured values come from the eval run):

| Assumption | Value | Source |
|---|---|---|
| Inbound emails per mailbox per day (base) | 5 | The assignment's specification (30 mailboxes per customer). |
| Inbound emails per mailbox per day (stress test) | 120 | A heavy business inbox. Radicati reports 122 emails *sent and received* per business user per day ([2015 report](https://www.radicati.com/wp/wp-content/uploads/2015/02/Email-Statistics-Report-2015-2019-Executive-Summary.pdf)) and ~78 *received* ([2012 survey](https://www.radicati.com/?p=8785)), so 120 inbound is pessimistic. |
| Compute price | $0.04 per vCPU-hour | AWS c7g.large (2 vCPU, on-demand, us-east-1) lists at $0.0725/hour ≈ $0.036/vCPU-hour per third-party trackers ([DoIT](https://www.doit.com/compute/spot/us-east-1/c7g.large), [Holori](https://calculator.holori.com/aws/ec2/c7g.large/us-east-1)); rounded up. |
| Overhead on measured compute | 3× | Assumption: MIME parsing, queueing and retries are not in the measured ~1 ms. |
| Lookups per email | 2.7 | Measured: IP + sender WHOIS + URL reputation and WHOIS per unique link. |
| Lookup cache hit rate | 90% | Assumption: senders, IPs and link domains repeat heavily within hours. |
| Price per uncached lookup | $0.0001 | Assumption: blend of self-hosted feeds and commercial reputation APIs; prices vary widely. |
| Attachments per email | 0.25 | Measured on the synthetic test set (likely higher than real mail). |
| Attachment hash cache hit rate | 50% | Assumption: the same files (invoices, decks, campaign payloads) reach many mailboxes. |
| Static AV scan | $0.00005 per file | Assumption: self-hosted signature scanner, CPU cost only. |
| Sandbox detonation | $0.002 per file | Assumption: order of magnitude for a commercial sandbox; only archives, macro documents and executables on mail that was not already quarantined (0.022 per email measured). |

The first estimate sent every attachment to the sandbox: $0.04 at the base volume, but **$1.00 in the
stress test**, over budget. Tiering the scan (cheap AV for everything, sandbox only for risky types on
mail that will actually be delivered) is the design change that keeps a heavy inbox within budget. The
biggest remaining lever is the lookup cache.

## Demo

`make demo` opens a Streamlit app. Pick one of seven curated test-period emails (routine invoice, a
real CFO's urgent wire, a lookalike phish blocked at Tier 0, a CEO gift-card request, a gray-zone
email decided by the intent check, a macro malware invoice, and an attack that is missed) or paste
your own. It shows the action, predicted class, tier, latency, reason codes, intent probabilities
(Tier 2) and a per-email SHAP chart, then waits for the async attachment scan.

## Limitations

- **Synthetic data, optimistic numbers.** Emails come from templates with a few phrasings each, so
  even with shared wording, plain-language attacks and label noise, the model sees far less variety
  than real mail. Expect noticeably lower precision and recall on real traffic. The value of this repo
  is the design, the point-in-time evaluation and the ablation, not the absolute scores.
- **Compromised vendor accounts** (7 of 9 delivered in seed 42). The email comes from the real vendor,
  passes SPF/DKIM/DMARC, sits in a real thread and may copy the vendor's normal invoice wording. Because
  the vendor is an established correspondent, the intent check can at most banner it (a deliberate
  trade: real vendors' payment requests must not be quarantined). Proposed fixes:
  - a **new-bank-details flag**: any email that changes payment details triggers a banner and an
    out-of-band verification workflow, whoever sends it;
  - **sender behaviour anomalies**: writing style (sentence length, greeting, signature, vocabulary)
    and send-time / sending-IP / client changes compared with that sender's history.
- **Password-protected zips from known contacts.** All 3 in this test period were caught by the model,
  but the scanner can't open them and the sender is trusted, so detection rests on weak signals (an
  earlier data draw missed 5 of 6). Proposed fix: a **banner on password-protected archives from
  senders who have not sent one before**, and blocking archives whose password is in the same email.
- **Why Tier 2 adds little here.** Rules and LightGBM settle ~99% of mail on their own, so only ~0.7%
  reaches the gray zone (+1.8 points BEC recall and +6.7 points hard-positive recall over LightGBM
  alone, for ~2.4 legit banners per run). Topic shift is a weak signal on this data because legit
  senders already write about many topics (median shift 0.77 for legit vs 0.83 for BEC); real vendor
  payment chasers often look "shifted". Since established correspondents are only bannered, the
  intent check no longer quarantines legit mail on the validation window at any gray-zone bound, but
  widening still costs banners: lowering it from 0.3 to 0.1 lifts hard-positive recall from 46% to 67%
  and bannered legit mail from 3 to 26 emails (0.3% → 2.8% of legit mail). With a budget of at most 1%
  of legit mail bannered, 0.3 stays. Tier 2 earns its place when Tier 1 is less certain (real traffic,
  new tenants) and as the slot for a stronger model (below).
- **The async virus scan caught nothing extra** in this test set: everything it can detect was already
  quarantined by the sync path, and what it can't open (encrypted archives) it can't help with.
- **No feedback loop.** User "report phishing" clicks, admin overrides and per-tenant thresholds are
  not modelled.

## Future work

- **Sentence embeddings** (a small local model such as MiniLM on CPU) for the text score and topic
  shift, to catch paraphrases that TF-IDF misses.
- **An LLM tier for the gray zone only** (~1% of mail), asking "is this a request to move money or
  credentials, and is it unusual for this sender?" Only affordable because the cascade filters 99%
  first, and only with a provider and data-handling terms suitable for customer mail.
- Per-tenant calibration and thresholds, behavioural sender profiles (send times, clients, IPs),
  and an analyst feedback loop.

## Repository layout

```
configs/default.yaml     all parameters, seeds, cost assumptions
src/data/                synthetic tenants, email stream and sent-mail log (generate.py, templates.py)
src/services/            mocked WHOIS / IP / URL reputation / virus scan with latency + timeouts
src/rules/engine.py      Tier 0 rules and reason codes
src/features/extract.py  point-in-time features, incl. subject-line features
src/models/              text model + LightGBM training
src/pipeline/            cascade and Tier 2 intent model
src/eval/report.py       evaluation -> reports/
src/eval/multiseed.py    whole pipeline over 5 seeds -> reports/multiseed.md
demo/streamlit_app.py    demo app
tests/                   services, data, features, cascade
```

Design trade-offs are in [DESIGN.md](DESIGN.md).
