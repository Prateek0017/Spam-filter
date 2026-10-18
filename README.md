# bec-guard

A tiered spam / phishing / BEC (business email compromise) filter for a multi-tenant B2B email
platform. Cheap rules and a gradient-boosted model handle almost all mail in tens of milliseconds;
only gray-zone emails get a second look; a slow attachment scan runs in the background. Everything
runs locally, no API keys, on reproducible synthetic data.

**Estimated variable cost** (under the deployment assumptions stated [below](#estimated-variable-cost)),
at the specified 5 inbound emails per mailbox per day: **$0.115 per mailbox per month as implemented
(38% of the $0.30 budget)**, or $0.008 (3%) with the proposed caching and selective sandboxing.

## Key result

Mean ± standard deviation over **5 seeds**: each seed regenerates the synthetic data and retrains every
model, then evaluates on its own held-out last 12 days (~1,940 emails, ~380 malicious, ~70 BEC; true
labels). "Detected" means any action other than DELIVER; models were trained on labels with 2% noise.
BEC recall is shown twice: **blocked** (spam folder or quarantine) and **blocked or bannered**. Legit
flagged is a count per run (~1,550 legit test emails each).

| Approach | PR-AUC | Precision | Recall | BEC recall, blocked | BEC recall, blocked or bannered | Hard-positive recall | Legit flagged |
|---|---|---|---|---|---|---|---|
| Rules only (Tier 0 block) | 0.582 ± 0.021 | 99.1 ± 2.1% | 11.7 ± 1.9% | 29.2 ± 6.2% | 29.2 ± 6.2% | 0.0 ± 0.0% | 0.4 ± 0.9 |
| Text only (TF-IDF + LR) | 0.895 ± 0.016 | 63.3 ± 2.7% | 85.6 ± 2.4% | 82.3 ± 6.1% | 82.3 ± 6.1% | 65.8 ± 5.6% | 190.8 ± 23.3 |
| Metadata only (no text or subject features) | 0.984 ± 0.005 | 95.5 ± 1.4% | 92.2 ± 1.0% | 84.5 ± 3.5% | 84.5 ± 3.5% | 41.5 ± 17.9% | 16.6 ± 5.4 |
| Full model (LightGBM, no subject features) | 0.993 ± 0.004 | 98.9 ± 0.6% | 97.0 ± 1.2% | 92.3 ± 3.3% | 92.3 ± 3.3% | 59.8 ± 16.0% | 4.2 ± 2.3 |
| Full model + subject features | **0.994 ± 0.004** | 99.2 ± 0.6% | 97.1 ± 1.2% | 92.1 ± 3.7% | 92.1 ± 3.7% | 60.3 ± 13.4% | 3.0 ± 2.0 |
| Cascade without intent check (gray zone → banner) | – | 98.2 ± 0.6% | 97.7 ± 0.8% | 88.1 ± 5.3% | 93.8 ± 3.5% | 65.4 ± 13.0% | 7.0 ± 2.3 |
| **Full cascade** (rules → model → intent check) | – | 98.2 ± 0.6% | 97.7 ± 0.8% | **91.5 ± 4.8%** | **93.8 ± 3.5%** | **65.4 ± 13.0%** | 7.0 ± 2.3 |

For score rows, "blocked" and "blocked or bannered" are the same (score ≥ 0.5). Per-seed values:
[reports/multiseed.md](reports/multiseed.md) (`make multiseed`, ~5 minutes).

**Hand-written challenge set** (10 emails written by hand, mostly in styles the generator does not use,
never used for tuning): **5.0 ± 0.7 of 6 attacks caught, 3 of 4 legit delivered cleanly** in every seed.
See [Hand-written challenge set](#hand-written-challenge-set).

- **Text alone is not enough.** It finds most attacks only by also flagging ~191 legit emails per run
  (12% of legit mail), because legit invoices, payment chasers and IT notices use the same words.
- **Relationship + infrastructure features carry BEC.** Who is writing (first-time sender, prior
  exchanges, lookalike or freemail domain, display-name and reply-to tricks) is what separates a real
  CFO's urgent wire request from a fake one. Combining them with the text score gives the best of both.
- **The cascade adds a little on top of the model:** +1.7 points BEC recall (blocked or bannered) and
  +5.1 points hard-positive recall, for ~4 more legit emails flagged per run (warning banners).
- **What the intent check itself adds:** with the same rules and thresholds, bannering every gray-zone
  email detects exactly as much; the intent check turns banners into quarantines for attacks (BEC
  blocked 88.1% → 91.5%) without flagging more legit mail.
- **Subject-line features add little** (PR-AUC 0.993 → 0.994; ~1 fewer legit email flagged per run).
  See [Subject-line features](#subject-line-features).
- **Hijacked real accounts remain hard.** Compromised-vendor BEC is the main miss; see
  [Limitations](#limitations).
- **Why five seeds:** each run has only ~70 BEC and ~25 hard-positive test emails, so one email moves
  BEC recall by ~1.4 points and hard-positive recall by ~4. Single runs moved BEC recall (blocked or
  bannered) between 88% and 97%; the standard deviations above are the honest error bars.

The detailed sections below (per-class results, hard cases, SHAP, latency, cost table, demo) come from
a **single run, seed 42**; the full report is [reports/eval_report.md](reports/eval_report.md).

## Quickstart

```bash
make setup               # Python 3.11 venv via uv (macOS: run `brew install libomp` once first)
make data train eval     # ~10k synthetic emails -> models/ -> reports/   (~1 minute)
make demo                # Streamlit app on http://localhost:8501
```

`make test` runs the test suite, `make validate` reruns model selection (see
[DESIGN.md](DESIGN.md#9-model-selection-is-a-script)), and `make multiseed` reruns everything over 5 seeds.
**macOS:** LightGBM needs the OpenMP runtime; without `brew install libomp`, importing it fails with
`Library not loaded: @rpath/libomp.dylib`.

## The problem and the constraints

A B2B email provider must classify every inbound email into **DELIVER**, **WARNING_BANNER**,
**SPAM_FOLDER** or **QUARANTINE**, with reason codes the customer's admin can read.

- **Budget: $0.30 per mailbox per month.** At the specified 5 inbound emails per mailbox per day
  (30 mailboxes per customer) that is 150 emails, so **$0.002 per email** for compute, reputation
  lookups and attachment scanning together. A heavy inbox (a 120/day projection) leaves $0.00008 per
  email, where a hosted LLM call on every email is out of reach.
- **Latency: the provider gives up after 5 s** and delivers anyway (fail open). Target p99 < 2 s.
- **BEC is the expensive failure.** It has no malicious link or file to detect; the signal is
  *who* is asking *what*, compared with how this sender normally behaves.
- **Multi-tenant.** Every tenant has its own executives, vendors and correspondents, so "normal"
  must be learned per tenant from point-in-time history.

## Architecture

```mermaid
flowchart LR
    A[Inbound email] --> S["Signals: auth, history, keywords, subject line<br/>+ WHOIS / IP / URL lookups in parallel (5 s deadline)"]
    A -. attachments .-> V[(Virus scan<br/>async, median ~2.5 s)]
    S -- "deadline expired" --> D[DELIVER]
    S --> R{Tier 0<br/>rules}
    R -- "block rule + first-time sender<br/>(no model runs)" --> Q[QUARANTINE]
    R -- otherwise --> M[Tier 1<br/>text score + LightGBM]
    M -- "P < 0.3" --> D
    M -- "P ≥ 0.8" --> X[SPAM_FOLDER or<br/>QUARANTINE by class]
    M -- "0.3 ≤ P < 0.8" --> I{"Tier 2 intent check:<br/>asks for money, gift cards, login<br/>or a phone / chat contact?<br/>relationship looks off?"}
    I -- "both, untrusted sender" --> Q
    I -- "both, established sender" --> B
    I -- one --> B[WARNING_BANNER]
    I -- neither --> D
    V -- "infected, after delivery" --> P[Pull from mailbox]
```

| Tier | What it does | Share of test mail (seed 42) |
|---|---|---|
| deadline | WHOIS / IP / URL lookups run concurrently, each with its own timeout, under the shared 5 s sync deadline. If it expires the verdict is DELIVER (fail open); the async scan can still pull the email. | 0 fail-open verdicts |
| 0: rules | 7 reason-coded rules. Two can quarantine alone (lookalike domain, young domain sending in bulk), only for first-time senders, and before any model runs. None looks at the subject. | 2.7% |
| 1: model | TF-IDF text score + 30 other features in a LightGBM classifier (5 classes). | 96.0% |
| 2: intent check | Gray-zone scores only: what the email asks for (classifier + keyword layer) plus whether the relationship looks off. Never quarantines an established correspondent. | 1.3% |
| async | Attachment scan; never delays delivery, pulls infected mail afterwards. | 0.26 attachments per email |

**Trust is earned, not received.** A sender is *established* (Tier 2 can only banner them) when this
mailbox has written to them (sent-mail log), or when at least 3 of their earlier emails were
**delivered** without a banner. Quarantined, spam-foldered or bannered mail never earns trust, so a
stranger's repeated payment requests stay quarantine-eligible, and a message failing DMARC inherits no
trust at all (its From address may be spoofed).

## How it works

**Synthetic data** (`src/data/`). 10 tenants (one per industry) × 30 mailboxes, 60 days, 10,000 emails
(~0.56 emails per mailbox per day): 78% legit, 8% spam, 6% phishing, 4% BEC, 4% malware. Attacks arrive
as campaigns (bulk spam across tenants, targeted BEC). It includes hard negatives (real CFO urgent
wires, vendor payment chasers, IT password notices, staff writing from personal Gmail, a third-party
tool failing DMARC, recruiters talking about fees with a phone number in the signature) and hard
positives (hijacked vendor and partner accounts, credential pages on real SharePoint, password-protected
zips). Phishing includes advance-fee and fake-job scams (a too-good offer, an upfront fee in some
currency, "message us on WhatsApp") with varied wording. 2% label noise, and threat intel for the
mocked WHOIS / IP / URL / AV services. A **sent-mail log** records the tenant's real replies, so "have
these two people actually corresponded?" can be answered from history. Fully seeded.

**Rules** (`src/rules/engine.py`): auth failure, internal-domain spoof, employee display name from
outside, lookalike domain (rapidfuzz vs the tenant's domain, its vendors and major brands), young
domain + high volume, blocklisted IP, reply-to mismatch. Each returns a reason code. Rules whose
precision on the training period was not near-perfect only add reasons; they never decide alone.

**Point-in-time features** (`src/features/extract.py`). 31 features computed by walking inbound mail
and the sent-mail log in time order: each email only sees history from earlier messages (sender's
prior messages to this tenant, prior exchanges with this mailbox in either direction, domain volume
in the last 24 h, topic shift vs the sender's past mail). The quoted thread inside an email is never
trusted, because attackers forge it. A test checks that adding future emails never changes past
features. The split is by time (last 12 days are test). The first 7 days are excluded from LightGBM
training only, because every sender looks new there; the text and intent models do train on them.

**Missing values get a typical value.** Some features have nothing to measure: topic shift for a
sender with no earlier mail, link age for an email without links, any lookup that timed out. Left as
NaN, LightGBM learned that "missing" itself means attack (a missing topic shift pushed +0.175 toward
attack, because new senders are mostly attackers in training). The model now receives the training
median instead. That supplies a typical value, not a guaranteed neutral contribution: in seed 42 a
missing topic shift still pushes +0.036 and a missing link age −0.067 on average. "New sender" is
carried by the explicit `first_time_sender` feature. Rules still see the raw value, so a timeout never
fires a rule.

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

Why they add little here: `subject_body_sim` ranks 5th by SHAP, but `fake_reply` adds almost nothing
because every fake reply in this data comes from a brand-new attacker address, which
`first_time_sender` already flags; it would matter for a hijacked account faking a reply. The style
features mainly fire on spam, which is already caught 100%.

### The text approach

- **Tier 1: TF-IDF + logistic regression → `text_score`.** Unigrams and bigrams (never crossing a
  sentence boundary) over subject + body, with URLs, reply prefixes, the sender's display name and the
  recipient's name removed so the model reads *what is said*, not *who signed it*. Its P(malicious) is
  one feature of LightGBM. On training rows the score is **out-of-fold** (5-fold), so LightGBM never
  learns from a score that has already seen that row's label.
- **Tier 2: TF-IDF intent classifier + keyword layer + topic-shift cosine.** A one-vs-rest logistic
  regression predicts four request intents (payment, gift card, credential, urgency), trained on weak
  labels from simple patterns. Next to it, a **deterministic keyword layer** catches any money request
  (a currency amount such as "$5000", "5000 dollar", "Rs 15,000", "USD 250", or words like pay, fee,
  deposit, transfer) and any **off-channel contact** (a phone number, WhatsApp, Telegram). If it fires,
  the intent counts as present whatever the classifier says: a bag-of-words model scored "pay 5000
  dollar as resignation fee" at 0.02 for payment because it had never seen that phrasing. Topic shift is
  1 − cosine similarity between this email's TF-IDF vector and the centroid of the sender's earlier
  emails to this tenant.
- **Why this and not embeddings or an LLM:** it is fast (a few ms of CPU per email), free (no GPU, no
  API calls, nothing leaves the tenant boundary) and explainable (every weight maps to a word or
  phrase you can read, below; every keyword hit is a reason code).
- **Limitation:** it matches words, not meaning. A paraphrase it has not seen ("handle this discreetly
  for me") or an attacker copying a real vendor's wording passes as normal; that is why the metadata
  and relationship features exist, and why embeddings are listed under future work. The keyword layer
  is deliberately broad, so it also fires on legit invoices and signatures with phone numbers; it only
  acts in the gray zone and only quarantines when the relationship also looks off.

### What the text model learned

Top 15 TF-IDF terms by logistic-regression weight (seed 42, from `make eval`):

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

## Hand-written challenge set

`data/challenge/emails.json` holds 10 emails written by hand: a fake remote job asking for a deposit
via Telegram, a lottery win with a WhatsApp claims agent, sextortion with a Bitcoin wallet, an
SMS-style parcel notice, a callback scam ("call this number to cancel"), BEC written in Spanish, and
four unusual but legit emails. They were written before any fix was evaluated on them and are never
used for tuning. `make eval` writes [reports/challenge.md](reports/challenge.md).

Not all of them are new to the generator, so this is a challenge set, not a clean out-of-distribution
test. **Overlaps:** the job scam (the generator gained fake-job advance-fee scams afterwards), the
lottery (prize advance-fee templates exist; the wording is new), the parcel notice (a "delivery attempt
failed" brand phish exists; the SMS style is new), the Spanish BEC (its metadata pattern, a freemail
sender using the CEO's name, is common; the language is new), and the vendor email (the vendor domain is
known, but this address has never written before). Sextortion, the callback scam and the three other
legit emails have no generator counterpart.

| | Attacks caught (of 6) | Legit delivered cleanly (of 4) |
|---|---|---|
| Before the keyword layer and advance-fee data (seed 42) | 2 | 3 |
| Now, seed 42 | 6 | 3 |
| Now, 5 seeds | 5.0 ± 0.7 | 3.0 ± 0.0 |

Seed 42, email by email:

| Email | Truth | Action | Tier | Why |
|---|---|---|---|---|
| Fake remote job, deposit via Telegram | phishing | QUARANTINE | 1 | model confident (0.97) |
| Lottery win, agent on WhatsApp | phishing | QUARANTINE | 1 | model confident (0.84), auth failure |
| Sextortion, Bitcoin wallet, spoofs the recipient's own address | phishing | QUARANTINE | 2 | money request + no trust (DMARC fails, so the spoofed address inherits none) |
| SMS-style parcel notice with a link | phishing | WARNING_BANNER | 2 | new sender, auth failure |
| Callback scam, phone number only | phishing | QUARANTINE | 1 | model confident (1.00) |
| BEC in Spanish from Gmail with the CEO's name | BEC | QUARANTINE | 1 | model confident (0.89), display-name mismatch |
| Emoji-heavy internal note | legit | DELIVER | 1 | |
| Terse email from a new address at a known vendor domain | legit | DELIVER | 1 | |
| First-time customer on Gmail asking for a refund | legit | **QUARANTINE** | 1 | model confident (0.93): "new freemail sender + money request" is the scam pattern |
| HR sign-in reminder with a Workday link | legit | DELIVER | 1 | |

Across seeds, the sextortion email is still delivered in 4 of 5 runs (seed 42 is the exception) and the
refund request is quarantined in all 5. Both are listed under [Limitations](#limitations).

## Results (single run, seed 42)

**Per class** (full cascade, final output after the async scan):

| Class | Precision | Recall | F1 | Support | PR-AUC (LightGBM) |
|---|---|---|---|---|---|
| legit | 99.2% | 99.4% | 99.3% | 1574 | 0.999 |
| spam | 97.5% | 100.0% | 98.7% | 115 | 1.000 |
| phishing | 100.0% | 95.2% | 97.5% | 104 | 0.999 |
| **BEC** | **94.2%** | **87.8%** | **90.9%** | 74 | 0.961 |
| malware | 93.2% | 97.2% | 95.2% | 71 | 0.997 |

Classic BEC patterns (CEO gift cards, wire requests from lookalike and freemail domains, payroll
diversion, direct spoofing, vendor-invoice fraud) were detected 64 of 67 times. Most BEC misses came
from **compromised real vendor accounts**: 6 of 7 delivered, 1 bannered.

**Hard cases.** Hard positives: 44.4% detected (compromised partner accounts 3/5, compromised vendor
1/7, password-protected zips 4/6). Hard negatives: 247 in test, 1 quarantined (a legit
password-protected archive), 8 bannered (4 real vendor payment requests, 4 legit archives).

**Latency.** Wall time of the synchronous path, measured once per email, with the mock lookups really
sleeping their simulated latency and running concurrently: p50 **14.8 ms**, p95 **30.0 ms**, p99
**38.1 ms** (p99 over 5 seeds: 41.3 ± 3.4 ms), well under the 2 s target and the 5 s deadline. No
verdict hit the deadline in any seed. CPU time is ~4.5 ms per email; the slowest lookup dominates.

**What drives the model (SHAP, top 10):** text_score, risky_attachments, sender_domain_age_days,
payment_kw, subject_body_sim, topic_shift, min_url_domain_age_days, lookalike_score, ip_score, n_urls.
Chart: [reports/shap_top_features.png](reports/shap_top_features.png).

### Estimated variable cost

This is an **estimated variable cost under stated deployment assumptions**, not a measurement. It
separates what is implemented from what is proposed:

- **As implemented:** every WHOIS / IP / URL lookup is a paid call, and every attachment goes through
  the single (mock) virus scanner, priced as a sandbox scan.
- **Proposed, not implemented:** a lookup cache, an attachment hash cache, a cheap static AV scan on
  every file, and the sandbox only for archives, macro documents and executables on mail that was not
  already quarantined.

The **base case** uses the specified 5 inbound emails per mailbox per day. The **cost projection** uses
120/day (a heavy inbox). The synthetic data itself has only ~0.56 emails per mailbox per day, so both
reuse the per-email rates observed in the replay (lookups, attachments, sandbox submissions, CPU time).

| $/mailbox/month | Base, as implemented | Base, with proposed savings | Projection (120/day), as implemented | Projection, with proposed savings |
|---|---|---|---|---|
| **5 seeds** | **0.115 ± 0.003 (38%)** | 0.008 ± 0.001 (3%) | 2.77 ± 0.07 (923%) | 0.200 ± 0.014 (67%) |
| Seed 42: compute | 0.0000 | 0.0000 | 0.0005 | 0.0005 |
| Seed 42: reputation / WHOIS lookups | 0.0396 | 0.0040 | 0.9503 | 0.0950 |
| Seed 42: attachment scanning | 0.0791 | 0.0048 | 1.8985 | 0.1148 |
| Seed 42: total | 0.1187 (40%) | 0.0088 (3%) | 2.8493 (950%) | 0.2103 (70%) |

The base case fits as implemented. A heavy inbox only fits with the proposed savings, mostly from
scanning: sending every attachment to a sandbox is what breaks the budget.

**Headroom for a smarter Tier 2** (base case, as implemented, seed 42): $0.18/mailbox/month left; with
1.3% of mail in the gray zone that is ~1.9 emails per mailbox per month, so up to **~$0.09 per
gray-zone email** for embeddings or an LLM call.

Assumptions (all in `configs/default.yaml`; measured values come from the eval run):

| Assumption | Value | Source |
|---|---|---|
| Inbound emails per mailbox per day (base) | 5 | The assignment's specification (30 mailboxes per customer). |
| Inbound emails per mailbox per day (projection) | 120 | A heavy business inbox. Radicati reports 122 emails *sent and received* per business user per day ([2015 report](https://www.radicati.com/wp/wp-content/uploads/2015/02/Email-Statistics-Report-2015-2019-Executive-Summary.pdf)) and ~78 *received* ([2012 survey](https://www.radicati.com/?p=8785)), so 120 inbound is pessimistic. |
| Synthetic rate | ~0.56/day | Measured: 10,000 emails / 300 mailboxes / 60 days. Not used for cost; per-email rates are. |
| Compute price | $0.04 per vCPU-hour | AWS c7g.large (2 vCPU, on-demand, us-east-1) lists at $0.0725/hour ≈ $0.036/vCPU-hour per third-party trackers ([DoIT](https://www.doit.com/compute/spot/us-east-1/c7g.large), [Holori](https://calculator.holori.com/aws/ec2/c7g.large/us-east-1)); rounded up. |
| CPU per email | ~4.5 ms | Measured (process CPU time of the sync path). |
| Overhead on measured compute | 3× | Assumption: MIME parsing, queueing and retries are not in the measured time. |
| Lookups per email | 2.6 | Measured: IP + sender WHOIS + URL reputation and WHOIS per unique link. |
| Price per lookup | $0.0001 | Assumption: blend of self-hosted feeds and commercial reputation APIs; prices vary widely. |
| Lookup cache hit rate (proposed) | 90% | Assumption: senders, IPs and link domains repeat heavily within hours. |
| Attachments per email | 0.26 | Measured on the synthetic test set (likely higher than real mail). |
| Scanner / sandbox price | $0.002 per file | Assumption: order of magnitude for a commercial sandbox. |
| Static AV scan (proposed) | $0.00005 per file | Assumption: self-hosted signature scanner, CPU cost only. |
| Sandbox submissions (proposed) | 0.025 per email | Measured: archives, macro documents and executables on mail not already quarantined. |
| Attachment hash cache hit rate (proposed) | 50% | Assumption: the same files (invoices, decks, campaign payloads) reach many mailboxes. |

## Demo

`make demo` opens a Streamlit app. Pick one of eight examples (routine invoice, a real CFO's urgent
wire, a lookalike phish blocked at Tier 0, a CEO gift-card request, a gray-zone email decided by the
intent check, a macro malware invoice, a missed hijacked-vendor email, and a job scam reported by a
tester: "You are hired at tesla, pay 5000 dollar as resignation fee at <phone>") or paste your own. It
shows the action, predicted class, tier, latency, reason codes and intent probabilities (Tier 2), then
waits for the async attachment scan. For model decisions it draws a per-email SHAP chart: each bar is a
feature's contribution to LightGBM's **legit-class raw score** (multiclass log-odds), sign flipped, so a
bar to the right lowers P(legit) and raises P(malicious) = 1 − P(legit). The bars add up in log-odds,
not in probability. Tier 0 blocks and fail-open verdicts never ran the model, so they show reasons only.

## Limitations

- **Synthetic data, optimistic numbers.** Emails come from templates with a few phrasings each, so
  even with shared wording, plain-language attacks and label noise, the model sees far less variety
  than real mail. Expect noticeably lower precision and recall on real traffic. The hand-written
  challenge set (5 of 6 attacks, 3 of 4 legit) is the closest thing here to a real-world check, and it
  is only 10 emails, several of which overlap generator scenarios. The value of this repo is the
  design, the point-in-time evaluation and the ablation, not the absolute scores.
- **Compromised vendor accounts** (6 of 7 delivered in seed 42). The email comes from the real vendor,
  passes SPF/DKIM/DMARC, sits in a real thread and may copy the vendor's normal invoice wording. Because
  the vendor is an established correspondent, the intent check can at most banner it (a deliberate
  trade: real vendors' payment requests must not be quarantined). Proposed fixes:
  - a **new-bank-details flag**: any email that changes payment details triggers a banner and an
    out-of-band verification workflow, whoever sends it;
  - **sender behaviour anomalies**: writing style (sentence length, greeting, signature, vocabulary)
    and send-time / sending-IP / client changes compared with that sender's history.
- **Password-protected zips from known contacts.** 4 of 6 were caught in seed 42, but the scanner
  can't open them and the sender is trusted, so detection rests on weak signals. Proposed fix: a
  **banner on password-protected archives from senders who have not sent one before**, and blocking
  archives whose password is in the same email.
- **Self-spoofed extortion (challenge set).** Sextortion "from" the recipient's own address with DMARC
  failing is still delivered in 4 of 5 seeds: it usually scores just under the gray zone, and the
  model has never seen extortion wording. Proposed fix: quarantine mail whose From is the recipient's
  own address and fails DMARC (a precise rule that does not exist yet).
- **First-time customers asking for money (challenge set).** A refund request from a new Gmail address
  is quarantined in every seed: "new freemail sender + money request" is exactly the scam pattern.
  Proposed fix: per-tenant inbox roles (a support or billing mailbox expects strangers asking about
  money, so it should banner there, not quarantine).
- **Why Tier 2 adds modestly here.** Rules and LightGBM settle ~99% of mail on their own, so only
  ~1% reaches the gray zone. Topic shift is a weak signal on this data because legit senders already
  write about many topics (median shift 0.78 for legit vs 0.83 for BEC). On the validation window,
  lowering the gray-zone bound from 0.3 to 0.1 would lift hard-positive recall from 77% to 91% but flag
  22 legit emails instead of 8 (0.9% → 2.4% of legit mail); with a budget of at most 1%, 0.3 stays.
- **Trust needs history.** In the offline replay, mail from before the test period has no verdicts,
  so its observed label stands in for "delivered and not reported". A real deployment would use its
  own delivery log.
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
- The proposed cost savings (lookup and hash caches, AV + selective sandbox), per-tenant calibration
  and thresholds, behavioural sender profiles (send times, clients, IPs), and an analyst feedback loop.

## Repository layout

```
configs/default.yaml       all parameters, seeds, cost assumptions
src/data/                  synthetic tenants, email stream and sent-mail log (generate.py, templates.py)
src/services/              mocked WHOIS / IP / URL reputation / virus scan with latency + timeouts
src/rules/engine.py        Tier 0 rules and reason codes
src/features/extract.py    point-in-time features (lookups in parallel under a deadline)
src/models/                text model + LightGBM training
src/pipeline/              cascade and Tier 2 intent model
src/eval/report.py         evaluation -> reports/eval_report.md
src/eval/validate.py       model selection on the validation window -> reports/validation.md
src/eval/multiseed.py      whole pipeline over 5 seeds -> reports/multiseed.md
src/eval/challenge.py      hand-written challenge set -> reports/challenge.md
data/challenge/emails.json the 10 hand-written emails
demo/streamlit_app.py      demo app
tests/                     services, data, features, cascade
```

Design trade-offs are in [DESIGN.md](DESIGN.md).
