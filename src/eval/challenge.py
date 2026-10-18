"""Evaluate the trained cascade on the hand-written challenge set (data/challenge/emails.json).

Ten emails written by hand, mostly in styles the generator does not produce (each case notes any
overlap with a generator scenario). They are only ever evaluated, never used to tune anything.
Output: reports/challenge.md

Usage: python -m src.eval.challenge --config configs/default.yaml
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import timedelta
from pathlib import Path

import pandas as pd

from src.common.config import REPO_ROOT, load_config
from src.data.io import load_tenants
from src.data.schema import Attachment, AuthResults, Email, Tenant, Url
from src.eval.report import table
from src.models.train import split_dates
from src.pipeline.cascade import Cascade

CHALLENGE_PATH = REPO_ROOT / "data" / "challenge" / "emails.json"


def _fill(text: str, t: Tenant) -> str:
    def sub(m: re.Match[str]) -> str:
        kind, _, arg = m.group(1).partition(":")
        if kind == "tenant_domain":
            return t.domain
        if kind == "mailbox":
            return t.mailboxes[int(arg)]
        if kind == "exec":
            return t.executives[arg]
        if kind == "name":
            return t.names[t.executives[arg]]
        if kind == "vendor":
            return t.vendors[int(arg)]
        raise KeyError(m.group(0))
    return re.sub(r"\{(tenant_domain|(?:mailbox|exec|name|vendor):[\w]+)\}", sub, text)


def load_challenge(cfg: dict) -> list[tuple[dict, Email]]:
    spec = json.loads(CHALLENGE_PATH.read_text())
    t = next(t for t in load_tenants(Path(cfg["paths"]["raw"]) / "tenants.json") if t.tenant_id == spec["tenant"])
    _, test_start = split_dates(cfg)
    out = []
    for i, d in enumerate(spec["emails"]):
        f = {k: _fill(v, t) if isinstance(v, str) else v for k, v in d.items()}
        display = f["from_display"] or t.names.get(f["from_addr"], "")
        email = Email(
            message_id=f"<{f['id']}@challenge>", tenant_id=t.tenant_id, to_addr=f["to"],
            timestamp=test_start + timedelta(days=3, hours=9 + i), from_addr=f["from_addr"], from_display=display,
            subject=f["subject"], body=f["body"], auth=AuthResults(**f["auth"]), sender_ip=f"198.51.100.{20 + i}",
            urls=[Url(href=u, anchor_text=u) for u in f.get("urls", [])],
            attachments=[Attachment(filename=a, sha256=f"challenge{i}{a}") for a in f.get("attachments", [])],
            category=f["category"], true_category=f["category"], label=int(f["category"] != "legit"))
        out.append((f, email))
    return out


def run(cfg: dict) -> pd.DataFrame:
    cas = Cascade.load(cfg)                       # sender history as of the train/test split
    rows = []
    for spec, e in load_challenge(cfg):
        v = cas.classify(e)
        ok = (v.action.value == "DELIVER") == (e.true_category == "legit")
        rows.append({"email": spec["id"], "style": spec["style"], "overlaps generator?": spec["overlap"],
                     "truth": e.true_category,
                     "action": v.action.value, "tier": v.tier, "P(malicious)": v.score,
                     "reasons": ", ".join(v.reasons) or "–", "correct": "yes" if ok else "**no**"})
    df = pd.DataFrame(rows).set_index("email")
    attacks, legit = df[df["truth"] != "legit"], df[df["truth"] == "legit"]
    md = f"""# Hand-written challenge set

{len(df)} hand-written emails ({len(attacks)} attacks, {len(legit)} legit), mostly in styles the generator does not use;
the overlap column says where a case resembles a generator scenario. Classified by the seed-{cfg['seed']} cascade
with sender history as of the train/test split. Never used for tuning. Correct = attack not delivered
silently, or legit delivered without a banner.

**Attacks caught: {(attacks['action'] != 'DELIVER').sum()} / {len(attacks)}** · **Legit delivered cleanly:
{(legit['action'] == 'DELIVER').sum()} / {len(legit)}**

{table(df, {"P(malicious)": ".2f"})}
"""
    out = Path(cfg["paths"]["reports"])
    out.mkdir(parents=True, exist_ok=True)
    (out / "challenge.md").write_text(md)
    print(table(df[["truth", "action", "tier", "P(malicious)", "reasons", "correct"]], {"P(malicious)": ".2f"}))
    return df


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=None)
    run(load_config(ap.parse_args().config))


if __name__ == "__main__":
    main()
