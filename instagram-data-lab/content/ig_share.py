#!/usr/bin/env python3
"""
ig_share.py - prepare an anonymised export for hand-in, and pool the class's hand-ins
=====================================================================================

Student side (notebook 02, last cell):

    from ig_share import prepare_share
    prepare_share("anonymised")          # -> share_<id>.zip, ready to upload

  * re-scans the anonymised folder and REFUSES to pack if the scanner still finds a
    HIGH item (e-mail, phone, IP, coordinates, card number) or a leftover real name;
  * leaves out pseudonym_map.csv (the only thing that can undo the pseudonyms);
  * drops the JSON tree by default (the CSV tables are what the class works with; the
    JSON is kept on the student's computer) - include_json=True keeps it;
  * names the zip after a random share id (share_k7f3q2.zip), so the file name does not
    carry the student's name; the id is printed and also written inside the zip
    (MANIFEST.json: id, date, tool version, row counts, settings, scanner verdict);
  * writes CONSENT.txt describing what is in the zip and what is not.

Instructor side (own computer, Python 3):

    python3 ig_share.py pool  hand-ins/  pooled/

  reads every share_*.zip (or anonymised.zip) in a folder, checks each manifest and
  re-scans each one, and writes pooled/<table>.csv with a `student` column (the share
  id) in front; pseudonyms are prefixed with the id (k7f3q2:user_0012) so that the
  same pseudonym in two students' files is never mistaken for the same person.
  pooled/SUMMARY.md lists what came in.
"""
from __future__ import annotations

import csv
import io
import json
import re
import secrets
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import ig_pii_scan as S
    import ig_anonymise as A
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ig_pii_scan as S
    import ig_anonymise as A

PSEUDO_RE = re.compile(r"^(me|user_\d+)$")
PSEUDO_COLUMNS = {"author", "author_name", "user", "sender", "thread", "on_post_by", "actor", "participant", "account", "owner",
                  "brand_partner", "counterpart", "with"}
CONSENT = """This zip was produced by the ECOSM 2026 Instagram data lab (ig_anonymise.py) from one
Instagram data export. It contains ONLY:
  - csv/: tidy tables with pseudonyms (me, user_0001, ...) for every person; businesses,
    public accounts and topics keep their names; message, caption and comment text is
    reduced to word counts, hashtags and pseudonymised mentions;
  - anonymisation_report.md: what was removed and the scanner's re-check of the output;
  - MANIFEST.json: the share id, date, settings and row counts.
It does NOT contain the pseudonym map, any photo or video, any e-mail, phone number, IP
address, location, device identifier, payment detail, or any message/caption text.
The share id in the file name is random and is the only identifier of this file.
"""


def _manifest(out: Path, share_id: str, report_ok: bool, high: int, leftovers: int, rows: dict) -> dict:
    settings = {}
    try:
        for line in (out / "anonymisation_report.md").read_text(encoding="utf-8").splitlines():
            if line.startswith("Output:"):
                for part in line.split("   "):
                    if ":" in part:
                        k, v = part.split(":", 1)
                        settings[k.strip().lower().replace(" ", "_")] = v.strip()
    except OSError:
        pass
    return {"share_id": share_id, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": {"ig_anonymise": A.__version__, "ig_pii_scan": getattr(S, "__version__", "")},
            "settings": settings, "tables": rows, "scan_ok": report_ok, "scan_high": high, "scan_leftover_names": leftovers}


def _rescan(out: Path) -> tuple:
    """HIGH findings and leftover non-pseudonym names in the anonymised folder (public accounts excluded)."""
    rep = S.scan(str(out))
    high = [f for f in rep.findings if f.severity == "high"]
    public = set()
    try:
        txt = (out / "anonymisation_report.md").read_text(encoding="utf-8")
        m = re.search(r"PUBLIC ACCOUNTS KEPT VISIBLE[^\n]*\n  ([^\n]+)", txt)
        if m:
            public = {x.strip().lower() for x in m.group(1).split(",")}
    except OSError:
        pass
    names = {f.value.strip().lower() for f in rep.findings
             if f.category in ("username", "person_name") and not PSEUDO_RE.match(f.value.strip().lower())
             and f.file_type in ("private_messages", "social_graph", "identity", "address_book")
             and f.value.strip().lower() not in public}
    return high, names


def prepare_share(out_dir: str = "anonymised", include_json: bool = False, share_id: Optional[str] = None,
                  force: bool = False) -> Optional[str]:
    """Check, then pack csv/ + report (+ json/) into share_<id>.zip. Returns the zip path, or None if refused."""
    out = Path(out_dir)
    if not (out / "csv").is_dir():
        print(f"{out}/csv not found - run the anonymiser first.")
        return None
    high, names = _rescan(out)
    rows = {}
    for p in sorted((out / "csv").glob("*.csv")):
        with open(p, newline="", encoding="utf-8") as fh:
            rows[p.stem] = max(0, sum(1 for _ in fh) - 1)
    ok = not high and not names
    if not ok and not force:
        print("NOT packed: the scanner still finds something in the anonymised folder:")
        for f in high[:5]:
            print(f"  HIGH {f.category}: {f.mask} in {f.file}")
        if names:
            print(f"  {len(names)} name(s) that are not pseudonyms in people files (masked): "
                  + ", ".join(sorted(n[:1] + '*' * (len(n) - 1) for n in names)[:8]))
        print("Re-run notebook 02 with the latest tools, or ask the instructor; prepare_share(force=True) packs anyway.")
        return None
    share_id = share_id or secrets.token_hex(3)
    zpath = out.parent / f"share_{share_id}.zip"
    manifest = _manifest(out, share_id, ok, len(high), len(names), rows)
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(out.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(out).as_posix()
            if rel == "pseudonym_map.csv" or rel.startswith("report/"):
                continue
            if rel.startswith("json/") and not include_json:
                continue
            zf.write(p, rel)
        zf.writestr("MANIFEST.json", json.dumps(manifest, indent=1))
        zf.writestr("CONSENT.txt", CONSENT)
    n = sum(rows.values())
    print(f"Packed {zpath.name}: {len(rows)} tables, {n:,} rows, {'json tree included' if include_json else 'CSV tables only'}, "
          f"no pseudonym map; scanner: 0 HIGH, 0 leftover names.")
    print(f"Your share id is {share_id} - keep it: it is how your file will be referred to in class.")
    return str(zpath)


# ---------------------------------------------------------------------------
# Instructor side
# ---------------------------------------------------------------------------

def pool(in_dir: str, out_dir: str = "pooled", rescan: bool = True) -> dict:
    """Merge every share_*.zip / anonymised.zip in in_dir into out_dir/<table>.csv with a `student` column."""
    src = Path(in_dir)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    tables: dict = {}
    summary = []
    zips = sorted(list(src.glob("share_*.zip")) + list(src.glob("anonymised*.zip")))
    for zp in zips:
        with zipfile.ZipFile(zp) as zf:
            names = zf.namelist()
            manifest = json.loads(zf.read("MANIFEST.json")) if "MANIFEST.json" in names else {}
            sid = manifest.get("share_id") or re.sub(r"^share_|\.zip$", "", zp.name) or zp.stem
            has_map = any(n.endswith("pseudonym_map.csv") for n in names)
            verdict = ""
            if rescan:
                tmp = out / "_check" / sid
                tmp.mkdir(parents=True, exist_ok=True)
                zf.extractall(tmp)
                high, left = _rescan(tmp)
                verdict = f"{len(high)} HIGH, {len(left)} leftover names"
                import shutil
                shutil.rmtree(out / "_check", ignore_errors=True)
            n_rows = 0
            for n in names:
                m = re.match(r"(?:.*/)?csv/([^/]+)\.csv$", n)
                if not m:
                    continue
                table = m.group(1)
                text = zf.read(n).decode("utf-8", errors="replace")
                rdr = csv.DictReader(io.StringIO(text))
                for r in rdr:
                    for k in list(r):
                        if k in PSEUDO_COLUMNS and isinstance(r[k], str) and PSEUDO_RE.match(r[k].strip()):
                            r[k] = f"{sid}:{r[k].strip()}"
                    r = {"student": sid, **r}
                    tables.setdefault(table, []).append(r)
                    n_rows += 1
            summary.append((zp.name, sid, n_rows, has_map, verdict, manifest.get("created", "")))
    written = {}
    for table, rows in tables.items():
        fields = ["student"] + [k for k in {k: 1 for r in rows for k in r if k != "student"}]
        with open(out / f"{table}.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        written[table] = len(rows)
    with open(out / "SUMMARY.md", "w", encoding="utf-8") as fh:
        fh.write(f"# Pooled hand-ins ({len(zips)} files, {datetime.now(timezone.utc).date()})\n\n")
        fh.write("| file | share id | rows | pseudonym map inside? | re-scan | created |\n|---|---|---|---|---|---|\n")
        for f, sid, n, hm, v, c in summary:
            fh.write(f"| {f} | {sid} | {n:,} | {'YES - delete it' if hm else 'no'} | {v} | {c} |\n")
        fh.write("\n## Tables\n\n" + "\n".join(f"- {t}.csv: {n:,} rows" for t, n in sorted(written.items())) + "\n")
    print(f"Pooled {len(zips)} hand-ins into {out}/ : " + ", ".join(f"{t} {n:,}" for t, n in sorted(written.items())))
    flagged = [s for s in summary if s[3] or (s[4] and not s[4].startswith("0 HIGH, 0"))]
    if flagged:
        print("CHECK these files before using them:", ", ".join(s[0] for s in flagged))
    return written


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="prepare a hand-in zip, or pool the class's hand-ins")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("prepare")
    p1.add_argument("out_dir", nargs="?", default="anonymised")
    p1.add_argument("--json", action="store_true", help="include the json tree")
    p2 = sub.add_parser("pool")
    p2.add_argument("in_dir")
    p2.add_argument("out_dir", nargs="?", default="pooled")
    p2.add_argument("--no-rescan", action="store_true")
    a = ap.parse_args()
    if a.cmd == "prepare":
        prepare_share(a.out_dir, include_json=a.json)
    else:
        pool(a.in_dir, a.out_dir, rescan=not a.no_rescan)
