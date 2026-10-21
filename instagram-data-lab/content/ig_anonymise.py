#!/usr/bin/env python3
"""
ig_anonymise.py - turn an Instagram data export into a copy that is safe to share
================================================================================

Companion of ig_pii_scan.py (which must sit next to this file). Reads the raw
export (folder or .zip) and writes an anonymised copy:

  * files that are pure identifiers are dropped (login/IP history, devices,
    synced phone contacts, inferred locations, phone/email records, advertisers,
    off-Meta activity, link history, settings, photos and videos);
  * the identity file is replaced by a minimal profile.json (account age,
    private/public flag, follower/following counts);
  * every username and display name becomes a stable pseudonym (user_0001, ...),
    the export owner becomes "me"; the same person gets the same pseudonym
    everywhere - follow lists, likes, comments, DM participants, senders,
    reaction actors, @mentions, profile links, name mentions in text;
  * free text is handled according to a policy (see TextPolicy);
  * location tags and device ids are stripped from post metadata; links are
    reduced to their domain; Instagram post links lose their post code;
  * timestamps are kept, or shifted by a random number of days (--shift-days);
  * the result is written both as a JSON tree (original layout, so code written
    for a raw export still runs) and as tidy CSV tables, plus
    anonymisation_report.md and - kept by the owner, never shared -
    pseudonym_map.csv.

Standard library only, so it runs in JupyterLite / Pyodide as well as on a laptop.

Command line
    python ig_anonymise.py EXPORT_DIR_OR_ZIP                 # -> ./anonymised/
    python ig_anonymise.py EXPORT -o out --text own          # keep own DM text
    python ig_anonymise.py EXPORT -o out --text all --shift-days
    python ig_anonymise.py EXPORT -o out --zip               # also pack the result

Notebook
    from ig_anonymise import anonymise
    r = anonymise("instagram-export.zip", "anonymised", text="metadata")
    print(r.report())
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import random
import re
import shutil
import sys
import unicodedata
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Optional
from urllib.parse import urlsplit

try:
    import ig_pii_scan as S
except ImportError:  # notebook opened from another folder
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ig_pii_scan as S

__version__ = "0.1.0"
__all__ = ["anonymise", "Anonymised", "TEXT_POLICIES"]

ADS_POLICIES = ("keep", "drop")
ADS_POLICY_HELP = {
    "keep": "ads and posts shown to you, suggested accounts, inferred interests, advertisers holding your data and "
            "apps/sites reporting to Meta are kept; business, app and topic names stay, people from your network "
            "are pseudonymised, authors you do not follow (public accounts by construction) stay visible",
    "drop": "all of that is removed",
}
PLATFORM_TYPES = {"platform_activity"}
TEXT_POLICIES = ("metadata", "own", "all")
TEXT_POLICY_HELP = {
    "metadata": "other people's messages reduced to timestamps/lengths; your own messages too",
    "own": "your own messages kept (redacted); other people's reduced to metadata",
    "all": "all message text kept, with pattern redaction and pseudonyms (needs a manual read before sharing)",
}

# File types (from ig_pii_scan.FILE_RULES) that are removed entirely.
DROP_TYPES = {"address_book", "security_log", "device_info", "location", "contact_details",
              "off_platform_activity", "settings", "media_file"}
# Keys whose values are a path to a media file inside the export (the files are dropped,
# so the paths are replaced by a flag).
MEDIA_KEYS = {"uri", "media_uri", "thumbnail_uri", "photo_uri", "video_uri"}
# Keys that carry a person (username or display name) and get a pseudonym.
PERSON_KEYS = {"sender_name", "name", "actor", "title", "value", "username", "media owner",
               "original_content_owner", "owner", "author", "creator", "mentioned", "tagged",
               "account name", "participant", "user", "profile owner"}
# Keys dropped from post / story / reel metadata.
EXIF_DROP = {"latitude", "longitude", "device_id", "camera_position", "source_type", "software",
             "scene_capture_type", "scene_type", "iso", "focal_length", "lens_model", "lens_make",
             "aperture", "shutter_speed", "metering_mode", "date_time_digitized", "date_time_original",
             "original_width", "original_height", "subject_location", "white_balance", "flash",
             "exposure_program", "exposure_time", "f_number"}
# Free-text keys inside message objects.
MESSAGE_TEXT_KEYS = {"content", "share_text", "original_message_text", "text"}
# Keys whose string value is free text outside messages (captions, comments, bios...).
FREE_TEXT_KEYS = {"title", "comment", "caption", "text", "content", "bio", "description", "question",
                  "answer", "note", "body", "message", "reply", "status"}
# Field labels in the identity file that are safe to keep (everything else goes).
PROFILE_KEEP = {"private account": "private_account", "account privacy": "private_account"}

PLACEHOLDERS = {"email": "[EMAIL]", "phone": "[PHONE]", "ip_address": "[IP]", "geo_coordinates": "[COORDINATES]",
                "card_number": "[CARD]", "bank_account": "[IBAN]", "street_address": "[ADDRESS]", "date_of_birth": "[DATE]"}
EMOJI_RE = re.compile("[\U0001F300-\U0001FAFF☀-➿\U0001F1E6-\U0001F1FF⭐⭕‼⁉〰〽㊗㊙"
                      "\U0001F000-\U0001F2FF]")
HASHTAG_RE = re.compile(r"(?<!\w)#(\w+)")
WORD_RE = re.compile(r"\w+", re.U)


# ---------------------------------------------------------------------------
# Pseudonyms
# ---------------------------------------------------------------------------

MIN_MERGE_SLUG = 6   # forms of a name are merged into one person only when the skeleton is this long


def _slug(s: str) -> str:
    """'Anna Kowalski' -> 'annakowalski', 'anna.kowalski' -> 'annakowalski' (how IG names DM folders).
    Unicode-aware, so non-Latin names get a skeleton too (and never an empty one that could collide)."""
    t = unicodedata.normalize("NFKC", S._fix(s)).lower()
    return "".join(ch for ch in t if ch.isalnum())


class Pseudonymizer:
    """Stable mapping real name -> pseudonym, seeded so that reruns give the same map.

    The same person usually appears under several forms: username ("anna.kowalski"),
    display name ("Anna Kowalski"), DM folder slug ("annakowalski_1234..."). Forms whose
    letters-and-digits skeleton coincide are treated as one person and share a pseudonym.
    """

    def __init__(self, people: dict, self_names: set, seed: Optional[str] = None, network: Optional[set] = None):
        self.network = {n.lower() for n in (network or set())}
        self.network_slugs = {_slug(n) for n in self.network if len(_slug(n)) >= MIN_MERGE_SLUG}
        self.map: dict = {}           # lower-cased real value -> pseudonym
        self.kind: dict = {}          # lower-cased real value -> username | person_name
        self.display: dict = {}       # lower-cased real value -> original spelling
        self.by_slug: dict = {}       # skeleton (>= MIN_MERGE_SLUG chars) -> pseudonym
        self.used: set = set()        # pseudonyms that actually occur in the output
        self.self_names = {s.lower() for s in self_names}
        rnd = random.Random(seed if seed is not None else os.urandom(16))
        others = sorted(k for k in people if k not in self.self_names)
        rnd.shuffle(others)
        # group the forms of one person; short skeletons ("anna", "max") are not merged
        groups: dict = {}
        for k in others:
            slug = _slug(k)
            groups.setdefault(slug if len(slug) >= MIN_MERGE_SLUG else ("\0" + k), []).append(k)
        width = max(4, len(str(len(groups))))
        self.width = width
        self.n_next = 1
        for key, forms in groups.items():
            p = f"user_{self.n_next:0{width}d}"
            self.n_next += 1
            if not key.startswith("\0"):
                self.by_slug[key] = p
            for k in forms:
                self.map[k] = p
                self.kind[k] = people[k].kind
                self.display[k] = people[k].value
        for k in self.self_names:
            self.map[k] = "me"
            slug = _slug(k)
            if len(slug) >= MIN_MERGE_SLUG:
                self.by_slug[slug] = "me"
            self.kind[k] = people[k].kind if k in people else "username"
            self.display[k] = people[k].value if k in people else k
        self.matcher = S._NameMatcher({k: p for k, p in people.items()})

    def __call__(self, value: str) -> str:
        """Pseudonym for a whole-field value (a username, a display name or a folder slug)."""
        raw = S._fix(value).strip()
        k = raw.lower()
        if not k:
            return value
        if k in self.map:
            p = self.map[k]
        else:
            slug = _slug(k)
            if len(slug) >= MIN_MERGE_SLUG and slug in self.by_slug:
                p = self.by_slug[slug]
            else:
                # Someone not seen in the structured files: new sequential pseudonym.
                p = f"user_{self.n_next:0{self.width}d}"
                self.n_next += 1
                if len(slug) >= MIN_MERGE_SLUG:
                    self.by_slug[slug] = p
            self.map[k] = p
            self.kind[k] = "person_name" if " " in k else "username"
            self.display[k] = raw
        self.used.add(p)
        return p

    def in_network(self, value: str) -> bool:
        """Is this person you, someone you follow / who follows you, or a DM contact?"""
        k = S._fix(value).strip().lower()
        if not k:
            return False
        if k in self.self_names or k in self.network:
            return True
        slug = _slug(k)
        return len(slug) >= MIN_MERGE_SLUG and slug in self.network_slugs

    def in_text(self, text: str) -> str:
        """Replace @mentions, instagram.com/<user> links and known names inside free text."""
        out = text

        def repl_mention(m):
            return "@" + self(m.group(1))
        out = S.MENTION_RE.sub(repl_mention, out)

        def repl_url(m):
            u = S._ig_user(m)
            return f"instagram.com/{self(u)}" if u else m.group(0)
        out = S.IG_PROFILE_RE.sub(repl_url, out)
        # leftover path / query after a profile link (story ids, "?igsh=...") is dropped
        out = re.sub(r"(instagram\.com/(?:me|user_\w+))[/?#][^\s)]*", r"\1", out)
        hits = self.matcher.find(out)
        if hits:
            pieces, last = [], 0
            for a, b, person in hits:
                pieces.append(out[last:a])
                pieces.append(self(person.value))
                last = b
            pieces.append(out[last:])
            out = "".join(pieces)
        return out

    def rows(self) -> list:
        return sorted(({"pseudonym": p, "real_value": self.display[k], "kind": self.kind[k]}
                       for k, p in self.map.items()),
                      key=lambda r: (r["pseudonym"] != "me", r["pseudonym"], r["kind"], r["real_value"].lower()))


# ---------------------------------------------------------------------------
# Text redaction
# ---------------------------------------------------------------------------

def redact_patterns(text: str, counts: Counter) -> str:
    """Replace emails, phones, IPs, coordinates, card numbers and addresses by placeholders."""
    spans: list = []

    def claim(a, b, tag):
        for s, e, _ in spans:
            if a < e and b > s:
                return
        spans.append((a, b, tag))

    for m in S.EMAIL_RE.finditer(text):
        claim(*m.span(), PLACEHOLDERS["email"])
    for m in S.URL_RE.finditer(text):
        claim(*m.span(), None)  # protect URLs from the phone/IP patterns; they are handled by links()
    for m in S.IP4_CAND_RE.finditer(text):
        if S._is_ip(m.group()):
            claim(*m.span(), PLACEHOLDERS["ip_address"])
    for m in S.IP6_CAND_RE.finditer(text):
        if m.group().count(":") >= 2 and S._is_ip(m.group()):
            claim(*m.span(), PLACEHOLDERS["ip_address"])
    for m in S.COORD_PAIR_RE.finditer(text):
        claim(*m.span(), PLACEHOLDERS["geo_coordinates"])
    for m in S.IBAN_RE.finditer(text):
        if S._looks_like_iban(m.group()):
            claim(*m.span(), PLACEHOLDERS["bank_account"])
    for m in S.CARD_RE.finditer(text):
        if S._looks_like_card(m.group()):
            claim(*m.span(), PLACEHOLDERS["card_number"])
    for m in S.PHONE_RE.finditer(text):
        if S._looks_like_phone(m.group()):
            claim(*m.span(), PLACEHOLDERS["phone"])
    for m in S.ADDRESS_RE.finditer(text):
        claim(*m.span(), PLACEHOLDERS["street_address"])
    spans.sort()
    out, last = [], 0
    for a, b, tag in spans:
        if tag is None:
            continue
        out.append(text[last:a])
        out.append(tag)
        counts[tag] += 1
        last = b
    out.append(text[last:])
    return "".join(out)


def links_to_domains(text: str, counts: Counter) -> str:
    """Replace every URL by its domain (Instagram profile links are kept for pseudonymisation)."""
    def repl(m):
        url = m.group(0).rstrip(".,;:!?)]}'\"")
        tail = m.group(0)[len(url):]
        if S.IG_PROFILE_RE.search(url) and S._ig_user(S.IG_PROFILE_RE.search(url)):
            return m.group(0)
        host = urlsplit(url).hostname or "link"
        counts["links reduced to domain"] += 1
        return host + tail
    return S.URL_RE.sub(repl, text)


def text_features(text: str) -> dict:
    words = WORD_RE.findall(text)
    return {"n_chars": len(text), "n_words": len(words), "n_emoji": len(EMOJI_RE.findall(text)),
            "has_link": bool(S.URL_RE.search(text)), "has_mention": bool(S.MENTION_RE.search(text)),
            "has_question": "?" in text}


def domain_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# The result object
# ---------------------------------------------------------------------------

@dataclass
class Anonymised:
    source: str
    out_dir: str
    text_policy: str
    shift_days: int
    ads_policy: str = "keep"
    dropped: list = field(default_factory=list)          # (file, file_type)
    kept: list = field(default_factory=list)             # files written to the JSON tree
    counts: Counter = field(default_factory=Counter)     # what was transformed
    tables: dict = field(default_factory=dict)           # name -> number of rows
    n_people: int = 0
    pseudonymizer: Optional[Pseudonymizer] = None
    rescan: Optional[Any] = None                         # ig_pii_scan.Report of the output
    warnings: list = field(default_factory=list)
    unclassified: list = field(default_factory=list)     # kept files the scanner did not recognise
    public_accounts: set = field(default_factory=set)    # authors kept visible on purpose (not in your network)

    def report(self) -> str:
        L = [f"Anonymisation report  -  {S._display_path(Path(self.source).name)}", "=" * 78,
             f"Output: {Path(self.out_dir).name}/   text policy: {self.text_policy}   platform data: {self.ads_policy}   "
             f"timestamps: {'shifted by a hidden number of days' if self.shift_days else 'unchanged'}",
             f"People pseudonymised: {self.n_people:,} (you -> 'me'; map in pseudonym_map.csv - keep it private)"]
        for w in self.warnings:
            L.append(f"  ! {w}")
        L.append("")
        L.append("DROPPED FILES")
        by_type = Counter(t for _, t in self.dropped)
        for t, n in by_type.most_common():
            L.append(f"  {n:4d}  {t}")
        L += ["", "KEPT (transformed) FILES"]
        for f in self.kept:
            L.append(f"  {S._display_path(f)}")
        if self.unclassified:
            L += ["", "KEPT BUT NOT A KNOWN EXPORT FILE - check these by hand before sharing"]
            for f in self.unclassified:
                L.append(f"  {S._display_path(f)}")
        if self.ads_policy == "keep":
            L += ["", "PLATFORM DATA KEPT (business, app and topic names stay visible - review before sharing)"]
            for key, label in (("advertisers", "advertisers that hold your data"),
                               ("off_meta_activity", "events reported to Meta by apps/sites"),
                               ("topics", "inferred interests"), ("ads_viewed", "ads seen"),
                               ("posts_viewed", "posts seen"), ("videos_watched", "videos watched"),
                               ("suggested_accounts", "accounts suggested to you (pseudonymised)")):
                n = self.tables.get(key)
                if n:
                    L.append(f"  {n:6,d}  {label}")
        L += ["", "TRANSFORMATIONS"]
        for k, n in self.counts.most_common():
            L.append(f"  {n:6,d}  {k}")
        L += ["", "CSV TABLES"]
        for name, n in self.tables.items():
            L.append(f"  {n:6,d} rows  {name}.csv")
        if self.rescan is not None:
            cats = self.rescan.category_table()
            high = [c for c in cats if c["severity"] == "high"]
            L += ["", "RE-SCAN OF THE OUTPUT (ig_pii_scan)"]
            L.append(f"  HIGH findings: {sum(c['occurrences'] for c in high)}"
                     + ("   <- none, as it should be" if not high else "   <- LOOK AT THESE"))
            for c in high:
                L.append(f"     {c['category']}: {c['occurrences']} ({c['examples']})")
            others = [c for c in cats if c["severity"] != "high"]
            if others:
                L.append("  other findings: " + ", ".join(f"{c['category']} {c['occurrences']}" for c in others))
            names = {p.value for p in self.rescan.people.values()
                     if not re.fullmatch(r"(me|user_\w+|group_\w+)", p.value) and p.value.lower() not in self.public_accounts}
            L.append(f"  non-pseudonym names still present: {len(names)}"
                     + (f"  e.g. {[S.mask(n) for n in sorted(names)[:5]]} (masked; see pii_people.csv of a scan of the output)"
                        if names else "")
                     + (f"   (not counting {len(self.public_accounts)} public accounts kept on purpose)"
                        if self.public_accounts else ""))
        return "\n".join(L)


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

class _Anonymiser:
    def __init__(self, src: S._Source, scan: S.Report, out: Path, text: str, shift_days: int, seed: Optional[str],
                 ads: str = "keep"):
        self.src, self.scan, self.out, self.text, self.shift, self.ads = src, scan, out, text, shift_days, ads
        self.P = Pseudonymizer(scan.people, scan.self_names, seed, network=scan.network)
        self.res = Anonymised(str(src.path), str(out), text, shift_days, ads_policy=ads, pseudonymizer=self.P)
        self.counts = self.res.counts
        self.drop_types = set(DROP_TYPES) | (PLATFORM_TYPES if ads == "drop" else set())
        self.network_known = bool(scan.network)
        if ads == "keep" and not self.network_known:
            self.res.warnings.append("No followers/following/DM files in this export, so it is impossible to tell "
                                     "which accounts in 'posts viewed' / 'videos watched' are public: all of them "
                                     "were pseudonymised.")
        self.rows: dict = {k: [] for k in ("messages", "threads", "followers", "following", "posts", "comments",
                                           "likes", "saved", "stories", "reels", "ads_viewed", "posts_viewed",
                                           "videos_watched", "suggested_accounts", "advertisers",
                                           "off_meta_activity", "topics")}
        self.root_in = self._root_name()
        self.root_out = "instagram-anonymised"

    # -- helpers -------------------------------------------------------------
    def _root_name(self) -> str:
        rels = [fi.rel for fi in self.scan.files]
        firsts = {r.split("/")[0] for r in rels if "/" in r}
        if len(firsts) == 1:
            f = firsts.pop()
            if S.ROOT_RE.match(f):
                return f
        return ""

    def out_rel(self, rel: str) -> str:
        """Output path: the export root and every DM thread folder lose their real names."""
        parts = rel.replace("\\", "/").split("/")
        in_messages = False
        for i, p in enumerate(parts):
            if S.ROOT_RE.match(p):
                parts[i] = self.root_out
                continue
            if p in ("messages", "inbox", "message_requests", "archived_threads", "filtered_threads",
                     "secret_conversations"):
                in_messages = True
                continue
            if in_messages:
                tm = S.THREAD_RE.match(p)
                if tm:
                    parts[i] = self.P(tm.group(1)) + "_" + p.rsplit("_", 1)[-1][-6:]
        return "/".join(parts)

    def ts(self, value, unit: str = "s"):
        """Shift a timestamp (seconds or milliseconds) by self.shift days."""
        if not self.shift or isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            return value
        if unit == "s" and value > 1e11:   # a millisecond value under a plain "timestamp" key
            unit = "ms"
        delta = self.shift * 86400 * (1000 if unit == "ms" else 1)
        return value + delta

    def iso(self, value, unit: str = "s") -> str:
        try:
            v = float(value)
            if unit == "s" and v > 1e11:
                unit = "ms"
            v = v / (1000 if unit == "ms" else 1)
            return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError, OSError):
            return ""

    def free_text(self, s: str) -> str:
        """Captions, comments, bios: keep, with pseudonyms, redaction and domain-only links."""
        t = S._fix(s)
        t = self.P.in_text(t)
        t = redact_patterns(t, self.counts)
        t = links_to_domains(t, self.counts)
        return t

    # -- generic JSON walk ---------------------------------------------------
    def walk(self, node: Any, rel: str, path: tuple = (), label: Optional[str] = None) -> Any:
        if isinstance(node, dict):
            if isinstance(node.get("label"), str):
                label = node["label"]
            out = {}
            for k, v in node.items():
                lk = str(k).lower()
                if lk in EXIF_DROP:
                    self.counts["metadata fields removed (location/device)"] += 1
                    continue
                if isinstance(v, (dict, list)):
                    out[k] = self.walk(v, rel, path + (k,), label)
                    continue
                out[k] = self.scalar(k, v, rel, path, label)
            return out
        if isinstance(node, list):
            return [self.walk(v, rel, path + (i,), label) for i, v in enumerate(node)]
        return node

    def scalar(self, k: str, v: Any, rel: str, path: tuple, label: Optional[str]) -> Any:
        lk = str(k).lower()
        if lk in ("timestamp", "creation_timestamp", "taken_at", "time", "imported_time") and isinstance(v, (int, float)):
            return self.ts(v)
        if lk.endswith("_ms") and isinstance(v, (int, float)):
            return self.ts(v, "ms")
        if not isinstance(v, str):
            return v
        sv = S._fix(v)
        if lk in MEDIA_KEYS or (lk == "href" and not sv.lower().startswith(("http://", "https://"))):
            self.counts["media references replaced"] += 1
            return "<media removed>" if sv else sv
        if lk == "href":
            return self.link(sv)
        # which semantic key labels this value? (same logic as the scanner, including the
        # per-file overrides: "value" in a followers file is a username, "title" in likes too)
        ctx = [p for p in path if isinstance(p, str)] + [k]
        if label and lk == "value":
            ctx.append(label)
        cat, _sev, sem = S._classify_key(ctx, k, rel.lower())
        nsem = S._norm_key(sem)
        if lk == "thread_path" or nsem == "thread path":
            return self.out_rel(sv)
        low = rel.lower()
        if cat in ("username", "person_name", "profile_history"):
            if cat == "username" and ("posts_viewed" in low or "videos_watched" in low):
                # content you saw: a private account's posts are only visible to followers, so an
                # author outside your network is a public account and may stay visible
                if self.network_known and not self.P.in_network(sv):
                    self.counts["public accounts kept visible (posts/videos viewed)"] += 1
                    self.res.public_accounts.add(sv.strip().lower())
                    return sv
                self.counts["network accounts pseudonymised (posts/videos viewed)"] += 1
            return self.P(sv)
        if cat in ("business_or_app", "topic"):
            self.counts[f"{'business/app' if cat == 'business_or_app' else 'topic'} names kept"] += 1
            return redact_patterns(sv, self.counts)
        if cat in ("email", "phone", "ip_address", "geo_coordinates", "date_of_birth", "contact_details",
                   "device_or_session", "location_text", "browsing_history", "gender"):
            self.counts[f"fields removed ({cat})"] += 1
            return "[removed]"
        if cat == "url" or sv.lower().startswith(("http://", "https://")):
            return self.link(sv)
        # everything else (captions, comments, and any string under a key we do not know) goes
        # through the full pass: pseudonyms for mentions/links/known names, pattern redaction, links
        return self.free_text(sv)

    def link(self, url: str) -> str:
        m = S.IG_PROFILE_RE.search(url)
        if m:
            u = S._ig_user(m)
            if u:
                self.counts["profile links pseudonymised"] += 1
                return "https://www.instagram.com/" + self.P(u)
            self.counts["instagram post links reduced"] += 1
            return "https://www.instagram.com/" + (m.group(1) or "")
        d = domain_of(url)
        self.counts["links reduced to domain"] += 1
        return f"https://{d}/" if d else "[link]"

    # -- messages --------------------------------------------------------------
    def message(self, m: dict, thread: str) -> dict:
        sender_raw = S._fix(m.get("sender_name") or "")
        sender = self.P(sender_raw) if sender_raw else "unknown"
        is_me = sender == "me"
        out: dict = {"sender_name": sender, "timestamp_ms": self.ts(m.get("timestamp_ms"), "ms")}
        text = m.get("content")
        text = S._fix(text) if isinstance(text, str) else None
        keep_text = self.text == "all" or (self.text == "own" and is_me)
        feats = text_features(text) if text else {"n_chars": 0, "n_words": 0, "n_emoji": 0,
                                                  "has_link": False, "has_mention": False, "has_question": False}
        if text is not None:
            if keep_text:
                out["content"] = self.free_text(text)
                self.counts["messages kept (redacted)"] += 1
            else:
                self.counts["messages reduced to metadata"] += 1
            out["text_features"] = feats
        kinds = []
        for key in ("photos", "videos", "audio_files", "gifs", "files", "sticker"):
            if key in m:
                items = m[key] if isinstance(m[key], list) else [m[key]]
                out[key] = [{"creation_timestamp": self.ts(i.get("creation_timestamp"))} if isinstance(i, dict) else {}
                            for i in items]
                kinds.append(key)
                self.counts["message attachments removed"] += len(items)
        if "share" in m and isinstance(m["share"], dict):
            sh = m["share"]
            link = S._fix(sh.get("link", "")) if isinstance(sh.get("link"), str) else ""
            out["share"] = {"domain": domain_of(link) if link else "",
                            "original_content_owner": self.P(sh["original_content_owner"])
                            if isinstance(sh.get("original_content_owner"), str) else None}
            kinds.append("share")
        if "reactions" in m and isinstance(m["reactions"], list):
            out["reactions"] = [{"reaction": S._fix(r.get("reaction") or ""),
                                 "actor": self.P(r["actor"]) if r.get("actor") else "unknown"}
                                for r in m["reactions"] if isinstance(r, dict)]
        if m.get("is_unsent"):
            out["is_unsent"] = True
        if m.get("call_duration") is not None:
            out["call_duration"] = m["call_duration"]
            kinds.append("call")
        self.rows["messages"].append({
            "thread": thread, "sender": sender, "is_me": is_me,
            "timestamp": self.iso(out["timestamp_ms"], "ms"),
            "has_text": text is not None, **{k: v for k, v in feats.items()},
            "attachment": "+".join(kinds), "n_reactions": len(out.get("reactions", [])),
            "text": out.get("content", "") if keep_text else "",
        })
        return out

    def thread_file(self, data: dict, rel: str) -> dict:
        title = S._fix(data.get("title", "")) if isinstance(data.get("title"), str) else ""
        participants = [self.P(p["name"]) if p.get("name") else "unknown"
                        for p in (data.get("participants") or []) if isinstance(p, dict)]
        others = [p for p in participants if p != "me"]
        is_group = len(participants) > 2
        if is_group:
            thread = "group_" + hashlib.sha1(("|".join(sorted(participants))).encode()).hexdigest()[:8]
        else:
            thread = self.P(title) if title else (others[0] if others else "unknown")
        msgs = [self.message(m, thread) for m in (data.get("messages") or []) if isinstance(m, dict)]
        out = {"participants": [{"name": p} for p in participants], "messages": msgs,
               "title": thread, "is_still_participant": data.get("is_still_participant"),
               "thread_path": self.out_rel(S._fix(data.get("thread_path", ""))) if isinstance(data.get("thread_path"), str) else "",
               "thread_type": "group" if is_group else "direct"}
        ts = [m["timestamp_ms"] for m in msgs if isinstance(m.get("timestamp_ms"), (int, float))]
        self.rows["threads"].append({
            "thread": thread, "thread_type": out["thread_type"], "n_participants": len(participants),
            "n_messages": len(msgs), "n_from_me": sum(1 for m in msgs if m["sender_name"] == "me"),
            "first_message": self.iso(min(ts), "ms") if ts else "", "last_message": self.iso(max(ts), "ms") if ts else "",
        })
        return out

    # -- content tables ------------------------------------------------------------
    def harvest_rows(self, data: Any, fi: S.FileInfo) -> None:
        """Fill the tidy tables from the anonymised JSON of a content file.

        Field labels are localised in real exports ("Comment" / "Commento" / "Kommentar"), so
        entries of string_map_data are looked up by the scanner's category, not by English label.
        """
        low = fi.rel_lower
        name = PurePosixPath(low).name

        def entries(d: dict) -> list:
            m = d.get("string_map_data") or {}
            return [(S._classify_key([k], k, low)[0], v) for k, v in m.items() if isinstance(v, dict)]

        def by_cat(d: dict, *cats):
            for cat, v in entries(d):
                if cat in cats:
                    return v
            return {}

        def when(d: dict):
            """First timestamp found: string_list_data[0].timestamp or any string_map_data entry's."""
            lst = d.get("string_list_data") or []
            if lst and isinstance(lst[0], dict) and lst[0].get("timestamp"):
                return lst[0]["timestamp"]
            for _cat, v in entries(d):
                if v.get("timestamp"):
                    return v["timestamp"]
            return None

        def sld_first(d: dict):
            lst = d.get("string_list_data") or []
            return lst[0] if lst and isinstance(lst[0], dict) else {}

        def items_of(d):
            if isinstance(d, list):
                return [x for x in d if isinstance(x, dict)]
            if isinstance(d, dict):
                return [x for x in next((v for v in d.values() if isinstance(v, list)), []) if isinstance(x, dict)]
            return []

        def media_first(it: dict) -> dict:
            media = it.get("media") or []
            return media[0] if media and isinstance(media[0], dict) else {}

        if name.startswith("followers"):
            for it in items_of(data):
                s = sld_first(it)
                self.rows["followers"].append({"user": s.get("value", ""), "timestamp": self.iso(s.get("timestamp"))})
        elif name.startswith("following"):
            for it in items_of(data):
                s = sld_first(it)
                self.rows["following"].append({"user": s.get("value", ""), "timestamp": self.iso(s.get("timestamp"))})
        elif "comments" in name:
            for it in items_of(data):
                c, o = by_cat(it, "free_text"), by_cat(it, "username", "person_name")
                text = c.get("value", "") if isinstance(c.get("value"), str) else ""
                self.rows["comments"].append({"on_post_by": o.get("value", ""), "timestamp": self.iso(when(it)),
                                              "n_words": len(WORD_RE.findall(text)), "text": text})
        elif "liked" in name or "likes" in low:
            for it in items_of(data):
                self.rows["likes"].append({"post_by": it.get("title", ""), "kind": "comment" if "comment" in name else "post",
                                           "timestamp": self.iso(when(it))})
        elif "saved" in low:
            for it in items_of(data):
                self.rows["saved"].append({"post_by": it.get("title", ""), "timestamp": self.iso(when(it))})
        elif (name.startswith("posts") and "viewed" not in name) or "archived_posts" in name or "recently_deleted" in name:
            for it in items_of(data):
                m0 = media_first(it)
                cap = it.get("title") or m0.get("title", "") or ""
                ts = it.get("creation_timestamp") or m0.get("creation_timestamp")
                self.rows["posts"].append({"timestamp": self.iso(ts), "n_media": len(it.get("media") or []),
                                           "hashtags": " ".join(HASHTAG_RE.findall(cap)),
                                           "n_mentions": len(S.MENTION_RE.findall(cap)),
                                           "n_words": len(WORD_RE.findall(cap)), "caption": cap,
                                           "source": "archived" if "archived" in name else "deleted" if "deleted" in name else "posts"})
        elif "ads_viewed" in name or "ads_clicked" in name:
            for it in items_of(data):
                a = by_cat(it, "business_or_app", "username", "person_name")
                self.rows["ads_viewed"].append({"advertiser": a.get("value", ""),
                                                "kind": "clicked" if "clicked" in name else "viewed",
                                                "timestamp": self.iso(when(it))})
        elif "posts_viewed" in name or "videos_watched" in name:
            table = "posts_viewed" if "posts_viewed" in name else "videos_watched"
            for it in items_of(data):
                a = by_cat(it, "username", "person_name")
                author = a.get("value", "")
                self.rows[table].append({"author": author,
                                         "in_network": bool(re.fullmatch(r"me|user_\w+", author)),
                                         "timestamp": self.iso(when(it))})
        elif "suggested_accounts" in name:
            for it in items_of(data):
                a = by_cat(it, "username", "person_name")
                self.rows["suggested_accounts"].append({"account": a.get("value", ""), "timestamp": self.iso(when(it))})
        elif "advertisers_using" in name:
            for it in items_of(data):
                self.rows["advertisers"].append({
                    "advertiser": it.get("advertiser_name", ""),
                    "uploaded_your_contact_details": bool(it.get("has_data_file_custom_audience")),
                    "tracked_you_on_their_site": bool(it.get("has_remarketing_custom_audience")),
                    "in_store_visit": bool(it.get("has_in_person_store_visit"))})
        elif "off_meta" in low or "off_of_instagram" in low:
            for it in items_of(data):
                app = it.get("name", "")
                for ev in it.get("events") or []:
                    if isinstance(ev, dict):
                        self.rows["off_meta_activity"].append({"app_or_site": app, "event": ev.get("type", ""),
                                                               "timestamp": self.iso(ev.get("timestamp"))})
                if not it.get("events"):
                    self.rows["off_meta_activity"].append({"app_or_site": app, "event": "", "timestamp": ""})
        elif "your_topics" in name or "ads_interests" in name or "recommended_topics" in name:
            for it in items_of(data):
                t = by_cat(it, "topic", "business_or_app", "free_text", "person_name", "username")
                if t.get("value"):
                    self.rows["topics"].append({"topic": t.get("value", ""),
                                                "source": "ads_interests" if "interests" in name else "your_topics"})
        elif name.startswith("stories"):
            for it in items_of(data):
                self.rows["stories"].append({"timestamp": self.iso(it.get("creation_timestamp")),
                                             "has_caption": bool(it.get("title"))})
        elif name.startswith("reels"):
            for it in items_of(data):
                m0 = media_first(it)
                cap = it.get("title") or m0.get("title", "") or ""
                self.rows["reels"].append({"timestamp": self.iso(it.get("creation_timestamp") or m0.get("creation_timestamp")),
                                           "caption": cap})

    # -- identity ------------------------------------------------------------
    def profile(self, data: Any) -> dict:
        prof = {"username": "me", "private_account": None}
        for path, val, label, _ in S._iter_leaves(data):
            ctx, leaf = S._context(path, label)
            sem = next((c for c in reversed(ctx) if c.lower() not in S.GENERIC_KEYS), leaf)
            key = S._norm_key(sem)
            if key in PROFILE_KEEP and isinstance(val, str):
                prof[PROFILE_KEEP[key]] = val.strip().lower() in ("true", "yes", "private")
        return prof

    # -- run ---------------------------------------------------------------------
    def run(self) -> Anonymised:
        out = self.out
        _prepare_output_dir(out, self.src.path)
        (out / "json").mkdir(parents=True)
        (out / "csv").mkdir()
        json_root = (out / "json").resolve()
        parsed: dict = {}
        for fi in self.scan.files:
            if fi.kind == "json" and not fi.error:
                try:
                    parsed[fi.rel] = json.loads(self.src.read(fi.rel).decode("utf-8"))
                except Exception:
                    continue
        profile = {"username": "me", "private_account": None}
        signup_ts = None
        for fi in self.scan.files:
            if fi.file_type in self.drop_types or fi.kind != "json" or fi.rel not in parsed:
                if fi.kind == "json" and fi.file_type == "security_log" and "signup" in fi.rel_lower and fi.rel in parsed:
                    for path, val, label, _ in S._iter_leaves(parsed[fi.rel]):
                        if isinstance(path[-1], str) and path[-1] == "timestamp" and isinstance(val, (int, float)) and val:
                            signup_ts = val
                if fi.kind != "json" or fi.file_type in self.drop_types or fi.error:
                    self.res.dropped.append((fi.rel, fi.file_type))
                continue
            data = parsed[fi.rel]
            if fi.file_type == "identity":
                if "personal_information.json" in fi.rel_lower or "personal_information.htm" in fi.rel_lower:
                    profile.update(self.profile(data))
                self.res.dropped.append((fi.rel, fi.file_type))
                continue
            if fi.file_type == "private_messages" and isinstance(data, dict) and "messages" in data:
                new = self.thread_file(data, fi.rel)
            else:
                new = self.walk(data, fi.rel)
                self.harvest_rows(new, fi)
            rel_out = self.out_rel(fi.rel)
            p = out / "json" / rel_out
            if json_root not in p.resolve().parents:  # a hostile zip entry ("../x") never escapes out/json
                self.res.dropped.append((fi.rel, "unsafe path"))
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(new, ensure_ascii=False, indent=1), encoding="utf-8")
            self.res.kept.append(rel_out)
            if fi.file_type == "other":
                self.res.unclassified.append(rel_out)
        # profile.json
        profile["n_followers"] = len(self.rows["followers"])
        profile["n_following"] = len(self.rows["following"])
        if signup_ts:
            profile["account_created"] = self.iso(self.ts(signup_ts))[:7]  # year-month only
        root = out / "json" / (self.root_out if self.root_in else "")
        root.mkdir(parents=True, exist_ok=True)
        (root / "profile.json").write_text(json.dumps(profile, indent=1), encoding="utf-8")
        self.res.kept.append((self.root_out + "/" if self.root_in else "") + "profile.json")
        # csv tables
        for name, rows in self.rows.items():
            if not rows:
                continue
            cols = list(rows[0].keys())
            for r in rows:
                for c in r:
                    if c not in cols:
                        cols.append(c)
            with open(out / "csv" / f"{name}.csv", "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=cols)
                w.writeheader()
                w.writerows(rows)
            self.res.tables[name] = len(rows)
        # pseudonym map (private) and report
        with open(out / "pseudonym_map.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["pseudonym", "real_value", "kind"])
            w.writeheader()
            w.writerows(self.P.rows())
        self.res.n_people = len(self.P.used - {"me"})
        for note in self.scan.notes:
            if "media files" in note or "folder/zip name" in note:
                continue  # media are dropped and folder names renamed, so these are handled here
            self.res.warnings.append(note)
        if self.scan.formats.get("html") and not self.scan.formats.get("json"):
            self.res.warnings.append("HTML export: nothing could be anonymised (HTML pages are dropped). "
                                     "Request the export in JSON format.")
        return self.res


def _prepare_output_dir(out: Path, source: Path) -> None:
    """Create/empty the output directory without ever deleting anything that is not ours."""
    out_r, src_r = out.resolve(), source.resolve()
    for forbidden in (Path.cwd().resolve(), Path.home().resolve(), Path(Path.cwd().anchor).resolve(), src_r):
        if out_r == forbidden:
            raise ValueError(f"refusing to use {out} as output directory: choose a new, dedicated folder")
    if src_r == out_r or out_r in src_r.parents:
        raise ValueError(f"refusing to write into {out}: it contains the export itself")
    if not out.exists():
        return
    ours = {"json", "csv", "anonymisation_report.md", "pseudonym_map.csv"}
    foreign = [p.name for p in out.iterdir() if p.name not in ours and not p.name.startswith(".")]
    if foreign:
        raise ValueError(f"{out} already contains other files ({', '.join(foreign[:5])}): "
                         "choose an empty or new folder")
    for name in ours:
        p = out / name
        if p.is_dir():
            shutil.rmtree(p)
        elif p.exists():
            p.unlink()


def anonymise(source, out_dir="anonymised", text: str = "metadata", shift_days: bool | int = False,
              seed: Optional[str] = None, rescan: bool = True, ads: str = "keep") -> Anonymised:
    """Anonymise an export folder or .zip into out_dir. Returns an Anonymised result (see .report())."""
    if text not in TEXT_POLICIES:
        raise ValueError(f"text must be one of {TEXT_POLICIES}")
    if ads not in ADS_POLICIES:
        raise ValueError(f"ads must be one of {ADS_POLICIES}")
    src = S._Source(source)
    scan = S.scan(source)
    if shift_days is True:
        shift = random.Random(seed if seed is not None else os.urandom(8)).randint(30, 400)
    else:
        shift = int(shift_days or 0)
    forced = None
    if text == "own" and not scan.self_names:
        forced = ("your own account could not be identified (no personal_information file, or labels in a "
                  "language the scanner does not know), so 'own' would keep nobody's text safely: "
                  "the text policy was changed to 'metadata'")
        text = "metadata"
    anon = _Anonymiser(src, scan, Path(out_dir), text, shift, seed, ads=ads)
    if forced:
        anon.res.warnings.append(forced)
    res = anon.run()
    (Path(out_dir) / "anonymisation_report.md").write_text("# Anonymisation report\n\n```\n" + res.report() + "\n```\n",
                                                           encoding="utf-8")
    if rescan:
        res.rescan = S.scan(str(Path(out_dir) / "json"))
        (Path(out_dir) / "anonymisation_report.md").write_text(
            "# Anonymisation report\n\n```\n" + res.report() + "\n```\n", encoding="utf-8")
    return res


def pack(out_dir="anonymised", include_map: bool = False) -> str:
    """Zip the shareable part of the output (json/, csv/, report). The pseudonym map is left out unless asked."""
    out = Path(out_dir)
    zpath = out.parent / (out.name + ".zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(out.rglob("*")):
            if p.is_file():
                rel = p.relative_to(out).as_posix()
                if rel == "pseudonym_map.csv" and not include_map:
                    continue
                zf.write(p, rel)
    return str(zpath)


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Anonymise an Instagram data export.")
    ap.add_argument("source", help="export folder or .zip")
    ap.add_argument("-o", "--out", default="anonymised", help="output directory (default: anonymised)")
    ap.add_argument("--text", choices=TEXT_POLICIES, default="metadata",
                    help="; ".join(f"{k}: {v}" for k, v in TEXT_POLICY_HELP.items()))
    ap.add_argument("--ads", choices=ADS_POLICIES, default="keep",
                    help="; ".join(f"{k}: {v}" for k, v in ADS_POLICY_HELP.items()))
    ap.add_argument("--shift-days", action="store_true", help="shift all timestamps by a random 30-400 days")
    ap.add_argument("--seed", help="seed for the pseudonym order / day shift (same seed -> same output)")
    ap.add_argument("--no-rescan", action="store_true", help="skip re-scanning the output with ig_pii_scan")
    ap.add_argument("--zip", action="store_true", help="also write <out>.zip (without the pseudonym map)")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    res = anonymise(a.source, a.out, text=a.text, shift_days=a.shift_days, seed=a.seed, rescan=not a.no_rescan,
                    ads=a.ads)
    print(res.report())
    if a.zip:
        print("\nPacked:", pack(a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
