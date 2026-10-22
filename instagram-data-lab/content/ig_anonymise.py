#!/usr/bin/env python3
"""
ig_anonymise.py - turn an Instagram data export into a copy that is safe to share
================================================================================

Companion of ig_pii_scan.py (which must sit next to this file). Reads the raw
export (folder or .zip) and writes an anonymised copy:

  * every JSON file is kept (files="all", the default); photos and videos are
    dropped. In the sensitive files (identity, login/IP history, devices, synced
    contacts, inferred locations, phone/email records, payments) only structure,
    timestamps and yes/no values survive, everything else is "[removed]" or a
    pseudonym; files="minimal" drops those files instead;
  * a minimal profile.json (account age, private/public flag, follower/following
    counts) is written in both modes;
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
__all__ = ["anonymise", "Anonymised", "TEXT_POLICIES", "suggest_public", "pack"]

ADS_POLICIES = ("keep", "drop")
ADS_POLICY_HELP = {
    "keep": "ads and posts shown to you, suggested accounts, your interested / not-interested feedback, inferred "
            "interests, advertisers holding your data and "
            "apps/sites reporting to Meta are kept; business, app and topic names stay, people from your network "
            "are pseudonymised, authors you do not follow (public accounts by construction) stay visible",
    "drop": "all of that is removed",
}
PLATFORM_TYPES = {"platform_activity"}
TEXT_POLICIES = ("metadata", "own", "all")
TEXT_POLICY_HELP = {
    "metadata": "all text - messages, your captions and comments, captions of the posts and stories shown to you - "
                "reduced to metadata (word and emoji counts, hashtags, pseudonymised mentions)",
    "own": "your own messages, captions and comments kept (redacted); everyone else's text reduced to metadata",
    "all": "all text kept, with pattern redaction and pseudonyms (needs a manual read before sharing)",
}
CAPTION_META_RE = re.compile(r"\[(\d+) words, (\d+) emoji\]$")

# File types (from ig_pii_scan.FILE_RULES) that are removed entirely under files="minimal".
DROP_TYPES = {"address_book", "security_log", "device_info", "location", "contact_details",
              "off_platform_activity", "settings", "media_file", "payment_details", "search_history"}
FILES_POLICIES = ("all", "minimal")
FILES_POLICY_HELP = {
    "all": "every JSON file of the export is kept (media files excepted: a photo cannot be anonymised); the "
           "most sensitive ones (identity, logins, devices, locations, contacts, payments) keep only their "
           "structure, timestamps and yes/no values - every other value is removed or pseudonymised",
    "minimal": "identity, login, device, location, contact, payment, search and settings files are dropped",
}
# In these files any text the key rules do not recognise is removed rather than passed through.
STRICT_TYPES = {"address_book", "security_log", "device_info", "location", "contact_details",
                "payment_details", "identity"}
SAFE_ENUM_RE = re.compile(r"([Tt]rue|[Ff]alse|[Yy]es|[Nn]o|[Oo]n|[Oo]ff|[Ee]nabled|[Dd]isabled|[Aa]ctive|[Ii]nactive|"
                          r"[Uu]nknown|[Nn]one|[Uu]nspecified|[Pp]ublic|[Pp]rivate|\d+|[A-Z]{2}|[a-z_]{1,24})")
# files whose entries are content you consumed: an author outside your network is a public account
CONSUMED_RE = re.compile(r"posts_viewed|videos_watched|threads_viewed|ads_viewed|ads_clicked|liked_posts|"
                         r"saved_posts|story_likes|stories_viewed|liked_comments|posts_you.?re_(not_)?interested")
# files that list *people* the platform showed you (suggested profiles, profiles you dismissed): every
# account in them is pseudonymised, whether or not it is in your network, and its link is dropped
PEOPLE_RE = re.compile(r"suggested_(accounts|profiles)|profiles_you.?re_(not_)?interested")
# titles of nested blocks that describe a place, not a person
PLACE_TITLES = {"place", "location", "luogo", "ort", "lieu", "lugar"}
HASHTAG_TITLES = {"hashtags", "hashtag", "mentions", "topics", "topic"}
DROP_KEYS = {"fbid"}
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

    def __init__(self, people: dict, self_names: set, seed: Optional[str] = None, network: Optional[set] = None,
                 public: Optional[set] = None):
        self.network = {n.lower() for n in (network or set())}
        self.network_slugs = {_slug(n) for n in self.network if len(_slug(n)) >= MIN_MERGE_SLUG}
        # accounts declared public by the owner (or detected as businesses): never pseudonymised
        self.public = {S._fix(n).strip().lower().lstrip("@") for n in (public or set()) if n}
        self.public_slugs = {_slug(n) for n in self.public if len(_slug(n)) >= MIN_MERGE_SLUG}
        self.public_seen: set = set()
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
        if self.is_public(k) and k not in self.self_names:
            self.public_seen.add(k)
            return raw
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

    def is_public(self, value: str) -> bool:
        """Declared public (PUBLIC_ACCOUNTS) or detected as a business: name stays visible everywhere."""
        k = S._fix(value).strip().lower().lstrip("@")
        if not k:
            return False
        if k in self.public:
            return True
        slug = _slug(k)
        return len(slug) >= MIN_MERGE_SLUG and slug in self.public_slugs

    def visible(self, value: str) -> bool:
        """May this author of content you consumed stay visible? Public by declaration, or not in your
        network (a private account's posts are only visible to followers)."""
        return self.is_public(value) or not self.in_network(value)

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
# Tidy tables (works on the anonymised JSON tree; both export layouts)
# ---------------------------------------------------------------------------

TABLES = ("messages", "threads", "followers", "following", "follow_requests", "posts", "comments", "likes",
          "saved", "stories", "reels", "ads_viewed", "posts_viewed", "videos_watched", "threads_viewed",
          "stories_viewed", "story_likes", "suggested_accounts", "feedback", "advertisers", "off_meta_activity", "topics",
          "insights_posts", "insights_stories", "insights_summary")
PSEUDO_RE = re.compile(r"me|user_\w+")


def _iso_utc(value, unit: str = "s") -> str:
    try:
        v = float(value)
        if unit == "s" and v > 1e11:
            unit = "ms"
        return datetime.fromtimestamp(v / (1000 if unit == "ms" else 1), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def lv_fields(item: dict) -> dict:
    """Flatten a label_values item: {field name: value}. Nested blocks come back as lists of dicts."""
    out: dict = {}
    for e in item.get("label_values") or []:
        if not isinstance(e, dict):
            continue
        name = e.get("label") if isinstance(e.get("label"), str) else e.get("title") if "dict" in e else None
        if name is None:
            continue
        if "value" in e:
            out[name] = e["value"]
            if e.get("href"):
                out[name + " (href)"] = e["href"]
        elif "timestamp_value" in e:
            out[name] = e["timestamp_value"]
        elif "vec" in e:
            out[name] = [x.get("value") if isinstance(x, dict) else x for x in e["vec"]]
        elif "dict" in e:
            blocks = []
            for sub in e["dict"]:
                if isinstance(sub, dict):
                    b = lv_fields({"label_values": sub.get("dict", [])})
                    if sub.get("title"):
                        b["_title"] = sub["title"]
                    blocks.append(b)
            out[name] = blocks
        else:
            out.setdefault(name, None)
    return out


def _cat_of(label: str):
    hit = S._match_key_rules(S._norm_key(label.split(" (href)")[0]))
    return hit[0] if hit else None


def _by_cat(fields: dict, *cats):
    """First field whose name classifies as one of the categories (localised labels welcome)."""
    for k, v in fields.items():
        if _cat_of(k) in cats:
            return v
    return None


def lv_owner(fields: dict) -> dict:
    """The account block ("Owner"/"Author"/...) of an item: {name, username, url}."""
    for k, v in fields.items():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            sub = v[0]
            u = _by_cat(sub, "username")
            if isinstance(u, str) and u:
                n = _by_cat(sub, "person_name")
                url = _by_cat(sub, "url")
                return {"username": u, "name": n if isinstance(n, str) else "", "url": url if isinstance(url, str) else ""}
    for k, v in fields.items():  # {"label": "Author", "vec": [{"value": name}]} or a plain value
        if _cat_of(k) in ("username", "person_name", "business_or_app"):
            if isinstance(v, list) and v and isinstance(v[0], str):
                return {"username": v[0], "name": "", "url": ""}
            if isinstance(v, str) and v:
                return {"username": v, "name": "", "url": ""}
    return {"username": "", "name": "", "url": ""}


def lv_hashtags(fields: dict) -> list:
    for k, v in fields.items():
        if S._norm_key(k) in ("hashtags", "hashtag") and isinstance(v, list):
            return [x.get("Name") or x.get("name") or "" for x in v if isinstance(x, dict)]
    return []


def lv_media(fields: dict) -> dict:
    """The post described by an item: the item itself, or its nested "Media" block when the caption and
    hashtags live there (the "interested / not interested" feedback files)."""
    if isinstance(_by_cat(fields, "free_text"), str) or lv_hashtags(fields):
        return fields
    for k, v in fields.items():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            sub = v[0]
            if isinstance(_by_cat(sub, "free_text"), str) or lv_hashtags(sub):
                return sub
    return fields


def _smd(item: dict) -> dict:
    return item.get("string_map_data") or {}


def _smd_by_cat(item: dict, *cats) -> str:
    for k, v in _smd(item).items():
        if _cat_of(k) in cats and isinstance(v, dict):
            return v.get("value", "") if isinstance(v.get("value"), str) else ""
    return ""


def _old_when(item: dict):
    lst = item.get("string_list_data") or []
    if lst and isinstance(lst[0], dict) and lst[0].get("timestamp"):
        return lst[0]["timestamp"]
    for v in _smd(item).values():
        if isinstance(v, dict) and v.get("timestamp"):
            return v["timestamp"]
    return None


def _items_of(d):
    if isinstance(d, list):
        return [x for x in d if isinstance(x, dict)]
    if isinstance(d, dict):
        if "label_values" in d:
            return [d]
        return [x for x in next((v for v in d.values() if isinstance(v, list)), []) if isinstance(x, dict)]
    return []


def _n_words(t) -> int:
    if not isinstance(t, str):
        return 0
    m = CAPTION_META_RE.search(t)
    return int(m.group(1)) if m else len(WORD_RE.findall(t))


def harvest_file(data: Any, rel: str, rows: dict, iso=_iso_utc) -> None:
    """Append rows to `rows` (table name -> list of dicts) from one anonymised JSON file."""
    low = rel.lower()
    name = PurePosixPath(low).name
    for t in TABLES:
        rows.setdefault(t, [])
    items = _items_of(data)
    new_layout = bool(items) and "label_values" in items[0]

    def consumed(table, kind=None, extra=()):
        for it in items:
            if new_layout:
                f = lv_fields(it)
                o = lv_owner(f)
                m = lv_media(f)
                cap = _by_cat(m, "free_text")
                cap = cap if isinstance(cap, str) else ""
                row = {"author": o["username"], "author_name": o["name"],
                       "in_network": bool(PSEUDO_RE.fullmatch(o["username"] or "")),
                       "timestamp": iso(it.get("timestamp")), "n_words_caption": _n_words(cap),
                       "hashtags": " ".join(lv_hashtags(m))}
                for lab in ("Feedback", "Surface", "Source"):
                    if lab in extra:
                        v = f.get(lab)
                        row[lab.lower()] = v if isinstance(v, str) else ""
            else:
                o = _smd_by_cat(it, "username", "person_name", "business_or_app") or it.get("title", "")
                row = {"author": o, "author_name": "", "in_network": bool(PSEUDO_RE.fullmatch(o or "")),
                       "timestamp": iso(_old_when(it)), "n_words_caption": 0, "hashtags": ""}
            if kind:
                row["kind"] = kind
            rows[table].append(row)

    if name.startswith("followers"):
        for it in items:
            sl = (it.get("string_list_data") or [{}])[0]
            rows["followers"].append({"user": sl.get("value", ""), "timestamp": iso(sl.get("timestamp"))})
    elif name.startswith("following") and "hashtag" not in name:
        for it in items:
            sl = (it.get("string_list_data") or [{}])[0]
            rows["following"].append({"user": sl.get("value") or it.get("title", ""), "timestamp": iso(sl.get("timestamp"))})
    elif "follow_requests" in name or "pending_follow" in name:
        for it in items:
            if new_layout:
                u = _by_cat(lv_fields(it), "username")
            else:
                u = (it.get("string_list_data") or [{}])[0].get("value", "")
            rows["follow_requests"].append({"user": u if isinstance(u, str) else "",
                                            "direction": "received" if "received" in name else "sent",
                                            "timestamp": iso(it.get("timestamp") or _old_when(it))})
    elif "comments" in name and "liked" not in name:
        for it in items:
            text = _smd_by_cat(it, "free_text")
            owner = _smd_by_cat(it, "username", "person_name")
            rows["comments"].append({"on_post_by": owner, "timestamp": iso(_old_when(it)), "n_words": _n_words(text),
                                     "kind": "reel" if "reel" in name else "post", "text": text})
    elif "liked_posts" in name or "liked_comments" in name:
        consumed("likes", "comment" if "comment" in name else "post")
    elif "saved_posts" in name or (name.startswith("saved") and "collection" not in name):
        consumed("saved")
    elif "story_likes" in name:
        consumed("story_likes")
    elif "stories_viewed" in name:
        consumed("stories_viewed")
    elif "posts_viewed" in name:
        consumed("posts_viewed")
    elif "videos_watched" in name:
        consumed("videos_watched")
    elif "threads_viewed" in name:
        consumed("threads_viewed")
    elif name.startswith("ads_viewed") or name.startswith("ads_clicked"):
        consumed("ads_viewed", "clicked" if "clicked" in name else "viewed")
    elif "suggested_accounts" in name or "suggested_profiles" in name:
        consumed("suggested_accounts")
    elif name.startswith("posts_you") and "interested" in name:
        consumed("feedback", "post", extra=("Feedback", "Surface", "Source"))
        if "not_interested" in name and "interested_or" not in name:   # file without a Feedback label
            for r in rows["feedback"]:
                if not r.get("feedback"):
                    r["feedback"] = "Not interested"
    elif name.startswith("profiles_you") and "interested" in name:
        consumed("feedback", "profile")
        for r in rows["feedback"]:
            r.setdefault("feedback", "Not interested")
            r.setdefault("surface", "")
            r.setdefault("source", "")
    elif "advertisers_using" in name:
        for it in items:
            if new_layout:
                for lab, v in lv_fields(it).items():
                    if not isinstance(v, list):
                        continue
                    l = lab.lower()
                    how = ("tracked_you_on_their_site_or_app" if "interact" in l or "website" in l
                           else "uploaded_your_contact_details" if "upload" in l
                           else "store_visited" if "store" in l else lab)
                    for adv in v:
                        if isinstance(adv, str) and adv:
                            rows["advertisers"].append({"advertiser": adv, "how": how})
            else:
                rows["advertisers"].append({"advertiser": it.get("advertiser_name", ""),
                                            "how": "uploaded_your_contact_details" if it.get("has_data_file_custom_audience")
                                            else "tracked_you_on_their_site_or_app" if it.get("has_remarketing_custom_audience")
                                            else "store_visited" if it.get("has_in_person_store_visit") else "unknown"})
    elif ("off_meta" in low or "off_of_instagram" in low) and "settings" not in name:
        for it in items:
            app = it.get("name", "")
            for ev in it.get("events") or []:
                if isinstance(ev, dict):
                    rows["off_meta_activity"].append({"app_or_site": app, "event": ev.get("type", ""),
                                                      "timestamp": iso(ev.get("timestamp"))})
    elif any(x in name for x in ("your_topics", "ads_interests", "recommended_topics", "see_less_topics")):
        src = name.replace(".json", "")
        for it in items:
            if new_layout:
                for lab, v in lv_fields(it).items():
                    if isinstance(v, list):
                        for x in v:
                            t = (x.get("Name") or x.get("name") or x.get("Topic")) if isinstance(x, dict) else x
                            if isinstance(t, str) and t:
                                rows["topics"].append({"topic": t, "source": src})
            else:
                for v in _smd(it).values():
                    if isinstance(v, dict) and isinstance(v.get("value"), str) and v["value"]:
                        rows["topics"].append({"topic": v["value"], "source": src})
    elif "insights" in low:
        for it in items:
            sm = _smd(it)
            vals = {S._norm_key(k): (v.get("value") if isinstance(v, dict) else v) for k, v in sm.items()}
            ts = next((v.get("timestamp") for v in sm.values() if isinstance(v, dict) and v.get("timestamp")), None)
            thumb = (it.get("media_map_data") or {}).get("Media Thumbnail") or {}
            row = {"timestamp": iso(ts or thumb.get("creation_timestamp")), **vals}
            if name.startswith("posts"):
                rows["insights_posts"].append(row)
            elif name.startswith("stories"):
                rows["insights_stories"].append(row)
            else:
                rows["insights_summary"].append({"metric_set": name.replace(".json", ""), **row})
    elif (name.startswith("posts") and "viewed" not in name) or "archived_posts" in name or "recently_deleted" in name:
        if new_layout:
            return  # media/posts.json (new layout) duplicates posts_1.json, which carries the captions
        for it in items:
            media = it.get("media") or []
            m0 = media[0] if media and isinstance(media[0], dict) else {}
            cap = it.get("title") or m0.get("title", "") or ""
            rows["posts"].append({"timestamp": iso(it.get("creation_timestamp") or m0.get("creation_timestamp")),
                                  "n_media": len(media), "hashtags": " ".join(HASHTAG_RE.findall(cap)),
                                  "n_mentions": len(S.MENTION_RE.findall(cap)), "n_words": _n_words(cap), "caption": cap,
                                  "source": "archived" if "archived" in name else "deleted" if "deleted" in name else "posts"})
    elif name.startswith("stories") and "insights" not in low:
        for it in items:
            rows["stories"].append({"timestamp": iso(it.get("creation_timestamp")), "has_caption": bool(it.get("title"))})
    elif name.startswith("reels") and "comments" not in name:
        for it in items:
            media = it.get("media") or []
            m0 = media[0] if media and isinstance(media[0], dict) else {}
            rows["reels"].append({"timestamp": iso(it.get("creation_timestamp") or m0.get("creation_timestamp")),
                                  "caption": it.get("title") or m0.get("title", "") or ""})


def write_tables(rows: dict, out_dir) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for t, rs in rows.items():
        if not rs:
            continue
        cols: list = []
        for r in rs:
            for c in r:
                if c not in cols:
                    cols.append(c)
        with open(out / f"{t}.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(rs)
        written[t] = len(rs)
    return written


def tables_from_json(json_dir, out_dir) -> dict:
    """Re-derive the CSV tables (except messages/threads) from an anonymised json/ tree."""
    rows: dict = {}
    base = Path(json_dir)
    for f in sorted(base.rglob("*.json")):
        rel = f.relative_to(base).as_posix()
        if "/messages/" in rel or "/inbox/" in rel or "message_requests" in rel:
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        harvest_file(data, rel, rows)
    return write_tables(rows, out_dir)


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
    files_policy: str = "all"
    dropped: list = field(default_factory=list)          # (file, file_type)
    kept: list = field(default_factory=list)             # files written to the JSON tree
    counts: Counter = field(default_factory=Counter)     # what was transformed
    tables: dict = field(default_factory=dict)           # name -> number of rows
    n_people: int = 0
    pseudonymizer: Optional[Pseudonymizer] = None
    rescan: Optional[Any] = None                         # ig_pii_scan.Report of the output
    warnings: list = field(default_factory=list)
    unclassified: list = field(default_factory=list)     # kept files the scanner did not recognise
    kept_visible: set = field(default_factory=set)       # names kept visible on purpose: public accounts, businesses, topics
    public_accounts: set = field(default_factory=set)    # declared / detected public accounts that occurred

    def report(self) -> str:
        L = [f"Anonymisation report  -  {S._display_path(Path(self.source).name)}", "=" * 78,
             f"Output: {Path(self.out_dir).name}/   text policy: {self.text_policy}   platform data: {self.ads_policy}   files: {self.files_policy}   "
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
                               ("topics", "inferred interests / topic settings"), ("ads_viewed", "ads seen"),
                               ("posts_viewed", "posts seen"), ("videos_watched", "videos watched"),
                               ("threads_viewed", "Threads posts seen"),
                               ("suggested_accounts", "accounts suggested to you (pseudonymised)"),
                               ("feedback", "posts / profiles you marked (not) interesting")):
                n = self.tables.get(key)
                if n:
                    L.append(f"  {n:6,d}  {label}")
        if self.public_accounts:
            L += ["", f"PUBLIC ACCOUNTS KEPT VISIBLE ({len(self.public_accounts)}: declared in PUBLIC_ACCOUNTS or advertising)"]
            L.append("  " + ", ".join(sorted(self.public_accounts)))
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
                     if not re.fullmatch(r"(me|user_\w+|group_\w+)", p.value) and p.value.lower() not in self.kept_visible}
            L.append(f"  non-pseudonym names still present: {len(names)}"
                     + (f"  e.g. {[S.mask(n) for n in sorted(names)[:5]]} (masked; see pii_people.csv of a scan of the output)"
                        if names else "")
                     + (f"   (not counting {len(self.kept_visible)} public accounts / businesses kept on purpose)"
                        if self.kept_visible else ""))
        return "\n".join(L)


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def business_accounts(src: S._Source, scan: S.Report) -> set:
    """Usernames that advertise on the platform (ad owners and brand partners in ads_viewed / ads_clicked):
    businesses by construction, so their names may stay visible wherever they occur."""
    out: set = set()
    for fi in scan.files:
        if fi.kind != "json" or fi.error or not re.search(r"(^|/)ads_viewed|(^|/)ads_clicked", fi.rel_lower):
            continue
        try:
            data = json.loads(src.read(fi.rel).decode("utf-8"))
        except Exception:
            continue
        for it in _items_of(data):
            if not isinstance(it, dict):
                continue
            f = lv_fields(it) if "label_values" in it else {}
            for k, v in f.items():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    u = _by_cat(v[0], "username")
                    if isinstance(u, str) and u.strip():
                        out.add(S._fix(u).strip().lower())
            if not f:
                u = _smd_by_cat(it, "username")
                if isinstance(u, str) and u.strip():
                    out.add(S._fix(u).strip().lower())
    return out


def suggest_public(source, n: int = 40) -> list:
    """Accounts in your network whose content you liked / saved most often, with how many times:
    the ones that are public (brands, media, creators) can go into PUBLIC_ACCOUNTS so their names
    stay visible. Prints real usernames - run it on your own computer only."""
    src = S._Source(source)
    scan = S.scan(source)
    net = {x.lower() for x in scan.network}
    counts: Counter = Counter()
    for fi in scan.files:
        if fi.kind != "json" or fi.error or not re.search(r"liked_posts|saved_posts|story_likes|liked_comments", fi.rel_lower):
            continue
        try:
            data = json.loads(src.read(fi.rel).decode("utf-8"))
        except Exception:
            continue
        for it in _items_of(data):
            if not isinstance(it, dict):
                continue
            if "label_values" in it:
                u = lv_owner(lv_fields(it))["username"]
            else:
                u = _smd_by_cat(it, "username", "person_name") or it.get("title", "")
            u = S._fix(u).strip().lower() if isinstance(u, str) else ""
            if u and u in net:
                counts[u] += 1
    rows = counts.most_common(n)
    width = max((len(u) for u, _ in rows), default=10)
    print(f"{'account (in your network)':{width}}  likes/saves")
    for u, c in rows:
        print(f"{u:{width}}  {c}")
    print("\nCopy the PUBLIC ones (brands, media, creators, institutions) into PUBLIC_ACCOUNTS.")
    return rows


class _Anonymiser:
    def __init__(self, src: S._Source, scan: S.Report, out: Path, text: str, shift_days: int, seed: Optional[str],
                 ads: str = "keep", files: str = "all", public: Optional[set] = None):
        self.src, self.scan, self.out, self.text, self.shift, self.ads = src, scan, out, text, shift_days, ads
        self.files_policy = files
        self.public = set(public or ()) | (business_accounts(src, scan) if ads == "keep" else set())
        self.P = Pseudonymizer(scan.people, scan.self_names, seed, network=scan.network, public=self.public)
        self.res = Anonymised(str(src.path), str(out), text, shift_days, ads_policy=ads, pseudonymizer=self.P,
                              files_policy=files)
        self.counts = self.res.counts
        self.drop_types = ({"media_file"} if files == "all" else set(DROP_TYPES)) \
            | (PLATFORM_TYPES if ads == "drop" else set())
        self.strict_rels = {fi.rel for fi in scan.files if fi.file_type in STRICT_TYPES}
        # the owner's own captions / comments (not the captions of posts shown to them)
        self.own_text_rels = {fi.rel for fi in scan.files
                              if fi.file_type == "activity_content" and not CONSUMED_RE.search(fi.rel_lower)}
        self.network_known = bool(scan.network)
        if ads == "keep" and not self.network_known:
            self.res.warnings.append("No followers/following/DM files in this export, so it is impossible to tell "
                                     "which accounts in 'posts viewed' / 'videos watched' are public: all of them "
                                     "were pseudonymised.")
        self.rows: dict = {k: [] for k in TABLES}
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

    def caption_meta(self, s: str) -> str:
        """A caption or comment reduced to what it is about: hashtags, pseudonymised @mentions, and
        its size - '#rome #sunset @user_0012 [14 words, 2 emoji]'."""
        t = S._fix(s)
        tags = ["#" + h for h in HASHTAG_RE.findall(t)]
        mentions = [self.P.in_text("@" + m) for m in S.MENTION_RE.findall(t)]
        self.counts["captions/comments reduced to metadata"] += 1
        return " ".join(tags + mentions + [f"[{len(WORD_RE.findall(t))} words, {len(EMOJI_RE.findall(t))} emoji]"])

    def free_text(self, s: str) -> str:
        """Captions, comments, bios: keep, with pseudonyms, redaction and domain-only links."""
        t = S._fix(s)
        t = self.P.in_text(t)
        t = redact_patterns(t, self.counts)
        t = links_to_domains(t, self.counts)
        return t

    # -- generic JSON walk ---------------------------------------------------
    def walk(self, node: Any, rel: str, path: tuple = (), label: Optional[str] = None, block: str = "") -> Any:
        if isinstance(node, dict):
            names = S._field_name_keys(node)
            if "label" in names:
                label = node["label"]
            elif "title" in names and node["title"].strip():
                label = node["title"]
                block = node["title"].strip().lower()    # "Owner", "Place", "Hashtags", ...
            ab = self.author_block(node, rel, label)
            if ab is not None:
                return ab
            out = {}
            for k, v in node.items():
                lk = str(k).lower()
                if lk in EXIF_DROP or lk in DROP_KEYS:
                    self.counts["metadata fields removed (location/device/identifier)"] += 1
                    continue
                if k in names:
                    out[k] = v                      # a field name, never data
                    continue
                if isinstance(v, (dict, list)):
                    out[k] = self.walk(v, rel, path + (k,), label, block)
                    continue
                out[k] = self.scalar(k, v, rel, path, label, block)
            return out
        if isinstance(node, list):
            return [self.walk(v, rel, path + (i,), label, block) for i, v in enumerate(node)]
        return node

    def author_block(self, node: dict, rel: str, label: Optional[str]) -> Optional[dict]:
        """{"dict": [{"label": "URL"...}, {"label": "Name"...}, {"label": "Username"...}], "title": ""}
        describes one account; treat its three fields as a unit so that name, handle and link
        get the same treatment (kept visible for a public account, one pseudonym otherwise)."""
        ekey = "dict" if "dict" in node else "label_values"     # an item that *is* an account (suggested profiles)
        entries = node.get(ekey)
        if not isinstance(entries, list) or not entries or not all(isinstance(e, dict) and "label" in e for e in entries):
            return None
        labels = {S._norm_key(e.get("label", "")): i for i, e in enumerate(entries)}
        ukey = next((l for l in labels if S._match_key_rules(l) and S._match_key_rules(l)[0] == "username"), None)
        if ukey is None:
            return None
        if (label or "").strip().lower() in PLACE_TITLES:
            return None
        username = S._fix(entries[labels[ukey]].get("value") or "")
        public = bool(username) and self.network_known and bool(CONSUMED_RE.search(rel.lower())) \
            and self.P.visible(username)
        pseud = self.P(username) if username and not public else None
        out = []
        for e in entries:
            cat = S._match_key_rules(S._norm_key(e.get("label", "")))
            cat = cat[0] if cat else None
            ee = dict(e)
            if cat in ("username", "person_name"):
                if public:
                    self.res.kept_visible.add(S._fix(e.get("value") or "").strip().lower())
                else:
                    ee["value"] = pseud if e.get("value") else e.get("value")
                for hk in ("href",):
                    if hk in ee and ee[hk]:
                        ee[hk] = ee[hk] if public else "https://www.instagram.com/" + pseud
            elif cat == "url" or str(e.get("value", "")).lower().startswith("http"):
                if not public:
                    for hk in ("value", "href"):
                        if ee.get(hk):
                            ee[hk] = "https://www.instagram.com/" + pseud if S.IG_PROFILE_RE.search(ee[hk]) else self.link(ee[hk], rel)
            else:
                ee = self.walk(e, rel, (), label, "owner")
            out.append(ee)
        if public:
            self.counts["public accounts kept visible (content you consumed)"] += 1
        elif username:
            self.counts["accounts pseudonymised (content you consumed)" if CONSUMED_RE.search(rel.lower())
                        else "accounts pseudonymised"] += 1
        res = {}
        for k, v in node.items():
            if k == ekey:
                res[k] = out
            elif str(k).lower() in DROP_KEYS:
                self.counts["metadata fields removed (location/device/identifier)"] += 1
            elif isinstance(v, (dict, list)):
                res[k] = self.walk(v, rel, (k,), label, "owner")
            else:
                res[k] = self.scalar(k, v, rel, (), label, "owner")
        return res

    def scalar(self, k: str, v: Any, rel: str, path: tuple, label: Optional[str], block: str = "") -> Any:
        lk = str(k).lower()
        if lk in ("timestamp", "creation_timestamp", "taken_at", "time", "imported_time", "timestamp_value") \
                and isinstance(v, (int, float)):
            return self.ts(v)
        if lk.endswith("_ms") and isinstance(v, (int, float)):
            return self.ts(v, "ms")
        if not isinstance(v, str):
            return v
        sv = S._fix(v)
        if lk in MEDIA_KEYS or (lk == "href" and not sv.lower().startswith(("http://", "https://"))):
            self.counts["media references replaced"] += 1
            return "<media removed>" if sv else sv
        if lk == "href" or sv.lower().startswith(("http://", "https://")):
            return self.link(sv, rel)
        # which semantic key labels this value? (same logic as the scanner, including the
        # per-file overrides: "value" in a followers file is a username, "title" in likes too)
        ctx = [p for p in path if isinstance(p, str)] + [k]
        if label and lk in ("value", "timestamp_value"):
            ctx.append(label)
        cat, _sev, sem = S._classify_key(ctx, k, rel.lower())
        nsem = S._norm_key(sem)
        if lk == "thread_path" or nsem == "thread path":
            return self.out_rel(sv)
        low = rel.lower()
        if block in PLACE_TITLES:
            cat = "location_text"          # a place's name/description, not a person
        elif block in HASHTAG_TITLES:
            self.counts["hashtags / topics kept"] += 1
            return self.free_text(sv)      # "#brunch" is a topic word, kept; a name inside it is caught by the name pass
        if cat in ("username", "person_name", "profile_history"):
            if cat == "username" and CONSUMED_RE.search(low):
                # content you consumed: a private account's posts are only visible to followers, so an
                # author outside your network is a public account and may stay visible
                if self.network_known and self.P.visible(sv):
                    self.counts["public accounts kept visible (content you consumed)"] += 1
                    self.res.kept_visible.add(sv.strip().lower())
                    return sv
                self.counts["accounts pseudonymised (content you consumed)"] += 1
            return self.P(sv)
        if cat in ("business_or_app", "topic"):
            self.counts[f"{'business/app' if cat == 'business_or_app' else 'topic'} names kept"] += 1
            self.res.kept_visible.add(sv.strip().lower())
            return redact_patterns(sv, self.counts)
        if cat in ("email", "phone", "ip_address", "geo_coordinates", "date_of_birth", "contact_details",
                   "device_or_session", "location_text", "browsing_history", "gender", "identifier"):
            self.counts[f"fields removed ({cat})"] += 1
            return "[removed]"
        if cat == "url":
            return self.link(sv, rel)
        # everything else (captions, comments, and any string under a key we do not know) goes
        # through the full pass: pseudonyms for mentions/links/known names, pattern redaction, links
        if rel in self.strict_rels and sv.strip() and not SAFE_ENUM_RE.fullmatch(sv.strip()):
            self.counts["values removed (sensitive file, unknown field)"] += 1
            return "[removed]"
        if cat == "free_text" and sv.strip() and (self.text == "metadata"
                                                   or (self.text == "own" and rel not in self.own_text_rels)):
            return self.caption_meta(sv)   # captions of posts/stories shown to you, and your own ones
        return self.free_text(sv)

    def link(self, url: str, rel: str = "") -> str:
        if rel and PEOPLE_RE.search(rel.lower()):     # lists of people: a personal site identifies them
            self.counts["links removed (lists of people)"] += 1
            return "[removed]"
        m = S.IG_PROFILE_RE.search(url)
        if m:
            u = S._ig_user(m)
            if u:
                if rel and CONSUMED_RE.search(rel.lower()) and self.network_known and self.P.visible(u):
                    self.res.kept_visible.add(u.strip().lower())
                    return "https://www.instagram.com/" + u
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
        """Fill the tidy tables from the anonymised JSON of one file (see harvest_file)."""
        harvest_file(data, fi.rel, self.rows, self.iso)

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
                if self.files_policy != "all":
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
        self.res.tables = write_tables(self.rows, out / "csv")
        # pseudonym map (private) and report
        with open(out / "pseudonym_map.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["pseudonym", "real_value", "kind"])
            w.writeheader()
            w.writerows(self.P.rows())
        self.res.n_people = len(self.P.used - {"me"})
        self.res.public_accounts = set(self.P.public_seen)
        self.res.kept_visible |= self.P.public_seen
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
              seed: Optional[str] = None, rescan: bool = True, ads: str = "keep", files: str = "all",
              public=()) -> Anonymised:
    """Anonymise an export folder or .zip into out_dir. Returns an Anonymised result (see .report())."""
    if text not in TEXT_POLICIES:
        raise ValueError(f"text must be one of {TEXT_POLICIES}")
    if ads not in ADS_POLICIES:
        raise ValueError(f"ads must be one of {ADS_POLICIES}")
    if files not in FILES_POLICIES:
        raise ValueError(f"files must be one of {FILES_POLICIES}")
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
    anon = _Anonymiser(src, scan, Path(out_dir), text, shift, seed, ads=ads, files=files,
                       public={str(u).strip().lstrip("@").lower() for u in (public or ()) if str(u).strip()})
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
