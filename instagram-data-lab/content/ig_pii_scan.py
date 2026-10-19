#!/usr/bin/env python3
"""
ig_pii_scan.py - inventory the personal data inside an Instagram data export
============================================================================

Point it at the folder or the .zip you got from Meta's "Download your
information" (ask for the JSON format; HTML exports work too, but only with
pattern matching). It reads every file and tells you which kinds of personal
data are where, whose they are (yours vs. other people's), and what to do with
each file before the data is shared or analysed.

Standard library only, so this same file runs on a laptop, inside JupyterLite /
Pyodide / marimo-WASM in a browser tab, or on a server. It never uploads
anything: it reads the export and writes report files only where you ask it to.

Command line
    python ig_pii_scan.py EXPORT_DIR_OR_ZIP                       # masked summary on screen
    python ig_pii_scan.py EXPORT_DIR_OR_ZIP -o report             # + csv/markdown report files
    python ig_pii_scan.py EXPORT_DIR_OR_ZIP -o report --no-values # report files without raw values
    python ig_pii_scan.py EXPORT_DIR_OR_ZIP --scan-media          # also open photos for EXIF tags (needs Pillow)

Notebook (JupyterLite, Jupyter, marimo, Colab...)
    from ig_pii_scan import scan
    r = scan("instagram-export.zip")       # or a folder
    print(r.summary())                     # masked examples only - safe on a projector
    r.findings                             # list of Finding objects, full values
    r.to_dataframe()                       # pandas DataFrame (if pandas is installed)
    r.write("report")                      # pii_findings.csv, pii_people.csv, pii_files.csv, pii_summary.md

What it looks for
    by file      known export files (login history, synced contacts, devices, ...) are
                 classified and given a suggested action: DROP / PSEUDONYMIZE / REDACT / REVIEW
    by key       fields named Email, Phone Number, IP Address, latitude, User Agent, Name,
                 sender_name, participants, Media Owner, City Name, Date of Birth, ...
    by pattern   emails, phone numbers, IPv4/IPv6, coordinate pairs, street addresses,
                 card numbers (Luhn-checked), @mentions, instagram.com/<user> links
    by name list every username / display name found in the structured files is then
                 searched for inside free text (DMs, captions, comments, bios)
    in paths     the export folder name and the DM thread folders contain usernames
    in photos    EXIF GPS / camera tags (optional, --scan-media)

What it cannot do
    Recognise names of people who are not in your network (there is no NER model),
    see what is inside images (faces, screenshots), or judge context. Treat free
    text as "review or drop", never as "clean because nothing was flagged".
"""
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterator, Optional

__version__ = "0.1.0"
__all__ = ["scan", "Report", "Finding", "FileInfo", "Person", "mask"]

SEVERITY_RANK = {"high": 0, "medium": 1, "review": 2, "low": 3}
NAME_CATEGORIES = {"username", "person_name", "name_in_text"}

# ---------------------------------------------------------------------------
# 1. Knowledge about the export layout - edit these tables as Meta changes it
# ---------------------------------------------------------------------------

# Matched in order against the lower-cased relative path (forward slashes).
# First match wins, so the most distinctive folders come first.
FILE_RULES = [
    # (regex on path, file_type, severity, suggested action, what the file holds)
    (r"message_requests|secret_conversations|(^|/)messages/|(^|/)inbox/",
     "private_messages", "high",
     "REDACT message text, PSEUDONYMIZE participants, DROP attachments",
     "Other people's messages (they never consented), their names, shared links, photos, reactions."),
    (r"synced_contacts|contacts_contact",
     "address_book", "high", "DROP",
     "Names, phone numbers and emails from your phone's address book: third parties, many not on Instagram."),
    (r"security_and_login|login_activity|logout_activity|signup_details|password_change|"
     r"login_and_profile|account_privacy|two_factor|recovery|login_information",
     "security_log", "high", "DROP",
     "IP addresses, user agents, cookie names, login timestamps."),
    (r"device_information|devices\.json|camera_information",
     "device_info", "high", "DROP",
     "Device identifiers, user agents, camera models."),
    (r"last_known_location|account_based_in|profile_based_in|locations_of_interest|location",
     "location", "high", "DROP",
     "Inferred home city / coordinates."),
    (r"possible_phone|possible_email|autofill|contact_info",
     "contact_details", "high", "DROP",
     "Phone numbers, emails or addresses Meta associates with you."),
    (r"personal_information\.(json|html?)|account_information|instagram_profile_information|"
     r"profile_changes|personal_information/personal_information",
     "identity", "high", "DROP, or keep only non-identifying fields",
     "Name, username, email, phone, birthday, gender, bio, previous usernames."),
    (r"advertisers_using|off_meta|off_of_instagram|apps_and_websites|link_history|ads_and_businesses|"
     r"ads_and_topics|your_topics|ads_viewed|posts_viewed|videos_watched|ads_about|subscription|information_about_you",
     "off_platform_activity", "medium", "DROP (or keep aggregate counts only)",
     "Businesses that uploaded your data, apps/sites that reported your activity, links you opened, inferred interests."),
    (r"followers|following|close_friends|blocked|pending_follow|unfollowed|restricted|muted|hide_story|"
     r"favorite|follow_requests|removed_suggestions|relationships|(^|/)connections/",
     "social_graph", "medium", "PSEUDONYMIZE usernames",
     "Usernames of other people."),
    (r"comments|likes|saved|story_sticker|polls|questions|quizzes|emoji_slider|countdown|reels|posts|stories|"
     r"archived|recently_deleted|profile_photos|(^|/)content/|your_instagram_activity|events|fundraisers|"
     r"shopping|monetization|threads|avatar|notes|(^|/)media/",
     "activity_content", "review", "PSEUDONYMIZE usernames, STRIP exif, REVIEW free text",
     "Captions, comments, the usernames you interacted with; EXIF coordinates on posts."),
    (r"preferences|settings",
     "settings", "low", "keep or drop",
     "App settings; usually no identifiers, but check."),
]

MEDIA_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp", ".tif", ".tiff",
             ".mp4", ".mov", ".m4v", ".webm", ".avi", ".mp3", ".m4a", ".wav", ".aac", ".ogg"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".heic", ".heif"}

# JSON keys that carry no meaning of their own; the parent key is the real label.
GENERIC_KEYS = {"value", "string_map_data", "string_list_data", "media_map_data", "media_list_data",
                "data", "media", "string_data", "timestamp", "items", "vec", "label_values", "dict"}

# Leaf-key overrides, decided by where the file lives (the same key means different
# things in different files: "title" is a caption in posts, a username in likes,
# the other person's name in a DM thread). Evaluated before KEY_RULES.
KEY_OVERRIDES = [
    # (regex on path, regex on the leaf key, category, severity)
    (r"(^|/)messages/|(^|/)inbox/|message_requests|secret_conversations", r"^title$", "person_name", "medium"),
    (r"likes|liked|saved", r"^title$", "username", "medium"),
    (r"followers|following|close_friends|blocked|pending|unfollowed|restricted|muted|favorite|"
     r"hide_story|follow_requests|removed_suggestions|relationships", r"^(title|value)$", "username", "medium"),
    (r"off_meta|off_of_instagram|apps_and_websites|advertisers|your_topics|ads_and_businesses",
     r"^(name|title|value|advertiser_name)$", "business_or_app", "medium"),
    (r"link_history", r"^(href|url|value)$", "browsing_history", "medium"),
    (r"profile_changes", r"^(previous value|new value)$", "profile_history", "medium"),
    (r".", r"^title$", "free_text", "review"),
]

# Generic key rules, matched against the normalised key ("Phone_Number" -> "phone number").
# Order matters: the first match wins.
KEY_RULES = [
    (r"\be-?mail", "email", "high"),
    (r"\bphone|\bmobile\b|\btel\b|\bwhatsapp\b", "phone", "high"),
    (r"\bip\b", "ip_address", "high"),
    (r"latitude|longitude|\blat\b|\blng\b|\blon\b|coordinate", "geo_coordinates", "high"),
    (r"\bbirth|\bdob\b", "date_of_birth", "high"),
    (r"\bgender\b|\bpronoun", "gender", "medium"),
    (r"\bcontact\b", "contact_details", "high"),
    (r"user agent|\bdevice|\bcookie|app version|\bimei\b|\bserial\b|\bmac address|\bbrowser\b|\bplatform\b",
     "device_or_session", "medium"),
    (r"advertiser|\bbusiness\b|\bapp\b|\bbrand\b|\bmerchant\b|\bshop\b|\bstore\b", "business_or_app", "medium"),
    (r"\bcity\b|location|\baddress\b|\bplace\b|\bcountry\b|\bregion\b|\bzip\b|\bpostal\b|\bstate\b|\bhometown\b",
     "location_text", "medium"),
    (r"user ?name|media owner|\bauthor\b|\bowner\b|\bhandle\b|\bcreator\b|\bmentioned\b|\btagged\b|"
     r"\baccount name\b|thread path", "username", "medium"),
    (r"\bname\b|\bparticipant|\bactor\b|\bsender\b|\brecipient\b", "person_name", "medium"),
    (r"\bbio\b|content|caption|comment|\btext\b|message|question|answer|\bnote|description|\btitle\b|"
     r"\bstatus\b|\breply|\bbody\b|\bsubject\b", "free_text", "review"),
    (r"\bhref\b|\burl\b|\blink\b|website|\buri\b", "url", "low"),
]

_KEY_OVERRIDES = [(re.compile(p, re.I), re.compile(k, re.I), c, s) for p, k, c, s in KEY_OVERRIDES]
_KEY_RULES = [(re.compile(p), c, s) for p, c, s in KEY_RULES]

# ---------------------------------------------------------------------------
# 2. Value patterns
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}")
URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`)\]]+", re.I)
IP4_CAND_RE = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
IP6_CAND_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:]{2,45}(?![\w:.])")
COORD_PAIR_RE = re.compile(r"(?<![\d.-])-?\d{1,2}\.\d{3,}\s*,\s*-?\d{1,3}\.\d{3,}(?![\d.])")
CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
PHONE_RE = re.compile(
    r"(?<![\w.+-])(?:\+\d{8,15}|(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?|\d{2,4}[\s.-])(?:\d{2,4}[\s.-]?){1,3}\d{2,4})"
    r"(?![\w:-])")
DATE_IN_RE = re.compile(r"\d{4}[-./]\d{1,2}[-./]\d{1,2}|\d{1,2}[-./]\d{1,2}[-./]\d{2,4}")
ADDRESS_RE = re.compile(
    r"\b\d{1,5}[A-Za-z]?\s+(?:[A-Z][A-Za-z'.-]*\s){1,3}"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Square|Sq|"
    r"Terrace|Ter|Parkway|Pkwy|Highway|Hwy)\b\.?"
    r"|\b[A-ZÄÖÜ][\w'.-]*(?:straße|strasse|gasse|weg|platz|allee)\s+\d{1,5}[A-Za-z]?\b"
    r"|\b(?:Rue|Via|Calle|Avenida|Rua|Piazza|Viale|Corso)\s+(?:[\w'-]+\s){1,4}\d{1,5}[A-Za-z]?\b")
MENTION_RE = re.compile(r"(?<![\w.@/])@([A-Za-z0-9_](?:[A-Za-z0-9_.]{0,28}[A-Za-z0-9_])?)")
IG_PROFILE_RE = re.compile(r"instagram\.com/([A-Za-z0-9_.]+)(?:/([A-Za-z0-9_.]+))?", re.I)
IG_RESERVED = {"p", "reel", "reels", "tv", "igtv", "explore", "accounts", "direct", "stories", "s", "share",
               "static", "about", "developer", "legal", "privacy", "terms", "press", "api", "web", "challenge",
               "ar", "guide", "guides", "emails", "locations", "sessions", "n", "www", "help", "oauth", "embed"}
TOKEN_RE = re.compile(r"[\w.]+")
ROOT_RE = re.compile(r"^instagram-([A-Za-z0-9_.]+)-\d{4}-\d{2}-\d{2}", re.I)
THREAD_RE = re.compile(r"^(.+?)_\d{6,}$")

STOP_NAMES = {"instagram", "instagram user", "user", "facebook", "meta", "unknown", "deleted", "admin",
              "anonymous", "username", "name", "participant", "instagram.com", "www.instagram.com"}
_BORING = {"", "true", "false", "none", "null", "n/a", "na", "unknown", "-", "--", "0", "on", "off", "yes", "no"}
USERNAME_LIKE_RE = re.compile(r"[A-Za-z0-9_.]{2,30}")


# ---------------------------------------------------------------------------
# 3. Small helpers
# ---------------------------------------------------------------------------

def _fix(s: str) -> str:
    """Undo Instagram's encoding quirk: UTF-8 bytes written as one \\u00XX escape each."""
    try:
        return s.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def _norm_key(k: str) -> str:
    return re.sub(r"[_\-]+", " ", str(k)).strip().lower()


def _boring(s: str) -> bool:
    t = s.strip()
    if t.lower() in _BORING:
        return True
    return not re.search(r"[A-Za-z0-9À-￿]", t)


def _path_str(path: tuple) -> str:
    out = []
    for p in path:
        out.append(f"[{p}]" if isinstance(p, int) else (f".{p}" if out else str(p)))
    return "".join(out)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _looks_like_card(s: str) -> bool:
    digits = re.sub(r"\D", "", s)
    if not 13 <= len(digits) <= 19 or len(set(digits)) < 2 or DATE_IN_RE.search(s):
        return False
    groups = [len(g) for g in re.split(r"[ -]+", s.strip())]
    if len(groups) > 1:  # 4-4-4-4(-3), or Amex 4-6-5
        regular = all(g == 4 for g in groups[:-1]) and 1 <= groups[-1] <= 4
        if not regular and groups not in ([4, 6, 5], [4, 6, 4]):
            return False
    elif len(digits) not in (15, 16):
        return False
    return _luhn(digits)


def _looks_like_phone(s: str) -> bool:
    digits = re.sub(r"\D", "", s)
    if not 7 <= len(digits) <= 15 or DATE_IN_RE.search(s):
        return False
    seps = len(re.findall(r"[\s.()-]", s))
    return s.startswith("+") or "(" in s or seps >= 2 or (seps >= 1 and len(digits) >= 9)


def _ig_user(m: "re.Match") -> Optional[str]:
    first, second = m.group(1), m.group(2)
    f = first.lower().strip(".")
    if f in IG_RESERVED:
        if f == "stories" and second and second.lower() not in IG_RESERVED and not second.isdigit():
            return second.strip(".")
        return None
    if len(f) < 2 or f.isdigit():
        return None
    return first.strip(".")


def _display_path(rel: str) -> str:
    """A path with the usernames that Instagram puts into folder names masked out."""
    parts = rel.replace("\\", "/").split("/")
    out = []
    for i, p in enumerate(parts):
        m = ROOT_RE.match(p)
        if m:
            p = p.replace(m.group(1), mask(m.group(1), "username"), 1)
        elif i > 0 and parts[i - 1] in ("inbox", "message_requests", "archived_threads", "filtered_threads"):
            tm = THREAD_RE.match(p)
            if tm:
                p = mask(tm.group(1), "person_name") + "_..."
        out.append(p)
    return "/".join(out)


def mask(value: Any, category: str = "") -> str:
    """A masked rendering that is safe to show on a shared screen."""
    v = str(value)
    if category == "email" and "@" in v:
        local, _, dom = v.rpartition("@")
        tld = dom.rsplit(".", 1)[-1] if "." in dom else ""
        return f"{local[:1]}***@{dom[:1]}***.{tld}"
    if category == "phone":
        d = re.sub(r"\D", "", v)
        return "***" + d[-2:]
    if category == "card_number":
        d = re.sub(r"\D", "", v)
        return "**** **** **** " + d[-4:]
    if category == "ip_address":
        return (v.split(":")[0] + ":****:****") if ":" in v else (v.split(".")[0] + ".*.*.*")
    if category == "geo_coordinates":
        return "<coordinates>"
    if category == "date_of_birth":
        return "<date>"
    if category in ("url", "browsing_history") or v.lower().startswith(("http://", "https://")):
        m = re.match(r"(https?://[^/]+)", v, re.I)
        return (m.group(1) if m else v[:12]) + "/..."
    if len(v) <= 1:
        return "*"
    return v[0] + "*" * min(len(v) - 1, 7)


# ---------------------------------------------------------------------------
# 4. Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str      # high | medium | review | low
    category: str      # email, phone, ip_address, username, person_name, name_in_text, ...
    file: str          # path inside the export
    file_type: str     # from FILE_RULES
    location: str      # JSON path, HTML chunk, EXIF tag, or folder name
    key: str           # the field label that led here
    value: str         # the raw value (never printed by summary())
    masked: str        # safe rendering
    subject: str = ""  # self | other | "" (not a person)
    method: str = ""   # key | pattern | url | mention | name_list | path | exif


@dataclass
class FileInfo:
    rel: str
    size: int
    kind: str          # json | html | media | other
    file_type: str
    severity: str
    action: str
    note: str
    ext: str = ""
    error: str = ""
    n_leaves: int = 0
    key_counts: Counter = field(default_factory=Counter)   # category -> number of fields (incl. free_text, url)
    findings: Counter = field(default_factory=Counter)     # category -> number of findings

    @property
    def rel_lower(self) -> str:
        return self.rel.lower()


@dataclass
class Person:
    value: str
    kind: str          # username | person_name
    subject: str       # self | other
    count: int = 0


# ---------------------------------------------------------------------------
# 5. The report
# ---------------------------------------------------------------------------

@dataclass
class Report:
    source: str
    root_name: str = ""
    files: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    people: dict = field(default_factory=dict)       # lower-cased value -> Person
    self_names: set = field(default_factory=set)
    media: Counter = field(default_factory=Counter)
    formats: Counter = field(default_factory=Counter)
    notes: list = field(default_factory=list)

    # -- building -----------------------------------------------------------
    def add(self, f: Finding, fi: Optional[FileInfo] = None) -> None:
        self.findings.append(f)
        if fi is not None:
            fi.findings[f.category] += 1

    def remember(self, value: str, kind: str, subject: Optional[str] = None) -> None:
        v = value.strip()
        if len(v) < 2 or _boring(v):
            return
        k = v.lower()
        p = self.people.get(k)
        if p is None:
            p = Person(v, kind, subject or "other")
            self.people[k] = p
        p.count += 1
        if subject == "self":
            p.subject = "self"
            self.self_names.add(k)

    def subject_of(self, value: str) -> str:
        return "self" if value.strip().lower() in self.self_names else "other"

    # -- reading ------------------------------------------------------------
    def category_table(self, max_examples: int = 3) -> list:
        groups: dict = {}
        for f in self.findings:
            g = groups.setdefault(f.category, {"category": f.category, "severity": f.severity,
                                               "occurrences": 0, "unique": set(), "examples": []})
            g["occurrences"] += 1
            g["unique"].add(f.value.lower())
            if SEVERITY_RANK[f.severity] < SEVERITY_RANK[g["severity"]]:
                g["severity"] = f.severity
            if f.masked not in g["examples"] and len(g["examples"]) < max_examples:
                g["examples"].append(f.masked)
        rows = [{**g, "unique": len(g["unique"]), "examples": ", ".join(g["examples"])} for g in groups.values()]
        rows.sort(key=lambda r: (SEVERITY_RANK[r["severity"]], -r["occurrences"]))
        return rows

    def file_rows(self) -> list:
        rows = []
        for fi in self.files:
            n = sum(fi.findings.values())
            if n == 0 and (fi.kind in ("media", "other") or fi.severity == "low"):
                continue
            rows.append(fi)
        rows.sort(key=lambda fi: (SEVERITY_RANK.get(fi.severity, 9), -sum(fi.findings.values()), fi.rel))
        return rows

    def summary(self, max_examples: int = 3, max_files: int = 60) -> str:
        L = [f"Instagram export scan  -  {_display_path(self.source)}", "=" * 78]
        fmt = ", ".join(f"{n} {k}" for k, n in self.formats.most_common())
        n_media = sum(self.media.values())
        media_s = f"; media files: {n_media}"
        if n_media:
            media_s += " (" + ", ".join(f"{n} {e}" for e, n in self.media.most_common(5)) + ")"
        L.append(f"Files: {len(self.files)} ({fmt}){media_s}")
        n_self = sum(1 for p in self.people.values() if p.subject == "self")
        L.append(f"People referenced (unique usernames / display names): you = {n_self}, "
                 f"other people = {len(self.people) - n_self:,}")
        L.append(f"Findings: {len(self.findings):,} occurrences in {sum(1 for fi in self.files if fi.findings):,} files")
        for note in self.notes:
            L.append(f"  ! {note}")

        L += ["", "BY CATEGORY                            occurrences / unique   masked examples", "-" * 78]
        for r in self.category_table(max_examples):
            L.append(f"{r['severity'].upper():7} {r['category']:22} {r['occurrences']:>9,} / {r['unique']:<7,} {r['examples']}")
        ft = sum(fi.key_counts.get("free_text", 0) for fi in self.files)
        urls = sum(fi.key_counts.get("url", 0) for fi in self.files)
        ms = sum(fi.key_counts.get("messages_from_self", 0) for fi in self.files)
        mo = sum(fi.key_counts.get("messages_from_others", 0) for fi in self.files)
        L.append(f"{'':7} {'(free-text fields)':22} {ft:>9,}           captions, comments, bios, DM text: "
                 f"listed above only where a pattern matched")
        L.append(f"{'':7} {'(links)':22} {urls:>9,}")
        if ms or mo:
            L.append(f"{'':7} {'(DM messages)':22} {ms + mo:>9,}           {ms:,} sent by you, {mo:,} by other people")

        L += ["", "BY FILE  (most sensitive first;  type -> suggested action | what was found)", "-" * 78]
        rows = self.file_rows()
        for fi in rows[:max_files]:
            found = ", ".join(f"{c} {n:,}" for c, n in fi.findings.most_common(6)) or "nothing flagged"
            extras = []
            if fi.key_counts.get("free_text"):
                extras.append(f"free text {fi.key_counts['free_text']:,}")
            if fi.key_counts.get("messages_from_others"):
                extras.append(f"msgs by others {fi.key_counts['messages_from_others']:,}")
            if fi.error:
                extras.append(f"ERROR {fi.error}")
            L.append(f"[{fi.severity.upper()}] {_display_path(fi.rel)}")
            L.append(f"        {fi.file_type} -> {fi.action} | {found}" + (f" | {'; '.join(extras)}" if extras else ""))
        rest = len(rows) - min(len(rows), max_files)
        quiet = len(self.files) - len(rows)
        if rest:
            L.append(f"... and {rest} more files with findings (see pii_files.csv)")
        if quiet:
            L.append(f"({quiet} other files: media, settings or nothing flagged)")
        return "\n".join(L)

    def to_dataframe(self):
        import pandas as pd  # optional
        return pd.DataFrame([asdict(f) for f in self.findings])

    def write(self, out_dir: str, include_values: bool = True) -> list:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        written = []
        cols = ["severity", "category", "subject", "file", "file_type", "location", "key", "method", "masked"]
        if include_values:
            cols.append("value")
        p = out / "pii_findings.csv"
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for f in sorted(self.findings, key=lambda f: (SEVERITY_RANK[f.severity], f.category, f.file)):
                w.writerow(asdict(f))
        written.append(p)

        p = out / "pii_files.csv"
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["file", "kind", "file_type", "severity", "suggested_action", "bytes", "findings",
                        "free_text_fields", "links", "messages_from_self", "messages_from_others", "note", "error"])
            for fi in sorted(self.files, key=lambda fi: (SEVERITY_RANK.get(fi.severity, 9), fi.rel)):
                w.writerow([fi.rel, fi.kind, fi.file_type, fi.severity, fi.action, fi.size,
                            "; ".join(f"{c}={n}" for c, n in fi.findings.most_common()),
                            fi.key_counts.get("free_text", 0), fi.key_counts.get("url", 0),
                            fi.key_counts.get("messages_from_self", 0), fi.key_counts.get("messages_from_others", 0),
                            fi.note, fi.error])
        written.append(p)

        if include_values:
            p = out / "pii_people.csv"
            with open(p, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["value", "kind", "subject", "occurrences"])
                for person in sorted(self.people.values(), key=lambda x: (x.subject != "self", -x.count, x.value.lower())):
                    w.writerow([person.value, person.kind, person.subject, person.count])
            written.append(p)

        p = out / "pii_summary.md"
        p.write_text("# Instagram export - personal data inventory\n\n```\n" + self.summary() + "\n```\n", encoding="utf-8")
        written.append(p)
        return written


# ---------------------------------------------------------------------------
# 6. Reading the export (folder or zip)
# ---------------------------------------------------------------------------

class _Source:
    def __init__(self, path):
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(path)
        self.path = p
        self.zf = None
        if p.is_file():
            if not zipfile.is_zipfile(p):
                raise ValueError(f"{path} is neither a folder nor a .zip file")
            self.zf = zipfile.ZipFile(p)
        self.root_name = p.name

    def entries(self) -> Iterator[tuple]:
        if self.zf is not None:
            for info in self.zf.infolist():
                if not info.is_dir():
                    yield info.filename, info.file_size
        else:
            for f in sorted(self.path.rglob("*")):
                if f.is_file():
                    yield f.relative_to(self.path).as_posix(), f.stat().st_size

    def read(self, rel: str) -> bytes:
        if self.zf is not None:
            return self.zf.read(rel)
        return (self.path / rel).read_bytes()


def _classify_file(rel: str, size: int) -> FileInfo:
    low = rel.lower()
    ext = Path(low).suffix
    if ext in MEDIA_EXT:
        return FileInfo(rel, size, "media", "media_file", "review",
                        "EXCLUDE from the shared dataset (faces, places); keep counts/timestamps only",
                        "Photos and videos of you and other people; may carry EXIF location/device tags.", ext)
    kind = "json" if ext == ".json" else "html" if ext in (".html", ".htm") else "other"
    for pat, ftype, sev, action, note in FILE_RULES:
        if re.search(pat, low):
            return FileInfo(rel, size, kind, ftype, sev, action, note, ext)
    return FileInfo(rel, size, kind, "other", "low", "REVIEW", "Not a known export file - check by hand.", ext)


def _load_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# 7. Classifying keys and walking JSON
# ---------------------------------------------------------------------------

def _match_key_rules(nk: str):
    for rx, cat, sev in _KEY_RULES:
        if rx.search(nk):
            return cat, sev
    return None


def _classify_key(ctx_keys: list, leaf_key: str, rel_lower: str):
    """-> (category, severity, semantic_key); category is None when no rule applies.

    The semantic key is the nearest key that carries meaning: for
    string_map_data["IP Address"]["value"] it is "IP Address", not "value".
    """
    sem = leaf_key
    for k in reversed(ctx_keys):
        if k.lower() not in GENERIC_KEYS:
            sem = k
            break
    nl, ns = _norm_key(leaf_key), _norm_key(sem)
    for prx, krx, cat, sev in _KEY_OVERRIDES:
        if (krx.search(nl) or krx.search(ns)) and prx.search(rel_lower):
            return cat, sev, sem
    hit = _match_key_rules(ns)
    return (hit[0], hit[1], sem) if hit else (None, None, sem)


def _iter_leaves(node: Any, path: tuple = (), label: Optional[str] = None) -> Iterator[tuple]:
    """Yield (path, value, label, sibling_text) for every scalar, dict by dict.

    `label` is the nearest enclosing {"label": ..., "value"/"vec": ...} label, which
    newer exports use instead of a named key.
    """
    if isinstance(node, dict):
        if isinstance(node.get("label"), str):
            label = node["label"]
        leaves = [(k, v) for k, v in node.items() if not isinstance(v, (dict, list))]
        sib = " ".join(_fix(v).lower() for _, v in leaves if isinstance(v, str))
        for k, v in leaves:
            yield path + (k,), v, (label if k == "value" else None), sib
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                yield from _iter_leaves(v, path + (k,), label)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _iter_leaves(v, path + (i,), label)
    else:
        yield path, node, None, ""


def _context(path: tuple, label: Optional[str]) -> tuple:
    ctx = [p for p in path if isinstance(p, str)]
    if label:
        ctx.append(label)
    leaf_key = path[-1] if path and isinstance(path[-1], str) else ""
    return ctx, leaf_key


# ---------------------------------------------------------------------------
# 8. Name list matcher (names harvested from the export, searched in free text)
# ---------------------------------------------------------------------------

def _words(value: str) -> list:
    return [w.strip(".") for w in TOKEN_RE.findall(value.lower()) if w.strip(".")]


class _NameMatcher:
    def __init__(self, people: dict):
        self.table: dict = {}
        for p in people.values():
            if p.value.lower() in STOP_NAMES:
                continue
            words = _words(p.value)
            if not words:
                continue
            joined = "".join(words)
            if len(words) == 1 and (len(joined) < 5 or joined.isdigit()):
                continue
            self.table.setdefault(tuple(words), p)
            if len(words) > 1 and len(words[0]) >= 5 and words[0] not in STOP_NAMES:
                self.table.setdefault((words[0],), p)
        self.maxn = max((len(k) for k in self.table), default=0)

    def find(self, text: str) -> list:
        if not self.table:
            return []
        toks = [(m.start(), m.end(), m.group().lower().strip(".")) for m in TOKEN_RE.finditer(text)]
        toks = [t for t in toks if t[2]]
        out, i = [], 0
        while i < len(toks):
            step = 1
            for n in range(min(self.maxn, len(toks) - i), 0, -1):
                key = tuple(t[2] for t in toks[i:i + n])
                if key in self.table:
                    out.append((toks[i][0], toks[i + n - 1][1], self.table[key]))
                    step = n
                    break
            i += step
        return out


# ---------------------------------------------------------------------------
# 9. Scanning
# ---------------------------------------------------------------------------

def _pattern_findings(text: str, key_cat: Optional[str], fi: FileInfo, loc: str, key: str,
                      rep: Report, matcher: _NameMatcher, sibling_text: str) -> list:
    claimed: list = []
    out: list = []
    contact_field = key_cat in ("phone", "email", "contact_details")

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e in claimed)

    def emit(cat: str, sev: str, val: str, a: int, b: int, method: str = "pattern", subject: str = "") -> None:
        claimed.append((a, b))
        if key_cat == cat and val.strip().lower() == text.strip().lower():
            return  # the whole field was already reported through its key
        out.append(Finding(sev, cat, fi.rel, fi.file_type, loc, key, val, mask(val, cat), subject, method))

    for m in EMAIL_RE.finditer(text):
        emit("email", "high", m.group(), *m.span())
    for m in URL_RE.finditer(text):
        a, b = m.span()
        if not free(a, b):
            continue
        claimed.append((a, b))
        url = m.group().rstrip(".,;:!?)]}'\"")
        pm = IG_PROFILE_RE.search(url)
        user = _ig_user(pm) if pm else None
        if user and not (key_cat == "url" and user.lower() in sibling_text):
            out.append(Finding("medium", "username", fi.rel, fi.file_type, loc, key, user,
                               mask(user, "username"), rep.subject_of(user), "url"))
        elif key_cat != "url":
            fi.key_counts["url"] += 1
    for m in IP4_CAND_RE.finditer(text):
        a, b = m.span()
        if free(a, b) and _is_ip(m.group()):
            emit("ip_address", "high", m.group(), a, b)
    for m in IP6_CAND_RE.finditer(text):
        a, b = m.span()
        c = m.group()
        if c.count(":") >= 2 and free(a, b) and _is_ip(c):
            emit("ip_address", "high", c, a, b)
    for m in COORD_PAIR_RE.finditer(text):
        a, b = m.span()
        if free(a, b):
            emit("geo_coordinates", "high", m.group(), a, b)
    for m in CARD_RE.finditer(text):
        a, b = m.span()
        if free(a, b) and _looks_like_card(m.group()):
            emit("card_number", "high", m.group(), a, b)
    for m in PHONE_RE.finditer(text):
        a, b = m.span()
        if free(a, b) and _looks_like_phone(m.group()):
            emit("phone", "high" if contact_field else "medium", m.group(), a, b)
    for m in ADDRESS_RE.finditer(text):
        a, b = m.span()
        if free(a, b):
            emit("street_address", "medium", m.group(), a, b)
    for m in MENTION_RE.finditer(text):
        a, b = m.span()
        if free(a, b):
            emit("username", "medium", m.group(1), a, b, "mention", rep.subject_of(m.group(1)))
    if key_cat not in NAME_CATEGORIES and key_cat != "profile_history":
        for a, b, person in matcher.find(text):
            if free(a, b):
                emit("name_in_text", "review", person.value, a, b, "name_list", person.subject)
    return out


def _harvest_json(data: Any, fi: FileInfo, rep: Report) -> None:
    """Pass 1: collect every username / display name, and learn which ones are yours."""
    for path, val, label, _sib in _iter_leaves(data):
        if not isinstance(val, str):
            continue
        ctx, leaf_key = _context(path, label)
        cat, _sev, _k = _classify_key(ctx, leaf_key, fi.rel_lower)
        if cat not in ("username", "person_name", "profile_history"):
            continue
        v = _fix(val).strip()
        if _boring(v) or v.startswith("inbox/"):
            continue
        if cat == "profile_history":  # previous usernames / names; skip old bios
            if not (USERNAME_LIKE_RE.fullmatch(v) or (len(v) <= 40 and len(v.split()) <= 4)):
                continue
            cat = "username" if USERNAME_LIKE_RE.fullmatch(v) else "person_name"
        subject = None
        if fi.file_type == "identity" or (fi.file_type == "security_log" and cat == "username"):
            subject = "self"
        rep.remember(v, cat, subject)


def _scan_json(data: Any, fi: FileInfo, rep: Report, matcher: _NameMatcher) -> None:
    """Pass 2: report findings field by field."""
    for path, val, label, sib in _iter_leaves(data):
        if val is None or isinstance(val, bool):
            continue
        fi.n_leaves += 1
        ctx, leaf_key = _context(path, label)
        if leaf_key == "sender_name" and isinstance(val, str):
            s = _fix(val).strip().lower()
            fi.key_counts["messages_from_self" if s in rep.self_names else "messages_from_others"] += 1
        cat, sev, skey = _classify_key(ctx, leaf_key, fi.rel_lower)
        sval = _fix(val) if isinstance(val, str) else None
        text = sval if sval is not None else str(val)
        loc = _path_str(path)
        if cat == "url":
            if sval is None or not sval.lower().startswith(("http://", "https://")):
                fi.key_counts["media_reference"] += 1
                continue  # a path to a media file inside the export, not a link
            fi.key_counts["url"] += 1
        elif cat and not _boring(text):
            fi.key_counts[cat] += 1
        if _norm_key(skey) == "thread path" and sval:  # "inbox/<name>_<digits>" -> the other person's name
            tm = THREAD_RE.match(sval.rsplit("/", 1)[-1])
            if tm:
                rep.add(Finding("medium", "person_name", fi.rel, fi.file_type, loc, skey, tm.group(1),
                                mask(tm.group(1), "person_name"), rep.subject_of(tm.group(1)), "key"), fi)
            continue
        pattern_hits = _pattern_findings(sval, cat, fi, loc, skey or leaf_key, rep, matcher, sib) \
            if sval and len(sval) >= 3 else []
        if cat and cat not in ("url", "free_text") and not _boring(text):
            whole = any(f.value.strip().lower() == text.strip().lower() for f in pattern_hits)
            if not (cat == "contact_details" and whole):  # the pattern already says email/phone
                subj = rep.subject_of(text) if cat in NAME_CATEGORIES else ""
                rep.add(Finding(sev, cat, fi.rel, fi.file_type, loc, skey, text, mask(text, cat), subj, "key"), fi)
        for f in pattern_hits:
            rep.add(f, fi)


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.chunks: list = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        for k, v in attrs:
            if k == "href" and v:
                self.chunks.append(("href", v))

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            t = data.strip()
            if t:
                self.chunks.append(("text", t))


def _harvest_html(text: str, fi: FileInfo, rep: Report) -> list:
    p = _TextExtractor()
    p.feed(text)
    chunks = p.chunks
    for i, (kind, t) in enumerate(chunks):
        if kind != "text" or len(t) > 40 or i + 1 >= len(chunks) or chunks[i + 1][0] != "text":
            continue
        hit = _match_key_rules(_norm_key(t))
        if hit and hit[0] in ("username", "person_name"):
            v = chunks[i + 1][1]
            if not _boring(v):
                rep.remember(v, hit[0], "self" if fi.file_type == "identity" else None)
    return chunks


def _scan_html(chunks: list, fi: FileInfo, rep: Report, matcher: _NameMatcher) -> None:
    labelled: dict = {}
    for i, (kind, t) in enumerate(chunks):
        if kind == "href":
            if t.lower().startswith(("http://", "https://")):
                fi.key_counts["url"] += 1
                for f in _pattern_findings(t, "url", fi, f"href#{i}", "href", rep, matcher, ""):
                    rep.add(f, fi)
            continue
        fi.n_leaves += 1
        if len(t) > 60:
            fi.key_counts["free_text"] += 1
        if len(t) <= 40 and i + 1 < len(chunks) and chunks[i + 1][0] == "text":
            hit = _match_key_rules(_norm_key(t))
            if hit and hit[0] not in ("free_text", "url"):
                v = chunks[i + 1][1]
                if not _boring(v):
                    subj = rep.subject_of(v) if hit[0] in NAME_CATEGORIES else ""
                    rep.add(Finding(hit[1], hit[0], fi.rel, fi.file_type, f"text#{i + 1}", t, v,
                                    mask(v, hit[0]), subj, "key"), fi)
                    labelled[i + 1] = hit[0]
        for f in _pattern_findings(t, labelled.get(i), fi, f"text#{i}", "", rep, matcher, ""):
            rep.add(f, fi)


def _scan_paths(rep: Report) -> None:
    seen: set = set()
    for rel in [rep.root_name] + [fi.rel for fi in rep.files]:
        parts = rel.split("/")
        for idx, part in enumerate(parts):
            m = ROOT_RE.match(part)
            if m and ("root", m.group(1).lower()) not in seen:
                seen.add(("root", m.group(1).lower()))
                rep.remember(m.group(1), "username", "self")
                rep.add(Finding("medium", "username", "/".join(parts[:idx + 1]), "path", "folder name",
                                "export folder", m.group(1), mask(m.group(1), "username"), "self", "path"))
                rep.notes.append("The export folder/zip name itself contains your username.")
            if idx > 0 and parts[idx - 1] in ("inbox", "message_requests", "archived_threads", "filtered_threads"):
                tm = THREAD_RE.match(part)
                if tm and ("thread", part) not in seen:
                    seen.add(("thread", part))
                    rep.add(Finding("medium", "person_name", "/".join(parts[:idx + 1]), "private_messages",
                                    "folder name", "thread folder", tm.group(1), mask(tm.group(1), "person_name"),
                                    "other", "path"))


def _scan_exif(src: _Source, fi: FileInfo, rep: Report) -> bool:
    try:
        from PIL import Image  # optional dependency
    except ImportError:
        return False
    if fi.ext not in IMAGE_EXT:
        return True
    try:
        img = Image.open(io.BytesIO(src.read(fi.rel)))
        exif = img.getexif()
    except Exception:
        return True
    if not exif:
        return True
    gps = {}
    try:
        gps = dict(exif.get_ifd(0x8825))
    except Exception:
        pass
    if gps and (2 in gps or 4 in gps):
        rep.add(Finding("high", "geo_coordinates", fi.rel, fi.file_type, "EXIF:GPSInfo", "GPSInfo",
                        str({k: str(v) for k, v in gps.items()}), "<coordinates>", "", "exif"), fi)
    for tag, name in ((271, "Make"), (272, "Model"), (305, "Software")):
        v = exif.get(tag)
        if v and str(v).strip():
            rep.add(Finding("medium", "device_or_session", fi.rel, fi.file_type, f"EXIF:{name}", name,
                            str(v).strip(), mask(str(v).strip()), "", "exif"), fi)
    return True


def scan(source, scan_media: bool = False) -> Report:
    """Scan an export folder or .zip and return a Report (nothing is written or uploaded)."""
    src = _Source(source)
    rep = Report(source=str(source), root_name=src.root_name)
    parsed: list = []
    for rel, size in src.entries():
        fi = _classify_file(rel, size)
        rep.files.append(fi)
        rep.formats[fi.kind] += 1
        if fi.kind == "json":
            try:
                data = _load_json(src.read(rel))
            except Exception as e:  # not valid JSON - still worth listing
                fi.error = f"could not parse: {e}"
                continue
            parsed.append((fi, data))
            _harvest_json(data, fi, rep)
        elif fi.kind == "html":
            try:
                chunks = _harvest_html(src.read(rel).decode("utf-8", "replace"), fi, rep)
            except Exception as e:
                fi.error = f"could not parse: {e}"
                continue
            parsed.append((fi, chunks))
    _scan_paths(rep)

    if rep.formats.get("html") and not rep.formats.get("json"):
        rep.notes.append("HTML export: only pattern matching was possible. Request the JSON format for a full inventory.")
    if not rep.self_names:
        rep.notes.append("No personal_information file found, so your own name/username could not be told apart: "
                         "everyone is listed as 'other'.")

    matcher = _NameMatcher(rep.people)
    for fi, data in parsed:
        if fi.kind == "json":
            _scan_json(data, fi, rep, matcher)
        else:
            _scan_html(data, fi, rep, matcher)

    exif_ok = True
    for fi in rep.files:
        if fi.kind == "media":
            rep.media[fi.ext] += 1
            if scan_media and exif_ok:
                exif_ok = _scan_exif(src, fi, rep)
    if rep.media:
        if not scan_media:
            rep.notes.append(f"{sum(rep.media.values())} media files were not opened; rerun with --scan-media "
                             "(needs Pillow) to check EXIF location/device tags.")
        elif not exif_ok:
            rep.notes.append("Pillow is not installed, so photos were counted but their EXIF tags were not checked.")
    return rep


# ---------------------------------------------------------------------------
# 10. Command line
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Inventory the personal data inside an Instagram data export.")
    ap.add_argument("source", help="export folder or .zip file")
    ap.add_argument("-o", "--out", help="directory for pii_findings.csv, pii_files.csv, pii_people.csv, pii_summary.md")
    ap.add_argument("--no-values", action="store_true",
                    help="write masked values only (for shared screens or when the report leaves your machine)")
    ap.add_argument("--scan-media", action="store_true", help="open photos and check EXIF tags (needs Pillow)")
    ap.add_argument("--examples", type=int, default=3, help="masked examples per category in the summary")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    rep = scan(a.source, scan_media=a.scan_media)
    print(rep.summary(a.examples))
    if a.out:
        print("\nWritten:")
        for p in rep.write(a.out, include_values=not a.no_values):
            print("  ", p)
        if not a.no_values:
            print("  (pii_findings.csv and pii_people.csv contain the raw values - keep them with the export)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
