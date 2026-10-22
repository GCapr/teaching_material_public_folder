#!/usr/bin/env python3
"""
ig_topics.py - describe what the posts you liked / saved were about, with a local model
=======================================================================================

Companion of ig_anonymise.py. The anonymised tables keep, for every like and save, the
author (pseudonymised when the account is in your network) and the caption's metadata -
but not what the post was about. This optional step asks a language model running on
YOUR computer (Ollama, https://ollama.com) for a short, generic topic per caption and adds
a `topic` column to likes.csv / saved.csv. The captions never leave your computer; only the
model's few-word answer, passed through the anonymiser's name pass, goes into the tables.

    from ig_topics import describe_likes
    describe_likes("export.zip", result)              # result = what anonymise() returned

Needs Ollama running locally with a model pulled, e.g.   ollama pull qwen2.5:3b
Running from JupyterLite (the browser) also needs Ollama to accept requests from the lab's
origin:  OLLAMA_ORIGINS="https://gcapr.github.io" ollama serve
"""
from __future__ import annotations

import collections
import csv
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Optional

try:
    import ig_pii_scan as S
    import ig_anonymise as A
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ig_pii_scan as S
    import ig_anonymise as A

DEFAULT_MODEL = "qwen2.5:3b"
DEFAULT_URL = "http://localhost:11434"
PROMPT = ("You label Instagram posts for a statistics class. Say in at most 6 words what the post is about, "
          "as a generic topic (for example: 'home-made pasta recipe', 'friends at a wedding', 'mountain hike', "
          "'political commentary', 'baby photos', 'fitness motivation'). Never include names of people, "
          "usernames, brands, companies, cities or places. Answer with the topic only.\n\nCaption:\n{caption}\n\nTopic:")
FILES_RE = re.compile(r"liked_posts|saved_posts")
COMMENT_FILES_RE = re.compile(r"(^|/)(post_comments|reels_comments|comments)[^/]*\.json$")
MAX_TOPIC_CHARS = 60
TONE_PROMPT = ("Classify the tone of this Instagram comment as exactly one word: positive, negative, neutral, "
               "or mixed. Answer with the word only.\n\nComment:\n{comment}\n\nTone:")
TONES = ("positive", "negative", "neutral", "mixed")
# offline fallback when no model is available: a small lexicon + emoji, Italian and English
_POS = {"bello", "bella", "bellissimo", "bellissima", "bravo", "brava", "bravi", "grazie", "complimenti", "stupendo",
        "stupenda", "meraviglioso", "meravigliosa", "fantastico", "fantastica", "adoro", "amo", "top", "wow",
        "auguri", "love", "lovely", "beautiful", "amazing", "great", "awesome", "congrats", "congratulations",
        "thanks", "thank", "perfect", "best", "cute", "gorgeous", "happy", "yes", "sì", "si", "😍", "❤", "❤️", "😂",
        "🤩", "👏", "🔥", "💕", "🥰", "😘", "🙌", "👍", "💪", "🎉", "😊", "🙏"}
_NEG = {"brutto", "brutta", "orribile", "schifo", "vergogna", "no", "mai", "peggio", "odio", "triste", "male",
        "terribile", "noioso", "bad", "worst", "hate", "sad", "awful", "terrible", "ugly", "boring", "wrong",
        "shame", "disgusting", "angry", "😡", "😠", "👎", "😢", "😭", "💔", "🤮", "😞"}


# offline topic categories: a few hundred keywords and hashtag stems, Italian and English
TOPIC_LEXICON = {
    "food & cooking": "food foodie recipe recipes ricetta ricette cucina cucinare cooking pasta pizza dolce dessert cake torta pane bread colazione breakfast pranzo lunch cena dinner vino wine birra beer caffè coffee ristorante restaurant chef vegan vegetarian homemade fattoincasa aperitivo brunch gelato cioccolato chocolate",
    "travel & places": "travel viaggio viaggi viaggiare trip wanderlust vacanza vacanze holiday holidays beach spiaggia mare sea island isola montagna mountain mountains hiking trekking escursione roma rome firenze florence milano milan venezia venice paris parigi london londra italia italy europe sunset tramonto landscape paesaggio city città borgo",
    "fitness & sport": "fitness workout gym palestra allenamento training running corsa run marathon maratona yoga pilates crossfit sport calcio football soccer tennis basket nuoto swim swimming bike bici cycling ciclismo ski sci climbing arrampicata healthy salute wellness benessere",
    "fashion & beauty": "fashion moda outfit ootd style stile look dress vestito shoes scarpe bag borsa makeup trucco beauty bellezza skincare hair capelli nails unghie jewelry gioielli vintage shopping",
    "home & design": "home casa interior interiors design arredamento furniture mobili decor decoration architecture architettura ristrutturazione renovation garden giardino plants piante kitchen bathroom bagno tiles ceramica wood legno craft handmade artigianato diy",
    "art & culture": "art arte artist artista painting pittura dipinto drawing disegno illustration illustrazione sculpture scultura museum museo mostra exhibition gallery galleria photography fotografia photo foto cinema film movie teatro theatre book books libro libri reading lettura poetry poesia history storia",
    "music": "music musica song canzone concert concerto live album band singer cantante piano guitar chitarra jazz rock pop opera dj festival playlist",
    "family & friends": "family famiglia friends amici amiche friend amico amica love amore wedding matrimonio sposi bride anniversary anniversario birthday compleanno auguri baby bimbo bimba neonato kids bambini figli mamma papà mom dad nonna grandma together insieme",
    "pets & animals": "dog cane cani puppy cat gatto gatti kitten pet pets animals animali horse cavallo bird uccello wildlife nature natura zoo",
    "humour & memes": "meme memes funny lol divertente ridere laugh haha joke battuta comedy satira sarcasm ironia",
    "news & politics": "news notizie politics politica government governo elezioni election vote voto parliament parlamento minister ministro president presidente war guerra peace pace protest manifestazione rights diritti climate clima economy economia inflation lavoro work strike sciopero europe eu ue",
    "science & education": "science scienza research ricerca study studio studiare university università phd professor lecture lezione school scuola students studenti learning education educazione data dati statistics economics space spazio nasa physics fisica math matematica biology medicine medicina health",
    "work & business": "work lavoro business startup entrepreneur imprenditore marketing career carriera office ufficio meeting conference conferenza linkedin brand company azienda product prodotto launch lancio sale saldi offer offerta discount sconto promo adv sponsored ad pubblicità",
    "motivation & wellbeing": "motivation motivazione mindset inspiration ispirazione quote citazione quotes grateful gratitude gratitudine mindfulness meditation meditazione mentalhealth salutementale selfcare therapy anxiety happiness felicità positive",
    "nature & outdoors": "nature natura forest foresta bosco lake lago river fiume flowers fiori flower fiore tree alberi sky cielo clouds nuvole snow neve autumn autunno spring primavera summer estate winter inverno sunrise alba stars stelle outdoor",
    "tech & gaming": "tech technology tecnologia ai artificialintelligence app software coding programming computer phone smartphone iphone gaming videogames videogiochi game console",
    "cars & motors": "car cars auto automobile moto motorcycle motorbike ferrari porsche bmw f1 formula1 motogp racing corsa engine motore",
    "faith & spirituality": "faith fede church chiesa prayer preghiera god dio pope papa gospel vangelo bible bibbia blessed benedetto spirituality spiritualità saint santo",
}
_TOPIC_INDEX = {w: cat for cat, words in TOPIC_LEXICON.items() for w in words.split()}


def topic_offline(caption: str, hashtags: str = "") -> str:
    """Best-matching topic category from caption words and hashtags; 'other' when nothing matches.
    No model, no network: runs anywhere, including in the browser."""
    toks = re.findall(r"[\w']+", (caption + " " + hashtags).lower())
    hits = collections.Counter()
    for t in toks:
        t = t.strip("'")
        cat = _TOPIC_INDEX.get(t)
        if cat is None and len(t) > 5:          # hashtag stems: #foodporn -> food, #travelgram -> travel
            cat = next((c for w, c in _TOPIC_INDEX.items() if len(w) >= 4 and t.startswith(w)), None)
        if cat:
            hits[cat] += 1
    return hits.most_common(1)[0][0] if hits else "other"


def tone_offline(text: str) -> str:
    """Rough tone from a word/emoji lexicon - used when no local model is available."""
    toks = re.findall(r"\w+|[^\w\s]", text.lower())
    pos = sum(t in _POS for t in toks)
    neg = sum(t in _NEG for t in toks)
    if pos and neg:
        return "mixed"
    if pos:
        return "positive"
    if neg:
        return "negative"
    return "neutral"


def _post_json(url: str, payload: dict, timeout: int = 120) -> dict:
    """POST JSON and return the JSON reply - with urllib on a computer, with a synchronous
    XMLHttpRequest inside Pyodide (JupyterLite)."""
    body = json.dumps(payload)
    try:
        import js  # type: ignore  # Pyodide only
        xhr = js.XMLHttpRequest.new()
        xhr.open("POST", url, False)
        xhr.setRequestHeader("Content-Type", "application/json")
        xhr.send(body)
        if int(xhr.status) != 200:
            raise RuntimeError(f"HTTP {xhr.status} from {url}: {str(xhr.responseText)[:200]}")
        return json.loads(str(xhr.responseText))
    except ImportError:
        req = urllib.request.Request(url, data=body.encode("utf-8"), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - local server chosen by the user
            return json.loads(resp.read().decode("utf-8"))


def ask(caption: str, model: str = DEFAULT_MODEL, url: str = DEFAULT_URL) -> str:
    reply = _post_json(url.rstrip("/") + "/api/generate",
                       {"model": model, "prompt": PROMPT.format(caption=caption[:1500]), "stream": False,
                        "options": {"temperature": 0, "num_predict": 24}})
    return str(reply.get("response", "")).strip()


def ask_tone(comment: str, model: str = DEFAULT_MODEL, url: str = DEFAULT_URL) -> str:
    reply = _post_json(url.rstrip("/") + "/api/generate",
                       {"model": model, "prompt": TONE_PROMPT.format(comment=comment[:800]), "stream": False,
                        "options": {"temperature": 0, "num_predict": 4}})
    word = re.sub(r"[^a-z]", "", str(reply.get("response", "")).strip().lower().split()[0] if reply.get("response") else "")
    return word if word in TONES else "neutral"


def _clean(topic: str, P: Optional[A.Pseudonymizer]) -> str:
    """One short line, no quotes, names pseudonymised and patterns redacted as everywhere else."""
    t = topic.splitlines()[0] if topic else ""
    t = t.strip().strip("\"'`*.:- ").rstrip(".")
    t = re.sub(r"^(topic|answer)\s*:\s*", "", t, flags=re.I)
    if P is not None:
        t = P.in_text(t)
    t = A.redact_patterns(t, A.Counter())
    t = A.links_to_domains(t, A.Counter())
    t = re.sub(r"\s+", " ", t)[:MAX_TOPIC_CHARS].strip()
    return t.lower()


def available(url: str = DEFAULT_URL, model: Optional[str] = None) -> bool:
    """Is Ollama reachable on this computer (and, if given, is the model pulled)? Works from a terminal
    and from the browser (JupyterLite); from the browser Ollama must have been started with
    OLLAMA_ORIGINS set to the lab's origin, otherwise this returns False and the lexicon is used."""
    try:
        if model:
            return bool(_post_json(url.rstrip("/") + "/api/show", {"model": model}, timeout=5))
        try:
            import js  # type: ignore  # Pyodide: a synchronous GET through the browser
            xhr = js.XMLHttpRequest.new()
            xhr.open("GET", url.rstrip("/") + "/api/tags", False)
            xhr.send()
            return int(xhr.status) == 200
        except ImportError:
            with urllib.request.urlopen(url.rstrip("/") + "/api/tags", timeout=5) as resp:
                return resp.status == 200
    except Exception:
        return False


def _captions(source) -> list:
    """(table, raw timestamp, caption) for every liked / saved post that has a caption."""
    src = S._Source(source)
    scan = S.scan(source)
    out = []
    for fi in scan.files:
        if fi.kind != "json" or fi.error or not FILES_RE.search(fi.rel_lower):
            continue
        table = "likes" if "liked" in fi.rel_lower else "saved"
        try:
            data = json.loads(src.read(fi.rel).decode("utf-8"))
        except Exception:
            continue
        for it in A._items_of(data):
            if not isinstance(it, dict):
                continue
            if "label_values" in it:
                f = A.lv_fields(it)
                cap = A._by_cat(A.lv_media(f), "free_text")
                ts = it.get("timestamp")
            else:
                cap = A._smd_by_cat(it, "free_text")
                ts = A._old_when(it)
            if isinstance(cap, str) and cap.strip() and ts:
                out.append((table, ts, S._fix(cap)))
    return out


def describe_likes(source, result: Optional[A.Anonymised] = None, out_dir: Optional[str] = None,
                   model: str = DEFAULT_MODEL, url: str = DEFAULT_URL, limit: Optional[int] = None,
                   offline: Optional[bool] = None, verbose: bool = True) -> dict:
    """Add a `topic` column to likes.csv and saved.csv in the anonymised output.

    source  - the raw export (folder or zip), read locally for the captions
    result  - the Anonymised object returned by anonymise(): gives the output folder, the
              timestamp shift and the pseudonymiser used to clean the model's answers
    limit   - stop after this many captions (try 20 first to see the speed of your machine)
    offline - True: classify with the built-in keyword lexicon (18 categories, no model needed);
              None (default): use the local model when Ollama answers, the lexicon otherwise
    Returns {"asked": n, "written": {"likes": n, "saved": n}, "skipped": n, "method": ...}.
    """
    if offline is None:
        offline = not available(url)
    out = Path(out_dir or (result.out_dir if result else "anonymised"))
    P = result.pseudonymizer if result else None
    shift = result.shift_days if result else 0
    iso = (lambda v: A._iso_utc(v + shift * 86400)) if shift else A._iso_utc
    items = _captions(source)
    if limit:
        items = items[:limit]
    if not items:
        print("No liked / saved posts with a caption found.")
        return {"asked": 0, "written": {}, "skipped": 0}
    topics: dict = {}
    skipped = 0
    for i, (table, ts, cap) in enumerate(items, 1):
        if offline:
            topics[(table, iso(ts))] = topic_offline(cap)
            continue
        try:
            t = _clean(ask(cap, model, url), P)
        except Exception as e:  # the model is optional: never fail the whole run
            skipped += 1
            if verbose and skipped <= 3:
                print(f"  could not get a topic ({type(e).__name__}: {e}); continuing")
            if skipped >= 5 and not topics:
                raise RuntimeError(f"Ollama does not answer at {url} (is it running? is the model pulled? "
                                   f"from the browser, was OLLAMA_ORIGINS set?)") from e
            continue
        if t:
            topics[(table, iso(ts))] = t
        if verbose and i % 25 == 0:
            print(f"  {i}/{len(items)} captions described")
    method = "lexicon (offline)" if offline else model
    written = {}
    for table in ("likes", "saved"):
        path = out / "csv" / f"{table}.csv"
        if not path.exists():
            continue
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
            fields = list(rows[0].keys()) if rows else []
        if not rows:
            continue
        if "topic" not in fields:
            fields.append("topic")
        n = 0
        for r in rows:
            t = topics.get((table, r.get("timestamp", "")))
            if t:
                r["topic"] = t
                n += 1
            else:
                r.setdefault("topic", "")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        written[table] = n
    if verbose:
        print(f"Described {len(topics)} posts by {method}; topics written: {written}; failed: {skipped}.")
        print("Topics:", dict(collections.Counter(topics.values()).most_common(10)))
        if not offline:
            print("Read the topic column before sharing: the model was told to stay generic, but check it did.")
    return {"asked": len(items), "written": written, "skipped": skipped, "method": method}


def _comments(source) -> list:
    """(raw timestamp, comment text) for every comment you wrote."""
    src = S._Source(source)
    scan = S.scan(source)
    out = []
    for fi in scan.files:
        if fi.kind != "json" or fi.error or not COMMENT_FILES_RE.search(fi.rel_lower) or "liked" in fi.rel_lower:
            continue
        try:
            data = json.loads(src.read(fi.rel).decode("utf-8"))
        except Exception:
            continue
        for it in A._items_of(data):
            if not isinstance(it, dict):
                continue
            if "label_values" in it:
                f = A.lv_fields(it)
                text, ts = A._by_cat(f, "free_text"), it.get("timestamp")
            else:
                text, ts = A._smd_by_cat(it, "free_text"), A._old_when(it)
            if isinstance(text, str) and text.strip() and ts:
                out.append((ts, S._fix(text)))
    return out


def tone_of_comments(source, result: Optional[A.Anonymised] = None, out_dir: Optional[str] = None,
                     model: str = DEFAULT_MODEL, url: str = DEFAULT_URL, offline: Optional[bool] = None,
                     verbose: bool = True) -> dict:
    """Add a `tone` column (positive / negative / neutral / mixed) to comments.csv.

    The comment text itself stays out of the tables. With Ollama running, the model classifies
    each comment; otherwise (offline=True, or when Ollama is not reachable) a small Italian/English
    word-and-emoji lexicon is used instead - cruder, but it needs nothing installed.
    """
    out = Path(out_dir or (result.out_dir if result else "anonymised"))
    shift = result.shift_days if result else 0
    iso = (lambda v: A._iso_utc(v + shift * 86400)) if shift else A._iso_utc
    items = _comments(source)
    if not items:
        print("No comments found.")
        return {"comments": 0, "written": 0, "method": None}
    if offline is None:
        offline = not available(url)
    tones: dict = {}
    for i, (ts, text) in enumerate(items, 1):
        if offline:
            t = tone_offline(text)
        else:
            try:
                t = ask_tone(text, model, url)
            except Exception:
                t = tone_offline(text)
        tones[iso(ts)] = t
        if verbose and not offline and i % 25 == 0:
            print(f"  {i}/{len(items)} comments classified")
    path = out / "csv" / "comments.csv"
    n = 0
    if path.exists():
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
            fields = list(rows[0].keys()) if rows else []
        if rows:
            if "tone" not in fields:
                fields.append("tone")
            for r in rows:
                t = tones.get(r.get("timestamp", ""))
                r["tone"] = t or r.get("tone", "")
                n += bool(t)
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=fields)
                w.writeheader()
                w.writerows(rows)
    method = "lexicon (offline)" if offline else model
    if verbose:
        from collections import Counter
        print(f"Tone of {len(tones)} comments by {method}: {dict(Counter(tones.values()))}; written to comments.csv: {n}")
    return {"comments": len(tones), "written": n, "method": method}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    ap.add_argument("source")
    ap.add_argument("--out", default="anonymised")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--limit", type=int)
    a = ap.parse_args()
    describe_likes(a.source, out_dir=a.out, model=a.model, url=a.url, limit=a.limit)
    tone_of_comments(a.source, out_dir=a.out, model=a.model, url=a.url)
