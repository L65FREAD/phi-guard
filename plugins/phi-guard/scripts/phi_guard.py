#!/usr/bin/env python3
"""Claude Code UserPromptSubmit hook: block prompts containing likely PHI.

If PHI is found, the prompt is rejected (exit 2) so it never reaches the model,
and a scrubbed copy is printed and placed on the clipboard for resending.

False positives: add a regex per line to ~/.claude/phi-guard-allowlist.txt
(matched case-insensitively against the whole flagged text).

Skip for one session: start Claude Code with PHI_GUARD=off.
"""
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

ALLOWLIST_PATH = os.path.expanduser("~/.claude/phi-guard-allowlist.txt")

MONTH = (
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|"
    r"Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?"
)
NUMERIC_DATE = r"\d{1,2}[/.-]\d{1,2}[/.-](?:\d{4}|\d{2})"
ISO_DATE = r"(?:19|20)\d{2}-\d{1,2}-\d{1,2}"
WORD_DATE = rf"(?:{MONTH}\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}|\d{{1,2}}(?:st|nd|rd|th)?\s+{MONTH},?\s+\d{{4}})"
YEAR_FIRST_DATE = r"(?:19|20)\d{2}/\d{1,2}/\d{1,2}"
ANY_DATE = rf"(?:{ISO_DATE}|{YEAR_FIRST_DATE}|{NUMERIC_DATE}|{WORD_DATE})"

NAME = r"[A-Z][a-z]+(?:[-'][A-Z]?[a-z]+)?"
FULL_NAME = rf"{NAME}(?:\s+[A-Z]\b\.?)?(?:\s+{NAME}){{0,2}}"
# Common first names, minus ones that double as ordinary words (Will, Mark, Grant...).
FIRST_NAMES = (
    "James|John|Robert|Michael|William|David|Richard|Joseph|Thomas|Charles|Christopher|"
    "Daniel|Matthew|Anthony|Donald|Steven|Paul|Andrew|Joshua|Kenneth|Kevin|Brian|George|"
    "Edward|Ronald|Timothy|Jason|Jeffrey|Ryan|Jacob|Gary|Nicholas|Eric|Jonathan|Stephen|"
    "Larry|Justin|Scott|Brandon|Benjamin|Samuel|Gregory|Alexander|Patrick|Raymond|Dennis|"
    "Jerry|Tyler|Aaron|Jose|Adam|Nathan|Henry|Douglas|Zachary|Peter|Kyle|Walter|Ethan|"
    "Jeremy|Harold|Keith|Roger|Gerald|Carl|Terry|Sean|Arthur|Lawrence|Jesse|Dylan|Bryan|"
    "Joe|Billy|Bruce|Albert|Willie|Gabriel|Logan|Alan|Juan|Wayne|Roy|Ralph|Randy|Eugene|"
    "Vincent|Russell|Louis|Bobby|Philip|Johnny|Carlos|Luis|Miguel|Jorge|Pedro|Noah|Liam|"
    "Lucas|Elijah|Oliver|Mary|Patricia|Jennifer|Linda|Elizabeth|Barbara|Susan|Jessica|"
    "Sarah|Karen|Nancy|Lisa|Betty|Margaret|Sandra|Ashley|Kimberly|Emily|Donna|Michelle|"
    "Dorothy|Amanda|Melissa|Deborah|Stephanie|Rebecca|Sharon|Laura|Cynthia|Kathleen|Amy|"
    "Shirley|Angela|Helen|Anna|Brenda|Pamela|Nicole|Emma|Samantha|Katherine|Christine|"
    "Debra|Rachel|Catherine|Carolyn|Janet|Ruth|Maria|Heather|Diane|Julie|Joyce|Victoria|"
    "Olivia|Kelly|Christina|Lauren|Joan|Evelyn|Judith|Megan|Cheryl|Andrea|Hannah|Martha|"
    "Jacqueline|Frances|Gloria|Ann|Teresa|Kathryn|Sara|Janice|Jean|Alice|Abigail|Julia|"
    "Judy|Sophia|Denise|Marilyn|Beverly|Danielle|Theresa|Diana|Natalie|Brittany|"
    "Charlotte|Marie|Kayla|Alexis|Lori|Rosa|Ana|Carmen|Isabella|Mia|Ava"
)
DATE_LEAD = r"\s*[,;:(|\u2013-]*\s*(?:(?i:dob|d\.o\.b\.?|born|birth ?date|date of birth)\s*[:=]?\s*)?"
STREET_SUFFIX = (
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|"
    r"Place|Pl|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Terrace|Ter|Trail|Trl)"
)

# Capitalized words that follow "patient"/"name" in ordinary dev talk, not names.
NOT_NAMES = {
    "portal", "record", "records", "table", "tables", "model", "models", "id", "ids",
    "data", "info", "service", "services", "schema", "api", "list", "lists", "name",
    "names", "profile", "profiles", "search", "screen", "view", "form", "field",
    "fields", "object", "type", "types", "controller", "endpoint", "page", "card",
    "detail", "details", "lookup", "sync", "import", "export", "queue", "status",
    "the", "a", "an", "is", "was", "has", "and", "or", "not", "null", "none", "true",
    "false", "string", "error", "column", "key", "value", "component", "module",
    "last", "updated", "created", "modified", "released", "date", "due", "on", "since",
    "until", "from", "effective", "expires", "expired", "version", "build", "started",
    "ended", "completed", "scheduled", "posted", "published", "as", "of", "by", "at",
    "in", "to", "for", "with", "this", "that", "these", "those", "it", "we", "i",
}

# (label, pattern, group to redact). Earlier entries win when matches overlap.
DETECTORS = [
    ("SSN", re.compile(r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])"), 0),
    ("SSN", re.compile(r"(?i)\b(?:ssn|social(?: security)?(?: number| no\.?| #)?)\s*[:#=]?\s*(\d{9})\b"), 1),
    ("DOB", re.compile(rf"(?i)\b(?:dob|d\.o\.b\.?|date of birth|birth ?date|birthday|born(?: on)?)\s*[:=]?\s*({ANY_DATE})"), 1),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"), 0),
    ("MRN", re.compile(r"(?i)\b(?:mrn|medical record(?: number| no\.?| #)?|patient ?id|pt ?id|chart(?: number| no\.?| #))\s*[:#=]?\s*([A-Z0-9][A-Z0-9-]{3,})"), 1),
    ("RX#", re.compile(r"(?i)\b(?:rx|prescription|script)\s*(?:number|num|no\.?|#)?\s*[:#=]?\s*(\d{5,})\b"), 1),
    ("MEMBER_ID", re.compile(r"(?i)\b(?:member ?id|subscriber ?id|insurance ?id|policy(?: number| no\.?| #)|group(?: number| no\.?| #))\s*[:#=]?\s*([A-Z0-9][A-Z0-9-]{4,})"), 1),
    ("PHONE", re.compile(r"(?<![\w.+-])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\w-])"), 0),
    ("PHONE", re.compile(r"(?<![\w.])\+1\d{10}(?!\d)"), 0),
    ("PHONE", re.compile(r"(?i)\b(?:phone|cell|mobile|tel|telephone|fax|callback)(?: number| no\.?| #)?\s*[:#=]?\s*(\d{10})\b"), 1),
    ("DATE", re.compile(rf"(?<![\w/.-])\d{{1,2}}/\d{{1,2}}/(?:\d{{4}}|\d{{2}})(?![\w/-])"), 0),
    ("DATE", re.compile(rf"(?<![\w/.-]){YEAR_FIRST_DATE}(?![\w/-])"), 0),
    ("DATE", re.compile(r"(?<![\w/.-])(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01])(?![\w-]|\.\w|\s+\d{1,2}:\d{2})"), 0),
    ("DATE", re.compile(rf"\b{WORD_DATE}"), 0),
    ("ADDRESS", re.compile(rf"\b\d{{1,6}}\s+(?:[NSEW]\.?\s+)?(?:[A-Z0-9][A-Za-z0-9.'-]*\s+){{1,4}}{STREET_SUFFIX}\b\.?(?:,?\s+(?:Apt|Apartment|Suite|Ste|Unit|#)\.?\s*[A-Za-z0-9-]+)?"), 0),
    ("ADDRESS", re.compile(r"(?i)\bP\.?\s?O\.?\s+Box\s+\d+"), 0),
    ("NAME", re.compile(rf"\b(?:[Pp]atient|PATIENT|[Pp]t|[Mm]ember|[Ss]ubscriber|[Cc]aregiver|[Gg]uarantor)(?:'s)?(?:\s+(?:[Nn]ame|is|named|called))?\s*[:=]?\s+({FULL_NAME})"), 1),
    ("NAME", re.compile(rf"\b({NAME}(?:\s+[A-Z]\b\.?)?(?:\s+{NAME}){{1,2}})(?={DATE_LEAD}{ANY_DATE})"), 1),
    ("NAME", re.compile(rf"\b({NAME},\s+{NAME}(?:\s+[A-Z]\b\.?)?)(?={DATE_LEAD}{ANY_DATE})"), 1),
    ("NAME", re.compile(rf"{ANY_DATE}\s*[,;:)|\u2013-]*\s*({NAME}(?:\s+[A-Z]\b\.?)?(?:\s+{NAME}){{1,2}})"), 1),
    ("NAME", re.compile(rf"\b((?:{FIRST_NAMES})\s+(?:[A-Z]\b\.?\s+)?{NAME})"), 1),
    ("NAME", re.compile(rf"\b(?:Mr|Mrs|Ms|Miss|Mx)\.?\s+({FULL_NAME})"), 1),
    ("NAME", re.compile(rf"(?i:\b(?:first|last|full|patient|pt)?[ _]?name)\s*[:=]\s*[\"']?({FULL_NAME})"), 1),
]


def load_allowlist():
    patterns = []
    try:
        with open(ALLOWLIST_PATH) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        patterns.append(re.compile(line, re.IGNORECASE))
                    except re.error:
                        patterns.append(re.compile(re.escape(line), re.IGNORECASE))
    except FileNotFoundError:
        pass
    return patterns


def find_phi(text):
    allow = load_allowlist()
    spans = []
    for label, pattern, group in DETECTORS:
        for m in pattern.finditer(text):
            start, end = m.span(group)
            value = text[start:end]
            if label == "NAME":
                # Drop trailing/leading ordinary words ("Patient Portal", "Patient Record ID").
                words = value.split()
                while words and words[-1].lower().strip(".,") in NOT_NAMES:
                    words.pop()
                if not words or any(w.lower().strip(".,") in NOT_NAMES for w in words):
                    continue
                value = " ".join(words)
                end = start + len(value)
            if any(p.fullmatch(value) for p in allow):
                continue
            if any(start < e and s < end for s, e, _ in spans):
                continue
            spans.append((start, end, label))
    return sorted(spans)


def scrub(text, spans):
    out, pos = [], 0
    for start, end, label in spans:
        out.append(text[pos:start])
        out.append(f"[{label}]")
        pos = end
    out.append(text[pos:])
    return "".join(out)


def copy_to_clipboard(text):
    if os.environ.get("PHI_GUARD_NO_CLIPBOARD"):
        return False
    if sys.platform == "darwin":
        candidates = [(["pbcopy"], "utf-8")]
    elif sys.platform.startswith("win"):
        candidates = [(["clip"], "utf-16")]
    else:
        candidates = [(["wl-copy"], "utf-8"), (["xclip", "-selection", "clipboard"], "utf-8"), (["xsel", "--clipboard", "--input"], "utf-8")]
    for cmd, encoding in candidates:
        if not shutil.which(cmd[0]):
            continue
        try:
            subprocess.run(cmd, input=text.encode(encoding), check=True, timeout=5)
            return True
        except Exception:
            continue
    return False


def main():
    if os.environ.get("PHI_GUARD", "").strip().lower() in {"off", "0", "false", "no"}:
        return 0
    prompt = json.load(sys.stdin).get("prompt", "")
    if not isinstance(prompt, str) or not prompt:
        return 0
    spans = find_phi(prompt)
    if not spans:
        return 0

    scrubbed = scrub(prompt, spans)
    copied = copy_to_clipboard(scrubbed)
    counts = Counter(label for _, _, label in spans)
    summary = ", ".join(f"{n} {label}" for label, n in counts.most_common())
    lines = [
        f"PHI guard blocked this message ({summary}). Nothing was sent.",
        "Scrubbed version" + (" (copied to clipboard, paste to resend):" if copied else ":"),
        "",
        scrubbed,
        "",
        f"False positive? Add a regex line to {ALLOWLIST_PATH}",
    ]
    print("\n".join(lines), file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # fail closed: a broken guard must not let PHI through
        print(
            f"PHI guard failed ({type(exc).__name__}: {exc}); message blocked to be safe. "
            "Disable the phi-guard plugin in /plugin, or start Claude Code with PHI_GUARD=off, to get unblocked.",
            file=sys.stderr,
        )
        sys.exit(2)
