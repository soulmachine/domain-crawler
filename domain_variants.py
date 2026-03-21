"""
Domain Name Variant Generator

Given an English root word, generates startup-style domain name variants
using common naming patterns (e.g., clue → cluely, cluify, getcluely, etc.)
"""

import argparse
from pathlib import Path
from typing import Optional

_stopwords_file = Path(__file__).parent / "stopwords-en" / "stopwords-en.txt"
STOPWORDS = {
    line.strip().lower()
    for line in _stopwords_file.read_text(encoding="utf-8").splitlines()
    if line.strip().isalpha()
}

VOWELS = set("aeiou")

# Common suffixes used by startups, ordered by popularity
SUFFIXES = [
    "ly",       # grammarly, calendly, cluely, optimizely
    "ify",      # shopify, spotify, expensify, healthify
    "fy",       # shopfy, wakefy
    "able",     # reachable, teachable
    "er",       # docker, buffer, tinder
    "io",       # rubio, cheerio (as name suffix, not TLD)
    "al",       # removal, signal
    "ous",      # luminous
    "ist",      # todoist
    "ity",      # electricity → pattern: "choosarity"
    "ize",      # authorize
    "sy",       # etsy-style
    "in",       # plugin-style
    "os",       # kudos-style
    "ia",       # trivia-style
    "ry",       # foundry-style
]

# Common prefixes
PREFIXES = [
    "get",      # getballoon.com
    "go",       # godaddy
    "use",      # usehover.com
    "try",      # trysomething.com
    "my",       # myspace
    "on",       # onboard
    "the",      # theskimm
    "hello",    # helloyumi.com
    "hi",       # hichat
    "join",     # joinslack
    "be",       # behance
    "un",       # unsplash
    "re",       # rethink
    "all",      # allbirds-style
    "super",    # superhuman
    "hyper",    # hyperloop
    "open",     # openai
    "smart",    # smartsheet
]

# Popular TLD-based splits (where the TLD is part of the brand)
TLD_SUFFIXES = [
    ".ly",      # bit.ly, musical.ly, ow.ly
    ".io",      # segment.io, customer.io
    ".ai",      # play.ai, character.ai
    ".co",      # angel.co, drop.co
    ".me",      # about.me, read.me
    ".app",     # cash.app
    ".so",      # notion.so
]

# Compound word modifiers (second word in two-word domains)
COMPOUND_WORDS = [
    "hub",      # smarthub, githubgithub
    "lab",      # codelab, hashlab
    "box",      # dropbox, chatbox
    "stack",    # techstack, fullstack
    "base",     # coinbase, codebase
    "flow",     # webflow, taskflow
    "dash",     # doordash, datadash
    "spot",     # blogspot, hotspot
    "bit",      # fitbit, cloudbit
    "deck",     # slidedeck, pitchdeck
    "pad",      # launchpad, notepad
    "grid",     # sendgrid
    "wave",     # brainwave, airwave
    "cloud",    # soundcloud
    "space",    # rackspace, myspace
    "desk",     # freshdesk, helpdesk
    "craft",    # mindcraft, aircraft
    "port",     # viewport, transport
    "path",     # classpath, datapath
    "hq",       # basecamphq
    "app",      # bufferapp, curtsyapp
]


def _drop_trailing_e(word: str) -> str:
    """Drop trailing 'e' for cleaner suffix attachment (optimize → optimiz)."""
    if len(word) > 2 and word.endswith("e") and word[-2] not in VOWELS:
        return word[:-1]
    return word


def _drop_trailing_vowel(word: str) -> str:
    """Drop trailing vowel to avoid awkward double-vowel joins."""
    if len(word) > 2 and word[-1] in VOWELS:
        return word[:-1]
    return word


def _should_drop_trailing_for_suffix(word: str, suffix: str) -> bool:
    """Decide whether to drop the trailing char to make a smoother join."""
    if not word:
        return False
    # Drop trailing 'e' before vowel-starting suffixes (optimize + ly → optimizely)
    if word[-1] == "e" and suffix[0] in VOWELS:
        return True
    # Drop trailing 'y' before 'y'-starting suffixes (clue + ly is fine, but tidy + ly → tidily? keep both)
    if word[-1] == "y" and suffix.startswith("y"):
        return True
    # Avoid double vowels: if word ends with vowel and suffix starts with same vowel
    if word[-1] == suffix[0] and word[-1] in VOWELS:
        return True
    return False


def generate_variants(
    word: str,
    include_suffixes: bool = True,
    include_prefixes: bool = True,
    include_tld_splits: bool = True,
    include_compounds: bool = True,
    max_length: int = 20,
    dedupe: bool = True,
) -> list[dict[str, str]]:
    """
    Generate startup-style domain name variants from an English root word.

    Args:
        word:               The root English word (e.g., "clue", "brain", "calendar")
        include_suffixes:   Generate word+suffix variants (cluely, cluify, ...)
        include_prefixes:   Generate prefix+word variants (getclue, tryclue, ...)
        include_tld_splits: Generate TLD-as-brand variants (clue.ly, clue.io, ...)
        include_compounds:  Generate two-word compounds (cluehub, clueflow, ...)
        max_length:         Max length for the domain name (excluding TLD)
        dedupe:             Remove duplicates

    Returns:
        List of dicts with keys: "domain", "pattern", "category"
    """
    word = word.strip().lower()
    results: list[dict[str, str]] = []

    # --- 1. Suffix variants (the "cluely" pattern) ---
    if include_suffixes:
        for suffix in SUFFIXES:
            # Plain join: word + suffix
            plain = word + suffix
            if len(plain) <= max_length:
                results.append({
                    "domain": f"{plain}.com",
                    "pattern": f"{word} + {suffix}",
                    "category": "suffix",
                })

            # Smoothed join: drop trailing char if it makes a better name
            if _should_drop_trailing_for_suffix(word, suffix):
                trimmed = word[:-1] + suffix
                if trimmed != plain and len(trimmed) <= max_length:
                    results.append({
                        "domain": f"{trimmed}.com",
                        "pattern": f"{word[:-1]}~ + {suffix}",
                        "category": "suffix_smoothed",
                    })

    # --- 2. Prefix variants (the "getclue" pattern) ---
    if include_prefixes:
        for prefix in PREFIXES:
            name = prefix + word
            if len(name) <= max_length:
                results.append({
                    "domain": f"{name}.com",
                    "pattern": f"{prefix} + {word}",
                    "category": "prefix",
                })

    # --- 3. TLD-as-brand splits (the "bit.ly" pattern) ---
    if include_tld_splits:
        for tld in TLD_SUFFIXES:
            tld_bare = tld.lstrip(".")
            # Full word + TLD: clue.ly
            results.append({
                "domain": f"{word}{tld}",
                "pattern": f"{word} + {tld}",
                "category": "tld_split",
            })
            # If word ends with letters matching TLD start, do a creative split
            # e.g., "supply" with .ly → supp.ly
            if len(tld_bare) <= len(word) and word.endswith(tld_bare):
                stem = word[: -len(tld_bare)]
                if len(stem) >= 2:
                    results.append({
                        "domain": f"{stem}{tld}",
                        "pattern": f"{stem} + {tld} (overlap)",
                        "category": "tld_overlap",
                    })

    # --- 4. Compound word variants (the "cluehub" pattern) ---
    if include_compounds:
        for comp in COMPOUND_WORDS:
            name = word + comp
            if len(name) <= max_length:
                results.append({
                    "domain": f"{name}.com",
                    "pattern": f"{word} + {comp}",
                    "category": "compound",
                })

    # --- Deduplicate ---
    if dedupe:
        seen = set()
        unique = []
        for r in results:
            if r["domain"] not in seen:
                seen.add(r["domain"])
                unique.append(r)
        results = unique

    return results


def print_variants(word: str, **kwargs) -> None:
    """Pretty-print all generated variants grouped by category."""
    variants = generate_variants(word, **kwargs)

    categories = {
        "suffix": "Suffix Variants (word + suffix → .com)",
        "suffix_smoothed": "Suffix Variants (smoothed join)",
        "prefix": "Prefix Variants (prefix + word → .com)",
        "tld_split": "TLD-as-Brand (word + creative TLD)",
        "tld_overlap": "TLD Overlap (word naturally ends with TLD)",
        "compound": "Compound Words (word + modifier → .com)",
    }

    print(f"\n{'='*60}")
    print(f"  Domain variants for: \"{word}\"")
    print(f"{'='*60}")

    for cat_key, cat_label in categories.items():
        group = [v for v in variants if v["category"] == cat_key]
        if not group:
            continue
        print(f"\n  {cat_label}")
        print(f"  {'-'*50}")
        for v in group:
            print(f"    {v['domain']:<28} ({v['pattern']})")

    print(f"\n  Total: {len(variants)} variants generated\n")


if __name__ == "__main__":
    # download top 1 million domains csv file from https://radar.cloudflare.com/domains
    parser = argparse.ArgumentParser(description="Generate startup-style domain variants for words.")
    parser.add_argument("--words", required=True, help="Path to a word list file (one word per line)")
    parser.add_argument("--top", type=int, default=10, help="Number of words to process (default: 10)")
    parser.add_argument("--len", type=int, default=20, help="Max domain name length excluding TLD (default: 20)")
    args = parser.parse_args()

    with open(args.words, encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip().isalpha() and line.strip().lower() not in STOPWORDS]

    for word in words[:args.top]:
        print_variants(word, max_length=args.len)
