#!/usr/bin/env python3
"""Read unregistered domains from domains.sqlite and rank them by estimated value."""

import argparse
import sqlite3
import re

DB_PATH = "domains.sqlite"

# Common stopwords / function words — not brandable
STOPWORDS = {
    "the", "that", "this", "with", "from", "they", "what", "when",
    "here", "also", "help", "been", "some", "than", "back", "into",
    "used", "have", "will", "just", "your", "were", "each", "make",
    "like", "long", "look", "many", "then", "them", "would", "come",
    "made", "find", "more", "other", "about", "after", "could",
    "which", "their", "there", "these", "those", "where", "being",
    "does", "done", "for", "and", "but", "not", "you", "all",
    "can", "her", "was", "are", "our", "out", "has", "his",
    "how", "its", "may", "she", "who", "did", "get", "let",
    "say", "too", "use", "way", "very", "much", "most", "such",
    "only", "over", "any", "own", "same", "tell", "take",
    "need", "want", "give", "keep", "even", "because", "between",
    "good", "great", "still", "should", "every", "under", "never",
    "before", "while", "right", "think", "again", "might", "went",
    "page", "name", "year", "view",
}

# Premium prefixes — evocative words that make strong brand names
PREMIUM_PREFIXES = {
    # Animals / predators
    "bear", "wolf", "lion", "hawk", "eagle", "tiger", "dragon",
    "cat", "fox", "bat", "ape", "owl", "ram", "elk",
    # Power / aggression
    "iron", "steel", "sharp", "red", "ice", "fire", "dark", "war",
    "death", "storm", "thunder", "rage", "fury", "shadow",
    # Tech / AI
    "data", "code", "dev", "bot", "cyber", "deep", "mega", "nano",
    "auto", "smart", "hyper", "ultra", "meta", "pro", "max", "super",
    "tech", "web", "net", "cloud",
    # Branding
    "gold", "top", "big", "fast", "prime", "core", "elite", "power",
    "blue", "sky", "star", "flash", "bolt", "edge", "swift",
}

# Load system dictionary
DICTIONARY = set()
try:
    with open("/usr/share/dict/words") as f:
        for line in f:
            w = line.strip().lower()
            if len(w) >= 3:
                DICTIONARY.add(w)
except FileNotFoundError:
    pass


def score_domain(domain: str, tld: str, suffix: str | None = None) -> float:
    """Score a domain. Higher = more valuable."""
    name = domain.removesuffix(f".{tld}").lower()

    if suffix and name.endswith(suffix):
        prefix = name[:-len(suffix)]
    else:
        prefix = name

    if not prefix:
        return 0.0

    score = 0.0
    plen = len(prefix)

    # 1) Is the prefix a real English word? (most important signal)
    is_word = prefix in DICTIONARY
    if is_word:
        score += 50

    # 2) Stopword penalty
    if prefix in STOPWORDS:
        score -= 40

    # 3) Premium prefix bonus
    if prefix in PREMIUM_PREFIXES:
        score += 35

    # 3) Length: sweet spot is 3-5 chars for branding
    if is_word:
        if plen == 3:
            score += 25
        elif plen == 4:
            score += 30  # 4-letter words are the sweet spot
        elif plen == 5:
            score += 22
        elif plen == 6:
            score += 12
        elif plen <= 2:
            score += 5   # too short, often just prepositions
        else:
            score += max(0, 8 - (plen - 6))
    else:
        # Non-words: short is better but less valuable overall
        if plen <= 3:
            score += 10
        elif plen <= 5:
            score += 5

    # 4) Pronounceability
    vowels = sum(1 for c in prefix if c in "aeiou")
    if prefix.isalpha():
        score += 3
    if plen > 0 and vowels == 0:
        score -= 25
    elif plen > 0 and 0.25 <= vowels / plen <= 0.6:
        score += 5

    # 5) Penalize awkward combinations with suffix
    if suffix and prefix.endswith(("aw", "ow", "law", suffix)):
        score -= 10

    # 6) Penalize numbers and hyphens
    if re.search(r"\d", prefix):
        score -= 15
    if "-" in prefix:
        score -= 15

    return score


def main():
    parser = argparse.ArgumentParser(description="Rank unregistered domains by estimated value.")
    parser.add_argument("tld", help="Top-level domain (e.g. ai, io, com)")
    parser.add_argument("--suffix", default=None, help="Suffix to strip from domain names for scoring (e.g. claw)")
    args = parser.parse_args()
    tld = args.tld.lstrip(".")
    suffix = args.suffix
    table_name = f"{tld}_domains"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(
        f"SELECT domain FROM {table_name} WHERE registered = 0"
    )
    domains = [row[0] for row in cursor.fetchall()]
    conn.close()

    ranked = sorted(domains, key=lambda d: score_domain(d, tld, suffix), reverse=True)

    print(f"Total unregistered .{tld} domains: {len(ranked)}\n")
    print(f"{'Rank':<6} {'Domain':<25} {'Prefix':<15} {'Score':>8}")
    print("-" * 56)
    for i, domain in enumerate(ranked[:50], 1):
        name = domain.removesuffix(f".{tld}")
        prefix = name[:-len(suffix)] if suffix and name.endswith(suffix) else name
        s = score_domain(domain, tld, suffix)
        print(f"{i:<6} {domain:<25} {prefix:<15} {s:>8.1f}")


if __name__ == "__main__":
    main()
