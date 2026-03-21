#!/usr/bin/env python3
"""Find the most popular prefixes among the top 10 million domains."""

import argparse
import csv
from collections import Counter


def extract_name(domain: str) -> str:
    """Strip www. and TLD, returning the bare second-level domain name."""
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    # Strip TLD (everything after the last dot)
    parts = domain.rsplit(".", 1)
    return parts[0] if len(parts) == 2 else domain


def main():
    # download top 1 million domains csv file from https://radar.cloudflare.com/domains
    parser = argparse.ArgumentParser(description="Find top popular prefixes in a domain list CSV.")
    parser.add_argument("--csv", required=True, help="Path to the domcop CSV file")
    parser.add_argument("--words", help="Path to a word list file; count how many domains start with each word")
    parser.add_argument("--min-len", type=int, default=2, help="Minimum prefix length for n-gram mode (default: 2)")
    parser.add_argument("--max-len", type=int, default=5, help="Maximum prefix length for n-gram mode (default: 5)")
    parser.add_argument("--top", type=int, default=10, help="Number of top prefixes to show (default: 10)")
    args = parser.parse_args()

    total = 0

    if args.words:
        with open(args.words, encoding="utf-8") as wf:
            candidates = {line.strip().lower() for line in wf if line.strip().isalpha() and len(line.strip()) >= args.min_len}

        word_counter: Counter = Counter()
        with open(args.csv, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header
            for row in reader:
                if len(row) < 2:
                    continue
                name = extract_name(row[1])
                if not name.isalpha():
                    continue
                total += 1
                for word in candidates:
                    if name.startswith(word) and len(name) > len(word):
                        word_counter[word] += 1

        print(f"Analyzed {total:,} purely alphabetic domains\n")
        print(f"Top {args.top} word prefixes (from word list):")
        print(f"  {'Prefix':<12} {'Count':>10}  {'% of total':>10}")
        print("  " + "-" * 37)
        for prefix, count in word_counter.most_common(args.top):
            pct = count / total * 100
            print(f"  {prefix:<12} {count:>10,}  {pct:>9.2f}%")
    else:
        counters: dict[int, Counter] = {length: Counter() for length in range(args.min_len, args.max_len + 1)}
        with open(args.csv, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header
            for row in reader:
                if len(row) < 2:
                    continue
                name = extract_name(row[1])
                if not name.isalpha():
                    continue
                total += 1
                for length, counter in counters.items():
                    if len(name) >= length:
                        counter[name[:length]] += 1

        print(f"Analyzed {total:,} purely alphabetic domains\n")
        for length in range(args.min_len, args.max_len + 1):
            print(f"Top {args.top} prefixes of length {length}:")
            print(f"  {'Prefix':<10} {'Count':>10}  {'% of total':>10}")
            print("  " + "-" * 35)
            for prefix, count in counters[length].most_common(args.top):
                pct = count / total * 100
                print(f"  {prefix:<10} {count:>10,}  {pct:>9.2f}%")
            print()


if __name__ == "__main__":
    main()
