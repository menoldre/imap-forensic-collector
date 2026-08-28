#!/usr/bin/env python3
"""
Compare two collections produced by imap_forensic_collector.py.

    python tests/compare_collections.py testdata/expected  <your_collection_dir>

For every (folder, uidvalidity, uid) in the expected manifest, checks that the
candidate manifest has the same sha256, size_bytes, internaldate_utc, flags,
message_id and subject, and that the .eml file on disk hashes to that sha256.
Reports extras/missing on either side. Exit 0 only when everything matches.

Flags: the \\Recent flag is ignored. It is per-session state (RFC 3501 §2.3.2)
that a server may or may not report depending on whether another session has
seen the mailbox since it was restored; it is not a property of the message.
"""

import csv
import hashlib
import sys
from pathlib import Path

FIELDS = ["sha256", "size_bytes", "internaldate_utc", "flags", "message_id", "subject"]


def load(d: Path) -> dict[tuple, dict]:
    rows = {}
    with open(d / "manifest.csv", newline="", encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            key = (r["folder"], r["uidvalidity"], r["uid"])
            rows[key] = r  # last row for a key wins (append-only manifest)
    return rows


def norm_flags(s: str) -> str:
    return " ".join(sorted(f for f in s.split() if f.lower() != "\\recent"))


def file_sha(d: Path, rel: str) -> str | None:
    p = d / Path(*rel.split("/"))
    if not p.is_file():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    exp_dir, cand_dir = Path(sys.argv[1]), Path(sys.argv[2])
    exp, cand = load(exp_dir), load(cand_dir)
    problems = 0

    for key in sorted(set(exp) - set(cand)):
        print(f"MISSING in candidate: folder={key[0]} uidvalidity={key[1]} uid={key[2]}")
        problems += 1
    for key in sorted(set(cand) - set(exp)):
        print(f"EXTRA in candidate:   folder={key[0]} uidvalidity={key[1]} uid={key[2]}")
        problems += 1

    compared = 0
    for key in sorted(set(exp) & set(cand)):
        e, c = exp[key], cand[key]
        compared += 1
        for f in FIELDS:
            ev, cv = e.get(f, ""), c.get(f, "")
            if f == "flags":
                ev, cv = norm_flags(ev), norm_flags(cv)
            if ev != cv:
                print(f"DIFF {f}: folder={key[0]} uid={key[2]}: expected {ev!r}, got {cv!r}")
                problems += 1
        actual = file_sha(cand_dir, c["relative_path"])
        if actual is None:
            print(f"FILE MISSING: {c['relative_path']}")
            problems += 1
        elif actual != e["sha256"]:
            print(f"FILE HASH DIFF: {c['relative_path']}: expected {e['sha256']}, got {actual}")
            problems += 1

    print(f"compared {compared} message(s); expected={len(exp)} candidate={len(cand)}; problems={problems}")
    print("RESULT:", "MATCH" if problems == 0 else "MISMATCH")
    return 0 if problems == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
