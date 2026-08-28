#!/usr/bin/env python3
"""
Seed the local Dovecot test server with folders and messages.

This script deliberately uses IMAP write commands (CREATE, APPEND). It is a test
fixture only and is kept separate from the collector, which never writes.

    python seed_mailbox.py                 # seed defaults
    python seed_mailbox.py --count 50      # more messages per folder
"""

import argparse
import datetime as dt
import imaplib
import random
import ssl
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOST, PORT, USER, PASS = "127.0.0.1", 9993, "tester", "testpass"

FOLDERS = [
    # raw IMAP name (modified UTF-7 where needed), messages, flags pattern
    ("INBOX", None),
    ("INBOX.Sent", None),
    ("INBOX.Drafts", None),
    ("INBOX.Archive", None),
    ("INBOX.Archive.2019", None),
    ("INBOX.Archive.2019.Q4 Invoices", None),
    ("INBOX.&AOQ-ltere Projekte", None),          # "ältere Projekte"
    ("INBOX.Clients.Smith &- Co", None),          # "&" encoded as "&-"
]


def make_message(i: int, folder: str) -> bytes:
    when = dt.datetime(2019, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(days=i * 3, hours=i % 24)
    subj_variants = [
        f"Test message {i} in {folder}",
        f"=?UTF-8?B?w4TDtsO8?= umlaut subject {i}",
        f"=?ISO-8859-1?Q?R=E9sum=E9?= {i}",
        f"Re: Q4 report {i} — attached",
    ]
    subject = subj_variants[i % len(subj_variants)]
    body = f"This is test message {i} in {folder}.\r\n" * (1 + i % 5)
    msg = (
        f"From: Sender {i} <sender{i}@example.com>\r\n"
        f"To: tester@example.com\r\n"
        f"Cc: cc{i}@example.com\r\n"
        f"Date: {when.strftime('%a, %d %b %Y %H:%M:%S +0000')}\r\n"
        f"Message-ID: <{i}.{folder.replace(' ', '_')}@example.com>\r\n"
        f"Subject: {subject}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n{body}"
    ).encode("utf-8")
    if i % 7 == 0:
        # Deliberately malformed: no Message-ID, bare LF line endings, raw high bytes.
        msg = (
            f"From: broken{i}@example.com\nTo: tester@example.com\n"
            f"Subject: broken message {i}\n\n"
        ).encode() + b"raw bytes \xff\xfe here\nno CRLF\n"
    return msg


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=12, help="messages per folder")
    args = ap.parse_args()

    ctx = ssl.create_default_context(cafile=str(HERE / "certs" / "server.crt"))
    conn = imaplib.IMAP4_SSL(HOST, PORT, ssl_context=ctx)
    conn.login(USER, PASS)
    print("logged in")

    rnd = random.Random(42)
    for raw, _ in FOLDERS:
        if raw != "INBOX":
            typ, data = conn.create(f'"{raw}"')
            print(f"CREATE {raw}: {typ} {data}")
        for i in range(1, args.count + 1):
            flags = r"\Seen" if rnd.random() < 0.5 else ""
            if rnd.random() < 0.15:
                flags += r" \Flagged"
            internaldate = imaplib.Time2Internaldate(time.time() - rnd.randint(0, 3 * 365 * 86400))
            typ, data = conn.append(f'"{raw}"', flags.strip() or None, internaldate, make_message(i, raw))
            if typ != "OK":
                print(f"APPEND {raw} #{i}: {typ} {data}")
        print(f"seeded {args.count} messages into {raw}")

    conn.logout()
    print("done")


if __name__ == "__main__":
    main()
