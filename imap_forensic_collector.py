#!/usr/bin/env python3
"""
imap_forensic_collector.py — read-only forensic collection of an IMAP mailbox.

Collects every message in every selectable folder to individual .eml files
(verbatim bytes), records a verification manifest, and never issues an IMAP
command that mutates server state.

Standard library only. Python 3.11+.
"""

from __future__ import annotations

import argparse
import configparser
import csv
import datetime as dt
import email.header
import email.parser
import getpass
import hashlib
import imaplib
import logging
import os
import platform
import re
import socket
import ssl
import sys
import time
from pathlib import Path

__version__ = "1.0.0"

MANIFEST_NAME = "manifest.csv"
FAILURES_NAME = "failures.csv"
LOG_NAME = "collection.log"
MAIL_DIRNAME = "mail"

MANIFEST_COLUMNS = [
    "folder",
    "folder_dir",
    "uidvalidity",
    "uid",
    "relative_path",
    "internaldate_utc",
    "date_header",
    "flags",
    "size_bytes",
    "rfc822_size",
    "sha256",
    "message_id",
    "from",
    "to",
    "cc",
    "subject",
]
FAILURE_COLUMNS = ["folder", "uid", "error", "attempts"]

# The one FETCH item list this script ever sends. BODY.PEEK[] does not set \Seen.
FETCH_ITEMS = "(BODY.PEEK[] INTERNALDATE FLAGS RFC822.SIZE)"

MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (2, 4, 8)
MIN_FETCH_INTERVAL = 0.1  # ~10 fetches/second
MAX_DIRNAME_LEN = 100

# Raise imaplib's default literal limit so large attachments are not rejected client-side.
imaplib._MAXLINE = max(imaplib._MAXLINE, 100 * 1024 * 1024)

log = logging.getLogger("collector")


# --------------------------------------------------------------------------- #
# Helpers: folder names
# --------------------------------------------------------------------------- #

def decode_modified_utf7(name: str) -> str:
    """Decode IMAP modified UTF-7 (RFC 3501 §5.1.3) to a Unicode string."""
    out: list[str] = []
    i = 0
    while i < len(name):
        ch = name[i]
        if ch != "&":
            out.append(ch)
            i += 1
            continue
        j = name.find("-", i + 1)
        if j == -1:
            out.append(name[i:])
            break
        chunk = name[i + 1 : j]
        if chunk == "":
            out.append("&")
        else:
            b64 = chunk.replace(",", "/")
            b64 += "=" * (-len(b64) % 4)
            try:
                import base64

                out.append(base64.b64decode(b64).decode("utf-16-be"))
            except Exception:
                out.append(name[i : j + 1])
        i = j + 1
    return "".join(out)


_ILLEGAL_RE = re.compile(r'[<>:"|?*\\/\x00-\x1f\x7f]')


def sanitize_dirname(folder_unicode: str, delimiter: str | None) -> str:
    """Flatten a folder path into a single Windows-safe directory name."""
    name = folder_unicode
    if delimiter:
        name = name.replace(delimiter, ".")
    name = _ILLEGAL_RE.sub("_", name)
    name = name.rstrip(" .") or "_"
    return name[:MAX_DIRNAME_LEN]


_LIST_RE = re.compile(
    rb'\((?P<attrs>[^)]*)\)\s+(?:"(?P<delim>(?:\\.|[^"\\])*)"|(?P<delim_atom>NIL|\S+))\s+'
    rb'(?:"(?P<name_q>(?:\\.|[^"\\])*)"|\{(?P<lit>\d+)\}|(?P<name_atom>\S+))\s*$'
)


def parse_list_line(line) -> tuple[list[str], str | None, str] | None:
    """Parse one LIST response entry -> (attributes, delimiter, raw_name)."""
    if isinstance(line, tuple):
        # Literal folder name: (b'(\\HasNoChildren) "." {5}', b'INBOX')
        head, literal = line[0], line[1]
        m = re.match(rb"\((?P<attrs>[^)]*)\)\s+(?:\"(?P<delim>[^\"]*)\"|(?P<delim_atom>NIL|\S+))", head)
        if not m:
            return None
        attrs = m.group("attrs").decode("ascii", "replace").split()
        delim = m.group("delim").decode("ascii") if m.group("delim") is not None else None
        if delim is None and m.group("delim_atom") and m.group("delim_atom") != b"NIL":
            delim = m.group("delim_atom").decode("ascii")
        return attrs, delim, literal.decode("ascii", "replace")
    m = _LIST_RE.match(line)
    if not m:
        return None
    attrs = m.group("attrs").decode("ascii", "replace").split()
    delim: str | None
    if m.group("delim") is not None:
        delim = m.group("delim").decode("ascii").replace("\\\\", "\\").replace('\\"', '"')
    elif m.group("delim_atom") == b"NIL":
        delim = None
    else:
        delim = m.group("delim_atom").decode("ascii")
    if m.group("name_q") is not None:
        raw = m.group("name_q").decode("ascii", "replace").replace("\\\\", "\\").replace('\\"', '"')
    else:
        raw = m.group("name_atom").decode("ascii", "replace")
    return attrs, delim, raw


def quote_mailbox(raw_name: str) -> str:
    """Quote a raw (modified UTF-7) mailbox name for use in a command."""
    return '"' + raw_name.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------------------------------------------------------- #
# Helpers: FETCH parsing
# --------------------------------------------------------------------------- #

_UID_RE = re.compile(rb"\bUID (\d+)")
_SIZE_RE = re.compile(rb"\bRFC822\.SIZE (\d+)")
_IDATE_RE = re.compile(rb'\bINTERNALDATE "([^"]*)"')
_FLAGS_RE = re.compile(rb"\bFLAGS \(([^)]*)\)")
_BODY_LIT_RE = re.compile(rb"\bBODY\[\]\s*\{(\d+)\}\s*$")


class FetchParseError(Exception):
    pass


def parse_fetch_response(data, expected_uid: int) -> dict:
    """
    Turn imaplib's UID FETCH response into a dict:
    uid, rfc822_size, internaldate_raw, flags, body (bytes).
    Attribute order in the response is server-defined, so all non-literal text
    parts are concatenated and searched.
    """
    text_parts: list[bytes] = []
    body: bytes | None = None
    for item in data:
        if item is None:
            continue
        if isinstance(item, tuple):
            head, literal = item[0], item[1]
            text_parts.append(head)
            if _BODY_LIT_RE.search(head):
                if body is not None:
                    raise FetchParseError("multiple BODY[] literals in response")
                body = literal
            else:
                # A literal for something else (should not happen with our FETCH items)
                text_parts.append(b"<literal>")
        else:
            text_parts.append(item)
    meta = b" ".join(text_parts)

    if body is None:
        raise FetchParseError(f"no BODY[] literal in response: {meta[:200]!r}")

    m = _UID_RE.search(meta)
    if not m:
        raise FetchParseError(f"no UID in response: {meta[:200]!r}")
    uid = int(m.group(1))
    if uid != expected_uid:
        raise FetchParseError(f"response UID {uid} != requested {expected_uid}")

    # Sanity-check literal length against the announced octet count.
    for item in data:
        if isinstance(item, tuple):
            mm = _BODY_LIT_RE.search(item[0])
            if mm and int(mm.group(1)) != len(item[1]):
                raise FetchParseError(
                    f"literal length mismatch: announced {mm.group(1).decode()} got {len(item[1])}"
                )

    m = _SIZE_RE.search(meta)
    rfc822_size = int(m.group(1)) if m else None
    m = _IDATE_RE.search(meta)
    internaldate_raw = m.group(1).decode("ascii", "replace") if m else ""
    m = _FLAGS_RE.search(meta)
    flags = m.group(1).decode("ascii", "replace").strip() if m else ""

    return {
        "uid": uid,
        "rfc822_size": rfc822_size,
        "internaldate_raw": internaldate_raw,
        "flags": flags,
        "body": body,
    }


def internaldate_to_utc_iso(raw: str) -> str:
    """'28-Aug-2026 10:00:00 +0200' -> '2026-08-28T08:00:00+00:00'. Empty on failure."""
    if not raw:
        return ""
    try:
        d = dt.datetime.strptime(raw.strip(), "%d-%b-%Y %H:%M:%S %z")
        return d.astimezone(dt.timezone.utc).isoformat()
    except ValueError:
        return ""


def decode_subject(raw: str | None) -> str:
    if raw is None:
        return ""
    try:
        return str(email.header.make_header(email.header.decode_header(raw)))
    except Exception:
        return raw


def header_str(msg, name: str) -> str:
    """Raw header value as a str; empty if absent. Never raises."""
    try:
        v = msg.get(name)
    except Exception:
        return ""
    if v is None:
        return ""
    return str(v)


def csv_safe(s: str) -> str:
    """Strip characters that can't be encoded as UTF-8 (lone surrogates from bad bytes)."""
    return s.encode("utf-8", "replace").decode("utf-8")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

class UTCFormatter(logging.Formatter):
    converter = time.gmtime

    def formatTime(self, record, datefmt=None):  # noqa: N802
        t = dt.datetime.fromtimestamp(record.created, dt.timezone.utc)
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(record.msecs):03d}Z"


def setup_logging(log_path: Path, verbose: bool) -> None:
    fmt = UTCFormatter("%(asctime)s %(levelname)-8s %(message)s")
    log.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh.setFormatter(fmt)
    log.handlers.clear()
    log.addHandler(fh)
    log.addHandler(sh)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

class Settings:
    def __init__(self) -> None:
        self.host = ""
        self.port = 993
        self.user = ""
        self.password = ""
        self.output_dir = Path(f"./collection_{utc_now():%Y-%m-%d}")
        self.folders: list[str] | None = None  # None == ALL
        self.examiner = ""
        self.case_id = ""
        self.resume = False
        self.verify_only = False
        self.dry_run = False
        self.verbose = False


def load_settings(argv: list[str] | None = None) -> Settings:
    ap = argparse.ArgumentParser(
        description="Read-only forensic collection of an IMAP mailbox to .eml files.",
    )
    ap.add_argument("--config", default=None, help="path to config.ini (default: next to script)")
    ap.add_argument("--output", default=None, help="output directory")
    ap.add_argument("--folders", default=None, help="ALL or comma-separated IMAP folder names")
    ap.add_argument("--resume", action="store_true", help="skip messages already in manifest.csv")
    ap.add_argument("--verify-only", action="store_true", help="re-hash files listed in manifest.csv")
    ap.add_argument("--dry-run", action="store_true", help="enumerate folders and counts; write only the log")
    ap.add_argument("--verbose", action="store_true", help="log per-message progress (DEBUG)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    s = Settings()
    cfg_path = Path(args.config) if args.config else Path(__file__).resolve().parent / "config.ini"
    cp = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
    if cfg_path.exists():
        cp.read(cfg_path, encoding="utf-8")
    elif args.config:
        ap.error(f"config file not found: {cfg_path}")

    s.host = cp.get("source", "host", fallback="")
    s.port = cp.getint("source", "port", fallback=993)
    s.user = cp.get("source", "user", fallback="")
    out = cp.get("collection", "output_dir", fallback=None)
    if out:
        s.output_dir = Path(out.replace("YYYY-MM-DD", f"{utc_now():%Y-%m-%d}"))
    folders = cp.get("collection", "folders", fallback="ALL")
    s.examiner = cp.get("collection", "examiner", fallback="")
    s.case_id = cp.get("collection", "case_id", fallback="")

    if args.output:
        s.output_dir = Path(args.output)
    if args.folders:
        folders = args.folders
    if folders.strip().upper() != "ALL":
        s.folders = [f.strip() for f in folders.split(",") if f.strip()]

    s.resume = args.resume
    s.verify_only = args.verify_only
    s.dry_run = args.dry_run
    s.verbose = args.verbose

    if not s.verify_only:
        if not s.host or not s.user:
            ap.error("source host and user must be set in config.ini")
        s.password = os.environ.get("IMAP_PASSWORD", "")
        if not s.password:
            s.password = getpass.getpass(f"IMAP password for {s.user}@{s.host}: ")
    return s


# --------------------------------------------------------------------------- #
# IMAP connection wrapper
# --------------------------------------------------------------------------- #

# Errors that mean the connection is gone and must be re-established.
RECONNECT_ERRORS = (
    imaplib.IMAP4.abort,
    OSError,
    ssl.SSLError,
    socket.timeout,
    EOFError,
)
# Errors that are a server NO/BAD reply on a live connection (retry, no reconnect).
PROTOCOL_ERRORS = (imaplib.IMAP4.error, FetchParseError)


class Connection:
    def __init__(self, s: Settings) -> None:
        self.s = s
        self.conn: imaplib.IMAP4_SSL | None = None
        self.selected: str | None = None
        self.uidvalidity: int | None = None

    def open(self) -> None:
        ctx = ssl.create_default_context()  # certificate verification stays ON
        log.info("Connecting to %s:%d (IMAP over TLS)", self.s.host, self.s.port)
        self.conn = imaplib.IMAP4_SSL(self.s.host, self.s.port, ssl_context=ctx, timeout=120)
        typ, _ = self.conn.login(self.s.user, self.s.password)
        if typ != "OK":
            raise imaplib.IMAP4.error("login failed")
        log.info("Logged in as %s", self.s.user)
        self.selected = None
        self.uidvalidity = None

    def close(self) -> None:
        if self.conn is None:
            return
        try:
            # LOGOUT only; never CLOSE (CLOSE would expunge on a read-write mailbox).
            self.conn.logout()
        except Exception:
            pass
        self.conn = None
        self.selected = None

    def reconnect(self) -> None:
        log.warning("Reconnecting to %s", self.s.host)
        self.close()
        delay = 2
        for attempt in range(1, 6):
            try:
                self.open()
                return
            except RECONNECT_ERRORS as e:
                log.warning("Reconnect attempt %d failed: %s", attempt, e)
                time.sleep(delay)
                delay = min(delay * 2, 60)
        raise RuntimeError("could not re-establish IMAP connection")

    def list_folders(self) -> list[tuple[list[str], str | None, str]]:
        assert self.conn is not None
        typ, data = self.conn.list()
        if typ != "OK":
            raise imaplib.IMAP4.error(f"LIST failed: {typ}")
        out = []
        for line in data:
            if not line:
                continue
            parsed = parse_list_line(line)
            if parsed is None:
                log.warning("Unparseable LIST line: %r", line)
                continue
            out.append(parsed)
        return out

    def examine(self, raw_name: str) -> int:
        """EXAMINE a folder read-only and return its UIDVALIDITY."""
        assert self.conn is not None
        typ, data = self.conn.select(quote_mailbox(raw_name), readonly=True)
        if typ != "OK":
            raise imaplib.IMAP4.error(f"EXAMINE {raw_name!r} failed: {data}")
        uv = self.conn.response("UIDVALIDITY")[1]
        if not uv or uv[0] is None:
            raise imaplib.IMAP4.error(f"no UIDVALIDITY returned for {raw_name!r}")
        self.selected = raw_name
        self.uidvalidity = int(uv[0])
        return self.uidvalidity

    def search_all(self) -> list[int]:
        assert self.conn is not None
        typ, data = self.conn.uid("SEARCH", None, "ALL")
        if typ != "OK":
            raise imaplib.IMAP4.error(f"UID SEARCH failed: {data}")
        uids: list[int] = []
        for chunk in data:
            if chunk:
                uids.extend(int(x) for x in chunk.split())
        return sorted(set(uids))

    def fetch(self, uid: int) -> dict:
        assert self.conn is not None
        typ, data = self.conn.uid("FETCH", str(uid), FETCH_ITEMS)
        if typ != "OK":
            raise imaplib.IMAP4.error(f"UID FETCH {uid} failed: {data}")
        if not data or data == [None]:
            raise FetchParseError(f"UID FETCH {uid} returned no data (message gone?)")
        return parse_fetch_response(data, uid)


# --------------------------------------------------------------------------- #
# Manifest / failures files
# --------------------------------------------------------------------------- #

class Manifest:
    def __init__(self, path: Path, append: bool) -> None:
        exists = path.exists()
        mode = "a" if append and exists else "w"
        # utf-8-sig writes a BOM in "w" mode only; in "a" mode the existing BOM is kept.
        self.fh = open(path, mode, newline="", encoding="utf-8-sig")
        self.w = csv.DictWriter(self.fh, fieldnames=MANIFEST_COLUMNS)
        if mode == "w":
            self.w.writeheader()
            self.fh.flush()

    def write(self, row: dict) -> None:
        self.w.writerow({k: csv_safe(str(row.get(k, ""))) for k in MANIFEST_COLUMNS})
        self.fh.flush()
        os.fsync(self.fh.fileno())

    def close(self) -> None:
        self.fh.close()


class Failures:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.fh = None
        self.w = None

    def write(self, folder: str, uid: int, error: str, attempts: int) -> None:
        if self.fh is None:
            new = not self.path.exists() or self.path.stat().st_size == 0
            self.fh = open(self.path, "a", newline="", encoding="utf-8-sig" if new else "utf-8")
            self.w = csv.DictWriter(self.fh, fieldnames=FAILURE_COLUMNS)
            if new:
                self.w.writeheader()
        self.w.writerow(
            {"folder": csv_safe(folder), "uid": uid, "error": csv_safe(error), "attempts": attempts}
        )
        self.fh.flush()

    def close(self) -> None:
        if self.fh:
            self.fh.close()


def read_manifest(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #

class FolderStats:
    def __init__(self, name: str, folder_dir: str, uidvalidity: int) -> None:
        self.name = name
        self.folder_dir = folder_dir
        self.uidvalidity = uidvalidity
        self.search_count = 0
        self.attempted = 0
        self.written = 0
        self.skipped = 0
        self.failed = 0
        self.bytes = 0
        self.uidvalidity_changed = False


class Collector:
    def __init__(self, s: Settings) -> None:
        self.s = s
        self.out = s.output_dir
        self.mail_dir = self.out / MAIL_DIRNAME
        self.cx = Connection(s)
        self.manifest: Manifest | None = None
        self.failures = Failures(self.out / FAILURES_NAME)
        self.stats: list[FolderStats] = []
        self.used_dirnames: set[str] = set()
        self.last_fetch_at = 0.0
        # resume state
        self.done: set[tuple[str, int, int]] = set()  # (folder, uidvalidity, uid)
        self.prior_uidvalidity: dict[str, int] = {}
        self.prior_dirs: dict[str, str] = {}  # folder -> folder_dir from prior manifest

    # ---- lifecycle ------------------------------------------------------- #

    def run(self) -> int:
        start = utc_now()
        self.write_header(start)
        rc = 0
        try:
            self.cx.open()
            folders = self.enumerate_folders()
            if self.s.dry_run:
                self.dry_run(folders)
            else:
                self.load_resume_state()
                self.manifest = Manifest(self.out / MANIFEST_NAME, append=self.s.resume)
                for attrs, delim, raw in folders:
                    self.collect_folder(raw, delim)
        except KeyboardInterrupt:
            log.error("Interrupted by user; partial collection. Re-run with --resume.")
            rc = 130
        except Exception as e:  # noqa: BLE001
            log.exception("Fatal error: %s", e)
            rc = 2
        finally:
            self.cx.close()
            if self.manifest:
                self.manifest.close()
            self.failures.close()
            if not self.s.dry_run and self.write_footer(start) is False:
                rc = rc or 1
            else:
                end = utc_now()
                log.info("UTC end time: %s  elapsed: %s", end.isoformat(), end - start)
        return rc

    def write_header(self, start: dt.datetime) -> None:
        log.info("=" * 72)
        log.info("IMAP Forensic Collector v%s", __version__)
        log.info("UTC start time : %s", start.isoformat())
        log.info("Examiner       : %s", self.s.examiner)
        log.info("Case ID        : %s", self.s.case_id)
        log.info("Host           : %s:%d", self.s.host, self.s.port)
        log.info("User           : %s", self.s.user)
        log.info("Python         : %s (%s)", platform.python_version(), sys.executable)
        log.info("Platform       : %s", platform.platform())
        log.info("Collecting host: %s", socket.gethostname())
        log.info("Output dir     : %s", self.out.resolve())
        log.info(
            "Mode           : %s",
            "DRY-RUN" if self.s.dry_run else ("RESUME" if self.s.resume else "COLLECT"),
        )
        log.info("Folders        : %s", "ALL" if self.s.folders is None else ", ".join(self.s.folders))
        log.info("=" * 72)

    # ---- folder enumeration --------------------------------------------- #

    def enumerate_folders(self) -> list[tuple[list[str], str | None, str]]:
        listed = self.cx.list_folders()
        log.info("LIST returned %d entries", len(listed))
        selectable = []
        for attrs, delim, raw in listed:
            uni = decode_modified_utf7(raw)
            if any(a.lower() == "\\noselect" for a in attrs):
                log.info("  skip (\\Noselect): %s", uni)
                continue
            log.info("  folder: %s  [raw=%r delim=%r attrs=%s]", uni, raw, delim, " ".join(attrs))
            selectable.append((attrs, delim, raw))
        if self.s.folders is not None:
            wanted = set(self.s.folders)
            by_name = {decode_modified_utf7(raw): (attrs, delim, raw) for attrs, delim, raw in selectable}
            by_raw = {raw: (attrs, delim, raw) for attrs, delim, raw in selectable}
            chosen = []
            for w in self.s.folders:
                entry = by_name.get(w) or by_raw.get(w)
                if entry is None:
                    log.error("Requested folder not found on server or not selectable: %r", w)
                    continue
                chosen.append(entry)
            missing = wanted - {decode_modified_utf7(e[2]) for e in chosen} - {e[2] for e in chosen}
            if missing:
                log.error("Folders requested but not collected: %s", ", ".join(sorted(missing)))
            selectable = chosen
        log.info("%d selectable folder(s) to process", len(selectable))
        return selectable

    def dry_run(self, folders) -> None:
        total = 0
        for attrs, delim, raw in folders:
            uni = decode_modified_utf7(raw)
            try:
                uv = self.cx.examine(raw)
                uids = self.cx.search_all()
            except RECONNECT_ERRORS + PROTOCOL_ERRORS as e:
                log.error("Folder %s: %s", uni, e)
                continue
            total += len(uids)
            log.info("Folder %s -> dir %r  UIDVALIDITY=%d  messages=%d",
                     uni, sanitize_dirname(uni, delim), uv, len(uids))
        log.info("DRY-RUN total messages: %d", total)

    # ---- resume ----------------------------------------------------------- #

    def load_resume_state(self) -> None:
        mpath = self.out / MANIFEST_NAME
        if not self.s.resume:
            if mpath.exists():
                raise RuntimeError(
                    f"{mpath} already exists. Use --resume to continue it, or choose another --output."
                )
            return
        if not mpath.exists():
            log.warning("--resume given but no manifest found; starting fresh collection")
            return
        rows = read_manifest(mpath)
        for r in rows:
            try:
                key = (r["folder"], int(r["uidvalidity"]), int(r["uid"]))
            except (KeyError, ValueError):
                log.warning("Malformed manifest row ignored: %r", r)
                continue
            self.done.add(key)
            self.prior_uidvalidity.setdefault(r["folder"], key[1])
            self.prior_dirs.setdefault(r["folder"], r["folder_dir"])
            self.used_dirnames.add(r["folder_dir"])
        log.info("Resume: %d message(s) already in manifest across %d folder(s)",
                 len(self.done), len(self.prior_uidvalidity))

    # ---- per-folder ------------------------------------------------------- #

    def choose_dirname(self, uni: str, delim: str | None, uidvalidity: int, changed: bool) -> str:
        if not changed and uni in self.prior_dirs:
            return self.prior_dirs[uni]
        base = sanitize_dirname(uni, delim)
        if changed:
            base = f"{base}__uidvalidity{uidvalidity}"[:MAX_DIRNAME_LEN + 40]
        name = base
        n = 2
        while name in self.used_dirnames or (
            name not in self.prior_dirs.values() and (self.mail_dir / name).exists()
        ):
            name = f"{base}_{n}"
            n += 1
        self.used_dirnames.add(name)
        return name

    def collect_folder(self, raw: str, delim: str | None) -> None:
        uni = decode_modified_utf7(raw)
        log.info("-" * 72)
        log.info("Folder: %s", uni)
        try:
            uv = self.cx.examine(raw)
            uids = self.cx.search_all()
        except RECONNECT_ERRORS + PROTOCOL_ERRORS as e:
            log.error("Folder %s: cannot EXAMINE/SEARCH: %s", uni, e)
            self.cx.reconnect()
            try:
                uv = self.cx.examine(raw)
                uids = self.cx.search_all()
            except RECONNECT_ERRORS + PROTOCOL_ERRORS as e2:
                log.error("Folder %s: giving up: %s", uni, e2)
                st = FolderStats(uni, "", -1)
                st.failed = -1
                self.stats.append(st)
                return

        changed = False
        if self.s.resume and uni in self.prior_uidvalidity and self.prior_uidvalidity[uni] != uv:
            changed = True
            log.error(
                "UIDVALIDITY CHANGED for folder %s: manifest has %d, server now reports %d. "
                "Prior UIDs are no longer meaningful; re-collecting entire folder.",
                uni, self.prior_uidvalidity[uni], uv,
            )
        folder_dir = self.choose_dirname(uni, delim, uv, changed)
        st = FolderStats(uni, folder_dir, uv)
        st.uidvalidity_changed = changed
        st.search_count = len(uids)
        self.stats.append(st)
        log.info("Folder %s -> directory %r  UIDVALIDITY=%d  SEARCH count=%d  [raw=%r]",
                 uni, folder_dir, uv, len(uids), raw)

        target = self.mail_dir / folder_dir
        target.mkdir(parents=True, exist_ok=True)

        for uid in uids:
            key = (uni, uv, uid)
            path = target / f"{uid:06d}.eml"
            if key in self.done and path.exists():
                st.skipped += 1
                log.debug("skip (already collected) %s uid=%d", uni, uid)
                continue
            if key in self.done and not path.exists():
                log.warning("Manifest lists %s uid=%d but file is missing; re-fetching", uni, uid)
            st.attempted += 1
            self.collect_message(st, raw, uni, uid, uv, path, folder_dir)

        log.info("Folder %s done: search=%d attempted=%d written=%d skipped=%d failed=%d",
                 uni, st.search_count, st.attempted, st.written, st.skipped, st.failed)

    def throttle(self) -> None:
        wait = self.last_fetch_at + MIN_FETCH_INTERVAL - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self.last_fetch_at = time.monotonic()

    def collect_message(self, st: FolderStats, raw: str, uni: str, uid: int, uv: int,
                        path: Path, folder_dir: str) -> None:
        last_err = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self.throttle()
            try:
                if self.cx.selected != raw:
                    # Re-select after a reconnect; verify UIDVALIDITY is unchanged.
                    new_uv = self.cx.examine(raw)
                    if new_uv != uv:
                        raise RuntimeError(
                            f"UIDVALIDITY changed mid-folder ({uv} -> {new_uv}); "
                            "remaining UIDs in this folder cannot be trusted"
                        )
                r = self.cx.fetch(uid)
                self.write_message(st, uni, uid, uv, path, folder_dir, r)
                return
            except RECONNECT_ERRORS as e:
                last_err = f"{type(e).__name__}: {e}"
                log.warning("uid=%d attempt %d/%d failed (connection): %s",
                            uid, attempt, MAX_ATTEMPTS, last_err)
                if attempt < MAX_ATTEMPTS:
                    time.sleep(BACKOFF_SECONDS[attempt - 1])
                try:
                    self.cx.reconnect()
                except RuntimeError as e2:
                    last_err = str(e2)
                    break
            except PROTOCOL_ERRORS as e:
                last_err = f"{type(e).__name__}: {e}"
                log.warning("uid=%d attempt %d/%d failed: %s", uid, attempt, MAX_ATTEMPTS, last_err)
                if attempt < MAX_ATTEMPTS:
                    time.sleep(BACKOFF_SECONDS[attempt - 1])
            except RuntimeError as e:
                last_err = str(e)
                break
        st.failed += 1
        log.error("FAILED %s uid=%d after %d attempt(s): %s", uni, uid, attempt, last_err)
        self.failures.write(uni, uid, last_err, attempt)

    def write_message(self, st: FolderStats, uni: str, uid: int, uv: int, path: Path,
                      folder_dir: str, r: dict) -> None:
        body: bytes = r["body"]
        # Write verbatim bytes, then hash exactly what was written.
        tmp = path.with_suffix(".eml.part")
        with open(tmp, "wb") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        size = path.stat().st_size
        if size != len(body):
            raise RuntimeError(f"wrote {size} bytes but had {len(body)} for uid {uid}")
        sha = hashlib.sha256(body).hexdigest()

        rfc_size = r["rfc822_size"]
        if rfc_size is not None and rfc_size != size:
            log.warning("uid=%d size mismatch: RFC822.SIZE=%d written=%d", uid, rfc_size, size)

        # Scratch parse of a copy for header fields only; never touches what is on disk.
        try:
            msg = email.parser.BytesParser().parsebytes(bytes(body), headersonly=True)
        except Exception as e:  # noqa: BLE001
            log.warning("uid=%d header parse failed (%s); manifest header fields left empty", uid, e)
            msg = None

        row = {
            "folder": uni,
            "folder_dir": folder_dir,
            "uidvalidity": uv,
            "uid": uid,
            "relative_path": f"{MAIL_DIRNAME}/{folder_dir}/{path.name}",
            "internaldate_utc": internaldate_to_utc_iso(r["internaldate_raw"]),
            "date_header": header_str(msg, "Date") if msg else "",
            "flags": r["flags"],
            "size_bytes": size,
            "rfc822_size": rfc_size if rfc_size is not None else "",
            "sha256": sha,
            "message_id": header_str(msg, "Message-ID") if msg else "",
            "from": header_str(msg, "From") if msg else "",
            "to": header_str(msg, "To") if msg else "",
            "cc": header_str(msg, "Cc") if msg else "",
            "subject": decode_subject(header_str(msg, "Subject")) if msg else "",
        }
        assert self.manifest is not None
        self.manifest.write(row)
        st.written += 1
        st.bytes += size
        log.debug("wrote %s (%d bytes, sha256=%s)", row["relative_path"], size, sha)

    # ---- footer ----------------------------------------------------------- #

    def write_footer(self, start: dt.datetime) -> bool:
        end = utc_now()
        ok = True
        total_bytes = 0
        log.info("=" * 72)
        log.info("SUMMARY")
        log.info("UTC end time : %s", end.isoformat())
        log.info("Elapsed      : %s", end - start)
        for st in self.stats:
            if st.folder_dir == "":
                log.error("  %-40s  COULD NOT BE OPENED", st.name)
                ok = False
                continue
            on_disk = len(list((self.mail_dir / st.folder_dir).glob("*.eml")))
            total_bytes += st.bytes
            flag = "  ** UIDVALIDITY CHANGED **" if st.uidvalidity_changed else ""
            log.info(
                "  %-40s dir=%r uidvalidity=%d search=%d attempted=%d written=%d skipped=%d failed=%d files=%d%s",
                st.name, st.folder_dir, st.uidvalidity, st.search_count, st.attempted,
                st.written, st.skipped, st.failed, on_disk, flag,
            )
            if on_disk + st.failed != st.search_count:
                ok = False
                log.error(
                    "  COMPLETENESS MISMATCH in %s: files(%d) + failed(%d) = %d != SEARCH count %d",
                    st.name, on_disk, st.failed, on_disk + st.failed, st.search_count,
                )
        log.info("Total bytes written this run: %d", total_bytes)
        changed = [st.name for st in self.stats if st.uidvalidity_changed]
        if changed:
            log.error("UIDVALIDITY changed during resume for: %s", ", ".join(changed))
        failed_total = sum(max(st.failed, 0) for st in self.stats)
        if failed_total:
            log.error("%d message(s) could not be collected; see %s", failed_total, FAILURES_NAME)
        log.info("Completeness check: %s", "PASS" if ok else "FAIL")
        log.info("=" * 72)
        return ok


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #

def verify(out: Path) -> int:
    mpath = out / MANIFEST_NAME
    log.info("=" * 72)
    log.info("VERIFY  v%s  UTC %s  manifest=%s", __version__, utc_now().isoformat(), mpath.resolve())
    if not mpath.exists():
        log.error("manifest not found: %s", mpath)
        return 2
    rows = read_manifest(mpath)
    # The manifest is append-only: a --resume re-fetch of a message whose file had gone
    # missing appends a new row. The LAST row for a path is authoritative; earlier rows
    # are reported so the history is visible.
    latest: dict[str, dict] = {}
    for r in rows:
        rel = r.get("relative_path", "")
        if rel in latest:
            prev = latest[rel]
            level = logging.WARNING if prev.get("sha256") == r.get("sha256") else logging.ERROR
            log.log(level, "SUPERSEDED manifest row for %s (earlier sha256=%s, later sha256=%s)",
                    rel, prev.get("sha256"), r.get("sha256"))
        latest[rel] = r
    checked = missing = mismatched = 0
    seen_paths: set[str] = set(latest)
    for rel, r in latest.items():
        p = out / Path(*rel.split("/"))
        if not p.is_file():
            log.error("MISSING  %s", rel)
            missing += 1
            continue
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        digest = h.hexdigest()
        size = p.stat().st_size
        checked += 1
        if digest != r.get("sha256", "").lower():
            log.error("HASH MISMATCH  %s  manifest=%s actual=%s", rel, r.get("sha256"), digest)
            mismatched += 1
        elif str(size) != str(r.get("size_bytes", "")):
            log.error("SIZE MISMATCH  %s  manifest=%s actual=%d", rel, r.get("size_bytes"), size)
            mismatched += 1
        else:
            log.debug("ok  %s", rel)
    # Files on disk not in the manifest are also a finding.
    extra = 0
    mail_dir = out / MAIL_DIRNAME
    if mail_dir.exists():
        for p in mail_dir.rglob("*.eml"):
            rel = p.relative_to(out).as_posix()
            if rel not in seen_paths:
                log.error("UNLISTED FILE  %s", rel)
                extra += 1
    fpath = out / FAILURES_NAME
    if fpath.exists() and fpath.stat().st_size > 0:
        nfail = max(0, len(read_manifest(fpath)))
        log.warning("%s present with %d documented failure(s)", FAILURES_NAME, nfail)
    log.info("Verified %d file(s): %d missing, %d mismatched/duplicate, %d unlisted",
             checked, missing, mismatched, extra)
    ok = missing == 0 and mismatched == 0 and extra == 0
    log.info("VERIFY RESULT: %s", "PASS" if ok else "FAIL")
    log.info("=" * 72)
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    s = load_settings(argv)
    s.output_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(s.output_dir / LOG_NAME, s.verbose)
    if s.verify_only:
        return verify(s.output_dir)
    return Collector(s).run()


if __name__ == "__main__":
    sys.exit(main())
