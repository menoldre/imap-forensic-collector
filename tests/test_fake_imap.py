"""
End-to-end smoke test against an in-process fake IMAP server (plain TCP;
IMAP4_SSL is monkeypatched to IMAP4 for the test only).

Checks:
  * one .eml per message, bytes verbatim, --verify-only passes
  * server saw only non-mutating commands (no SELECT, STORE, COPY, APPEND, ...)
  * fetches used BODY.PEEK[] and no flags changed
  * resume after an aborted run: no duplicates, no gaps
  * UIDVALIDITY change on resume -> folder re-collected into __uidvalidity<N>
  * transient fetch failure -> retried; permanent failure -> failures.csv
  * modified UTF-7 folder names decoded; dir names sanitized

Run:  python tests/test_fake_imap.py
"""

from __future__ import annotations

import csv
import hashlib
import imaplib
import os
import re
import shutil
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import imap_forensic_collector as ifc  # noqa: E402

ifc.MIN_FETCH_INTERVAL = 0.0
ifc.BACKOFF_SECONDS = (0, 0, 0)

# --------------------------------------------------------------------------- #
# Fake server
# --------------------------------------------------------------------------- #

MSG_TEMPLATE = (
    b"From: Alice <alice@example.com>\r\n"
    b"To: bob@example.com\r\n"
    b"Cc: carol@example.com\r\n"
    b"Date: Mon, 24 Aug 2026 09:00:00 +0200\r\n"
    b"Message-ID: <%d@example.com>\r\n"
    b"Subject: =?UTF-8?B?w6TDtsO8?= Test %d\r\n"
    b"\r\n"
    b"Body of message %d with \xff raw high byte and bare\nLF line.\r\n"
)


class MailboxState:
    def __init__(self) -> None:
        # folder raw name -> dict(uidvalidity, delim, attrs, messages{uid: (bytes, flags)})
        self.folders: dict[str, dict] = {}
        self.commands: list[str] = []
        self.fail_fetch_once: set[tuple[str, int]] = set()
        self.fail_fetch_always: set[tuple[str, int]] = set()
        self.drop_after_fetches: int | None = None
        self.fetch_count = 0
        self.lock = threading.Lock()

    def add_folder(self, raw: str, uidvalidity: int, n: int, attrs="\\HasNoChildren", delim="."):
        msgs = {}
        for uid in range(1, n + 1):
            body = MSG_TEMPLATE % (uid, uid, uid)
            msgs[uid] = (body, "" if uid % 2 else "\\Seen")
        self.folders[raw] = {"uidvalidity": uidvalidity, "delim": delim, "attrs": attrs, "messages": msgs}


class Handler(socketserver.StreamRequestHandler):
    state: MailboxState

    def send(self, line: bytes) -> None:
        self.wfile.write(line + b"\r\n")

    def handle(self) -> None:
        st = self.state
        self.send(b"* OK fake IMAP ready")
        selected = None
        while True:
            line = self.rfile.readline()
            if not line:
                return
            line = line.rstrip(b"\r\n")
            parts = line.split(b" ", 2)
            tag = parts[0].decode()
            cmd = parts[1].decode().upper() if len(parts) > 1 else ""
            rest = parts[2].decode() if len(parts) > 2 else ""
            with st.lock:
                st.commands.append((cmd + " " + rest).strip())

            if cmd == "CAPABILITY":
                self.send(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN")
                self.send(f"{tag} OK done".encode())
            elif cmd == "LOGIN":
                self.send(f"{tag} OK logged in".encode())
            elif cmd == "LOGOUT":
                self.send(b"* BYE")
                self.send(f"{tag} OK bye".encode())
                return
            elif cmd == "LIST":
                self.send(b'* LIST (\\Noselect \\HasChildren) "." "Parent"')
                for raw, f in st.folders.items():
                    self.send(f'* LIST ({f["attrs"]}) "{f["delim"]}" "{raw}"'.encode())
                self.send(f"{tag} OK done".encode())
            elif cmd == "EXAMINE":
                raw = rest.strip().strip('"')
                f = st.folders.get(raw)
                if f is None:
                    self.send(f"{tag} NO no such mailbox".encode())
                    continue
                selected = raw
                self.send(f"* {len(f['messages'])} EXISTS".encode())
                self.send(f"* OK [UIDVALIDITY {f['uidvalidity']}] UIDs valid".encode())
                self.send(b"* FLAGS (\\Seen \\Answered)")
                self.send(f"{tag} OK [READ-ONLY] EXAMINE done".encode())
            elif cmd == "UID" and rest.upper().startswith("SEARCH"):
                f = st.folders[selected]
                self.send(("* SEARCH " + " ".join(str(u) for u in f["messages"])).encode())
                self.send(f"{tag} OK done".encode())
            elif cmd == "UID" and rest.upper().startswith("FETCH"):
                m = re.match(r"FETCH (\d+) \((.*)\)", rest, re.I)
                uid = int(m.group(1))
                items = m.group(2)
                assert "BODY.PEEK[]" in items, "test: fetch must use BODY.PEEK[]"
                assert "BODY[]" not in items.replace("BODY.PEEK[]", ""), "BODY[] would set \\Seen"
                f = st.folders[selected]
                with st.lock:
                    st.fetch_count += 1
                    n = st.fetch_count
                    drop = st.drop_after_fetches is not None and n > st.drop_after_fetches
                    if drop:
                        st.drop_after_fetches = None  # one-shot disconnect
                    if (selected, uid) in st.fail_fetch_once:
                        st.fail_fetch_once.discard((selected, uid))
                        self.send(f"{tag} NO temporary failure".encode())
                        continue
                    if (selected, uid) in st.fail_fetch_always:
                        self.send(f"{tag} NO permanent failure".encode())
                        continue
                if drop:
                    self.request.close()
                    return
                body, flags = f["messages"][uid]
                seq = list(f["messages"]).index(uid) + 1
                # Deliberately put FLAGS after the literal to exercise the parser.
                self.wfile.write(
                    f'* {seq} FETCH (UID {uid} RFC822.SIZE {len(body)} '
                    f'INTERNALDATE "24-Aug-2026 07:00:00 +0000" BODY[] {{{len(body)}}}\r\n'.encode()
                )
                self.wfile.write(body)
                self.wfile.write(f" FLAGS ({flags}))\r\n".encode())
                self.send(f"{tag} OK fetch done".encode())
            elif cmd == "NOOP":
                self.send(f"{tag} OK".encode())
            else:
                self.send(f"{tag} BAD unsupported {cmd}".encode())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server(state: MailboxState):
    Handler.state = state
    srv = Server(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


# --------------------------------------------------------------------------- #
# Test driver
# --------------------------------------------------------------------------- #

class PlainIMAP(imaplib.IMAP4):
    def __init__(self, host, port, ssl_context=None, timeout=None):
        super().__init__(host, port, timeout=timeout)


def run(args, port, out):
    cfg = out / "config.ini"
    cfg.write_text(
        f"[source]\nhost = 127.0.0.1\nport = {port}\nuser = tester\n"
        f"[collection]\noutput_dir = {out / 'coll'}\nexaminer = Test\ncase_id = T-1\n",
        encoding="utf-8",
    )
    os.environ["IMAP_PASSWORD"] = "x"
    return ifc.main(["--config", str(cfg), *args])


def manifest_rows(out):
    with open(out / "coll" / "manifest.csv", newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


MUTATING = {"SELECT", "STORE", "COPY", "MOVE", "APPEND", "EXPUNGE", "CLOSE", "CREATE",
            "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE", "SETACL"}


def assert_no_mutation(state: MailboxState):
    for c in state.commands:
        verb = c.split(" ", 1)[0]
        assert verb not in MUTATING, f"mutating command issued: {c}"
        if verb == "UID":
            sub = c.split(" ")[1].upper()
            assert sub in {"SEARCH", "FETCH"}, f"mutating UID command: {c}"
        if "FETCH" in c.upper():
            assert "BODY.PEEK[]" in c, f"non-PEEK fetch: {c}"


def main() -> None:
    imaplib.IMAP4_SSL = PlainIMAP  # test only
    tmp = Path(tempfile.mkdtemp(prefix="ifc_test_"))
    try:
        state = MailboxState()
        state.add_folder("INBOX", 1111, 7)
        state.add_folder("INBOX.Sent", 2222, 3)
        state.add_folder("INBOX.Archive.2019", 3333, 2)
        state.add_folder("&AOQ-ltere/Mail:x", 4444, 1)   # "ältere/Mail:x" -> sanitized
        srv, port = start_server(state)
        total = sum(len(f["messages"]) for f in state.folders.values())

        # 1. dry run writes only the log
        assert run(["--dry-run"], port, tmp) == 0
        assert not (tmp / "coll" / "manifest.csv").exists()
        assert (tmp / "coll" / "collection.log").exists()

        # 2. first run: connection dropped after 6 fetches -> reconnect; one uid fails once,
        #    one always fails -> failures.csv
        state.drop_after_fetches = 6
        state.fail_fetch_once.add(("INBOX.Sent", 2))
        state.fail_fetch_always.add(("INBOX.Sent", 3))
        rc = run([], port, tmp)
        state.drop_after_fetches = None
        rows = manifest_rows(tmp)
        assert rc == 0, rc  # completeness balances: written + failed == search
        assert len(rows) == total - 1, (len(rows), total)
        fails = list(csv.DictReader(open(tmp / "coll" / "failures.csv", encoding="utf-8-sig")))
        assert len(fails) == 1 and fails[0]["uid"] == "3" and fails[0]["attempts"] == "3", fails
        assert_no_mutation(state)
        # flags on server untouched
        assert state.folders["INBOX"]["messages"][1][1] == ""

        # bytes verbatim + hash + fields
        r = next(r for r in rows if r["folder"] == "INBOX" and r["uid"] == "1")
        p = tmp / "coll" / r["relative_path"]
        assert p.read_bytes() == MSG_TEMPLATE % (1, 1, 1)
        assert r["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()
        assert r["subject"] == "äöü Test 1", r["subject"]
        assert r["internaldate_utc"] == "2026-08-24T07:00:00+00:00"
        assert r["date_header"] == "Mon, 24 Aug 2026 09:00:00 +0200"
        assert r["flags"] == "" and r["uidvalidity"] == "1111"
        r2 = next(r for r in rows if r["folder"] == "INBOX" and r["uid"] == "2")
        assert r2["flags"] == "\\Seen"
        ru = next(r for r in rows if r["uid"] == "1" and r["folder"].startswith("ä"))
        assert ru["folder"] == "ältere/Mail:x" and ru["folder_dir"] == "ältere_Mail_x", ru
        assert (tmp / "coll" / "mail" / "INBOX.Archive.2019" / "000001.eml").exists()

        # 3. verify passes
        assert run(["--verify-only"], port, tmp) == 0
        # tamper -> verify fails
        p.write_bytes(p.read_bytes() + b"x")
        assert run(["--verify-only"], port, tmp) == 1
        p.write_bytes(MSG_TEMPLATE % (1, 1, 1))
        assert run(["--verify-only"], port, tmp) == 0

        # 4. resume: the permanently-failing message now succeeds; nothing else refetched
        state.fail_fetch_always.clear()
        before = state.fetch_count
        assert run(["--resume"], port, tmp) == 0
        assert state.fetch_count - before == 1, state.fetch_count - before
        rows = manifest_rows(tmp)
        assert len(rows) == total
        assert len({(r["folder"], r["uid"]) for r in rows}) == total  # no duplicates
        assert run(["--verify-only"], port, tmp) == 0

        # 5. simulate a killed run: delete a file that the manifest lists -> re-fetched on resume
        (tmp / "coll" / "mail" / "INBOX" / "000005.eml").unlink()
        assert run(["--verify-only"], port, tmp) == 1
        assert run(["--resume"], port, tmp) == 0
        assert run(["--verify-only"], port, tmp) == 0
        assert len(manifest_rows(tmp)) == total + 1  # re-fetch appends a row; latest row wins in verify

        # 6. UIDVALIDITY change on resume -> re-collect into __uidvalidity dir
        state.folders["INBOX.Sent"]["uidvalidity"] = 9999
        assert run(["--resume"], port, tmp) == 0
        assert (tmp / "coll" / "mail" / "INBOX.Sent__uidvalidity9999" / "000001.eml").exists()
        log_text = (tmp / "coll" / "collection.log").read_text(encoding="utf-8")
        assert "UIDVALIDITY CHANGED for folder INBOX.Sent" in log_text

        # 7. without --resume on an existing output dir -> refuses
        assert run([], port, tmp) == 2

        # 8. folder selection by name
        out2 = tmp / "sel"
        out2.mkdir()
        assert run(["--folders", "INBOX.Sent", "--output", str(out2 / "coll")], port, out2) == 0
        assert {r["folder"] for r in manifest_rows(out2)} == {"INBOX.Sent"}

        assert_no_mutation(state)
        srv.shutdown()
        print("ALL TESTS PASSED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
