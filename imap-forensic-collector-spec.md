# IMAP Forensic Collection Script — Build Spec

## Context

Build a single-purpose Python script that performs a defensible, read-only forensic
collection of an IMAP mailbox to individual `.eml` files plus a verification manifest.

The source is a Tucows/OpenSRS hosted mailbox (`mail.hostedemail.com` or
`mail.b.hostedemail.com`, IMAP over SSL on port 993). There is no vendor eDiscovery
export, so IMAP is the only collection interface. The output feeds into FTK.

This is evidence collection, not a backup utility. The overriding requirement is that
**the server is never modified and the message bytes are never altered.** Where a design
choice trades convenience against fidelity, choose fidelity.

## Environment

- Python 3.11+
- Standard library only (`imaplib`, `email`, `hashlib`, `csv`, `logging`, `argparse`,
  `ssl`, `datetime`, `pathlib`). Do not add third-party dependencies.
- Must run on both macOS and Windows. Windows path length is a real constraint — see
  the output layout section.

## Configuration

Read from a `config.ini` next to the script, with CLI overrides. Never hardcode
credentials and never write the password to the log or manifest.

```ini
[source]
host = mail.b.hostedemail.com
port = 993
user = custodian@example.com
# password read from IMAP_PASSWORD env var, or prompted via getpass if unset

[collection]
output_dir = ./collection_YYYY-MM-DD
folders = ALL          ; or comma-separated list of IMAP folder names
examiner = J. Smith    ; recorded in collection.log header
case_id = 2026-0042
```

CLI flags: `--config`, `--output`, `--folders`, `--resume`, `--verify-only`, `--dry-run`.

`--dry-run` enumerates folders and message counts and writes nothing but the log.

## Output layout

```
collection_2026-08-28/
├── manifest.csv
├── collection.log
└── mail/
    ├── INBOX/
    │   ├── 000001.eml
    │   └── 000002.eml
    ├── INBOX.Sent/
    └── INBOX.Archive.2019/
```

Rules:

- **One directory per IMAP folder, flat at a single level.** Do not recreate the folder
  hierarchy as nested directories. The full IMAP path becomes the directory name. This
  avoids both the server-dependent hierarchy delimiter (`.` vs `/`) and the Windows
  260-character path limit, which an old mailbox with dated archive folders will hit.
- Decode IMAP modified UTF-7 folder names to Unicode for display and logging. For the
  directory name, sanitize: replace the hierarchy delimiter with `.`, replace any
  character illegal on Windows (`<>:"|?*\/` and control characters) with `_`, and
  truncate to 100 characters. If sanitizing produces a collision, append `_2`, `_3`, etc.
  **Record both the raw IMAP folder name and the sanitized directory name in the log**,
  so the mapping is reconstructible.
- **Filename is the zero-padded IMAP UID**, six digits, `.eml` extension. Do not derive
  filenames from Subject or Message-ID — subjects collide and contain illegal
  characters, and Message-ID is frequently absent on older mail.

## Manifest schema

`manifest.csv`, UTF-8 with BOM (so Excel opens it correctly), one row per message:

| column | notes |
|---|---|
| `folder` | raw IMAP folder name, decoded to Unicode |
| `folder_dir` | sanitized directory name as written to disk |
| `uidvalidity` | from the folder's SELECT/EXAMINE response |
| `uid` | IMAP UID, integer |
| `relative_path` | e.g. `mail/INBOX/000001.eml` |
| `internaldate_utc` | ISO 8601, UTC, from IMAP INTERNALDATE |
| `date_header` | raw `Date:` header value, verbatim, empty if absent |
| `flags` | space-separated IMAP flags as returned |
| `size_bytes` | actual bytes written to disk |
| `rfc822_size` | size the server reported, for comparison |
| `sha256` | hash of the exact bytes written |
| `message_id` | raw `Message-ID:` header, empty if absent |
| `from` | raw `From:` header |
| `to` | raw `To:` header |
| `cc` | raw `Cc:` header |
| `subject` | decoded `Subject:` per RFC 2047; if decoding fails, write the raw value |

Two deliberate points:

- `internaldate_utc` and `date_header` sit side by side because the server's receipt
  time and the client-supplied send time are different claims. A discrepancy between
  them is evidentially interesting and must be visible without re-parsing the corpus.
- `uidvalidity` is captured per row, not once per run. If the server ever renumbers a
  folder, that value is what proves the UIDs no longer mean what they did.

## Core behavior

### Connection

- `imaplib.IMAP4_SSL` with a default `ssl.create_default_context()`. Do not disable
  certificate verification.
- Login, then enumerate folders with `LIST`. Skip any folder whose attributes include
  `\Noselect`.

### Per folder

1. `conn.select(folder, readonly=True)` — this issues `EXAMINE`, not `SELECT`. This is
   mandatory. `readonly=True` is what keeps the collection non-mutating.
2. Capture `UIDVALIDITY` from the response.
3. `conn.uid('SEARCH', None, 'ALL')` to get the full UID list. Record the count.
4. Fetch each message individually:
   `conn.uid('FETCH', uid, '(BODY.PEEK[] INTERNALDATE FLAGS RFC822.SIZE)')`

   **`BODY.PEEK[]`, never `BODY[]`.** `BODY[]` sets the `\Seen` flag, which writes to
   the server and alters the evidence. This is the single most important line in the
   script.

### Writing messages

- Write the returned message bytes **verbatim**, in binary mode. Do not decode to str,
  do not normalize line endings, do not parse-and-reserialize through the `email`
  module, do not strip or add anything.
- Compute SHA-256 over the exact byte string written.
- For manifest header fields, parse a **copy** of the bytes with
  `email.parser.BytesParser().parsebytes()`. The parsed object is read-only scratch —
  it must never be the source of what lands on disk.
- Compare `size_bytes` against `rfc822_size`. A mismatch is not necessarily fatal
  (servers sometimes report approximate sizes), but log it as a WARNING per message.

### Resume

`--resume` reads the existing `manifest.csv` and skips any `(folder, uidvalidity, uid)`
already present. If a folder's current UIDVALIDITY differs from what the manifest
recorded for it, do not skip — log an ERROR, re-collect the folder into a
`folder_dir__uidvalidity<N>` directory, and flag it prominently in the summary. Silent
resumption across a UIDVALIDITY change would corrupt the collection.

### Verification

`--verify-only` re-reads every file listed in the manifest, recomputes SHA-256, and
reports any mismatch or missing file. Exit non-zero if anything fails. This is the mode
that gets run after collection and whose output gets retained.

## Error handling

- Retry individual message fetches up to 3 times with exponential backoff (2s, 4s, 8s).
- On connection loss, reconnect and resume the current folder from the last successful
  UID rather than restarting.
- **Never skip a message silently.** Any message that cannot be fetched after retries
  gets a row in `failures.csv` (`folder`, `uid`, `error`, `attempts`) and an ERROR log
  entry. A collection with known gaps that are documented is defensible; one with
  undocumented gaps is not.
- Rate-limit to roughly 10 fetches/second. Hosted providers throttle aggressively and a
  disconnect mid-run is more expensive than the delay.

## Logging

`collection.log`, plaintext, timestamped in UTC, at INFO by default.

Header block written at start: script version, UTC start time, examiner, case_id, host,
user, Python version, hostname of the collecting machine.

Then: folder enumeration results, per-folder UIDVALIDITY and message count, per-message
progress at DEBUG, warnings and errors at their level.

Footer block at end: UTC end time, elapsed, per-folder counts of
attempted/written/failed, total bytes, and a completeness check — **for each folder,
assert that the number of `.eml` files written plus the number of failures equals the
count returned by SEARCH.** Report any mismatch as a prominent ERROR.

## Non-goals — do not implement

- No deletion, moving, flagging, appending, or any other write operation against the
  server. The script issues no IMAP command that mutates state.
- No deduplication, filtering, keyword search, or date-range limiting. Collect
  everything; culling happens downstream in FTK.
- No conversion to PST, mbox, or any other container.
- No modification of message content for any reason, including malformed headers,
  encoding errors, or apparent corruption. Broken messages get written broken.

## Acceptance criteria

1. A run against a test mailbox produces one `.eml` per message, and `--verify-only`
   passes clean.
2. Inspecting the test mailbox afterward shows **no messages changed from unread to
   read** and no flags altered.
3. Killing the process mid-run and re-running with `--resume` completes the collection
   with no duplicates and no gaps.
4. The per-folder completeness check in the log footer balances for every folder.
5. `manifest.csv` opens in Excel with correct Unicode in the subject column.
