# imap-forensic-collector

Defensible, **read-only** forensic collection of an IMAP mailbox to individual
`.eml` files plus a SHA-256 verification manifest. Built for Tucows/OpenSRS hosted
mail (`mail.hostedemail.com`, IMAP/SSL 993) where no vendor eDiscovery export
exists; output is intended for ingestion into FTK.

The script never modifies the server and never alters message bytes:

- Folders are opened with `EXAMINE` (`select(..., readonly=True)`), never `SELECT`.
- Messages are fetched with `BODY.PEEK[]`, never `BODY[]`, so `\Seen` is never set.
- No `STORE`, `COPY`, `MOVE`, `APPEND`, `EXPUNGE`, `CLOSE`, or any other mutating command is issued.
- Message bytes are written verbatim in binary mode; SHA-256 is computed over exactly those bytes.
- Header fields for the manifest are parsed from a scratch copy that never touches disk.

Standard library only; Python 3.11+; macOS and Windows.

## Usage

```
cp config.ini.example config.ini      # edit host / user / examiner / case_id
export IMAP_PASSWORD='...'            # or omit to be prompted via getpass

python imap_forensic_collector.py --dry-run        # enumerate folders + counts, writes only the log
python imap_forensic_collector.py                  # collect
python imap_forensic_collector.py --resume         # continue an interrupted run (no dupes, no gaps)
python imap_forensic_collector.py --verify-only    # re-hash everything in manifest.csv; exit 1 on any problem
```

Flags: `--config PATH`, `--output DIR`, `--folders ALL|A,B,C`, `--resume`,
`--verify-only`, `--dry-run`, `--verbose` (per-message DEBUG lines in the log).

## Output

`output_dir` in `config.ini` (or `--output`) accepts `{user}` (mailbox login) and
`{date}` (UTC run date) tokens; default is `./collection_{user}`. The run date is
recorded in the log header and footer.

```
collection_custodian@example.com/
├── manifest.csv       UTF-8 with BOM; one row per message (see spec for columns)
├── failures.csv       only if any message could not be fetched after 3 attempts
├── manifest.sha256    SHA-256 of manifest.csv as of the end of the last run
├── collection.log     UTC-timestamped; header/footer blocks + per-folder completeness check
└── mail/
    ├── INBOX/000001.eml
    ├── INBOX.Sent/
    └── INBOX.Archive.2019/
```

One flat directory per IMAP folder (full IMAP path, delimiter → `.`, Windows-illegal
characters → `_`, truncated to 100 chars); filenames are the zero-padded IMAP UID.
The raw IMAP folder name ↔ directory name mapping is recorded in the log and in every
manifest row (`folder`, `folder_dir`, `uidvalidity`).

## Resume semantics

`--resume` skips any `(folder, uidvalidity, uid)` already in `manifest.csv` whose
file exists on disk. If a folder's UIDVALIDITY has changed since the manifest was
written, it is logged as an ERROR and the folder is re-collected in full into
`<folder_dir>__uidvalidity<N>/`. The manifest is append-only; `--verify-only`
treats the last row for a given path as authoritative and reports superseded rows.

## Manifest hash chain

Every collect/resume run ends by hashing `manifest.csv`, logging the digest in the
footer, and writing it to `manifest.sha256`. `--resume` and `--verify-only` begin by
re-hashing the manifest and comparing to that sidecar: a match is logged as
"unchanged since last run"; a mismatch is logged as an ERROR (the manifest was edited
outside the tool) and fails verification. The log therefore records an unbroken chain
of manifest hashes across runs.

## Testing

`tests/test_fake_imap.py` runs the collector end to end against an in-process fake
IMAP server, covering: verbatim bytes and hash checks, reconnect mid-folder, transient
and permanent fetch failures, resume without duplicates or gaps, UIDVALIDITY change
handling, modified-UTF-7 folder names, and an assertion that no mutating command was
ever sent.

```
python tests/test_fake_imap.py
```

See `imap-forensic-collector-spec.md` for the full build specification.
