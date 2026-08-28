#!/usr/bin/env python3
"""
Restore the fixture Maildir into the running Dovecot test container.

    python restore_mailbox.py                       # restores ../testdata/dovecot-maildir-tester.tar.gz
    python restore_mailbox.py path/to/other.tar.gz

Replaces /srv/mail/tester inside the container with the tarball contents, which
reproduces the mailbox exactly: same folders, same UIDVALIDITY and UIDs
(dovecot-uidlist), same flags (Maildir filenames), same INTERNALDATE (file mtimes).

Test fixture only — this writes to the test server's storage, never to a real mailbox.
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT = HERE.parent / "testdata" / "dovecot-maildir-tester.tar.gz"


def main() -> int:
    tarball = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    if not tarball.is_file():
        print(f"tarball not found: {tarball}", file=sys.stderr)
        return 2
    compose = ["docker", "compose", "-f", str(HERE / "docker-compose.yml")]
    script = (
        "set -e; rm -rf /srv/mail/tester; mkdir -p /srv/mail; "
        "tar xzf - -C /srv/mail; chown -R 1000:1000 /srv/mail/tester; "
        "echo restored; find /srv/mail/tester -name dovecot-uidlist | wc -l"
    )
    with open(tarball, "rb") as fh:
        r = subprocess.run(compose + ["exec", "-T", "dovecot", "sh", "-c", script], stdin=fh)
    if r.returncode != 0:
        print("restore failed (is the container running? `docker compose up -d`)", file=sys.stderr)
        return r.returncode
    # Restart so Dovecot drops any cached index state from before the restore.
    subprocess.run(compose + ["restart", "dovecot"], check=True)
    print(f"restored {tarball.name} into container and restarted dovecot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
