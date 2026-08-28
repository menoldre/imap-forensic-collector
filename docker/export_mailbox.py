#!/usr/bin/env python3
"""
Export the tester Maildir from the running Dovecot test container to a tarball.

    python export_mailbox.py                        # writes ../testdata/dovecot-maildir-tester.tar.gz
    python export_mailbox.py path/to/output.tar.gz

This is how the fixture in testdata/ was produced (after seed_mailbox.py).
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT = HERE.parent / "testdata" / "dovecot-maildir-tester.tar.gz"


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    out.parent.mkdir(parents=True, exist_ok=True)
    compose = ["docker", "compose", "-f", str(HERE / "docker-compose.yml")]
    with open(out, "wb") as fh:
        r = subprocess.run(
            compose + ["exec", "-T", "dovecot", "sh", "-c", "cd /srv/mail && tar czf - tester"],
            stdout=fh,
        )
    if r.returncode != 0:
        print("export failed (is the container running?)", file=sys.stderr)
        return r.returncode
    print(f"exported to {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
