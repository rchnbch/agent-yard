"""yardd: the host-side poll loop (systemd unit host/systemd/yardd.service).

Every ``poll_seconds``: read each running job's status file and log size via
``openshell sandbox exec``, enforce the wall-clock and idle limits, refresh
GitHub tokens, handle policy proposals, finish jobs whose main process
exited, and delete orphaned yard sandboxes. State is on disk, so a restart
picks up where it left off.
"""

from __future__ import annotations

import signal
import sys
import time

from .config import load_host
from .host import Yard

_stop = False


def _handle(signum, frame):  # noqa: ARG001
    global _stop
    _stop = True


def main() -> int:
    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    cfg = load_host()
    yard = Yard(cfg)
    while not _stop:
        started = time.time()
        try:
            yard.tick()
        except Exception as err:  # noqa: BLE001 - keep serving; the event log records it
            try:
                yard.events.append("host.warning", None, {"error": str(err)[:1000], "where": "daemon"})
            except OSError:
                print(f"yardd: {err}", file=sys.stderr)
        delay = max(1.0, cfg.poll_seconds - (time.time() - started))
        end = time.time() + delay
        while not _stop and time.time() < end:
            time.sleep(min(1.0, end - time.time()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
