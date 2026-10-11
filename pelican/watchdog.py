"""
Last-resort, deliberately blunt process watchdog, shared by every crawler.

No per-call timeout can be trusted to catch every possible hang: SMB, HTTP
(OpenSearch, Graph) and subprocess calls have each been observed, directly, to
block indefinitely against a connection that's gone silent -- past their own
documented timeout, with no exception, no CPU use, and no way for the rest of
the program to notice. Worse, ThreadPoolExecutor's own worker threads are NOT
daemon threads, so even a caught, handled failure can leave a container's
Python process unable to exit afterward: normal shutdown tries to join every
worker thread, including one still blocked forever in a call nothing here can
interrupt.

Rather than hunt each specific hang, this watches for forward progress *at
all* (via heartbeat()) and kills the process outright if none happens for too
long. os._exit() skips normal shutdown (no thread joins, no atexit), so a
stuck thread can no longer prevent the container from ending and being
retried on the next scheduled run -- whichever call turns out to be stuck.

Usage: call start_watchdog() once, near the top of run(). Call heartbeat(note)
at every point that represents real progress (a batch indexed, a poll
attempt, a diagnostic tick) -- including right before a call that might be
the one that hangs, not just after it succeeds, so the watchdog's clock
reflects reality even when that specific call is the one stuck.
"""

import os
import threading
import time

WATCHDOG_TIMEOUT_SECONDS = int(os.environ.get("WATCHDOG_TIMEOUT_SECONDS", "600"))
_last_progress = time.time()
_last_progress_note = "startup"


def heartbeat(note: str) -> None:
    global _last_progress, _last_progress_note
    _last_progress = time.time()
    _last_progress_note = note


def _watchdog_loop() -> None:
    while True:
        time.sleep(30)
        idle = time.time() - _last_progress
        if idle > WATCHDOG_TIMEOUT_SECONDS:
            # print(), not logging -- this must survive right up to the abrupt
            # exit below. -u (unbuffered stdout, set on the container's
            # entrypoint) is what makes sure it actually reaches `docker logs`.
            print(f"WATCHDOG: no progress for {idle:.0f}s (last: '{_last_progress_note}') -- "
                  f"forcibly exiting so this container doesn't hang forever; will retry next scheduled run",
                  flush=True)
            os._exit(1)


def start_watchdog() -> None:
    threading.Thread(target=_watchdog_loop, daemon=True).start()
