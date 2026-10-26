#!/usr/bin/env python3
"""Short CPU-pressure workload for the AXES review demonstration."""

import hashlib
import os
import time


def main():
    duration_seconds = 12.0
    started = time.monotonic()
    interval_started = started
    interval_iterations = 0
    total_iterations = 0
    payload = b"AXES quota demonstration"

    print(f"[quota_demo] PID {os.getpid()} starting {duration_seconds:.0f}s CPU workload", flush=True)
    print("[quota_demo] Watch iterations/second fall after AXES reduces cpu.max", flush=True)

    while True:
        now = time.monotonic()
        if now - started >= duration_seconds:
            break

        payload = hashlib.sha256(payload).digest()
        interval_iterations += 1
        total_iterations += 1

        if now - interval_started >= 1.0:
            elapsed = now - interval_started
            rate = interval_iterations / elapsed
            print(
                f"[quota_demo] t={now - started:4.1f}s  work_rate={rate:,.0f} iterations/s",
                flush=True,
            )
            interval_started = now
            interval_iterations = 0

    print(f"[quota_demo] completed; total iterations={total_iterations:,}", flush=True)


if __name__ == "__main__":
    main()
