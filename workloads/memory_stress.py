#!/usr/bin/env python3
import time
import os
import sys

def main():
    print(f"[memory_stress] Starting memory allocation workload (PID {os.getpid()})...")
    chunks = []
    chunk_size_mb = 64
    target_chunks = 12 # Target ~768 MB (exceeds 512 MB default limit)

    try:
        for i in range(target_chunks):
            allocated_mb = (i + 1) * chunk_size_mb
            print(f"[memory_stress] Allocating chunk {i+1}/{target_chunks} ({chunk_size_mb} MB) -> Total Allocated: {allocated_mb} MB")
            # Allocate byte array filled with non-zero bytes to ensure physical RSS backing
            data = bytearray(chunk_size_mb * 1024 * 1024)
            for j in range(0, len(data), 4096):
                data[j] = 1
            chunks.append(data)
            time.sleep(0.8)
        print("[memory_stress] Completed all memory allocations successfully.")
    except MemoryError:
        print("[memory_stress] MemoryError caught! Memory limit successfully enforced by environment.")
        sys.exit(0)

if __name__ == "__main__":
    main()
