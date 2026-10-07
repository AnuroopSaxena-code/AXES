#!/usr/bin/env python3
import time
import math
import os

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.isqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def main():
    print(f"[normal_workload] Starting normal finite workload (PID {os.getpid()})...")
    start = time.time()
    
    # Calculate prime numbers up to 100,000
    primes = [n for n in range(2, 100000) if is_prime(n)]
    
    elapsed = time.time() - start
    print(f"[normal_workload] Found {len(primes)} prime numbers in {elapsed:.3f} seconds.")
    print("[normal_workload] Execution completed successfully with exit code 0.")

if __name__ == "__main__":
    main()
