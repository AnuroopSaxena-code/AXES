#!/usr/bin/env python3
import time
import multiprocessing
import os
import sys

def cpu_intensive_worker(worker_id):
    print(f"[cpu_burn] Worker {worker_id} (PID {os.getpid()}) started CPU burn loop.")
    start = time.time()
    count = 0
    while time.time() - start < 12.0:
        # Perform heavy mathematical computations
        _ = [x**2.5 for x in range(50000)]
        count += 1
    print(f"[cpu_burn] Worker {worker_id} finished after {count} iterations.")

def main():
    print(f"[cpu_burn] Starting CPU burn workload (PID {os.getpid()})...")
    num_workers = min(multiprocessing.cpu_count(), 2)
    processes = []
    
    for i in range(num_workers):
        p = multiprocessing.Process(target=cpu_intensive_worker, args=(i+1,))
        p.start()
        processes.append(p)
        
    for p in processes:
        p.join()
        
    print("[cpu_burn] CPU burn workload completed cleanly.")

if __name__ == "__main__":
    main()
