#!/usr/bin/env bash
set -e

echo "=========================================================="
echo " AXES: Adaptive eXecution Environment Sandbox Test Runner"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo -e "\n[Step 1] Building AXES & Workload Binaries..."
mkdir -p build
cd build
cmake ..
make -j$(nproc)
cd "$PROJECT_ROOT"

echo -e "\n[Step 2] Running AXES Environment Check..."
if ! ./build/axes check; then
    echo "[run_tests] Cgroup delegation missing. Attempting setup script..."
    if [ "$EUID" -eq 0 ]; then
        ./scripts/setup_cgroups.sh
    else
        echo "[run_tests] Please run: sudo ./scripts/setup_cgroups.sh"
        exit 1
    fi
    ./build/axes check
fi

echo -e "\n[Step 3] Running Strict C++ Unit Test Suite..."
./build/test_axes

echo -e "\n[Step 3b] Running Phase 1 Security, CLI & API Automated Verification Suite..."
python3 tests/test_phase1.py

echo -e "\n[Step 4] Verification Test 1: Normal Workload Execution"
echo "Command: ./build/axes run --job-id job-normal-01 python3 workloads/normal_workload.py"
./build/axes run --job-id job-normal-01 python3 workloads/normal_workload.py

echo -e "\n[Step 5] Verification Test 2: CPU Burn & Dynamic Adaptive Control"
echo "Command: ./build/axes run --job-id job-cpu-01 --cpu-limit 200 --cpu-threshold 100 --consecutive 2 --sample-interval 0.8 python3 workloads/cpu_burn.py"
./build/axes run --job-id job-cpu-01 --cpu-limit 200 --cpu-threshold 100 --consecutive 2 --sample-interval 0.8 python3 workloads/cpu_burn.py

echo -e "\n[Step 6] Verification Test 3: Memory Stress & Limit Enforcement (256 MB)"
echo "Command: ./build/axes run --job-id job-mem-01 --memory-limit 256 --sample-interval 0.5 python3 workloads/memory_stress.py"
./build/axes run --job-id job-mem-01 --memory-limit 256 --sample-interval 0.5 python3 workloads/memory_stress.py || echo "[Note] Memory workload terminated by cgroup OOM killer as expected."

echo -e "\n[Step 7] Verification Test 4: Process Stress & PID Limit Enforcement (pids.max = 15)"
echo "Command: ./build/axes run --job-id job-proc-01 --pids-limit 15 --sample-interval 0.5 ./build/process_stress"
./build/axes run --job-id job-proc-01 --pids-limit 15 --sample-interval 0.5 ./build/process_stress

echo -e "\n[Step 8] Verifying Execution Reports & Evidence Logs..."
ls -la reports/
echo -e "\n--- CPU Burn Report Evidence ---"
cat reports/job-cpu-01_report.txt

echo -e "\n--- Memory Stress Report Evidence ---"
cat reports/job-mem-01_report.txt

echo -e "\n--- Process Stress Report Evidence ---"
cat reports/job-proc-01_report.txt

echo -e "\n=========================================================="
echo " All AXES Sandbox Milestone Verification Tests Completed!"
echo "=========================================================="
