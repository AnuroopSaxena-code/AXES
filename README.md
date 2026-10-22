# AXES: Adaptive eXecution Environment Sandbox

[![Language](https://img.shields.io/badge/Language-C%2B%2B17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2-orange.svg)](https://www.kernel.org/)
[![Kernel](https://img.shields.io/badge/cgroups-v2-green.svg)](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
[![Security](https://img.shields.io/badge/Isolation-Namespaces%20%2B%20Seccomp--BPF-red.svg)](docs/THREAT_MODEL.md)
[![Workbench](https://img.shields.io/badge/Workbench-Developer%20GUI-brightgreen.svg)](http://127.0.0.1:8080)

AXES (**Adaptive eXecution Environment Sandbox**) is a lightweight, low-overhead Linux execution supervisor and developer workbench designed to safely execute untrusted programs, benchmarks, and autonomous workloads. AXES combines **Linux cgroups v2**, **Linux namespaces (PID, Mount, Net, IPC, UTS, Cgroup)**, and **Seccomp-BPF syscall filtering** to enforce strict resource bounds and defense-in-depth isolation with a strict **fail-closed guarantee (no host fallback)**.

---

## 📸 Architecture & Defense-in-Depth Model

```text
                                  +-----------------------+
                                  |  Developer Workbench  |
                                  |  (http://127.0.0.1)   |
                                  +-----------+-----------+
                                              | REST API (localhost only)
                                              v
+------------------+   CLI / REST    +-----------------------+
| Staged Workload  | --------------> |  AXES Supervisor C++  |
+------------------+                 +-----------+-----------+
                                                  |
         +----------------------------------------+----------------------------------------+
         |                                        |                                        |
         v                                        v                                        v
+-----------------------+                +-----------------------+                +-----------------------+
|   cgroups v2 Engine   |                |   Monitor & Policy    |                | Isolated Child Sandbox|
| /sys/fs/cgroup/axes/  |                | Real-time sampling    |                | Bubblewrap (bwrap)    |
| - cpu.max (quota)     |                | Two-way CPU policy    |                | - PID/MNT/NET/IPC/UTS |
| - memory.max (ceiling)|                | Consecutive threshold |                | - Read-only /workspace|
| - memory.swap.max = 0 |                | One-way hysteresis    |                | - Ephemeral /tmp tmpfs|
| - pids.max (limits)   |                | Subreaper cleanup     |                | - Cap-drop ALL        |
| - cgroup.kill (atomic)|                | JSON / text reports   |                | - Seccomp-BPF allowlist|
+-----------------------+                +-----------------------+                +-----------------------+
```

### Key Capabilities

1. **Defense-in-Depth Isolation (`--isolation isolated`)**
   - **Linux Namespaces:** Virtualizes PID, Mount, Network, IPC, UTS, and Cgroup hierarchies via Bubblewrap.
   - **Filesystem Virtualization:** Staged workspace is mounted read-only at `/workspace` (writes return `EROFS`). Ephemeral scratch space at `/tmp` backed by isolated `tmpfs`. Host roots (e.g. `/mnt/c`, `/sys/fs/cgroup`) are unmapped.
   - **Network Block:** Workload runs with loopback only; network sockets and connections return `EPERM` or `ENETUNREACH`.
   - **Privilege Stripping:** `PR_SET_NO_NEW_PRIVS` prevents setuid transitions; `cap-drop ALL` strips all Linux capabilities (`CapEff = 0`).
   - **Seccomp-BPF Syscall Filtering:** Classic BPF allowlist sealed in memory via `memfd_create`. Blocks `ptrace`, `unshare`, `setns`, `mount`, `bpf`, `kexec_load`, and module loading (`EPERM`), while forcing `clone3` to fall back to `clone()` (`ENOSYS`).
   - **Fail-Closed Guarantee:** Setup failures terminate the child (`_exit(126)`) and clean up the cgroup. AXES never falls back to host execution.

2. **Dedicated cgroups v2 Resource Containment**
   - Per-job execution sandboxes under `/sys/fs/cgroup/axes/<job_id>`.
   - Strictly enforces CPU bandwidth (`cpu.max`), memory ceilings (`memory.max`), swap suppression (`memory.swap.max = 0`), and process count ceilings (`pids.max`).
   - Atomic process tree termination using kernel `cgroup.kill` and fallback SIGKILL loops.

3. **Deterministic Adaptive CPU Policy**
   - Continuous metric sampling (`CPU %`, `Memory MB`, `PID count`, `Duration`).
   - Threshold detection: triggers only after `consecutive_samples_required` consecutive monitoring cycles above `cpu_threshold_pct`.
   - One-way hysteresis latch: reduces quota (e.g., from 150% down to 50%) and latches until job exit to prevent rapid quota thrashing.

4. **Non-Blocking Telemetry & Real Output Capture**
   - Workload `stdout`/`stderr` captured separately into `reports/<job_id>_output.log` without contaminating telemetry logs.
   - Bounded output stream capped at `max_output_bytes` (default 10 MB) to prevent disk exhaustion.

5. **Developer Execution Workbench (GUI)**
   - Embedded Python REST API server (`web/server.py`) serving an IDE-style workbench at `http://127.0.0.1:8080`.
   - Staged file explorer with drag-and-drop / multipart upload, in-situ C/C++ compilation with compiler diagnostic capture, live incremental terminal output streaming, real-time telemetry meters, and persisted report viewer.

---

## 📁 Repository Structure

```
AXES/
├── CMakeLists.txt              # CMake build configuration (C++17)
├── README.md                   # Complete system documentation
├── AXES_COMPLETION_PLAN.md     # Engineering phases and verification status
├── AXES_FINAL_VERIFICATION.md  # Final verification report and checklist
├── docs/
│   ├── API.md                  # REST API contract and schema specification
│   ├── THREAT_MODEL.md         # Comprehensive security and threat model
│   └── evidence/               # GUI and execution evidence screenshots
├── scripts/
│   └── setup_cgroups.sh        # cgroups v2 subtree delegation script
├── src/
│   ├── main.cpp                # CLI entry point, safe argument parser
│   ├── launcher.hpp            # Process execution launcher & supervisor header
│   ├── launcher.cpp            # Process launch, sync barrier, monitoring loop, report writer
│   ├── security.hpp            # Namespace isolation and seccomp header
│   ├── security.cpp            # Bubblewrap containment and sealed BPF seccomp filter
│   ├── policy.hpp              # Deterministic CPU hysteresis policy
│   ├── cgroup.hpp              # cgroups v2 controller interface header
│   ├── cgroup.cpp              # cgroups v2 directory & limit management
│   ├── monitor.hpp             # Resource tracking monitor header
│   └── monitor.cpp             # Periodic metric sampling
├── staging/                    # Managed directory for staged workloads & binaries
├── workloads/
│   ├── cpu_burn.py             # Multi-process sustained CPU burn workload
│   ├── memory_stress.py        # Gradual memory allocation stress workload
│   ├── process_stress.c        # Fork loop process creation stress workload
│   └── normal_workload.py      # Finite computation normal workload
├── tests/
│   ├── test_suite.cpp          # C++ unit test suite source
│   ├── test_phase1.py          # Phase 1 CLI validation & web security tests
│   ├── test_phase2.py          # Phase 2 runtime lifecycle & workbench backend tests
│   ├── test_workbench.py       # Workbench API contract & kernel evidence tests
│   ├── test_security.py        # Phase 4 security, namespace, and seccomp tests
│   └── fixtures/               # Test fixtures and compilation test cases
├── web/
│   ├── server.py               # Local REST API server (127.0.0.1:8080)
│   ├── index.html              # Developer workbench interface
│   ├── style.css               # Dark theme stylesheet
│   └── app.js                  # Workbench logic and incremental terminal poller
└── reports/                    # Execution report output directory (.txt & .json)
```

---

## 🚀 Quick Start & Building

### System Requirements
- **OS:** Linux / Ubuntu on WSL2 (Kernel >= 5.14 with cgroups v2 mounted at `/sys/fs/cgroup`).
- **Dependencies:** `bubblewrap` (`bwrap`), `gcc`, `g++`, `cmake`, `python3`.
- **User:** Ordinary unprivileged user account (supervisor and workloads refuse root).

### 1. One-Time Setup: cgroup v2 Subtree Delegation
Delegate write permissions for `/sys/fs/cgroup/axes` to your unprivileged user account:

```bash
sudo ./scripts/setup_cgroups.sh
```

### 2. Compilation
Build the AXES binaries (`axes`, `test_axes`, `process_stress`):

```bash
cmake -S . -B build
cmake --build build -j
```

### 3. Verify System Environment
Verify that cgroups v2 controllers (`cpu`, `memory`, `pids`) are active and writable:

```bash
./build/axes check
```

---

## 💻 CLI Usage

```bash
./build/axes run [options] [--] <program> [args...]
```

### CLI Options Summary
| Option | Default | Description |
| :--- | :--- | :--- |
| `--isolation <mode>` | `resource` | Isolation boundary: `isolated` (namespaces + seccomp) or `resource` (cgroups only) |
| `--workspace <path>` | `.` | Staging workspace path mounted read-only at `/workspace` in isolated mode |
| `--job-id <id>` | auto | Unique alphanumeric job identifier `[a-zA-Z0-9_-]` (1–64 chars) |
| `--cpu-limit <pct>` | `200` | Initial CPU quota limit percentage (`1.0%` to `10,000.0%`) |
| `--memory-limit <mb>` | `512` | Memory ceiling in MB (`1` to `1,048,576 MB`) |
| `--pids-limit <count>` | `64` | Maximum allowable active processes (`1` to `4,194,304`) |
| `--timeout <sec>` | `0.0` (off) | Wall-clock execution timeout in seconds (`0.01` to `86,400.0`) |
| `--output-file <path>` | auto | Target file for child stdout/stderr (default: `reports/<job_id>_output.log`) |
| `--max-output <mb>` | `10` | Maximum retained output size in MB before stream truncation |
| `--cpu-threshold <pct>`| `150` | CPU % threshold to trigger adaptive throttling |
| `--consecutive <n>` | `3` | Consecutive samples above threshold required to adapt |
| `--reduced-cpu <pct>` | `100` | Reduced CPU limit after adaptation trigger |
| `--sample-interval <s>`| `1.0` | Metric sampling interval in seconds (`0.05` to `3600.0`) |
| `--no-adaptive` | `false` | Disable dynamic adaptive CPU throttling |
| `--help` | - | Display CLI options and usage help |

---

## 🌐 Developer Workbench (GUI)

AXES includes a local developer workbench with an integrated terminal, real-time telemetry meters, file staging, and compilation controls.

### Launching the Workbench
From the repository root (as an unprivileged user):

```bash
python3 web/server.py
```

Open your browser at:  
👉 **`http://127.0.0.1:8080`**

### Workbench Capabilities
- **Execution Boundary Selector**: Choose between **Isolated** (`namespaces + Seccomp + read-only /workspace + no network`) and **Resource controls only** (for trusted benchmarking).
- **Staging Explorer**: Drag-and-drop or browse files into `staging/`. Supports Python scripts, shell scripts, and native binaries.
- **In-Situ Compilation**: Select `.c` or `.cpp` files and compile them into native `.bin` binaries with immediate GCC error diagnostics.
- **Streaming Terminal**: Non-blocking incremental output polling (renders up to 500,000 characters) with auto-scroll and clear controls.
- **Kernel Enforcement Panel**: Real-time display of measured CPU/Memory vs configured ceilings, supervisor PID attachment verification badge, and raw `/sys/fs/cgroup` control file inspector.
- **Execution History & Reports**: Access full historical reports (`.txt` and `.json`) with timing, peaks, and event logs.

---

## 🧪 Workload Verification Demos

### 1. Dynamic Adaptive CPU Control Demo
Runs a CPU burn workload under a 150% quota. When sustained usage exceeds 100% for 2 consecutive samples, AXES dynamically rewrites `cpu.max` down to 50%:

```bash
./build/axes run --job-id demo-cpu --timeout 3.0 --cpu-limit 150 --cpu-threshold 100 --consecutive 2 --reduced-cpu 50 python3 workloads/cpu_burn.py
```

### 2. Memory Containment (OOM Kill) Demo
Allocates memory up to the 64 MB ceiling. With swap disabled (`memory.swap.max = 0`), the kernel terminates the process via `SIGKILL` (exit code `137`):

```bash
./build/axes run --job-id demo-mem --timeout 5.0 --memory-limit 64 python3 workloads/memory_stress.py
```

### 3. Process Limit (PID Bounds) Demo
Forks child processes until reaching `pids.max = 4`, causing subsequent forks to fail with `EAGAIN` (`Resource temporarily unavailable`):

```bash
./build/axes run --job-id demo-pids --pids-limit 4 ./build/process_stress
```

### 4. Isolated Workload Execution Demo
Executes a Python script inside full namespace and Seccomp containment with read-only workspace:

```bash
./build/axes run --job-id demo-iso --isolation isolated --workspace staging --timeout 3.0 python3 /workspace/workbench_smoke.py
```

---

## 🧪 Automated Test Suites

AXES includes 53 comprehensive automated tests across 5 test suites:

```bash
# 1. C++ Unit Tests (Job validation, cgroup lifecycle, monitor, launcher timeout)
./build/test_axes

# 2. Phase 1 Integration Tests (CLI bounds, path traversal, origin/host security)
python3 tests/test_phase1.py

# 3. Phase 2 Integration Tests (Lifecycle, output bounding, staging, compilation, stop)
python3 tests/test_phase2.py

# 4. Workbench Contract Tests (Kernel controls, lossless UTF-8, process cleanup)
python3 tests/test_workbench.py

# 5. Phase 4 Security Integration Tests (Namespaces, seccomp, fail-closed, latching)
python3 -m unittest tests/test_security.py
```

---

## 🔒 Security Architecture & Threat Model

For detailed documentation of trust boundaries, privilege separation, Seccomp allowlists, and attack surface analysis, refer to [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## 📜 License

Developed for Operating Systems Architecture & Resource Management research. Distributed under the MIT License.
