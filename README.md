# AXES: Adaptive eXecution Environment Sandbox

[![Language](https://img.shields.io/badge/Language-C%2B%2B17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2-orange.svg)](https://www.kernel.org/)
[![Kernel](https://img.shields.io/badge/cgroups-v2-green.svg)](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
[![Web GUI](https://img.shields.io/badge/Dashboard-Python%20%7C%20REST-brightgreen.svg)](http://127.0.0.1:8080)

AXES (**Adaptive eXecution Environment Sandbox**) is a lightweight, low-overhead Linux execution supervisor designed to safely execute untrusted programs and autonomous workloads. AXES leverages **Linux cgroups v2** to strictly monitor resource consumption, enforce isolation ceilings, and dynamically adapt execution parameters (such as CPU throttling) in real time.

---

## 📸 Overview & Architecture

```text
                                  +-----------------------+
                                  |   Web Dashboard GUI   |
                                  |  (http://127.0.0.1)   |
                                  +-----------+-----------+
                                              | REST API
                                              v
+------------------+   CLI / REST    +-----------------------+
| User / Workload  | --------------> |  AXES Engine (C++17)  |
+------------------+                 +-----------+-----------+
                                                 |
         +---------------------------------------+---------------------------------------+
         |                                       |                                       |
         v                                       v                                       v
+------------------+                   +------------------+                   +------------------+
| cgroups v2 Ctrl  |                   | Monitor Engine   |                   | Process Lifecycle|
| /sys/fs/cgroup/  |                   | /proc & cgroups  |                   | fork() & execvp()|
| cpu, memory, pids|                   | periodic metrics |                   | sync pipes       |
+------------------+                   +------------------+                   +------------------+
```

### Key Features

1. **Process Lifecycle Tracking & Synchronization**
   - Precise process execution using POSIX `fork()` and `execvp()`.
   - Inter-process pipe synchronization ensuring cgroup limits and PID attachments are active before execution begins.

2. **Dedicated cgroups v2 Sandbox Isolation**
   - Per-job execution sandboxes under `/sys/fs/cgroup/axes/<job_id>`.
   - Enforces CPU bandwidth (`cpu.max`), memory ceilings (`memory.max`), swap suppression (`memory.swap.max = 0`), and PID limits (`pids.max`).

3. **Dynamic Adaptive CPU Throttling**
   - Continuous real-time metric sampling (CPU %, Memory MB, PID count, execution duration).
   - Autonomous CPU limit reduction (e.g., rewriting `cpu.max` from 200% down to 100%) when sustained high CPU utilization is detected over consecutive sample windows.

4. **Real-time Local Web Dashboard**
   - Embedded Python REST API server (`web/server.py`) serving a responsive, dark-mode dashboard at `http://127.0.0.1:8080`.
   - Live canvas charts for CPU & memory telemetry, cgroup system readiness badges, active raw kernel control table, and execution history modal log viewer.

5. **Built-in Workload Verification Suite**
   - Automated scripts demonstrating CPU burn, memory OOM containment, PID limit bounds, and normal process completion.
   - Structured text report generation with raw kernel control file evidence saved in `reports/`.

---

## 📁 Repository Structure

```
AXES/
├── CMakeLists.txt              # CMake build configuration (C++17)
├── README.md                   # Complete system documentation
├── .gitignore                  # Git ignore rules for build & temp files
├── scripts/
│   └── setup_cgroups.sh        # cgroup v2 subtree delegation setup script
├── src/
│   ├── main.cpp                # CLI entry point, argument parser, environment check
│   ├── launcher.hpp            # Process execution launcher & supervisor header
│   ├── launcher.cpp            # Process launch, sync pipe, monitoring loop, report writer
│   ├── cgroup.hpp              # cgroups v2 controller interface header
│   ├── cgroup.cpp              # cgroups v2 directory & limit management
│   ├── monitor.hpp             # Resource tracking monitor header
│   └── monitor.cpp             # Periodic metric sampling & procfs fallback
├── workloads/
│   ├── cpu_burn.py             # Multi-process sustained CPU burn workload
│   ├── memory_stress.py        # Gradual memory allocation stress workload
│   ├── process_stress.c        # Fork loop process creation stress workload
│   └── normal_workload.py      # Finite computation normal workload
├── tests/
│   ├── test_suite.cpp          # C++ unit test suite source
│   └── run_tests.sh            # End-to-end automated verification test runner
├── web/
│   ├── server.py               # Python REST API server (localhost:8080)
│   ├── index.html              # Dashboard HTML interface
│   ├── style.css               # Dark theme stylesheet
│   └── app.js                  # Live metrics polling & canvas chart renderer
└── reports/                    # Execution report output directory
```

---

## 🚀 Quick Start & Building

### System Requirements
- **OS:** Linux / Ubuntu on WSL2 with cgroups v2 mounted at `/sys/fs/cgroup`.
- **Compiler:** GCC / G++ >= 9.0 (C++17 standard support).
- **Build Tools:** CMake >= 3.14, Make.
- **Runtime:** Python 3.x.

### 1. One-Time Setup: cgroup v2 Subtree Delegation
Before running AXES, ensure cgroup v2 subtree write permissions are granted to your user account:

```bash
sudo ./scripts/setup_cgroups.sh
```

### 2. Compilation
Build the AXES binaries (`axes`, `test_axes`, `process_stress`):

```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
cd ..
```

---

## 💻 CLI Usage

### Check System Environment
Verify cgroups v2 availability and controller writability:

```bash
./build/axes check
```

### Run Job Command Format

```bash
./build/axes run [options] <program> [args...]
```

#### CLI Options Summary
| Option | Default | Description |
| :--- | :--- | :--- |
| `--job-id <id>` | `job-XXX` | Unique execution job identifier |
| `--cpu-limit <pct>` | `200` | Initial CPU limit percentage |
| `--memory-limit <mb>` | `512` | Memory ceiling limit in MB |
| `--pids-limit <count>` | `64` | Maximum allowable process count |
| `--cpu-threshold <pct>`| `150` | CPU % threshold to trigger dynamic adaptation |
| `--consecutive <n>` | `3` | Consecutive samples above threshold to trigger action |
| `--reduced-cpu <pct>` | `100` | Reduced CPU limit after adaptation trigger |
| `--sample-interval <s>`| `1.0` | Sampling interval in seconds |
| `--no-adaptive` | `false` | Disable dynamic adaptive CPU throttling |
| `--help` | - | Print usage help message |

---

## 🌐 Web Dashboard (GUI)

AXES includes a real-time web interface for visual monitoring and control.

### Launching the Dashboard

```bash
python3 web/server.py
```

Access the interface in your browser at:  
👉 **`http://127.0.0.1:8080`**

### Features
- **Live Metric Visualizations**: Real-time canvas charts rendering CPU % and Memory consumption.
- **System Readiness Panel**: Dynamic verification badges for kernel cgroup v2 controllers (`cpu`, `memory`, `pids`).
- **Interactive Job Launcher**: Quick preset selection for test workloads with customizable limits.
- **Kernel Evidence Table**: Direct inspection of `/sys/fs/cgroup/axes/<job_id>` control file values (`cpu.max`, `memory.max`, `pids.max`).
- **Report Archives**: Full historical log table with built-in modal report reader.

---

## 🧪 Workload Verification Demos

### 1. Dynamic Adaptive CPU Control
Executes a multi-process CPU burn workload under a 200% limit. When sustained usage exceeds 100%, AXES dynamically rewrites `cpu.max` down to 100% bandwidth.

```bash
./build/axes run --job-id job-cpu-demo --cpu-limit 200 --cpu-threshold 100 --consecutive 2 --sample-interval 0.8 python3 workloads/cpu_burn.py
```

### 2. Memory Containment (OOM Kill)
Allocates memory iteratively up to the 256 MB ceiling. With swap disabled, the kernel OOM killer terminates the target process via `SIGKILL`.

```bash
./build/axes run --job-id job-memory-demo --memory-limit 256 --sample-interval 0.5 python3 workloads/memory_stress.py
```

### 3. Process Limit (PID Bounds)
Fork-bombs child processes until reaching the max PID boundary (`pids.max = 15`), causing subsequent `fork()` calls to fail with `EAGAIN`.

```bash
./build/axes run --job-id job-process-demo --pids-limit 15 --sample-interval 0.5 ./build/process_stress
```

### 4. Normal Workload Execution
Runs a standard calculation task cleanly returning exit status 0.

```bash
./build/axes run --job-id job-normal-demo python3 workloads/normal_workload.py
```

---

## 🧪 Automated Testing

Execute unit tests and end-to-end automated sandbox verification:

```bash
./tests/run_tests.sh
```

---

## 🔒 Security Scope & Roadmap

AXES is currently focused on resource management and adaptive supervision.

- **Current Layer**: Linux cgroups v2 resource accounting and dynamic control (`cpu`, `memory`, `pids`).
- **Roadmap / Future Features**:
  - Namespace Isolation (`CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWNET`).
  - Syscall Filtering via Seccomp-BPF.
  - Kernel event tracing using eBPF probes.
  - Python SDK for autonomous agent integration.

---

## 📜 License & Citation

Developed for Operating Systems Architecture & Resource Management research. Distributed under the MIT License.
