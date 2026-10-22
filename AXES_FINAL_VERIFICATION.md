# AXES Final Integration & Verification Report

**Date:** October 22, 2026  
**System:** AXES (Adaptive eXecution Environment Sandbox)  
**Host Environment:** Linux (Ubuntu on WSL2, Kernel 6.18.33-microsoft-standard-WSL2, x86_64)  
**Supervision Model:** Unprivileged supervisor (UID 1000) with delegated cgroups v2 (`/sys/fs/cgroup/axes`), Bubblewrap namespaces, and Seccomp-BPF  

---

## 1. Feature Checklist & Implementation Status

| Component | Acceptance Criterion | Status | Verification Evidence |
| :--- | :--- | :---: | :--- |
| **CLI Validation** | Safe numeric argument parsing, overflow & negative rejection, help formatting | **VERIFIED** | `TestCLIValidation` (12 tests) in `tests/test_phase1.py` |
| **Path Traversal Protection** | Job ID regex `^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$`, directory traversal rejection | **VERIFIED** | Tests in `test_phase1.py` and `test_axes` |
| **Launch Barrier** | Strict sync pipe; child never runs `execvp` until cgroup attachment is verified | **VERIFIED** | `launcher.cpp` launch barrier + tests in `test_axes` |
| **Atomic Cleanup** | Zero parent migration; `cgroup.kill` + looping SIGKILL; no leftover cgroups | **VERIFIED** | `test_stop_finishes_supervisor_and_descendants` & CLI checks |
| **Execution Lifecycle** | Wall-clock timeouts (`--timeout`), signal handling (`SIGINT`/`SIGTERM`/`SIGHUP`) | **VERIFIED** | `TestPhase2CLILifecycle` (7 tests) in `tests/test_phase2.py` |
| **Output Streaming** | Non-blocking output pipe, bounded retention (default 10 MB), lossless UTF-8 | **VERIFIED** | `test_utf8_chunk_boundary_is_lossless` & `test_continuous_output_cannot_starve_timeout` |
| **Structured Reports** | Human-readable `.txt` and machine-readable `.json` with raw kernel evidence | **VERIFIED** | Validated in all report generation tests |
| **File Staging & Upload** | Staging API (`GET`/`POST`/`DELETE`), multipart upload, dotfile omission | **VERIFIED** | `test_file_staging_lifecycle` & browser inspection |
| **C/C++ Compilation** | Staged GCC/G++ compilation with diagnostic capture | **VERIFIED** | `test_staged_compilation_success` & `test_staged_compilation_failure_diagnostics` |
| **Web Workbench UI** | Split-pane IDE layout, terminal poller (500k chars), telemetry meters, controls | **VERIFIED** | Live browser subagent runs & responsive inspection |
| **Non-Root Execution** | Supervisor and workloads refuse root execution (`UID == 0 || EUID == 0`) | **VERIFIED** | Enforced in `main.cpp`, `launcher.cpp`, `security.cpp`, and `server.py` |
| **Namespace Isolation** | Unshare PID, MNT, NET, IPC, UTS, CGROUP via Bubblewrap | **VERIFIED** | `test_namespace_filesystem_network_and_privileges` |
| **Filesystem Boundaries** | Read-only `/workspace`, ephemeral `/tmp` (tmpfs), unmapped host roots (`/mnt/c`) | **VERIFIED** | `test_host_file_not_visible_even_through_proc_root` |
| **Network Block** | Loopback-only unshared network stack, socket creation denied | **VERIFIED** | Syscall probe verifying socket creation blocked (`EPERM`) |
| **Seccomp-BPF Filter** | Classic BPF positive allowlist sealed in memfd, blocking ptrace/unshare/mount/bpf | **VERIFIED** | `test_security.py` syscall probe |
| **Fail-Closed Guarantee** | Setup failure immediately aborts without executing payload; no host fallback | **VERIFIED** | `test_namespace_failure_never_executes_payload` & `test_seccomp_failure_never_executes_payload` |
| **Adaptive CPU Policy** | Consecutive threshold detection, one-way hysteresis latch, validated cgroup update | **VERIFIED** | `test_policy_reduction_and_latch` & CLI demo `demo-cpu` |

---

## 2. Test Execution Record & Results

All 53 automated tests executed and passed cleanly:

```text
======================================================================
1. C++ Unit Tests (build/test_axes)
======================================================================
[Test 1] Testing Job ID Validation Rules............................ PASS
[Test 2] Testing Security Rejection of Invalid Job IDs.............. PASS
[Test 3] Testing CGroupController Lifecycle......................... PASS
[Test 4] Testing Monitor Sampling & PID Attachment.................. PASS
[Test 5] Testing ExecutionLauncher Normal Run & Output Capture...... PASS
[Test 6] Testing ExecutionLauncher Wall-Clock Timeout............... PASS
Result: 6/6 PASSED (100%)

======================================================================
2. Phase 1 Integration Tests (python3 tests/test_phase1.py)
======================================================================
test_consecutive_samples_zero ...................................... PASS
test_cpu_limit_missing_value ....................................... PASS
test_cpu_limit_not_a_number ........................................ PASS
test_cpu_limit_zero_or_negative .................................... PASS
test_job_id_path_traversal ......................................... PASS
test_job_id_slash .................................................. PASS
test_job_id_starts_with_hyphen ..................................... PASS
test_memory_limit_negative ......................................... PASS
test_memory_limit_zero ............................................. PASS
test_pids_limit_invalid ............................................ PASS
test_sample_interval_too_low ....................................... PASS
test_unknown_option ................................................ PASS
test_cross_origin_blocked .......................................... PASS
test_duplicate_running_job_collision_prevention .................... PASS
test_job_path_traversal_rejected ................................... PASS
test_no_wildcard_cors .............................................. PASS
test_report_path_traversal_rejected ................................ PASS
test_run_empty_command ............................................. PASS
test_run_invalid_job_id ............................................ PASS
test_run_invalid_numeric_bounds .................................... PASS
test_untrusted_host_blocked ........................................ PASS
Result: 21/21 PASSED (100%)

======================================================================
3. Phase 2 Integration Tests (python3 tests/test_phase2.py)
======================================================================
test_max_output_negative_rejected .................................. PASS
test_output_file_empty_rejected .................................... PASS
test_real_output_capture_stdout_stderr ............................. PASS
test_timeout_negative_rejected ..................................... PASS
test_timeout_too_high_rejected ..................................... PASS
test_timeout_zero_rejected ......................................... PASS
test_wall_clock_timeout_enforcement ................................ PASS
test_file_staging_lifecycle ........................................ PASS
test_file_upload_traversal_rejected ................................ PASS
test_incremental_output_streaming .................................. PASS
test_job_cancellation_endpoint ..................................... PASS
test_staged_compilation_failure_diagnostics ........................ PASS
test_staged_compilation_success .................................... PASS
test_status_endpoint_staging ....................................... PASS
Result: 14/14 PASSED (100%)

======================================================================
4. Workbench Contract Tests (python3 tests/test_workbench.py)
======================================================================
test_kernel_evidence_and_restore_metadata .......................... PASS
test_stop_finishes_supervisor_and_descendants ...................... PASS
test_utf8_chunk_boundary_is_lossless ............................... PASS
Result: 3/3 PASSED (100%)

======================================================================
5. Phase 4 Security Integration Tests (python3 -m unittest tests/test_security.py)
======================================================================
test_namespace_filesystem_network_and_privileges ................... PASS
test_host_file_not_visible_even_through_proc_root .................. PASS
test_representative_benign_workloads ............................... PASS
test_namespace_failure_never_executes_payload ...................... PASS
test_seccomp_failure_never_executes_payload ........................ PASS
test_invalid_workspace_fails_closed ................................ PASS
test_nonzero_exit_and_normal_background_cleanup .................... PASS
test_continuous_output_cannot_starve_timeout ....................... PASS
test_policy_reduction_and_latch .................................... PASS
Result: 9/9 PASSED (100%)

TOTAL AUTOMATED TESTS: 53 PASSED, 0 FAILED (100% SUCCESS RATE)
```

---

## 3. Workload Containment & Policy Demos

Each core resource management demo was executed directly against the live C++ engine:

1. **Adaptive CPU Throttling (`workloads/cpu_burn.py`):**
   - **Command:** `./build/axes run --job-id demo-cpu --timeout 3.0 --cpu-limit 150 --cpu-threshold 100 --consecutive 2 --reduced-cpu 50 python3 workloads/cpu_burn.py`
   - **Observed Behavior:** Multi-threaded burn measured at 144.1% and 149.7% CPU. At 2.0s, consecutive threshold was met; `cpu.max` was rewritten from `150000 100000` to `50000 100000`. Event logged: `ADAPTIVE TRIGGER: CPU limit changed: 150% -> 50%`. At 3.0s, wall-clock timeout terminated processes with exit code `124`.
2. **Memory Containment & OOM Kill (`workloads/memory_stress.py`):**
   - **Command:** `./build/axes run --job-id demo-mem --timeout 5.0 --memory-limit 64 python3 workloads/memory_stress.py`
   - **Observed Behavior:** Process allocated memory up to 64 MB. With `memory.swap.max = 0`, the Linux OOM killer terminated the process immediately via SIGKILL. Status recorded: `KILLED (Exit Code: 137)`.
3. **Process Fork Limit (`workloads/process_stress.c`):**
   - **Command:** `./build/axes run --job-id demo-pids --pids-limit 4 ./build/process_stress`
   - **Observed Behavior:** Workload successfully spawned children #1, #2, #3 (total 4 processes including parent). Fork #4 failed with `EAGAIN` (`Resource temporarily unavailable`). Workload logged: `SUCCESS: PID / Process limit enforced by cgroup at 4 active processes!` and exited cleanly with code `0`.
4. **Normal Workload Execution (`workloads/normal_workload.py`):**
   - **Command:** `./build/axes run --job-id demo-norm python3 workloads/normal_workload.py`
   - **Observed Behavior:** Executed computation, captured 194 bytes of output, and finalized with status `COMPLETED (Exit Code: 0)`.
5. **Isolated Workload Execution (`staging/workbench_smoke.py`):**
   - **Command:** `./build/axes run --job-id demo-iso --isolation isolated --workspace staging --timeout 3.0 python3 /workspace/workbench_smoke.py`
   - **Observed Behavior:** Ran under Bubblewrap namespace and Seccomp containment. Verified stdout and stderr capture, confirmed PID attachment, and terminated cleanly after 3s timeout with code `124`.

---

## 4. Manual GUI Workflow Verification

Verified using real browser sessions via the automated browser subagent:
1. **Workbench Access:** Navigated to `http://127.0.0.1:8080/`. Verified dark-mode developer layout with toolbar, staged file explorer, configuration panel, live streaming terminal window, kernel enforcement meters, and history drawer.
2. **File Selection:** Selected `workbench_smoke.py` from staged files; configuration dynamically updated with target path.
3. **Execution Boundary Setting:** Selected `Isolated · namespaces + Seccomp · no network`.
4. **Execution & Real-Time Streaming:** Clicked "Run workload". Observed live status transition (`STARTING` -> `RUNNING`), real-time streaming of stdout (`sample 0`, `sample 1`, `sample 2`), and real-time CPU/memory meters.
5. **Supervisor Attachment Confirmation:** Kernel enforcement panel confirmed attachment (`PID Attached: YES`, `Confirmed by supervisor`).
6. **Timeout & Finalization:** After 3 seconds, status transitioned to `TIMED_OUT` (exit code `124`). Output and execution reports were persisted to `reports/`.
7. **C/C++ Compilation in Workbench:** Tested compiling `workbench_invalid.c` (observed GCC error diagnostics returned to UI) and `workbench_compile.c` (successfully generated `workbench_compile.bin`).
8. **Responsive Layout:** Inspected viewport rendering across desktop (1440px), intermediate (1000px), and mobile (390px) widths. Verified zero horizontal scroll overflow and proper control accessibility.
9. **Zero Leakage:** Inspected `/sys/fs/cgroup/axes` after all workbench runs; confirmed zero orphaned cgroups and zero surviving descendant processes.

---

## 5. Security Properties Verified

1. **Non-Root Execution:** Attempting to run supervisor or workloads as root triggers an immediate refusal and exit (`fail("root execution refused")`).
2. **Namespace Isolation:** Workload runs inside private PID, Mount, Network, IPC, UTS, and Cgroup namespaces. Host PIDs are hidden; `/proc` contains only sandbox processes.
3. **Filesystem Boundaries:** Host filesystems (including `/mnt/c`) are unmapped. The workspace is read-only (`EROFS` on write attempts). Ephemeral files in `/tmp` reside in a private `tmpfs`.
4. **Network Isolation:** Workload cannot create sockets or connect to external hosts (`EPERM` / `ENETUNREACH`).
5. **Privilege Dropping:** `PR_SET_NO_NEW_PRIVS` is set; all Linux capabilities are dropped (`CapEff = 0`). Setuid binaries cannot elevate privileges.
6. **Syscall Filtering:** High-risk syscalls (`ptrace`, `unshare`, `mount`, `bpf`, `kexec_load`, module loading) return `EPERM`. `clone3` returns `ENOSYS` forcing fallback to verified `clone()`.
7. **Fail-Closed Guarantee:** Any failure during Bubblewrap launch, seccomp profile sealing, or launch barrier verification aborts execution with code `126`. Workload code is **never executed uncontained**.
8. **Atomic Teardown:** Teardown utilizes `cgroup.kill` to atomically eliminate all descendant processes before cgroup directory removal. Surviving rogue processes are never migrated to host cgroups.

---

## 6. Exact Reproduction Commands

From an unprivileged user terminal on Linux or WSL2:

```bash
# 1. Build C++ binaries
cmake -S . -B build
cmake --build build -j

# 2. Check cgroups v2 readiness
./build/axes check

# 3. Run all test suites
./build/test_axes
python3 tests/test_phase1.py
python3 tests/test_phase2.py
python3 tests/test_workbench.py
python3 -m unittest tests/test_security.py

# 4. Run resource control demos
./build/axes run --job-id demo-cpu --timeout 3.0 --cpu-limit 150 --cpu-threshold 100 --consecutive 2 --reduced-cpu 50 python3 workloads/cpu_burn.py
./build/axes run --job-id demo-mem --timeout 5.0 --memory-limit 64 python3 workloads/memory_stress.py
./build/axes run --job-id demo-pids --pids-limit 4 ./build/process_stress
./build/axes run --job-id demo-norm python3 workloads/normal_workload.py

# 5. Launch the Developer Workbench GUI
python3 web/server.py
# Open http://127.0.0.1:8080 in your browser
```

---

## 7. Remaining Limitations & Environment Blockers

1. **Shared Kernel Attack Surface:** Namespaces and Seccomp provide OS-level container isolation, not hardware hypervisor virtualization (such as Firecracker or gVisor). Zero-day exploits in allowed kernel syscalls remain in scope.
2. **Microarchitectural Side Channels:** Spectre/Meltdown timing attacks across physical cores cannot be prevented without dedicated CPU core affinity pinning and cache partitioning.
3. **Hardware / Architecture Scope:** The Seccomp-BPF profile is native to Linux x86_64. ARM64 or foreign architectures require compiling an architecture-specific BPF syscall table.
4. **Timezone Representation in Legacy Reports:** Timestamps are recorded in local server time; legacy reports do not include explicit ISO 8601 UTC offsets.
5. **Combined Output Stream:** Workload `stdout` and `stderr` are both captured into `reports/<job_id>_output.log`. The terminal displays both streams sequentially but cannot color-code lines individually by descriptor.
