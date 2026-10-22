# AXES Implementation & Completion Plan

**Project:** AXES (Adaptive eXecution Environment Sandbox)  
**Current Milestone:** Phase 3 (Connected Execution Workbench) Complete
**Last Updated:** October 22, 2026  

---

## 1. Executive Summary & Phase Status

AXES is being systematically advanced from an early proof-of-concept into a secure, reliable developer execution workbench. The work is structured into four sequential phases:

| Phase | Description | Status | Verification State |
| :--- | :--- | :---: | :--- |
| **Phase 1** | **Critical Correctness & Security Defect Repair** | **COMPLETE** | **Verified via 21 automated integration tests + C++ unit test suite.** |
| **Phase 2** | **Core Runtime Capabilities & Workbench Backend API** | **COMPLETE** | **Verified via 14 automated integration tests + 6 C++ unit tests.** |
| **Phase 3** | **Desktop Workbench GUI (Staging, File Drop, Terminal, Stop Control)** | **COMPLETE** | **Verified via 3 workbench contract tests, responsive layout checks, and browser workflow.** |
| **Phase 4** | **True Security Sandboxing (Namespaces, Seccomp, Jail) & Final QA** | **COMPLETE** | **Verified via 9 security integration tests, 53 total automated tests passing, and browser end-to-end validation.** |

---

## 2. Phase 1: Verified Progress & Implemented Repairs

All Phase 1 requirements have been implemented and verified with zero compiler warnings and clean automated test passes.

### 1. Robust C++ CLI Argument Parsing (`src/main.cpp`)
- **Vulnerabilities Fixed:** Uncaught `std::invalid_argument` / `std::out_of_range` exceptions from `std::stod`, `std::stoull`, `std::stoll`, and `std::stoi` when malformed inputs were passed. Unsigned integer underflow on negative numbers (e.g. `--memory-limit -50` wrapping to 18 exabytes). Missing value argument falls-through.
- **Implementation:** Implemented safe parsing functions (`safe_parse_double`, `safe_parse_uint64`, `safe_parse_int64`, `safe_parse_int`) utilizing `std::strtod` / `std::strtoll` / `std::strtoull` with full end-pointer validation, explicit negative sign rejection for unsigned types, finite/NaN checks, and strict range boundary validation:
  - `--cpu-limit`: `1.0%` to `10,000.0%`
  - `--memory-limit`: `1 MB` to `1,048,576 MB` (1 TB)
  - `--pids-limit`: `1` to `4,194,304`
  - `--cpu-threshold`: `1.0%` to `10,000.0%`
  - `--consecutive`: `1` to `1,000`
  - `--reduced-cpu`: `1.0%` to `10,000.0%`
  - `--sample-interval`: `0.05s` to `3,600.0s`
- **Verification:** Verified via `TestCLIValidation` in `tests/test_phase1.py` and direct CLI execution.

### 2. Job ID Validation & Path Traversal Prevention (`src/cgroup.hpp`, `src/cgroup.cpp`, `src/launcher.cpp`, `web/server.py`)
- **Vulnerabilities Fixed:** Raw `job_id` strings were concatenated into filesystem paths (`/sys/fs/cgroup/axes/<job_id>` and `reports/<job_id>_report.txt`), enabling directory traversal (`../../`).
- **Implementation:**
  - Defined `is_valid_job_id()` in C++ and Python matching `^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$`.
  - Rejects empty strings, strings starting with hyphens, directory separators (`/`, `\`), dots (`.`, `..`), and strings exceeding 64 characters.
  - Enforced in `main.cpp`, `CGroupController` constructor/init, `ExecutionLauncher::run()`, `write_execution_report()`, and all `web/server.py` API endpoints.
  - In `web/server.py`, `get_safe_report_path()` uses `Path.resolve().relative_to(REPORTS_DIR)` to guarantee files stay inside `reports/`.
- **Verification:** Verified via `test_job_id_validation` and `test_invalid_job_id_rejection` in `test_axes`, as well as `TestCLIValidation.test_job_id_path_traversal` and `TestWebServerSecurity.test_report_path_traversal_rejected`.

### 3. Hardened Launch Barrier (`src/launcher.cpp`)
- **Vulnerabilities Fixed:** In the original implementation, if `verify_process_attached(pid)` returned false, the supervisor printed a warning but still sent `"G"` to release the blocked child process.
- **Implementation:**
  - Child process blocks on `read(sync_pipe[0], &buf, 1)` and explicitly checks `if (n != 1 || buf != 'G') _exit(126);`. The child never runs `execvp()` if the pipe closes or an error occurs.
  - Parent requires both `add_process(pid)` AND `verify_process_attached(pid)` to succeed. On any failure, parent immediately executes `kill(pid, SIGKILL)`, closes the write pipe, reaps the child zombie via `waitpid()`, cleans up the cgroup, and aborts with exit code 1.
- **Verification:** Verified in `launcher.cpp`.

### 4. Secure Cgroup Cleanup via `cgroup.kill` and SIGKILL Fallback (`src/cgroup.cpp`)
- **Vulnerabilities Fixed:** Original cleanup code migrated surviving untrusted processes into the parent cgroup `/sys/fs/cgroup/axes/cgroup.procs`, releasing rogue processes into the host.
- **Implementation:**
  - **Zero Migration:** Completely removed all code writing to parent `cgroup.procs`.
  - **Atomic Kill:** Writes `"1"` to `/sys/fs/cgroup/axes/<job_id>/cgroup.kill` if supported by kernel (Linux >= 5.14).
  - **Looping Fallback:** Reads `cgroup.procs` and sends `kill(p, SIGKILL)` to all active PIDs (`p > 1`) across multiple attempts with kernel reaping delays.
  - **Retried Removal:** Invokes `rmdir()` with retries to prevent `EBUSY` race conditions.
- **Verification:** Verified in `cgroup.cpp` and `test_axes`.

### 5. Web Server Security Hardening (`web/server.py`)
- **Vulnerabilities Fixed:** `Access-Control-Allow-Origin: *` allowed any website visited in a browser to make cross-origin requests to `http://127.0.0.1:8080/api/run` to execute arbitrary host commands. Lack of payload validation.
- **Implementation:**
  - Completely removed wildcard CORS header. Added `X-Content-Type-Options: nosniff`.
  - Added `_verify_origin_and_host()` validating `Host`, `Origin`, and `Sec-Fetch-Site` headers against localhost origins. Disallowed cross-origin requests receive HTTP 403 Forbidden.
  - Added strict payload validation: maximum content length (64 KB), non-empty command validation with null-byte rejection, and bounds validation on all numeric parameters.
  - Added dynamic port configuration via `AXES_PORT` environment variable and set `socketserver.TCPServer.allow_reuse_address = True`.
- **Verification:** Verified via `TestWebServerSecurity` (tests for CORS removal, origin blocking, host blocking, traversal rejection, invalid payload rejection).

### 6. Job ID Collision Prevention (`web/server.py`, `src/cgroup.cpp`, `src/main.cpp`)
- **Vulnerabilities Fixed:** Concurrent submissions with duplicate `job_id` overwrote state and collided in the same cgroup directory.
- **Implementation:**
  - `web/server.py` locks `active_jobs` during `do_POST` and checks if `job_id` is in `STARTING` or `RUNNING` status, returning HTTP 409 Conflict if so. Also checks if `/sys/fs/cgroup/axes/<job_id>/cgroup.procs` is active.
  - Auto-generated job IDs include high-resolution timestamps and PID suffixes.
  - `CGroupController::init()` checks for active PIDs in existing cgroup directories and aborts on collision.
- **Verification:** Verified via `TestWebServerSecurity.test_duplicate_running_job_collision_prevention`.

---

## 3. Phase 2: Core Runtime Capabilities & Workbench Backend API (COMPLETE)

All Phase 2 requirements have been implemented and verified:

### 1. Reliable Execution Lifecycle & Wall-Clock Timeouts
- **CLI Options:** Added `--timeout <sec>` (valid range `0.01s` to `86,400.0s`), `--output-file <path>`, and `--max-output <mb>` (default `10 MB`).
- **Timeout Enforcement:**
  - High-resolution wall-clock timer monitored via `std::chrono::steady_clock` within sub-interval polling (50ms responsiveness).
  - When elapsed runtime reaches `timeout_sec`, supervisor cleanly terminates workload process tree via `cgroup.cleanup()`, reaps processes, sets `timed_out = true`, `final_status = "TIMED_OUT"`, logs timeline event, and exits with code `124`.
- **Consistent States:** Standardized all lifecycle terminations to:
  - `COMPLETED`: Exited normally (exit code `0`).
  - `FAILED`: Exited with non-zero exit code or failed barrier/launch.
  - `TIMED_OUT`: Wall-clock timeout exceeded (exit code `124`).
  - `CANCELLED`: Stopped by supervisor signal or stop API (exit code `128 + sig`).
  - `KILLED`: Terminated by external signal (e.g. `SIGKILL`, OOM).

### 2. Graceful Signal Handling & Cancellation
- **Signal Handling:** Installed `sigaction` handlers in C++ supervisor for `SIGINT`, `SIGTERM`, and `SIGHUP`. Child processes restore `SIG_DFL` before `execvp`.
- **Clean In-Flight Teardown:** Upon signal reception, supervisor breaks loop immediately, writes `CANCELLED` status, terminates all descendant processes via `cgroup.cleanup()`, drains captured output, flushes and writes execution reports.

### 3. Real Workload Output Capture & Stream Bounding
- **Telemetry Isolation:** Workload `STDOUT_FILENO` and `STDERR_FILENO` are redirected to an output pipe before barrier unblocking. Supervisor telemetry stays exclusively on supervisor stdout, while workload output is captured directly into `reports/<job_id>_output.log`.
- **Bounded Output Growth:** Maximum captured bytes is strictly capped by `max_output_bytes` (default 10MB). If exceeded, remaining data is drained and discarded to prevent child blocking, and a truncation notice is appended.
- **Diagnostic Preservation:** Preserves all program errors, stack traces, compiler errors, and runtime diagnostics.

### 4. Structured Machine-Readable Reports
- In addition to human-readable `reports/<job_id>_report.txt`, supervisor now generates `reports/<job_id>_report.json` with complete structured metrics, timing, limits, peaks, raw kernel evidence, and event timelines.

### 5. File Staging & C/C++ Staged Compilation
- **Staging Directory:** Dedicated `staging/` directory managed by AXES.
- **Safe Staging Endpoints:** `GET /api/files`, `POST /api/files/upload` (supporting JSON and Multipart), `GET /api/files/<filename>`, and `DELETE /api/files/<filename>` with strict filename validation (`^[a-zA-Z0-9_.-]{1,128}$`), 10MB size limit, and `relative_to` path traversal protection.
- **Staged C/C++ Compilation (`POST /api/compile`):** Compiles `.c` or `.cpp` source files via explicit argument vectors (`gcc`/`g++`, no shell interpolation), captures compiler diagnostics, and returns compilation success/failure separately from workload runtime execution.

### 6. Incremental Output Streaming & Job Stop API
- **Incremental Streaming (`GET /api/job/<job_id>/output?offset=N&limit=bytes`):** Reads output logs incrementally using byte offsets without buffering large files in memory.
- **Job Cancellation (`POST /api/job/<job_id>/stop`):** Gracefully signals supervisor process via `SIGTERM` and ensures cgroup cleanup, updating job status to `CANCELLED`.

### 7. WSL2 Kernel Cgroup Delegation Systemd Service
- Added permanent delegation configuration in `scripts/setup_cgroups.sh` with `TARGET_USER` override support.
- Configured `/etc/tmpfiles.d/axes.conf` and enabled `axes-cgroups.service` under systemd in WSL2 to ensure `/sys/fs/cgroup/axes` delegation and process migration permissions persist across WSL microVM restarts.

---

## 4. Automated Test Verification Record

All 41 tests across all suites execute and pass cleanly on Linux kernel 6.18.33 in WSL2:

```text
==================================================
1. AXES Sandbox - C++ Unit Test Suite (build/test_axes)
==================================================
[Test 1] Testing Job ID Validation Rules...
  Job ID validation passed successfully!
[Test 2] Testing Security Rejection of Invalid Job IDs...
  Invalid job ID security rejection passed successfully!
[Test 3] Testing CGroupController Lifecycle...
  Cgroup Init Result: SUCCESS
  Dynamic CPU Limit Update: SUCCESS
  Stats Query Result: SUCCESS
  Cgroup lifecycle passed!
[Test 4] Testing Monitor Sampling & PID Attachment...
  PID Attached to cgroup.procs: YES
  Sampled Runtime: 0.200164s, Memory: 0 MB
  Monitor sampling passed!
[Test 5] Testing ExecutionLauncher Normal Run & Output Capture...
  Normal launcher run exit code: 0
  Output bytes captured: 26
  Normal launcher run passed!
[Test 6] Testing ExecutionLauncher Wall-Clock Timeout...
  Timeout elapsed: 0.55s (limit 0.5s), exit code: 124
  Launcher timeout test passed!
Unit Test Execution Finished Successfully! (6/6 PASS)

==================================================
2. Phase 1 Integration Suite (python3 tests/test_phase1.py)
==================================================
Ran 21 tests in 0.187s
OK (21/21 PASS)

==================================================
3. Phase 2 Integration Suite (python3 tests/test_phase2.py)
==================================================
test_max_output_negative_rejected (__main__.TestPhase2CLILifecycle) ... ok
test_output_file_empty_rejected (__main__.TestPhase2CLILifecycle) ... ok
test_real_output_capture_stdout_stderr (__main__.TestPhase2CLILifecycle) ... ok
test_timeout_negative_rejected (__main__.TestPhase2CLILifecycle) ... ok
test_timeout_too_high_rejected (__main__.TestPhase2CLILifecycle) ... ok
test_timeout_zero_rejected (__main__.TestPhase2CLILifecycle) ... ok
test_wall_clock_timeout_enforcement (__main__.TestPhase2CLILifecycle) ... ok
test_file_staging_lifecycle (__main__.TestPhase2WorkbenchServer) ... ok
test_file_upload_traversal_rejected (__main__.TestPhase2WorkbenchServer) ... ok
test_incremental_output_streaming (__main__.TestPhase2WorkbenchServer) ... ok
test_job_cancellation_endpoint (__main__.TestPhase2WorkbenchServer) ... ok
test_staged_compilation_failure_diagnostics (__main__.TestPhase2WorkbenchServer) ... ok
test_staged_compilation_success (__main__.TestPhase2WorkbenchServer) ... ok
test_status_endpoint_staging (__main__.TestPhase2WorkbenchServer) ... ok
Ran 14 tests in 6.735s
OK (14/14 PASS)

TOTAL AUTOMATED TESTS: 41 PASSED, 0 FAILED
```

---

## 5. Phase 3 Plan: Desktop Developer Workbench

Now that the backend contract (`docs/API.md`) and runtime capabilities are fully established, Phase 3 can proceed:

1. **Workbench Layout Redesign (`web/index.html`, `web/style.css`, `web/app.js`):**
   - Replace dashboard cards with an IDE-style split pane:
     - Left pane: Staged file explorer, drag-and-drop upload zone, delete action.
     - Center top: Execution config panel (Job ID, Staged File / Command, CPU %, RAM MB, PIDs, Timeout sec, Adaptive toggle).
     - Center bottom: Live streaming terminal output window with incremental polling.
     - Control buttons: Run Workload, Stop/Cancel Job, Compile C/C++.
     - Right pane: Real-time telemetry meters (CPU %, Memory MB, Active PIDs, Cgroup verification badge).
2. **File Staging Integration:**
   - Visual file uploader connected to `POST /api/files/upload`.
   - File click-to-run or click-to-compile.
3. **Cancellation & Terminal Output Controls:**
   - Real-time terminal output streaming connected to `GET /api/job/<id>/output?offset=...`.
   - Instant Cancel button calling `POST /api/job/<id>/stop`.

## 6. Phase 3 implemented: Connected execution workbench (October 22, 2026)

Implemented directly in the existing HTML/CSS/JavaScript stack. No framework, external font, chart dependency, mock measurements, or generated terminal messages were added.

- Compact toolbar, staged-file explorer, central configuration and terminal, runtime/policy inspector, and collapsible history drawer. Responsive layouts at desktop, intermediate and narrow widths; keyboard focus styles and native accessible controls.
- Real multipart uploads (browse/multiple files and drop handler), selection, same-name replacement, removal, file type/size display, supported-format and 10 MiB validation. Hidden workspace bookkeeping files are omitted. Backend path validation remains authoritative.
- Staged Python/shell/binary execution; C/C++ compilation and compiler diagnostics; explicit command mode; JSON-array arguments; CPU, memory, PID, timeout and adaptive policy controls.
- Serial incremental output polling with byte offsets, retry notices, stale-response generation guards, reload recovery, bounded terminal rendering (last 500,000 characters), follow/copy/clear controls, and report/output views.
- Runtime metrics distinguish measured values from configured ceilings. PID attachment is shown only after supervisor confirmation. Raw kernel diagnostics come from actual cgroup control-file reads; missing values remain unavailable. CPU use is not classified as malicious.
- Small API additions: live job responses expose command/staged-file/argument metadata and `kernel_controls` for reliable reload restoration. UTF-8 streaming retains incomplete multibyte sequences for the next chunk. Stop leaves a job active until supervisor output/report finalization; cancellation requested before process registration is honored. The C++ runtime and existing containment settings were not changed in this phase.

### Verification actually performed

- WSL Ubuntu: `./build/axes check` reported all cgroup v2 readiness checks passing.
- `./build/test_axes`: 6/6 passed.
- `python3 tests/test_phase1.py`: 21/21 passed.
- `python3 tests/test_phase2.py`: 14/14 passed; rerun after cancellation/streaming changes, also passed.
- `python3 tests/test_workbench.py`: 3/3 passed: actual kernel quota/memory/PID evidence and restoration metadata; lossless UTF-8 across a 65,536-byte boundary; cancellation finalization and no remaining cgroup descendants.
- `node --check web/app.js`: passed.
- Total distinct automated checks: **44 passed**. Existing Python suites emit subprocess/file ResourceWarnings despite passing; their fixture cleanup was not rewritten.
- Browser: uploaded `tests/fixtures/workbench_smoke.py` through Browse, configured CPU quota, ran it, observed actual stdout/stderr, memory/PID telemetry and confirmed attachment, reloaded and restored monitoring, stopped it, and opened the persisted CANCELLED report and output log. A second reload test confirmed selected staged file, 75% CPU quota and disabled policy restored correctly.
- Browser: uploaded invalid C source and saw GCC diagnostics; compiled valid C source, selected the generated binary, ran it and observed its output and COMPLETED/exit 0 report.
- Browser: ran a command producing over 600,000 characters; final marker arrived, visible output was capped at exactly 500,000 characters, Clear worked, and terminal content did not cause horizontal overflow.
- Browser responsive inspection: 390 × 844 and 1440 × 1000 viewport overrides. Document scroll width equaled client width (375 and 1425 CSS px after scrollbar allocation); screenshots inspected and saved. Intermediate default viewport was also inspected. Overrides reset afterward.
- Browse upload is browser-verified; native OS drag/drop, clipboard permission denial, and a prolonged network outage were not independently automated. Their handlers/error paths are implemented, not claimed as separately verified.
- Final diff inspected. Pre-existing modifications to setup script, C++ runtime, earlier tests and backend were preserved. Whole-repository `git diff --check` reports pre-existing whitespace in `src/launcher.cpp`; changed frontend files pass.

### Launch

From PowerShell in the repository:

```powershell
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/Users/anuro/Desktop/AXES && python3 web/server.py'
```

Open **http://127.0.0.1:8080/**. A local server was left running for review.

For a fresh Linux build/delegation, from the repository directory:

```bash
cmake -S . -B build
cmake --build build -j
sudo ./scripts/setup_cgroups.sh
./build/axes check
python3 web/server.py
```

### Evidence and remaining limitations

- `docs/evidence/workbench-desktop.png`: real running workload, terminal and raw kernel controls at desktop width.
- `docs/evidence/workbench-narrow.png`: responsive narrow layout.
- `tests/fixtures/`: repeatable Python, valid C and invalid C browser fixtures. Manual execution reports remain in local history as real evidence.
- Namespace, Seccomp and filesystem jail isolation remain Phase 4; the interface explicitly does not claim they are verified.
- Existing backend merges stdout/stderr into one log, so the terminal cannot attribute individual lines to separate streams. The supervisor's output cap still applies.
- History timestamps are displayed as server time because legacy reports contain no timezone offset.
- Recovery restores this browser's last tracked job; the API has no global list of active jobs from other browser sessions. A backend process restart cannot reconstruct an in-memory live supervisor handle.

Additional final browser verification: a CPU-bound Python workload triggered the configured adaptive rule after one sample (200% → 25%, `cpu.max: 25000 100000`), then reached its 3-second timeout and displayed TIMED OUT / exit 124. Actual event text and measured CPU use were visible; browser developer error logs were empty.

---

## 7. Phase 4 Implemented: Defense-in-Depth Security Model & Final Verification (October 22, 2026)

All Phase 4 security, adaptive policy, and QA requirements have been implemented, integrated, and verified across automated test suites, CLI demos, and the live browser workbench.

### 1. Threat Model & Privilege Separation (`docs/THREAT_MODEL.md`)
- Complete threat model documented detailing trust boundaries, in-scope threats (CPU/memory/fork DoS, filesystem escape, network attacks, privilege escalation, output flooding), and remaining kernel-sharing limitations.
- Strict non-root execution enforced in both C++ (`src/launcher.cpp`, `src/security.cpp`) and Python (`web/server.py`). The supervisor and workloads refuse root privileges (`UID == 0 || EUID == 0`). Privileged setup is strictly decoupled into `scripts/setup_cgroups.sh`.

### 2. Linux Namespaces & Filesystem Boundaries (`src/security.cpp`)
- Integrated unprivileged namespace isolation via Bubblewrap (`bwrap`) invoked right after launch barrier verification.
- **Unshared Namespaces:** PID, Mount, Network, IPC, UTS, and Cgroup (`--unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts --unshare-cgroup`).
- **Filesystem Virtualization:**
  - System runtimes (`/usr`, `/bin`, `/lib`, `/lib64`, `/etc/ld.so.cache`) mounted read-only.
  - Staged workspace mounted strictly read-only at `/workspace` (writes return `EROFS`).
  - Scratch space provided via private ephemeral `tmpfs` at `/tmp`.
  - Host filesystems (including `/mnt/c` and `/sys/fs/cgroup`) unmapped and hidden.
- **Network Isolation:** Workload runs with loopback only; network sockets and external connections blocked (`EPERM` / `ENETUNREACH`).
- **Fail-Closed Guarantee:** Any failure during namespace or bubblewrap setup immediately prints a diagnostic, exits with code `126`, terminates the cgroup, and **never falls back to host execution**.

### 3. Seccomp-BPF Syscall Filtering (`src/security.cpp`)
- Positive allowlist compiled into classic BPF and sealed into memory via `memfd_create` (`F_SEAL_SEAL`).
- Enforces native `AUDIT_ARCH_X86_64`; foreign ABIs are killed via `SECCOMP_RET_KILL_PROCESS`.
- Blocks high-risk syscalls (`ptrace`, `unshare`, `setns`, `mount`, `bpf`, `kexec_load`, module loading) returning `SECCOMP_RET_ERRNO | EPERM`.
- Blocks `clone3` with `SECCOMP_RET_ERRNO | ENOSYS` to ensure clean glibc fallback to verified `clone()`.
- Allows required compute, memory management, process lifecycle, signals, and file I/O (including `openat2` and `ioctl` for modern Python/glibc terminal/file support).

### 4. Deterministic Adaptive CPU Policy (`src/policy.hpp`, `src/launcher.cpp`)
- Consecutive-sample threshold detection: limits are adjusted only when CPU exceeds threshold for `consecutive_samples_required` cycles.
- One-way hysteresis latch: once reduced to `reduced_cpu_limit_pct`, limits stay reduced until workload completion. Automatic quota increases are deliberately avoided because throttled workloads cannot reveal unconstrained demand.
- All policy adjustments write validated cgroup controls to `cpu.max` and record structured events with measurements and limits.

### 5. Final Test Verification Results
- **C++ Unit Tests (`build/test_axes`):** 6/6 passed.
- **Phase 1 Integration (`tests/test_phase1.py`):** 21/21 passed.
- **Phase 2 Integration (`tests/test_phase2.py`):** 14/14 passed.
- **Workbench Contract (`tests/test_workbench.py`):** 3/3 passed.
- **Phase 4 Security Integration (`tests/test_security.py`):** 9/9 passed.
  - `test_namespace_filesystem_network_and_privileges`: PASS
  - `test_host_file_not_visible_even_through_proc_root`: PASS
  - `test_representative_benign_workloads`: PASS
  - `test_namespace_failure_never_executes_payload`: PASS (Fail-closed verified)
  - `test_seccomp_failure_never_executes_payload`: PASS (Fail-closed verified)
  - `test_invalid_workspace_fails_closed`: PASS
  - `test_nonzero_exit_and_normal_background_cleanup`: PASS
  - `test_continuous_output_cannot_starve_timeout`: PASS (10MB bounded drain verified)
  - `test_policy_reduction_and_latch`: PASS
- **Total Automated Tests:** **53 PASSED, 0 FAILED**.
- **Browser Workbench:** End-to-end isolated workload execution, output streaming, timeout handling, cgroup verification, and zero residual cgroups verified via live browser subagent inspection.

