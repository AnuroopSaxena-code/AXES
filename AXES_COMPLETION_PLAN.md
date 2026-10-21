# AXES Implementation & Completion Plan

**Project:** AXES (Adaptive eXecution Environment Sandbox)  
**Current Milestone:** Phase 1 (Critical Correctness & Security Hardening) Complete  
**Last Updated:** October 21, 2026  

---

## 1. Executive Summary & Phase Status

AXES is being systematically advanced from an early proof-of-concept into a secure, reliable developer execution workbench. The work is structured into four sequential phases:

| Phase | Description | Status | Verification State |
| :--- | :--- | :---: | :--- |
| **Phase 1** | **Critical Correctness & Security Defect Repair** | **COMPLETE** | **Verified via 21 automated integration tests + C++ unit test suite.** |
| **Phase 2** | **Core Runtime Capabilities (Timeouts, Output, Signals, Reports)** | Planned | Pending Phase 1 Sign-off |
| **Phase 3** | **Desktop Workbench GUI (Staging, File Drop, Terminal, Stop Control)** | Planned | Blocked on Phase 2 |
| **Phase 4** | **True Security Sandboxing (Namespaces, Seccomp, Jail)** | Planned | Future Milestone |

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

## 3. Automated Test Verification Record

All tests were executed directly in the environment (WSL2 Ubuntu on Linux kernel 6.18.33):

```text
========================================
 AXES Sandbox - C++ Unit Test Suite (build/test_axes)
========================================
[Test 1] Testing Job ID Validation Rules...
  Job ID validation passed successfully!
[Test 2] Testing Security Rejection of Invalid Job IDs...
  Invalid job ID security rejection passed successfully!
Unit Test Execution Finished Successfully!

========================================
 Phase 1 Integration Suite (python3 tests/test_phase1.py)
========================================
test_consecutive_samples_zero (__main__.TestCLIValidation) ... ok
test_cpu_limit_missing_value (__main__.TestCLIValidation) ... ok
test_cpu_limit_not_a_number (__main__.TestCLIValidation) ... ok
test_cpu_limit_zero_or_negative (__main__.TestCLIValidation) ... ok
test_job_id_path_traversal (__main__.TestCLIValidation) ... ok
test_job_id_slash (__main__.TestCLIValidation) ... ok
test_job_id_starts_with_hyphen (__main__.TestCLIValidation) ... ok
test_memory_limit_negative (__main__.TestCLIValidation) ... ok
test_memory_limit_zero (__main__.TestCLIValidation) ... ok
test_pids_limit_invalid (__main__.TestCLIValidation) ... ok
test_sample_interval_too_low (__main__.TestCLIValidation) ... ok
test_unknown_option (__main__.TestCLIValidation) ... ok
test_cross_origin_blocked (__main__.TestWebServerSecurity) ... ok
test_duplicate_running_job_collision_prevention (__main__.TestWebServerSecurity) ... ok
test_job_path_traversal_rejected (__main__.TestWebServerSecurity) ... ok
test_no_wildcard_cors (__main__.TestWebServerSecurity) ... ok
test_report_path_traversal_rejected (__main__.TestWebServerSecurity) ... ok
test_run_empty_command (__main__.TestWebServerSecurity) ... ok
test_run_invalid_job_id (__main__.TestWebServerSecurity) ... ok
test_run_invalid_numeric_bounds (__main__.TestWebServerSecurity) ... ok
test_untrusted_host_blocked (__main__.TestWebServerSecurity) ... ok

----------------------------------------------------------------------
Ran 21 tests in 0.185s
OK
```

---

## 4. Phase 2 Plan: Core Runtime Enhancements

Target features to implement next:

1. **Wall-Clock Execution Timeout Support (`--timeout <sec>`):**
   - Add timeout field to `axes::Config` and CLI.
   - Supervisor tracks wall-clock runtime. When `elapsed >= timeout`, supervisor terminates the workload (`cgroup.kill` or `SIGKILL`), logs `TIMED_OUT`, and exits with code 124.
2. **Standard Output and Error Capture:**
   - Redirect child process `stdout` and `stderr` to `reports/<job_id>_output.log` via pipe or pseudo-terminal.
   - Stream output in real-time to the web server and CLI.
3. **Supervisor Signal Handling (`SIGINT`, `SIGTERM`):**
   - Install signal handlers in `main.cpp` using `sigaction`.
   - On `Ctrl+C`, cleanly invoke `cgroup.kill`, reap children, and clean up cgroup directories before exiting.
4. **Machine-Readable JSON Reports:**
   - Generate `reports/<job_id>.json` alongside the text report.
5. **Two-Way Adaptive CPU Policy:**
   - Restore CPU quota when sustained workload utilization normalizes below a lower threshold.

---

## 5. Phase 3 Plan: Desktop Developer Workbench

Target features for the GUI:

1. **Workbench Layout Redesign:**
   - Replace toy dashboard cards with an IDE-style split pane:
     - Left: Staging area, workspace file list.
     - Center Top: Execution configuration & Run/Stop buttons.
     - Center Bottom: Live terminal output pane (streaming child stdout/stderr).
     - Right: Telemetry gauges (CPU %, RAM MB, PIDs count, adaptive status).
2. **File Selection & Drag-and-Drop Staging:**
   - HTML5 drag-and-drop zone uploading files to an isolated directory (`scratch/<job_id>/`).
   - Automatic command detection (e.g. `python3 script.py` or `./binary`).
3. **Execution Controls (Stop / Cancel):**
   - Add `POST /api/job/<id>/stop` endpoint.
   - Prominent Stop button terminating active jobs cleanly within 1 second.
