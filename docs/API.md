# AXES Workbench Backend API Contract

**Version:** 2.0.0  
**Base URL:** `http://127.0.0.1:8080` (or `http://127.0.0.1:<AXES_PORT>`)  
**Transport:** HTTP/1.1  
**Content-Type:** `application/json` (except static files and multipart file uploads)

---

## 1. Security Architecture & Access Control

1. **Localhost Binding:** The server strictly binds to `127.0.0.1` and rejects remote connections.
2. **Origin & Host Verification:**
   - Every API endpoint (`/api/*`) verifies `Host`, `Origin` (if present), and `Sec-Fetch-Site`.
   - Untrusted origins or external hosts receive `403 Forbidden`.
   - Wildcard CORS is removed to prevent cross-site execution attacks from external browser tabs.
3. **Path Traversal & Symlink Escapes:**
   - Job IDs are validated against `^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$`.
   - Staged file names are validated against `^[a-zA-Z0-9_.-]{1,128}$`.
   - Paths are resolved and verified with `relative_to` against `reports/` and `staging/` roots.
4. **Shell Injection Prevention:**
   - No user input is ever passed to `shell=True` or shell string interpolation.
   - All compilers and supervisors are executed with explicit argument vectors.

---

## 2. Execution Lifecycle States

Every workload managed by AXES transitions through a deterministic state machine:

| Status | Description |
| :--- | :--- |
| `STARTING` | Job slot reserved, cgroup initialized, process barrier pending. |
| `RUNNING` | Process attached to cgroup, barrier released, telemetry streaming. |
| `COMPLETED` | Workload exited normally with exit code `0`. |
| `FAILED` | Workload exited with a non-zero exit code or failed launch. |
| `TIMED_OUT` | Wall-clock execution timeout reached; process tree terminated (exit code `124`). |
| `CANCELLED` | Execution stopped by user request or supervisor signal (exit code `128 + sig`). |
| `KILLED` | Workload terminated by Linux signal (e.g. `SIGKILL`, OOM killer). |

---

## 3. Endpoints

### 3.1 System Readiness

#### `GET /api/status`
Checks host cgroups v2 availability, controller delegation, and staging directory readiness.

- **Response `200 OK`**:
```json
{
  "ready": true,
  "output": "...",
  "cgroups_v2": true,
  "cpu_controller": true,
  "memory_controller": true,
  "pids_controller": true,
  "axes_writable": true,
  "staging_writable": true,
  "staging_dir": "/path/to/staging",
  "staged_files_count": 3
}
```

---

### 3.2 File Staging

#### `GET /api/files`
Lists all files currently stored in the AXES staging directory.

- **Response `200 OK`**:
```json
[
  {
    "filename": "process_stress.c",
    "size_bytes": 1363,
    "modified_time": 1729500000.0,
    "file_type": "c",
    "is_executable": false
  }
]
```

#### `POST /api/files/upload`
Uploads a source code, script, or binary file to the staging directory.

- **Request Format 1 (JSON)**:
```json
{
  "filename": "workload.py",
  "content": "print('Hello AXES!')\n",
  "encoding": "utf-8"
}
```
*(For binary files, pass `"encoding": "base64"` and base64-encoded string in `content`)*

- **Request Format 2 (`multipart/form-data`)**:
Standard multipart form upload with a file attachment.

- **Limits**: Maximum file size is 10 MB (10,485,760 bytes).
- **Response `200 OK`**:
```json
{
  "success": true,
  "filename": "workload.py",
  "size_bytes": 22
}
```
- **Error Responses**:
  - `400 Bad Request`: Invalid filename, file size exceeds 10MB, or malformed payload.

#### `GET /api/files/{filename}`
Retrieves metadata and text content for a staged file.

- **Response `200 OK`**:
```json
{
  "filename": "workload.py",
  "size_bytes": 22,
  "content": "print('Hello AXES!')\n",
  "is_binary": false
}
```

#### `DELETE /api/files/{filename}`
Deletes a staged file safely.

- **Response `200 OK`**:
```json
{
  "success": true,
  "filename": "workload.py"
}
```
- **Error Responses**:
  - `404 Not Found`: File does not exist.

---

### 3.3 C/C++ Staged Compilation

#### `POST /api/compile`
Compiles a staged C or C++ source file into an executable binary using an explicit argument vector (`gcc`/`g++`). Compilation diagnostics are returned directly and isolated from workload execution.

- **Request Shape**:
```json
{
  "source_file": "process_stress.c",
  "output_name": "process_stress.bin",
  "compiler_flags": ["-O2", "-Wall", "-pthread"]
}
```

- **Response `200 OK` (Compilation Succeeded)**:
```json
{
  "success": true,
  "binary": "process_stress.bin",
  "exit_code": 0,
  "stdout": "",
  "stderr": "",
  "compile_time_sec": 0.085
}
```

- **Response `400 Bad Request` (Compilation Failed)**:
```json
{
  "success": false,
  "error": "Compilation failed",
  "exit_code": 1,
  "stdout": "",
  "stderr": "process_stress.c:12:3: error: unknown type name 'bad_type'...",
  "compile_time_sec": 0.042
}
```

---

### 3.4 Workload Execution

#### `POST /api/run`
Launches a contained workload through the AXES C++ supervisor. Supports either explicit commands or staged files.

- **Request Shape**:
```json
{
  "job_id": "job-stress-01",
  "staged_file": "process_stress.bin",
  "args": ["--mode", "fast"],
  "timeout": 10.0,
  "cpu_limit": 200.0,
  "memory_limit": 512,
  "pids_limit": 64,
  "cpu_threshold": 150.0,
  "consecutive": 3,
  "reduced_cpu": 100.0,
  "sample_interval": 0.5,
  "adaptive": true,
  "isolation": "isolated"
}
```
*Alternatively, pass `"command": "python3 workloads/cpu_burn.py"` instead of `"staged_file"`.*

`isolation` accepts `resource` (cgroup controls only, for trusted workloads) or `isolated` (required namespace, filesystem, network and Seccomp setup). Isolated setup failure terminates the job and never retries in resource mode. Staged files execute from `/workspace/<filename>` in isolated mode.

- **Response `200 OK`**:
```json
{
  "success": true,
  "job_id": "job-stress-01"
}
```
- **Error Responses**:
  - `400 Bad Request`: Missing command/staged file, invalid job ID, or numeric parameter out of range.
  - `409 Conflict`: Job with this ID is already running or cgroup is occupied.

---

### 3.5 Live Monitoring, Streaming & Control

#### `GET /api/job/{job_id}`
Returns live telemetry, resource usage, adaptive state, and status for an active or completed job.

- **Response `200 OK`**:
```json
{
  "job_id": "job-stress-01",
  "status": "RUNNING",
  "pid": 12345,
  "cgroup_path": "/sys/fs/cgroup/axes/job-stress-01",
  "pid_attached": "YES",
  "isolation_established": true,
  "metrics_valid": true,
  "sample_received_at": 1792648800.25,
  "runtime_sec": 3.5,
  "metrics": {
    "cpu_pct": 182.4,
    "memory_mb": 42.1,
    "pids": 16
  },
  "initial_cpu_limit": 200.0,
  "current_cpu_limit": 100.0,
  "adaptive_triggered": true,
  "timed_out": false,
  "cancelled": false,
  "exit_code": null,
  "events": [
    "[0.0s] AXES Sandbox job job-stress-01 scheduled.",
    "[1.0s] High CPU detected (185.0% >= 150.0%) [1/3]",
    "[2.0s] ADAPTIVE TRIGGER: CPU limit changed: 200.0% -> 100.0%"
  ]
}
```

#### `GET /api/job/{job_id}/output?offset={N}&limit={bytes}`
Streams real workload stdout/stderr incrementally without buffering entire logs in memory.

- **Query Parameters**:
  - `offset`: Byte offset to start reading (integer, default `0`).
  - `limit`: Maximum bytes to read in chunk (integer, default `65536`, max `262144`).

- **Response `200 OK`**:
```json
{
  "job_id": "job-stress-01",
  "offset": 0,
  "next_offset": 512,
  "output": "Workload starting...\nSpawning child 1 (PID 12346)\n",
  "bytes_read": 512,
  "eof": false,
  "job_status": "RUNNING"
}
```

#### `POST /api/job/{job_id}/stop`
Requests graceful supervisor termination and process-tree cancellation. The supervisor sends `cgroup.kill` to all contained processes, reaps zombies, records `CANCELLED` status, and generates the final report.

- **Response `200 OK`**:
```json
{
  "success": true,
  "job_id": "job-stress-01",
  "status": "CANCELLED"
}
```

---

### 3.6 Execution History & Reports

#### `GET /api/history`
Returns chronological list of all recorded executions from newest to oldest.

- **Response `200 OK`**:
```json
[
  {
    "job_id": "job-stress-01",
    "status": "COMPLETED",
    "start_time": "2026-10-21 18:30:00",
    "end_time": "2026-10-21 18:30:05",
    "runtime_sec": 5.02,
    "exit_code": 0,
    "peak_cpu_pct": 194.2,
    "peak_memory_mb": 48.0,
    "peak_pids": 32
  }
]
```

#### `GET /api/report/{job_id}`
Returns complete structured report data for a completed execution (parsed from JSON or TXT).

#### `GET /api/report/{job_id}/output`
Returns the full captured stdout/stderr log for a completed execution.

## Phase 3 additive contract details

Live `GET /api/job/{id}` responses also include:

- `command`: the actual argument vector passed to the supervisor.
- `staged_file`: staged filename, or null for command mode.
- `args`: staged argument array.
- `kernel_controls`: current reads of `cpu.max`, `memory.max`, `memory.swap.max`, `pids.max`, and `cgroup.procs`. Values are strings or null when a file is unavailable; completed cgroups may already have been removed.
- `isolation_established`: true only after the supervisor validates Bubblewrap namespace evidence. A requested mode alone never sets this field.
- `metrics_valid` and timestamped `history` entries: identify cgroup samples that were successfully read. The UI retains the last valid sample after the final empty-cgroup read.

Stop acknowledges the cancellation request, but live status stays STARTING/RUNNING until the supervisor exits and report/output finalization completes. `cancelled: true` during that interval means cancellation is pending. Output byte offsets leave an incomplete UTF-8 character for the following chunk instead of emitting corrupt replacement characters.
