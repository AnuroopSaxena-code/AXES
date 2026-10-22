#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
import sys
import subprocess
import threading
import time
import re
import urllib.parse
import signal
import base64
import codecs
import math
import uuid
import email
import email.policy
from pathlib import Path

PORT = int(os.environ.get("AXES_PORT", 8080))
HOST = "127.0.0.1"

BASE_DIR = Path(__file__).resolve().parent.parent
BUILD_DIR = BASE_DIR / "build"
AXES_BIN = BUILD_DIR / "axes"
REPORTS_DIR = BASE_DIR / "reports"
WEB_DIR = BASE_DIR / "web"
STAGING_DIR = BASE_DIR / "staging"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
STAGING_DIR.mkdir(parents=True, exist_ok=True)

active_jobs = {} # job_id -> dict state
job_processes = {} # job_id -> subprocess.Popen instance (not serialized)
job_lock = threading.Lock()

VALID_JOB_ID_REGEX = re.compile(r'^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$')
VALID_FILENAME_REGEX = re.compile(r'^[a-zA-Z0-9_.-]{1,128}$')

def is_valid_job_id(job_id: str) -> bool:
    if not job_id or not isinstance(job_id, str):
        return False
    return bool(VALID_JOB_ID_REGEX.match(job_id))

def is_safe_filename(filename: str) -> bool:
    if not filename or not isinstance(filename, str):
        return False
    if not VALID_FILENAME_REGEX.match(filename):
        return False
    if ".." in filename or "/" in filename or "\\" in filename or "\0" in filename:
        return False
    if filename.startswith("-"):
        return False
    return True

def get_safe_report_path(job_id: str):
    if not is_valid_job_id(job_id):
        return None
    report_file = (REPORTS_DIR / f"{job_id}_report.txt").resolve()
    reports_root = REPORTS_DIR.resolve()
    try:
        report_file.relative_to(reports_root)
        return report_file
    except ValueError:
        return None

def get_safe_json_report_path(job_id: str):
    if not is_valid_job_id(job_id):
        return None
    json_file = (REPORTS_DIR / f"{job_id}_report.json").resolve()
    reports_root = REPORTS_DIR.resolve()
    try:
        json_file.relative_to(reports_root)
        return json_file
    except ValueError:
        return None

def get_safe_output_path(job_id: str):
    if not is_valid_job_id(job_id):
        return None
    output_file = (REPORTS_DIR / f"{job_id}_output.log").resolve()
    reports_root = REPORTS_DIR.resolve()
    try:
        output_file.relative_to(reports_root)
        return output_file
    except ValueError:
        return None

def get_safe_staged_path(filename: str):
    if not is_safe_filename(filename):
        return None
    staged_file = (STAGING_DIR / filename).resolve()
    staging_root = STAGING_DIR.resolve()
    try:
        staged_file.relative_to(staging_root)
        return staged_file
    except ValueError:
        return None

def parse_report_file(filepath):
    path_obj = Path(filepath).resolve()
    reports_root = REPORTS_DIR.resolve()
    try:
        path_obj.relative_to(reports_root)
    except ValueError:
        return None
    if not path_obj.exists() or not path_obj.is_file():
        return None

    with open(path_obj, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    
    report_data = {
        "raw_text": content,
        "job_id": "",
        "command": "",
        "start_time": "",
        "end_time": "",
        "runtime_sec": 0.0,
        "status": "",
        "final_status": "",
        "exit_code_signal": "",
        "exit_code": None,
        "cgroup_path": "",
        "pid_attached": "NO",
        "cpu_limit_pct": 200.0,
        "memory_limit_mb": 512,
        "swap_limit": "Disabled",
        "pids_limit": 64,
        "peak_cpu_pct": 0.0,
        "peak_memory_mb": 0.0,
        "peak_pids": 0,
        "initial_cpu_limit": 200.0,
        "final_cpu_limit": 200.0,
        "threshold_pct": 150.0,
        "consecutive_samples": 3,
        "adaptive_triggered": False,
        "timed_out": False,
        "cancelled": False,
        "output_file": "",
        "output_bytes_captured": 0,
        "event_timeline": [],
        "cpu_max": "",
        "memory_max": "",
        "memory_swap_max": "",
        "pids_max": ""
    }

    for line in content.splitlines():
        line_str = line.strip()
        if line_str.startswith("Job ID:"):
            report_data["job_id"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("Command:"):
            report_data["command"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("Start time:"):
            report_data["start_time"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("End time:"):
            report_data["end_time"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("Runtime:"):
            val = line_str.split(":", 1)[1].replace("s", "").strip()
            try: report_data["runtime_sec"] = float(val)
            except: pass
        elif line_str.startswith("Status:"):
            st = line_str.split(":", 1)[1].strip()
            report_data["status"] = st
            report_data["final_status"] = st
        elif line_str.startswith("Exit code / Signal:"):
            report_data["exit_code_signal"] = line_str.split(":", 1)[1].strip()
            if "Code" in report_data["exit_code_signal"]:
                try: report_data["exit_code"] = int(report_data["exit_code_signal"].split("Code")[1].strip())
                except: pass
        elif line_str.startswith("Timed out:"):
            report_data["timed_out"] = "YES" in line_str
        elif line_str.startswith("Cancelled:"):
            report_data["cancelled"] = "YES" in line_str
        elif line_str.startswith("Output file:"):
            report_data["output_file"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("Output captured:"):
            val = line_str.split(":", 1)[1].split("bytes")[0].strip()
            try: report_data["output_bytes_captured"] = int(val)
            except: pass
        elif line_str.startswith("Path:"):
            report_data["cgroup_path"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("PID Attached:"):
            report_data["pid_attached"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("CPU:") and "PEAK" not in line_str and "%" in line_str:
            val = line_str.split(":", 1)[1].replace("%", "").strip()
            try: report_data["cpu_limit_pct"] = float(val)
            except: pass
        elif line_str.startswith("Memory:") and "PEAK" not in line_str and "MB" in line_str:
            val = line_str.split(":", 1)[1].replace("MB", "").strip()
            try: report_data["memory_limit_mb"] = int(val)
            except: pass
        elif line_str.startswith("PIDs:") and "PEAK" not in line_str:
            val = line_str.split(":", 1)[1].strip()
            try: report_data["pids_limit"] = int(val)
            except: pass
        elif line_str.startswith("CPU:") and "%" in line_str:
            val = line_str.split(":", 1)[1].replace("%", "").strip()
            try: report_data["peak_cpu_pct"] = float(val)
            except: pass
        elif line_str.startswith("Memory:") and "MB" in line_str:
            val = line_str.split(":", 1)[1].replace("MB", "").strip()
            try: report_data["peak_memory_mb"] = float(val)
            except: pass
        elif line_str.startswith("Processes:"):
            val = line_str.split(":", 1)[1].strip()
            try: report_data["peak_pids"] = int(val)
            except: pass
        elif line_str.startswith("Initial CPU:"):
            val = line_str.split(":", 1)[1].replace("%", "").strip()
            try: report_data["initial_cpu_limit"] = float(val)
            except: pass
        elif line_str.startswith("Final CPU:"):
            val = line_str.split(":", 1)[1].replace("%", "").strip()
            try: report_data["final_cpu_limit"] = float(val)
            except: pass
        elif line_str.startswith("Threshold:"):
            val = line_str.split(":", 1)[1].replace("%", "").strip()
            try: report_data["threshold_pct"] = float(val)
            except: pass
        elif line_str.startswith("Consecutive Samples:"):
            val = line_str.split(":", 1)[1].strip()
            try: report_data["consecutive_samples"] = int(val)
            except: pass
        elif line_str.startswith("Triggered:"):
            report_data["adaptive_triggered"] = "TRIGGERED" in line_str
        elif line_str.startswith("cpu.max:"):
            report_data["cpu_max"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("memory.max:"):
            report_data["memory_max"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("memory.swap.max:"):
            report_data["memory_swap_max"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("pids.max:"):
            report_data["pids_max"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("[") and "s]" in line_str:
            report_data["event_timeline"].append(line_str)

    return report_data

def get_report_data(job_id: str):
    json_path = get_safe_json_report_path(job_id)
    if json_path and json_path.exists() and json_path.is_file():
        try:
            with open(json_path, "r", encoding="utf-8") as jf:
                return json.load(jf)
        except Exception:
            pass
    txt_path = get_safe_report_path(job_id)
    if txt_path and txt_path.exists() and txt_path.is_file():
        return parse_report_file(txt_path)
    return None

def run_job_thread(job_id, cmd_list, config):
    with job_lock:
        if job_id in active_jobs:
            if active_jobs[job_id].get('cancelled'):
                active_jobs[job_id]['status'] = 'CANCELLED'
                active_jobs[job_id]['exit_code'] = 143
                return
            active_jobs[job_id]["status"] = "RUNNING"

    out_file = get_safe_output_path(job_id)

    exec_cmd = [str(AXES_BIN), "run", "--job-id", job_id]
    exec_cmd.extend(["--isolation", config.get("isolation", "resource"), "--workspace", str(STAGING_DIR)])
    exec_cmd.extend(["--cpu-limit", str(config.get("cpu_limit", 200.0))])
    exec_cmd.extend(["--memory-limit", str(config.get("memory_limit", 512))])
    exec_cmd.extend(["--pids-limit", str(config.get("pids_limit", 64))])
    exec_cmd.extend(["--cpu-threshold", str(config.get("cpu_threshold", 150.0))])
    exec_cmd.extend(["--consecutive", str(config.get("consecutive", 3))])
    exec_cmd.extend(["--reduced-cpu", str(config.get("reduced_cpu", 100.0))])
    exec_cmd.extend(["--sample-interval", str(config.get("sample_interval", 0.5))])
    if config.get("timeout", 0.0) > 0.0:
        exec_cmd.extend(["--timeout", str(config.get("timeout"))])
    if out_file:
        exec_cmd.extend(["--output-file", str(out_file)])
    if not config.get("adaptive", True):
        exec_cmd.append("--no-adaptive")
    
    exec_cmd.extend(["--"] + cmd_list)

    try:
        proc = subprocess.Popen(
            exec_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(BASE_DIR)
        )
    except Exception as exc:
        with job_lock:
            if job_id in active_jobs:
                active_jobs[job_id]["status"] = "FAILED"
                active_jobs[job_id]["events"].append(f"[0.0s] Failed to launch AXES supervisor: {str(exc)}")
        return

    with job_lock:
        if job_id in active_jobs:
            active_jobs[job_id]["supervisor_pid"] = proc.pid
        job_processes[job_id] = proc
        cancel_requested = active_jobs.get(job_id, {}).get('cancelled', False)
    if cancel_requested and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)

    # Parse supervisor stdout in real-time for telemetry
    snapshot_cpu = 0.0
    snapshot_mem = 0.0
    snapshot_pids = 1
    snapshot_runtime = 0.0

    for line in proc.stdout:
        line_str = line.strip()
        if not line_str: continue

        with job_lock:
            state = active_jobs.get(job_id)
            if not state: break

            if line_str.startswith("PID:") and "Cgroup" not in line_str:
                try: state["pid"] = int(line_str.split(":")[1].strip())
                except: pass
            elif line_str.startswith("Cgroup Path:"):
                state["cgroup_path"] = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("Cgroup PID:"):
                if "VERIFIED" in line_str:
                    state["pid_attached"] = "YES"

            if line_str.startswith("Metrics Valid:"):
                state["metrics_valid"] = line_str.endswith("YES")
            elif line_str.startswith("CPU Usage:"):
                try:
                    snapshot_cpu = float(line_str.split(":")[1].replace("%", "").strip())
                    state["metrics"]["cpu_pct"] = snapshot_cpu
                except: pass
            elif line_str.startswith("Memory Usage:"):
                try:
                    snapshot_mem = float(line_str.split(":")[1].replace("MB", "").strip())
                    state["metrics"]["memory_mb"] = snapshot_mem
                except: pass
            elif line_str.startswith("Processes:"):
                try:
                    snapshot_pids = int(line_str.split(":")[1].strip())
                    state["metrics"]["pids"] = snapshot_pids
                except: pass
            elif line_str.startswith("Runtime:"):
                try:
                    snapshot_runtime = float(line_str.split(":")[1].replace("s", "").strip())
                    state["runtime_sec"] = snapshot_runtime
                    state["sample_received_at"] = time.time()
                    state["history"].append({
                        "runtime": snapshot_runtime,
                        "cpu_pct": snapshot_cpu,
                        "memory_mb": snapshot_mem,
                        "pids": snapshot_pids
                    })
                    state["history"] = state["history"][-512:]
                except: pass

            if line_str.startswith("[") and "s]" in line_str:
                state["events"].append(line_str)
                state["events"] = state["events"][-2048:]
                if "ADAPTIVE TRIGGER" in line_str:
                    state["adaptive_triggered"] = True
                    state["current_cpu_limit"] = min(config["cpu_limit"], config["reduced_cpu"])

    proc.wait()

    with job_lock:
        state = active_jobs.get(job_id)
        if state:
            state["exit_code"] = proc.returncode
            if proc.returncode == 124:
                state["status"] = "TIMED_OUT"
                state["timed_out"] = True
            elif state.get("cancelled") or proc.returncode in (130, 143, 128 + 2, 128 + 15):
                state["status"] = "CANCELLED"
                state["cancelled"] = True
            elif proc.returncode == 0:
                state["status"] = "COMPLETED"
            elif proc.returncode > 128:
                state["status"] = "KILLED"
            else:
                state["status"] = "FAILED"

            # Load generated report data
            report = get_report_data(job_id)
            if report:
                state["report_data"] = report
                if report.get("final_status"):
                    state["status"] = report["final_status"]
                elif report.get("status"):
                    state["status"] = report["status"]
                if report.get("adaptive_triggered"):
                    state["adaptive_triggered"] = True
                    state["current_cpu_limit"] = report.get("adaptive", {}).get("final_cpu", report.get("final_cpu_limit", state["current_cpu_limit"]))

class AxesHTTPHandler(http.server.SimpleHTTPRequestHandler):
    @property
    def allowed_hosts(self):
        return {
            f"127.0.0.1:{PORT}",
            f"localhost:{PORT}",
            "127.0.0.1:8080",
            "localhost:8080",
            "127.0.0.1",
            "localhost"
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def _verify_origin_and_host(self) -> bool:
        # Validate Host header if provided
        host = self.headers.get("Host", "").strip()
        if host and host not in self.allowed_hosts:
            return False

        # Validate Origin header if present
        origin = self.headers.get("Origin")
        if origin:
            parsed = urllib.parse.urlparse(origin)
            if parsed.netloc not in self.allowed_hosts:
                return False

        # Validate Sec-Fetch-Site if present
        sec_fetch_site = self.headers.get("Sec-Fetch-Site")
        if sec_fetch_site and sec_fetch_site not in ("same-origin", "none", "same-site"):
            return False

        return True

    def _send_json(self, data, status=200):
        try:
            body = json.dumps(data).encode("utf-8")
        except Exception as e:
            body = json.dumps({"error": f"Serialization error: {str(e)}"}).encode("utf-8")
            status = 500
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        if path.startswith("/api/"):
            if not self._verify_origin_and_host():
                self._send_json({"error": "Forbidden: Cross-origin or untrusted request blocked."}, status=403)
                return

        # 1. System readiness status
        if path == "/api/status":
            try:
                res = subprocess.run([str(AXES_BIN), "check"], capture_output=True, text=True, timeout=5)
                output = res.stdout
                ready = "SYSTEM READY FOR CONTAINMENT EXECUTION [PASS]" in output
                staged_count = len([p for p in STAGING_DIR.iterdir() if p.is_file() and not p.name.startswith(".")]) if STAGING_DIR.exists() else 0
                data = {
                    "ready": ready,
                    "output": output,
                    "cgroups_v2": "Linux cgroups v2 mounted:   [PASS]" in output,
                    "cpu_controller": "CPU controller available:   [PASS]" in output,
                    "memory_controller": "Memory controller available:[PASS]" in output,
                    "pids_controller": "PIDs controller available:  [PASS]" in output,
                    "axes_writable": "AXES subtree writable:      [PASS]" in output,
                    "staging_writable": os.access(str(STAGING_DIR), os.W_OK),
                    "staging_dir": str(STAGING_DIR),
                    "staged_files_count": staged_count
                }
                self._send_json(data)
            except Exception as e:
                self._send_json({"ready": False, "error": str(e)}, status=500)
            return

        # 2. File staging: list all staged files
        elif path == "/api/files":
            files_list = []
            if STAGING_DIR.exists():
                for p in sorted(STAGING_DIR.iterdir()):
                    if p.is_file() and not p.name.startswith("."):
                        st = p.stat()
                        suffix = p.suffix.lower().lstrip(".")
                        is_exec = os.access(p, os.X_OK)
                        files_list.append({
                            "filename": p.name,
                            "size_bytes": st.st_size,
                            "modified_time": st.st_mtime,
                            "file_type": suffix if suffix else "binary",
                            "is_executable": is_exec
                        })
            self._send_json(files_list)
            return

        # 3. File staging: view specific file
        elif path.startswith("/api/files/"):
            fname = path[len("/api/files/"):].strip()
            safe_p = get_safe_staged_path(fname)
            if not safe_p or not safe_p.exists() or not safe_p.is_file():
                self._send_json({"error": "Staged file not found"}, status=404)
                return
            st = safe_p.stat()
            try:
                with open(safe_p, "r", encoding="utf-8") as f:
                    content = f.read()
                self._send_json({
                    "filename": fname,
                    "size_bytes": st.st_size,
                    "content": content,
                    "is_binary": False
                })
            except UnicodeDecodeError:
                self._send_json({
                    "filename": fname,
                    "size_bytes": st.st_size,
                    "is_binary": True
                })
            return

        # 4. Incremental job output retrieval: /api/job/<id>/output
        elif path.startswith("/api/job/") and path.endswith("/output"):
            job_id = path[len("/api/job/"): -len("/output")].strip()
            if not is_valid_job_id(job_id):
                self._send_json({"error": "Invalid job ID format"}, status=400)
                return

            qs = urllib.parse.parse_qs(url.query)
            try:
                offset = int(qs.get("offset", ["0"])[0])
                if offset < 0: offset = 0
            except (ValueError, TypeError):
                offset = 0

            try:
                limit = int(qs.get("limit", ["65536"])[0])
                if limit <= 0 or limit > 262144: limit = 65536
            except (ValueError, TypeError):
                limit = 65536

            out_path = get_safe_output_path(job_id)
            with job_lock:
                state = active_jobs.get(job_id)
                current_status = state["status"] if state else None

            if not current_status and out_path and out_path.exists():
                current_status = "COMPLETED"

            if not out_path or not out_path.exists():
                if current_status in ("STARTING", "RUNNING"):
                    self._send_json({
                        "job_id": job_id,
                        "offset": offset,
                        "next_offset": offset,
                        "output": "",
                        "bytes_read": 0,
                        "eof": False,
                        "job_status": current_status
                    })
                    return
                else:
                    self._send_json({"error": "Output file not found for job"}, status=404)
                    return

            file_size = out_path.stat().st_size
            output_chunk = ""
            bytes_read = 0

            if offset < file_size:
                with open(out_path, "rb") as of:
                    of.seek(offset)
                    raw_bytes = of.read(limit)
                    decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
                    final = current_status not in ('STARTING', 'RUNNING', None) and offset + len(raw_bytes) >= file_size
                    output_chunk = decoder.decode(raw_bytes, final=final)
                    pending, _ = decoder.getstate()
                    bytes_read = len(raw_bytes) - len(pending)

            next_offset = offset + bytes_read
            is_job_finished = current_status not in ("STARTING", "RUNNING", None)
            is_eof = is_job_finished and (next_offset >= file_size)

            self._send_json({
                "job_id": job_id,
                "offset": offset,
                "next_offset": next_offset,
                "output": output_chunk,
                "bytes_read": bytes_read,
                "eof": is_eof,
                "job_status": current_status or "UNKNOWN"
            })
            return

        # 5. Live job status: /api/job/<id>
        elif path.startswith("/api/job/"):
            job_id = path[len("/api/job/"):].strip()
            if not is_valid_job_id(job_id):
                self._send_json({"error": "Invalid job ID format"}, status=400)
                return

            with job_lock:
                state = active_jobs.get(job_id)
                if state:
                    # Read actual kernel values; never manufacture enforcement from config.
                    snapshot = dict(state)
                    controls = {}
                    root = Path('/sys/fs/cgroup/axes') / job_id
                    for name in ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.max', 'cgroup.procs'):
                        try:
                            controls[name] = (root / name).read_text().strip()
                        except OSError:
                            controls[name] = None
                    snapshot['kernel_controls'] = controls
                    self._send_json(snapshot)
                    return

            # Check if report exists
            report = get_report_data(job_id)
            if report:
                self._send_json({
                    "job_id": job_id,
                    "status": report.get("final_status", report.get("status", "COMPLETED")),
                    "report_data": report
                })
                return

            self._send_json({"error": "Job not found"}, status=404)
            return

        # 6. Execution history: /api/history
        elif path == "/api/history":
            history_list = []
            seen_jobs = set()
            if REPORTS_DIR.exists():
                for f in os.listdir(REPORTS_DIR):
                    cand = None
                    if f.endswith("_report.json"):
                        cand = f[:-len("_report.json")]
                    elif f.endswith("_report.txt"):
                        cand = f[:-len("_report.txt")]
                    if cand and is_valid_job_id(cand) and cand not in seen_jobs:
                        seen_jobs.add(cand)
                        rep = get_report_data(cand)
                        if rep:
                            history_list.append(rep)
            history_list.sort(key=lambda x: x.get("start_time", ""), reverse=True)
            self._send_json(history_list)
            return

        # 7. Completed report: /api/report/<id>/output
        elif path.startswith("/api/report/") and path.endswith("/output"):
            job_id = path[len("/api/report/"): -len("/output")].strip()
            if not is_valid_job_id(job_id):
                self._send_json({"error": "Invalid job ID format"}, status=400)
                return
            out_file = get_safe_output_path(job_id)
            if out_file and out_file.exists():
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                self._send_json({"job_id": job_id, "output": content})
                return
            self._send_json({"error": "Output log not found"}, status=404)
            return

        # 8. Completed report data: /api/report/<id>
        elif path.startswith("/api/report/"):
            job_id = path[len("/api/report/"):].strip()
            if not is_valid_job_id(job_id):
                self._send_json({"error": "Invalid job ID format"}, status=400)
                return

            rep = get_report_data(job_id)
            if rep:
                self._send_json(rep)
                return

            self._send_json({"error": "Report not found"}, status=404)
            return

        # Serve static web files
        return super().do_GET()

    def do_POST(self):
        if not self._verify_origin_and_host():
            self._send_json({"error": "Forbidden: Cross-origin or untrusted request blocked."}, status=403)
            return

        url = urllib.parse.urlparse(self.path)
        path = url.path

        # 1. File staging: upload file (JSON or Multipart)
        if path == "/api/files/upload":
            content_type = self.headers.get("Content-Type", "")
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                self._send_json({"error": "Invalid Content-Length header"}, status=400)
                return

            if length <= 0 or length > (10 * 1024 * 1024):
                self._send_json({"error": "Payload size invalid (must be between 1 and 10,485,760 bytes)"}, status=400)
                return

            body_bytes = self.rfile.read(length)

            filename = None
            file_data = None

            if "multipart/form-data" in content_type:
                try:
                    msg = email.message_from_bytes(
                        b"Content-Type: " + content_type.encode("utf-8") + b"\r\n\r\n" + body_bytes,
                        policy=email.policy.default
                    )
                    for part in msg.iter_parts():
                        fname_cand = part.get_filename()
                        if fname_cand:
                            filename = fname_cand
                            file_data = part.get_payload(decode=True)
                            break
                    if not filename or file_data is None:
                        self._send_json({"error": "No file found in multipart upload"}, status=400)
                        return
                except Exception as e:
                    self._send_json({"error": f"Failed to parse multipart data: {str(e)}"}, status=400)
                    return
            else:
                try:
                    data = json.loads(body_bytes.decode("utf-8"))
                    filename = data.get("filename", "").strip()
                    content_str = data.get("content", "")
                    encoding = data.get("encoding", "utf-8")
                    if encoding == "base64":
                        file_data = base64.b64decode(content_str)
                    else:
                        file_data = content_str.encode("utf-8")
                except Exception as e:
                    self._send_json({"error": f"Invalid JSON payload: {str(e)}"}, status=400)
                    return

            if not is_safe_filename(filename):
                self._send_json({"error": f"Invalid filename '{filename}'. Must be 1-128 chars matching [a-zA-Z0-9_.-] and not start with '-'."}, status=400)
                return

            target_path = get_safe_staged_path(filename)
            if not target_path:
                self._send_json({"error": "Invalid target path"}, status=400)
                return

            try:
                with open(target_path, "wb") as f:
                    f.write(file_data)
                # Set executable permissions if shell script or binary
                if filename.endswith(".sh") or filename.endswith(".bin") or filename.endswith(".py"):
                    target_path.chmod(0o755)
                self._send_json({
                    "success": True,
                    "filename": filename,
                    "size_bytes": len(file_data)
                })
            except Exception as e:
                self._send_json({"error": f"Failed to save file: {str(e)}"}, status=500)
            return

        # 2. C/C++ compilation endpoint
        elif path == "/api/compile":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(length)
                data = json.loads(body_bytes.decode("utf-8"))
            except Exception as e:
                self._send_json({"error": f"Invalid JSON payload: {str(e)}"}, status=400)
                return

            source_file = data.get("source_file", "").strip()
            if not is_safe_filename(source_file):
                self._send_json({"error": f"Invalid source filename '{source_file}'"}, status=400)
                return

            src_path = get_safe_staged_path(source_file)
            if not src_path or not src_path.exists() or not src_path.is_file():
                self._send_json({"error": f"Source file '{source_file}' not found in staging area"}, status=404)
                return

            suffix = src_path.suffix.lower()
            if suffix == ".c":
                compiler = "gcc"
            elif suffix in (".cpp", ".cc", ".cxx"):
                compiler = "g++"
            else:
                self._send_json({"error": f"Unsupported source file type '{suffix}'. Must be .c, .cpp, or .cc"}, status=400)
                return

            raw_out_name = data.get("output_name", "").strip()
            if raw_out_name:
                if not is_safe_filename(raw_out_name):
                    self._send_json({"error": f"Invalid output binary name '{raw_out_name}'"}, status=400)
                    return
                output_name = raw_out_name
            else:
                output_name = f"{src_path.stem}.bin"

            out_path = get_safe_staged_path(output_name)
            if not out_path:
                self._send_json({"error": "Invalid output path"}, status=400)
                return

            # Compiler flags validation
            compiler_flags = []
            raw_flags = data.get("compiler_flags", ["-O2", "-Wall"])
            if not isinstance(raw_flags, list):
                self._send_json({"error": "compiler_flags must be an array of strings"}, status=400)
                return

            for fl in raw_flags:
                if not isinstance(fl, str) or not re.match(r'^[a-zA-Z0-9_.=\-]+$', fl) or "\0" in fl:
                    self._send_json({"error": f"Invalid compiler flag: '{fl}'"}, status=400)
                    return
                compiler_flags.append(fl)

            extra_sources = []
            include_dirs = []
            if suffix in (".cpp", ".cc", ".cxx"):
                if not any(fl.startswith("-std=") for fl in compiler_flags):
                    compiler_flags.append("-std=c++17")
                if "-pthread" not in compiler_flags:
                    compiler_flags.append("-pthread")

                try:
                    with open(src_path, "r", encoding="utf-8", errors="ignore") as sf:
                        src_content = sf.read()
                    if "cgroup.hpp" in src_content or "axes::" in src_content or "launcher.hpp" in src_content:
                        include_dirs.extend(["-I", str(BASE_DIR / "src")])
                        for sname in ["cgroup.cpp", "launcher.cpp", "monitor.cpp", "security.cpp"]:
                            sp = BASE_DIR / "src" / sname
                            if sp.exists():
                                extra_sources.append(str(sp))
                except Exception:
                    pass

            # Explicit compiler argument vector (NEVER shell=True!)
            compile_cmd = [compiler] + compiler_flags + include_dirs + [str(src_path)] + extra_sources + ["-o", str(out_path)]

            t0 = time.time()
            try:
                cres = subprocess.run(
                    compile_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=str(BASE_DIR)
                )
                dur = round(time.time() - t0, 3)
            except subprocess.TimeoutExpired:
                self._send_json({
                    "success": False,
                    "error": "Compilation timed out after 30 seconds",
                    "compile_time_sec": 30.0
                }, status=400)
                return
            except Exception as e:
                self._send_json({
                    "success": False,
                    "error": f"Failed to execute compiler {compiler}: {str(e)}"
                }, status=500)
                return

            if cres.returncode == 0:
                out_path.chmod(0o755)
                self._send_json({
                    "success": True,
                    "binary": output_name,
                    "exit_code": 0,
                    "stdout": cres.stdout,
                    "stderr": cres.stderr,
                    "compile_time_sec": dur
                })
            else:
                self._send_json({
                    "success": False,
                    "error": "Compilation failed",
                    "exit_code": cres.returncode,
                    "stdout": cres.stdout,
                    "stderr": cres.stderr,
                    "compile_time_sec": dur
                }, status=400)
            return

        # 3. Stop running job: /api/job/<id>/stop
        elif path.startswith("/api/job/") and path.endswith("/stop"):
            job_id = path[len("/api/job/"): -len("/stop")].strip()
            if not is_valid_job_id(job_id):
                self._send_json({"error": "Invalid job ID format"}, status=400)
                return

            with job_lock:
                state = active_jobs.get(job_id)
                if not state:
                    self._send_json({"error": "Job not found in active records"}, status=404)
                    return

                if state.get("status") not in ("STARTING", "RUNNING"):
                    self._send_json({
                        "success": True,
                        "job_id": job_id,
                        "status": state.get("status"),
                        "message": "Job is already completed or stopped"
                    })
                    return

                # Mark state as cancelled
                state["cancelled"] = True
                # Keep polling until the supervisor has drained output and written its report.
                proc = job_processes.get(job_id)

            # Signal supervisor gracefully with SIGTERM
            if proc and proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGTERM)
                except Exception:
                    pass

            # Safety fallback: invoke cgroup.kill if kernel supports it
            cgroup_kill = Path(f"/sys/fs/cgroup/axes/{job_id}/cgroup.kill")
            if cgroup_kill.exists():
                try:
                    cgroup_kill.write_text("1")
                except Exception:
                    pass

            self._send_json({
                "success": True,
                "job_id": job_id,
                "status": "CANCELLED"
            })
            return

        # 4. Launch workload execution: /api/run
        elif path == "/api/run":
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                self._send_json({"error": "Invalid Content-Length header"}, status=400)
                return

            if length <= 0 or length > 65536:
                self._send_json({"error": "Payload size invalid (must be between 1 and 65,536 bytes)"}, status=400)
                return

            try:
                body_bytes = self.rfile.read(length)
                data = json.loads(body_bytes.decode("utf-8"))
                if not isinstance(data, dict):
                    self._send_json({"error": "JSON body must be a JSON object"}, status=400)
                    return
            except Exception as e:
                self._send_json({"error": f"Invalid JSON payload: {str(e)}"}, status=400)
                return

            isolation = data.get("isolation", "resource")
            if isolation not in ("resource", "isolated"):
                self._send_json({"error": "isolation must be resource or isolated"}, status=400)
                return
            # Support either staged_file or explicit command
            cmd_list = []
            staged_file = data.get("staged_file")
            raw_cmd = data.get("command")

            if staged_file:
                if not is_safe_filename(staged_file):
                    self._send_json({"error": f"Invalid staged_file '{staged_file}'"}, status=400)
                    return
                safe_staged = get_safe_staged_path(staged_file)
                if not safe_staged or not safe_staged.exists() or not safe_staged.is_file():
                    self._send_json({"error": f"Staged file '{staged_file}' does not exist"}, status=404)
                    return

                # Build argument list safely
                args_list = data.get("args", [])
                if not isinstance(args_list, list):
                    self._send_json({"error": "args must be a list of strings"}, status=400)
                    return
                for a in args_list:
                    if not isinstance(a, str) or "\0" in a:
                        self._send_json({"error": "Each arg must be a string without null characters"}, status=400)
                        return

                suffix = safe_staged.suffix.lower()
                execution_path = '/workspace/' + staged_file if isolation == 'isolated' else str(safe_staged)
                if suffix == ".py":
                    cmd_list = ["python3", execution_path] + args_list
                elif suffix == ".sh":
                    cmd_list = ["bash", execution_path] + args_list
                else:
                    cmd_list = [execution_path] + args_list

            elif raw_cmd:
                if not isinstance(raw_cmd, str) or not raw_cmd.strip():
                    self._send_json({"error": "Command is required and must be a non-empty string"}, status=400)
                    return
                raw_cmd = raw_cmd.strip()
                if len(raw_cmd) > 4096 or "\0" in raw_cmd:
                    self._send_json({"error": "Command exceeds length limit or contains null characters"}, status=400)
                    return

                import shlex
                try:
                    cmd_list = shlex.split(raw_cmd)
                    if not cmd_list:
                        self._send_json({"error": "Command is empty"}, status=400)
                        return
                except Exception as e:
                    self._send_json({"error": f"Failed to parse command arguments: {str(e)}"}, status=400)
                    return
            else:
                self._send_json({"error": "Either 'command' or 'staged_file' must be provided"}, status=400)
                return

            # Validate job_id
            raw_job_id = data.get("job_id", "")
            if raw_job_id:
                if not isinstance(raw_job_id, str) or not is_valid_job_id(raw_job_id.strip()):
                    self._send_json({
                        "error": f"Invalid job_id '{raw_job_id}'. Must be 1-64 characters matching [a-zA-Z0-9_-] and start with alphanumeric or underscore"
                    }, status=400)
                    return
                job_id = raw_job_id.strip()
            else:
                job_id = 'job-' + uuid.uuid4().hex

            # Validate numeric configuration parameters
            try:
                cpu_limit = float(data.get("cpu_limit", 200.0))
                memory_limit = int(data.get("memory_limit", 512))
                pids_limit = int(data.get("pids_limit", 64))
                cpu_threshold = float(data.get("cpu_threshold", 150.0))
                consecutive = int(data.get("consecutive", 3))
                reduced_cpu = float(data.get("reduced_cpu", 100.0))
                sample_interval = float(data.get("sample_interval", 0.5))
                adaptive = bool(data.get("adaptive", True))
                timeout = float(data.get("timeout", 0.0))
                if not all(math.isfinite(v) for v in (cpu_limit, cpu_threshold, reduced_cpu, sample_interval, timeout)):
                    raise ValueError("All numeric settings must be finite")

                if not (1.0 <= cpu_limit <= 10000.0):
                    raise ValueError("cpu_limit must be between 1.0% and 10000.0%")
                if not (1 <= memory_limit <= 1048576):
                    raise ValueError("memory_limit must be between 1 MB and 1,048,576 MB")
                if not (1 <= pids_limit <= 4194304):
                    raise ValueError("pids_limit must be between 1 and 4,194,304")
                if not (1.0 <= cpu_threshold <= 10000.0):
                    raise ValueError("cpu_threshold must be between 1.0% and 10000.0%")
                if not (1 <= consecutive <= 1000):
                    raise ValueError("consecutive must be between 1 and 1000")
                if not (1.0 <= reduced_cpu <= 10000.0):
                    raise ValueError("reduced_cpu must be between 1.0% and 10000.0%")
                if not (0.05 <= sample_interval <= 3600.0):
                    raise ValueError("sample_interval must be between 0.05s and 3600.0s")
                if timeout < 0.0 or timeout > 86400.0:
                    raise ValueError("timeout must be between 0.0s and 86400.0s")
            except (ValueError, TypeError) as val_err:
                self._send_json({"error": f"Invalid configuration parameter: {str(val_err)}"}, status=400)
                return

            config = {
                "isolation": isolation,
                "cpu_limit": cpu_limit,
                "memory_limit": memory_limit,
                "pids_limit": pids_limit,
                "cpu_threshold": cpu_threshold,
                "consecutive": consecutive,
                "reduced_cpu": reduced_cpu,
                "sample_interval": sample_interval,
                "adaptive": adaptive,
                "timeout": timeout
            }

            # Check for duplicate/running job_id collisions
            with job_lock:
                if get_report_data(job_id):
                    self._send_json({"error": "Job ID already has a report; choose a new ID."}, status=409)
                    return
                if job_id in active_jobs:
                    current_status = active_jobs[job_id].get("status")
                    if current_status in ("STARTING", "RUNNING"):
                        self._send_json({"error": f"Job '{job_id}' is already running."}, status=409)
                        return

                cgroup_procs_check = Path(f"/sys/fs/cgroup/axes/{job_id}/cgroup.procs")
                if cgroup_procs_check.exists():
                    try:
                        procs_text = cgroup_procs_check.read_text().strip()
                        if procs_text:
                            self._send_json({"error": f"Cgroup for job '{job_id}' is occupied by active processes."}, status=409)
                            return
                    except Exception:
                        pass

                # Reserve job slot
                active_jobs[job_id] = {
                    "job_id": job_id,
                    "command": cmd_list,
                    "staged_file": staged_file,
                    "args": data.get("args", []),
                    "config": config,
                    "status": "STARTING",
                    "pid": None,
                    "cgroup_path": f"/sys/fs/cgroup/axes/{job_id}",
                    "pid_attached": "PENDING",
                    "runtime_sec": 0.0,
                    "metrics": {"cpu_pct": 0.0, "memory_mb": 0.0, "pids": 0},
                    "history": [],
                    "events": [f"[0.0s] AXES Sandbox job {job_id} scheduled."],
                    "initial_cpu_limit": config["cpu_limit"],
                    "current_cpu_limit": config["cpu_limit"],
                    "adaptive_triggered": False,
                    "timed_out": False,
                    "cancelled": False,
                    "exit_code": None,
                    "output_file": str(get_safe_output_path(job_id)),
                    "report_data": None
                }

            t = threading.Thread(target=run_job_thread, args=(job_id, cmd_list, config), daemon=True)
            t.start()

            self._send_json({"success": True, "job_id": job_id})
            return

        self._send_json({"error": "Endpoint not found"}, status=404)

    def do_DELETE(self):
        if not self._verify_origin_and_host():
            self._send_json({"error": "Forbidden: Cross-origin or untrusted request blocked."}, status=403)
            return

        url = urllib.parse.urlparse(self.path)
        path = url.path

        if path.startswith("/api/files/"):
            filename = path[len("/api/files/"):].strip()
            if not is_safe_filename(filename):
                self._send_json({"error": "Invalid filename format"}, status=400)
                return

            target_path = get_safe_staged_path(filename)
            if not target_path or not target_path.exists() or not target_path.is_file():
                self._send_json({"error": "File not found"}, status=404)
                return

            try:
                target_path.unlink()
                self._send_json({"success": True, "filename": filename})
            except Exception as e:
                self._send_json({"error": f"Failed to delete file: {str(e)}"}, status=500)
            return

        self._send_json({"error": "Endpoint not found"}, status=404)

def main():
    if os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit("AXES API refuses root. Run privileged cgroup setup separately, then launch as an ordinary user.")
    if not AXES_BIN.exists():
        print(f"[Server Warning] AXES binary not found at {AXES_BIN}. Build AXES first using 'cmake -B build && cmake --build build'.")

    os.chdir(str(WEB_DIR))
    socketserver.TCPServer.allow_reuse_address = True
    server = http.server.ThreadingHTTPServer((HOST, PORT), AxesHTTPHandler)
    print(f"==================================================")
    print(f" AXES Web Dashboard Server Running")
    print(f" URL: http://{HOST}:{PORT}")
    print(f" Bound to localhost ONLY (127.0.0.1)")
    print(f" Staging Directory: {STAGING_DIR}")
    print(f"==================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()

if __name__ == "__main__":
    main()
