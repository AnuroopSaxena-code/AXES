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
from pathlib import Path

PORT = int(os.environ.get("AXES_PORT", 8080))
HOST = "127.0.0.1"

BASE_DIR = Path(__file__).resolve().parent.parent
BUILD_DIR = BASE_DIR / "build"
AXES_BIN = BUILD_DIR / "axes"
REPORTS_DIR = BASE_DIR / "reports"
WEB_DIR = BASE_DIR / "web"

active_jobs = {} # job_id -> dict state
job_lock = threading.Lock()

VALID_JOB_ID_REGEX = re.compile(r'^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$')

def is_valid_job_id(job_id: str) -> bool:
    if not job_id or not isinstance(job_id, str):
        return False
    return bool(VALID_JOB_ID_REGEX.match(job_id))

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
        "exit_code_signal": "",
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
            report_data["status"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("Exit code / Signal:"):
            report_data["exit_code_signal"] = line_str.split(":", 1)[1].strip()
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

def run_job_thread(job_id, cmd_list, config):
    with job_lock:
        if job_id in active_jobs:
            active_jobs[job_id]["status"] = "RUNNING"

    exec_cmd = [str(AXES_BIN), "run", "--job-id", job_id]
    exec_cmd.extend(["--cpu-limit", str(config.get("cpu_limit", 200.0))])
    exec_cmd.extend(["--memory-limit", str(config.get("memory_limit", 512))])
    exec_cmd.extend(["--pids-limit", str(config.get("pids_limit", 64))])
    exec_cmd.extend(["--cpu-threshold", str(config.get("cpu_threshold", 150.0))])
    exec_cmd.extend(["--consecutive", str(config.get("consecutive", 3))])
    exec_cmd.extend(["--reduced-cpu", str(config.get("reduced_cpu", 100.0))])
    exec_cmd.extend(["--sample-interval", str(config.get("sample_interval", 0.5))])
    if not config.get("adaptive", True):
        exec_cmd.append("--no-adaptive")
    
    exec_cmd.extend(cmd_list)

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
            active_jobs[job_id]["pid"] = proc.pid

    # Parse stdout in real-time
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

            if "PID:" in line_str and "Cgroup" not in line_str:
                try: state["pid"] = int(line_str.split(":")[1].strip())
                except: pass
            elif "Cgroup Path:" in line_str:
                state["cgroup_path"] = line_str.split(":", 1)[1].strip()
            elif "Cgroup PID:" in line_str:
                if "VERIFIED" in line_str:
                    state["pid_attached"] = "YES"

            if line_str.startswith("CPU Usage:"):
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
                    state["history"].append({
                        "runtime": snapshot_runtime,
                        "cpu_pct": snapshot_cpu,
                        "memory_mb": snapshot_mem,
                        "pids": snapshot_pids
                    })
                except: pass

            if line_str.startswith("[") and "s]" in line_str:
                state["events"].append(line_str)
                if "ADAPTIVE TRIGGER" in line_str:
                    state["adaptive_triggered"] = True
                    state["current_cpu_limit"] = config.get("reduced_cpu", 100.0)

    proc.wait()

    with job_lock:
        state = active_jobs.get(job_id)
        if state:
            state["exit_code"] = proc.returncode
            state["status"] = "FINISHED" if proc.returncode == 0 else "TERMINATED"
            # Read generated report
            report_file = get_safe_report_path(job_id)
            if report_file and report_file.exists():
                parsed = parse_report_file(report_file)
                if parsed:
                    state["report_data"] = parsed
                    if parsed.get("adaptive_triggered"):
                        state["adaptive_triggered"] = True
                        state["current_cpu_limit"] = parsed.get("final_cpu_limit", 100.0)

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
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # Wildcard CORS explicitly removed to prevent cross-site execution attacks
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        if path.startswith("/api/"):
            if not self._verify_origin_and_host():
                self._send_json({"error": "Forbidden: Cross-origin or untrusted request blocked."}, status=403)
                return

        if path == "/api/status":
            try:
                res = subprocess.run([str(AXES_BIN), "check"], capture_output=True, text=True, timeout=5)
                output = res.stdout
                ready = "SYSTEM READY FOR CONTAINMENT EXECUTION [PASS]" in output
                data = {
                    "ready": ready,
                    "output": output,
                    "cgroups_v2": "Linux cgroups v2 mounted:   [PASS]" in output,
                    "cpu_controller": "CPU controller available:   [PASS]" in output,
                    "memory_controller": "Memory controller available:[PASS]" in output,
                    "pids_controller": "PIDs controller available:  [PASS]" in output,
                    "axes_writable": "AXES subtree writable:      [PASS]" in output
                }
                self._send_json(data)
            except Exception as e:
                self._send_json({"ready": False, "error": str(e)}, status=500)
            return

        elif path.startswith("/api/job/"):
            job_id = path.replace("/api/job/", "").strip()
            if not is_valid_job_id(job_id):
                self._send_json({"error": "Invalid job ID format"}, status=400)
                return

            with job_lock:
                state = active_jobs.get(job_id)
                if state:
                    self._send_json(state)
                    return

            # Check if report exists
            report_file = get_safe_report_path(job_id)
            if report_file and report_file.exists():
                parsed = parse_report_file(report_file)
                if parsed:
                    self._send_json({"job_id": job_id, "status": parsed["status"], "report_data": parsed})
                    return

            self._send_json({"error": "Job not found"}, status=404)
            return

        elif path == "/api/history":
            history_list = []
            if REPORTS_DIR.exists():
                for f in os.listdir(REPORTS_DIR):
                    if f.endswith("_report.txt"):
                        job_id_cand = f[:-len("_report.txt")]
                        if is_valid_job_id(job_id_cand):
                            parsed = parse_report_file(REPORTS_DIR / f)
                            if parsed:
                                history_list.append(parsed)
            history_list.sort(key=lambda x: x.get("start_time", ""), reverse=True)
            self._send_json(history_list)
            return

        elif path.startswith("/api/report/"):
            job_id = path.replace("/api/report/", "").strip()
            if not is_valid_job_id(job_id):
                self._send_json({"error": "Invalid job ID format"}, status=400)
                return

            report_file = get_safe_report_path(job_id)
            if report_file and report_file.exists():
                parsed = parse_report_file(report_file)
                if parsed:
                    self._send_json(parsed)
                    return

            self._send_json({"error": "Report not found"}, status=404)
            return

        # Serve static web files
        return super().do_GET()

    def do_POST(self):
        if not self._verify_origin_and_host():
            self._send_json({"error": "Forbidden: Cross-origin or untrusted request blocked."}, status=403)
            return

        if self.path == "/api/run":
            # 1. Check Content-Length
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                self._send_json({"error": "Invalid Content-Length header"}, status=400)
                return

            if length <= 0 or length > 65536:
                self._send_json({"error": "Payload size invalid (must be between 1 and 65,536 bytes)"}, status=400)
                return

            # 2. Parse JSON body
            try:
                body_bytes = self.rfile.read(length)
                data = json.loads(body_bytes.decode("utf-8"))
                if not isinstance(data, dict):
                    self._send_json({"error": "JSON body must be a JSON object"}, status=400)
                    return
            except Exception as e:
                self._send_json({"error": f"Invalid JSON payload: {str(e)}"}, status=400)
                return

            # 3. Validate command
            raw_cmd = data.get("command")
            if not raw_cmd or not isinstance(raw_cmd, str) or not raw_cmd.strip():
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

            # 4. Validate job_id
            raw_job_id = data.get("job_id", "")
            if raw_job_id:
                if not isinstance(raw_job_id, str) or not is_valid_job_id(raw_job_id.strip()):
                    self._send_json({
                        "error": f"Invalid job_id '{raw_job_id}'. Must be 1-64 characters matching [a-zA-Z0-9_-] and start with alphanumeric or underscore"
                    }, status=400)
                    return
                job_id = raw_job_id.strip()
            else:
                now_us = int(time.time() * 1000000)
                job_id = f"job-{now_us % 1000000:06d}-{os.getpid()}"

            # 5. Validate numeric configuration parameters
            try:
                cpu_limit = float(data.get("cpu_limit", 200.0))
                memory_limit = int(data.get("memory_limit", 512))
                pids_limit = int(data.get("pids_limit", 64))
                cpu_threshold = float(data.get("cpu_threshold", 150.0))
                consecutive = int(data.get("consecutive", 3))
                reduced_cpu = float(data.get("reduced_cpu", 100.0))
                sample_interval = float(data.get("sample_interval", 0.5))
                adaptive = bool(data.get("adaptive", True))

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
            except (ValueError, TypeError) as val_err:
                self._send_json({"error": f"Invalid configuration parameter: {str(val_err)}"}, status=400)
                return

            config = {
                "cpu_limit": cpu_limit,
                "memory_limit": memory_limit,
                "pids_limit": pids_limit,
                "cpu_threshold": cpu_threshold,
                "consecutive": consecutive,
                "reduced_cpu": reduced_cpu,
                "sample_interval": sample_interval,
                "adaptive": adaptive
            }

            # 6. Check for duplicate/running job_id collisions
            with job_lock:
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
                    "exit_code": None,
                    "report_data": None
                }

            t = threading.Thread(target=run_job_thread, args=(job_id, cmd_list, config), daemon=True)
            t.start()

            self._send_json({"success": True, "job_id": job_id})
            return

        self._send_json({"error": "Endpoint not found"}, status=404)

def main():
    if not AXES_BIN.exists():
        print(f"[Server Warning] AXES binary not found at {AXES_BIN}. Build AXES first using 'cmake -B build && cmake --build build'.")

    os.chdir(str(WEB_DIR))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((HOST, PORT), AxesHTTPHandler)
    print(f"==================================================")
    print(f" AXES Web Dashboard Server Running")
    print(f" URL: http://{HOST}:{PORT}")
    print(f" Bounded to localhost ONLY (127.0.0.1)")
    print(f"==================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()

if __name__ == "__main__":
    main()
