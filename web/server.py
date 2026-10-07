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

PORT = 8080
HOST = "127.0.0.1"

BASE_DIR = Path(__file__).resolve().parent.parent
BUILD_DIR = BASE_DIR / "build"
AXES_BIN = BUILD_DIR / "axes"
REPORTS_DIR = BASE_DIR / "reports"
WEB_DIR = BASE_DIR / "web"

active_jobs = {} # job_id -> dict state
job_lock = threading.Lock()

def parse_report_file(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
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
        active_jobs[job_id] = {
            "job_id": job_id,
            "config": config,
            "status": "RUNNING",
            "pid": None,
            "cgroup_path": f"/sys/fs/cgroup/axes/{job_id}",
            "pid_attached": "YES",
            "runtime_sec": 0.0,
            "metrics": {"cpu_pct": 0.0, "memory_mb": 0.0, "pids": 1},
            "history": [],
            "events": [f"[0.0s] AXES Sandbox job {job_id} launched."],
            "initial_cpu_limit": config.get("cpu_limit", 200.0),
            "current_cpu_limit": config.get("cpu_limit", 200.0),
            "adaptive_triggered": False,
            "exit_code": None,
            "report_data": None
        }

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

    proc = subprocess.Popen(
        exec_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=str(BASE_DIR)
    )

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
            report_file = REPORTS_DIR / f"{job_id}_report.txt"
            if report_file.exists():
                parsed = parse_report_file(report_file)
                if parsed:
                    state["report_data"] = parsed
                    if parsed.get("adaptive_triggered"):
                        state["adaptive_triggered"] = True
                        state["current_cpu_limit"] = parsed.get("final_cpu_limit", 100.0)

class AxesHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        if path == "/api/status":
            # Check environment using ./axes check
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
            with job_lock:
                state = active_jobs.get(job_id)
                if state:
                    self._send_json(state)
                else:
                    # Check if report exists
                    report_file = REPORTS_DIR / f"{job_id}_report.txt"
                    if report_file.exists():
                        parsed = parse_report_file(report_file)
                        self._send_json({"job_id": job_id, "status": parsed["status"], "report_data": parsed})
                    else:
                        self._send_json({"error": "Job not found"}, status=404)
            return

        elif path == "/api/history":
            history_list = []
            if REPORTS_DIR.exists():
                for f in os.listdir(REPORTS_DIR):
                    if f.endswith("_report.txt"):
                        parsed = parse_report_file(REPORTS_DIR / f)
                        if parsed:
                            history_list.append(parsed)
            history_list.sort(key=lambda x: x.get("start_time", ""), reverse=True)
            self._send_json(history_list)
            return

        elif path.startswith("/api/report/"):
            job_id = path.replace("/api/report/", "").strip()
            report_file = REPORTS_DIR / f"{job_id}_report.txt"
            if report_file.exists():
                parsed = parse_report_file(report_file)
                self._send_json(parsed)
            else:
                self._send_json({"error": "Report not found"}, status=404)
            return

        # Serve static web files
        return super().do_GET()

    def do_POST(self):
        if self.path == "/api/run":
            length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(length)
            try:
                data = json.loads(body_bytes.decode("utf-8"))
            except Exception as e:
                self._send_json({"error": "Invalid JSON"}, status=400)
                return

            raw_cmd = data.get("command", "").strip()
            if not raw_cmd:
                self._send_json({"error": "Command is required"}, status=400)
                return

            # Split command string safely into args list
            import shlex
            cmd_list = shlex.split(raw_cmd)

            now_ms = int(time.time() * 1000)
            job_id = data.get("job_id", "").strip()
            if not job_id:
                job_id = f"job-{now_ms % 10000:04d}"

            config = {
                "cpu_limit": float(data.get("cpu_limit", 200.0)),
                "memory_limit": int(data.get("memory_limit", 512)),
                "pids_limit": int(data.get("pids_limit", 64)),
                "cpu_threshold": float(data.get("cpu_threshold", 150.0)),
                "consecutive": int(data.get("consecutive", 3)),
                "reduced_cpu": float(data.get("reduced_cpu", 100.0)),
                "sample_interval": float(data.get("sample_interval", 0.5)),
                "adaptive": bool(data.get("adaptive", True))
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
    server = socketserver.TCPServer((HOST, PORT), AxesHTTPHandler)
    server.allow_reuse_address = True
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
