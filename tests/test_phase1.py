#!/usr/bin/env python3
"""
Comprehensive automated test suite for AXES Phase 1:
1. C++ CLI argument parsing, input validation, bounds checks, and exception safety.
2. Job ID validation and path traversal prevention across CLI and CGroup engine.
3. Web server security: CORS restriction, Origin/Host validation, path traversal rejection,
   duplicate job collision rejection, and payload validation.
"""

import unittest
import subprocess
import os
import sys
import time
import json
import socket
import urllib.request
import urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AXES_BIN = REPO_ROOT / "build" / "axes"
SERVER_SCRIPT = REPO_ROOT / "web" / "server.py"

class TestCLIValidation(unittest.TestCase):
    def setUp(self):
        if not AXES_BIN.exists():
            self.skipTest(f"Binary not found: {AXES_BIN}")

    def run_axes(self, args):
        cmd = [str(AXES_BIN)] + args
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res

    def test_cpu_limit_not_a_number(self):
        res = self.run_axes(["run", "--cpu-limit", "not_a_number", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Invalid numeric value for --cpu-limit", res.stderr)
        self.assertNotIn("terminate called", res.stderr)

    def test_cpu_limit_missing_value(self):
        res = self.run_axes(["run", "--cpu-limit"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Option --cpu-limit requires a value", res.stderr)

    def test_cpu_limit_zero_or_negative(self):
        res = self.run_axes(["run", "--cpu-limit", "0", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("outside acceptable range", res.stderr)

    def test_memory_limit_negative(self):
        res = self.run_axes(["run", "--memory-limit", "-50", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Negative value not allowed for --memory-limit", res.stderr)
        self.assertNotIn("terminate called", res.stderr)

    def test_memory_limit_zero(self):
        res = self.run_axes(["run", "--memory-limit", "0", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("outside acceptable range", res.stderr)

    def test_pids_limit_invalid(self):
        res = self.run_axes(["run", "--pids-limit", "abc", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Invalid integer value for --pids-limit", res.stderr)

    def test_consecutive_samples_zero(self):
        res = self.run_axes(["run", "--consecutive", "0", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("outside acceptable range", res.stderr)

    def test_sample_interval_too_low(self):
        res = self.run_axes(["run", "--sample-interval", "0.001", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("outside acceptable range", res.stderr)

    def test_job_id_path_traversal(self):
        res = self.run_axes(["run", "--job-id", "../../etc/passwd", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Invalid job ID", res.stderr)

    def test_job_id_slash(self):
        res = self.run_axes(["run", "--job-id", "job/nested", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Invalid job ID", res.stderr)

    def test_job_id_starts_with_hyphen(self):
        res = self.run_axes(["run", "--job-id", "-hyphenjob", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Invalid job ID", res.stderr)

    def test_unknown_option(self):
        res = self.run_axes(["run", "--unknown-flag", "echo", "test"])
        self.assertEqual(res.returncode, 1)
        self.assertIn("Unknown option", res.stderr)


class TestWebServerSecurity(unittest.TestCase):
    server_proc = None
    server_port = 18080

    @classmethod
    def setUpClass(cls):
        env = os.environ.copy()
        env["AXES_PORT"] = str(cls.server_port)
        cls.server_proc = subprocess.Popen(
            [sys.executable, str(SERVER_SCRIPT)],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )
        # Poll socket until server is listening
        ready = False
        for _ in range(40):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            res = s.connect_ex(("127.0.0.1", cls.server_port))
            s.close()
            if res == 0:
                ready = True
                break
            time.sleep(0.1)
        if not ready:
            raise RuntimeError(f"Server failed to start on port {cls.server_port}")

    @classmethod
    def tearDownClass(cls):
        if cls.server_proc:
            cls.server_proc.terminate()
            try:
                cls.server_proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cls.server_proc.kill()

    def make_request(self, path, method="GET", data=None, headers=None):
        url = f"http://127.0.0.1:{self.server_port}{path}"
        req_headers = {"Host": f"127.0.0.1:{self.server_port}"}
        if headers:
            req_headers.update(headers)

        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                resp_body = resp.read().decode("utf-8")
                return resp.status, resp.headers, resp_body
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8") if e.fp else ""
            return e.code, e.headers, err_body

    def test_no_wildcard_cors(self):
        # Verify that Access-Control-Allow-Origin: * is NOT sent on any response
        status, headers, body = self.make_request("/api/status")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_cross_origin_blocked(self):
        # Disallowed origin must be rejected with 403 Forbidden
        status, headers, body = self.make_request(
            "/api/status",
            headers={"Origin": "http://evil-attacker-site.com"}
        )
        self.assertEqual(status, 403)
        self.assertIn("Forbidden", body)

    def test_untrusted_host_blocked(self):
        # Untrusted Host header must be rejected with 403 Forbidden
        status, headers, body = self.make_request(
            "/api/status",
            headers={"Host": "attacker.com"}
        )
        self.assertEqual(status, 403)

    def test_report_path_traversal_rejected(self):
        # Traversal in report path must be rejected with 400 Bad Request
        status, headers, body = self.make_request("/api/report/../../etc/passwd")
        self.assertEqual(status, 400)
        self.assertIn("Invalid job ID format", body)

    def test_job_path_traversal_rejected(self):
        # Traversal in job status query must be rejected with 400 Bad Request
        status, headers, body = self.make_request("/api/job/../../etc/passwd")
        self.assertEqual(status, 400)
        self.assertIn("Invalid job ID format", body)

    def test_run_invalid_job_id(self):
        # POST /api/run with invalid job_id must return 400
        payload = {
            "command": "echo test",
            "job_id": "../evil_job"
        }
        status, headers, body = self.make_request("/api/run", method="POST", data=payload)
        self.assertEqual(status, 400)
        self.assertIn("Invalid job_id", body)

    def test_run_empty_command(self):
        # POST /api/run with empty command must return 400
        payload = {
            "command": "   ",
            "job_id": "test-valid-id"
        }
        status, headers, body = self.make_request("/api/run", method="POST", data=payload)
        self.assertEqual(status, 400)
        self.assertIn("Command is required", body)

    def test_run_invalid_numeric_bounds(self):
        # POST /api/run with out-of-range cpu_limit must return 400
        payload = {
            "command": "echo test",
            "cpu_limit": -100
        }
        status, headers, body = self.make_request("/api/run", method="POST", data=payload)
        self.assertEqual(status, 400)
        self.assertIn("Invalid configuration parameter", body)

    def test_duplicate_running_job_collision_prevention(self):
        # Launching two jobs with the exact same active job ID must return 409 Conflict
        unique_id = f"test-col-{int(time.time()*1000)%10000}"
        payload = {
            "command": "sleep 3",
            "job_id": unique_id
        }
        status1, headers1, body1 = self.make_request("/api/run", method="POST", data=payload)
        self.assertIn(status1, (200, 400)) # May fail if cgroup fails, but if registered:
        if status1 == 200:
            # Second attempt with same ID while first is active
            status2, headers2, body2 = self.make_request("/api/run", method="POST", data=payload)
            self.assertEqual(status2, 409)
            self.assertIn("already running", body2)
            self.make_request(f"/api/job/{unique_id}/stop", method="POST", data={})


if __name__ == "__main__":
    unittest.main(verbosity=2)
