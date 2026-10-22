#!/usr/bin/env python3
"""
AXES Phase 2 Test Suite: Execution Lifecycle, Output Capture, File Staging & Workbench API
"""
import unittest
import subprocess
import json
import time
import os
import sys
import signal
import socket
import urllib.request
import urllib.error
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BUILD_DIR = BASE_DIR / "build"
AXES_BIN = BUILD_DIR / "axes"
REPORTS_DIR = BASE_DIR / "reports"
STAGING_DIR = BASE_DIR / "staging"
SERVER_SCRIPT = BASE_DIR / "web" / "server.py"

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class TestPhase2CLILifecycle(unittest.TestCase):
    """Verifies C++ supervisor CLI options, wall-clock timeouts, output capture, and signals."""

    def test_timeout_negative_rejected(self):
        res = subprocess.run([str(AXES_BIN), "run", "--timeout", "-1", "echo", "test"],
                             capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("outside acceptable range", res.stderr)

    def test_timeout_zero_rejected(self):
        res = subprocess.run([str(AXES_BIN), "run", "--timeout", "0", "echo", "test"],
                             capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("outside acceptable range", res.stderr)

    def test_timeout_too_high_rejected(self):
        res = subprocess.run([str(AXES_BIN), "run", "--timeout", "100000", "echo", "test"],
                             capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("outside acceptable range", res.stderr)

    def test_max_output_negative_rejected(self):
        res = subprocess.run([str(AXES_BIN), "run", "--max-output", "-1", "echo", "test"],
                             capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Negative value not allowed", res.stderr)

    def test_output_file_empty_rejected(self):
        res = subprocess.run([str(AXES_BIN), "run", "--output-file", "", "echo", "test"],
                             capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("cannot be empty", res.stderr)

    def test_wall_clock_timeout_enforcement(self):
        """Verifies supervisor terminates sleep workload within timeout window and exits with 124."""
        job_id = f"test-timeout-{int(time.time()*1000)%100000}"
        t0 = time.time()
        res = subprocess.run([
            str(AXES_BIN), "run",
            "--job-id", job_id,
            "--timeout", "1.0",
            "python3", "-c", "import time; time.sleep(10)"
        ], capture_output=True, text=True)
        elapsed = time.time() - t0

        # Should exit within ~1 to 2 seconds, NOT 10 seconds!
        self.assertLess(elapsed, 4.0, f"Execution took {elapsed}s; timeout was not enforced!")
        self.assertEqual(res.returncode, 124, f"Expected exit code 124, got {res.returncode}")
        self.assertIn("TIMED_OUT", res.stdout)

        # Check JSON report if generated
        json_rep = REPORTS_DIR / f"{job_id}_report.json"
        if json_rep.exists():
            with open(json_rep, "r") as f:
                data = json.load(f)
            self.assertEqual(data.get("final_status"), "TIMED_OUT")
            self.assertTrue(data.get("timed_out"))
            self.assertEqual(data.get("exit_code"), 124)

    def test_real_output_capture_stdout_stderr(self):
        """Verifies target stdout and stderr are captured into output file without mixing with telemetry."""
        job_id = f"test-output-{int(time.time()*1000)%100000}"
        out_file = REPORTS_DIR / f"{job_id}_output.log"
        if out_file.exists(): out_file.unlink()

        res = subprocess.run([
            str(AXES_BIN), "run",
            "--job-id", job_id,
            "--output-file", str(out_file),
            "python3", "-c", "import sys; print('AXES_STDOUT_TEST_MARKER'); sys.stderr.write('AXES_STDERR_TEST_MARKER\\n')"
        ], capture_output=True, text=True)

        self.assertEqual(res.returncode, 0, f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        self.assertTrue(out_file.exists(), "Output file was not created!")

        with open(out_file, "r") as f:
            captured = f.read()

        self.assertIn("AXES_STDOUT_TEST_MARKER", captured)
        self.assertIn("AXES_STDERR_TEST_MARKER", captured)
        # Verify supervisor telemetry is not in target output file
        self.assertNotIn("Job ID: ", captured)
        self.assertNotIn("AXES Sandbox Launcher", captured)

class TestPhase2WorkbenchServer(unittest.TestCase):
    """Verifies file staging, C/C++ compilation, and workbench API endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.port = find_free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        env = os.environ.copy()
        env["AXES_PORT"] = str(cls.port)
        cls.server_proc = subprocess.Popen(
            [sys.executable, str(SERVER_SCRIPT)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Wait for server to bind
        time.sleep(1.0)

    @classmethod
    def tearDownClass(cls):
        if cls.server_proc:
            try:
                out, err = cls.server_proc.communicate(timeout=2.0)
                if cls.server_proc.returncode != 0:
                    print("SERVER EXITED WITH CODE:", cls.server_proc.returncode)
                    print("SERVER STDERR:", err.decode())
            except:
                cls.server_proc.kill()

    def _api_get(self, path):
        req = urllib.request.Request(f"{self.base_url}{path}")
        req.add_header("Host", f"127.0.0.1:{self.port}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())

    def _api_post(self, path, payload):
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Host": f"127.0.0.1:{self.port}"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def _api_delete(self, path):
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            headers={"Host": f"127.0.0.1:{self.port}"},
            method="DELETE"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_status_endpoint_staging(self):
        status, data = self._api_get("/api/status")
        self.assertEqual(status, 200)
        self.assertIn("staging_writable", data)
        self.assertTrue(data["staging_writable"])

    def test_file_staging_lifecycle(self):
        """Tests uploading, listing, viewing, and deleting a staged file."""
        fname = f"stage_test_{int(time.time())}.py"
        test_content = "print('Staged file content')\n"

        # 1. Upload
        status, res = self._api_post("/api/files/upload", {
            "filename": fname,
            "content": test_content
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))

        # 2. List
        status, files = self._api_get("/api/files")
        self.assertEqual(status, 200)
        matched = [f for f in files if f["filename"] == fname]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["size_bytes"], len(test_content))

        # 3. View content
        status, file_view = self._api_get(f"/api/files/{fname}")
        self.assertEqual(status, 200)
        self.assertEqual(file_view["content"], test_content)

        # 4. Delete
        status, del_res = self._api_delete(f"/api/files/{fname}")
        self.assertEqual(status, 200)
        self.assertTrue(del_res.get("success"))

        # 5. Verify deleted
        status, _ = self._api_delete(f"/api/files/{fname}")
        self.assertEqual(status, 404)

    def test_file_upload_traversal_rejected(self):
        status, res = self._api_post("/api/files/upload", {
            "filename": "../malicious.py",
            "content": "bad"
        })
        self.assertEqual(status, 400)
        self.assertIn("Invalid filename", res.get("error", ""))

    def test_staged_compilation_success(self):
        """Tests compiling a valid C program in staging area."""
        c_name = f"valid_prog_{int(time.time())}.c"
        bin_name = f"valid_prog_{int(time.time())}.bin"
        c_code = "#include <stdio.h>\nint main() { printf(\"COMPILE_SUCCESS_TOKEN\\n\"); return 0; }\n"

        # Upload C file
        status, _ = self._api_post("/api/files/upload", {"filename": c_name, "content": c_code})
        self.assertEqual(status, 200)

        # Compile
        status, comp_res = self._api_post("/api/compile", {
            "source_file": c_name,
            "output_name": bin_name,
            "compiler_flags": ["-O2"]
        })
        self.assertEqual(status, 200)
        self.assertTrue(comp_res.get("success"))
        self.assertEqual(comp_res.get("exit_code"), 0)
        self.assertTrue((STAGING_DIR / bin_name).exists())

        # Cleanup
        (STAGING_DIR / c_name).unlink(missing_ok=True)
        (STAGING_DIR / bin_name).unlink(missing_ok=True)

    def test_staged_compilation_failure_diagnostics(self):
        """Tests compiling an invalid C program returns compiler diagnostics cleanly separated from execution."""
        c_name = f"invalid_prog_{int(time.time())}.c"
        c_code = "int main() { this is an invalid syntax error here; return 0; }\n"

        # Upload bad C file
        status, _ = self._api_post("/api/files/upload", {"filename": c_name, "content": c_code})
        self.assertEqual(status, 200)

        # Compile
        status, comp_res = self._api_post("/api/compile", {"source_file": c_name})
        self.assertEqual(status, 400)
        self.assertFalse(comp_res.get("success"))
        self.assertNotEqual(comp_res.get("exit_code"), 0)
        self.assertIn("error:", comp_res.get("stderr", ""))

        (STAGING_DIR / c_name).unlink(missing_ok=True)

    def test_incremental_output_streaming(self):
        """Tests incremental output streaming with offset and limit."""
        job_id = f"stream-test-{int(time.time()*1000)%100000}"
        status, res = self._api_post("/api/run", {
            "job_id": job_id,
            "command": "python3 -c \"for i in range(10): print(f'LINE_{i}')\""
        })
        self.assertEqual(status, 200)

        # Wait for workload to complete
        time.sleep(1.5)

        # Read first chunk
        status, out1 = self._api_get(f"/api/job/{job_id}/output?offset=0&limit=30")
        self.assertEqual(status, 200)
        self.assertEqual(out1["offset"], 0)
        self.assertGreater(out1["bytes_read"], 0)
        self.assertIn("LINE_0", out1["output"])

        # Read next chunk using next_offset
        next_off = out1["next_offset"]
        status, out2 = self._api_get(f"/api/job/{job_id}/output?offset={next_off}&limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(out2["offset"], next_off)

    def test_job_cancellation_endpoint(self):
        """Tests stopping a running job via /api/job/<id>/stop."""
        job_id = f"cancel-test-{int(time.time()*1000)%100000}"
        status, res = self._api_post("/api/run", {
            "job_id": job_id,
            "command": "python3 -c \"import time; time.sleep(10)\""
        })
        self.assertEqual(status, 200)

        time.sleep(0.3)
        # Send stop request
        status, stop_res = self._api_post(f"/api/job/{job_id}/stop", {})
        self.assertEqual(status, 200)
        self.assertTrue(stop_res.get("success"))
        self.assertEqual(stop_res.get("status"), "CANCELLED")

        # Verify job is no longer running
        time.sleep(0.5)
        status, job_state = self._api_get(f"/api/job/{job_id}")
        self.assertEqual(status, 200)
        self.assertEqual(job_state.get("status"), "CANCELLED")

if __name__ == "__main__":
    unittest.main()
