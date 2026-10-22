"""Regression checks for workbench metadata, kernel evidence and UTF-8 streaming."""
import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

class WorkbenchContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        cls.server = subprocess.Popen([sys.executable, str(ROOT / 'web/server.py')],
            env={**os.environ, 'AXES_PORT': str(cls.port)}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                cls.request('/files')
                break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('Server did not start')

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=5)

    @classmethod
    def request(cls, path, data=None):
        body = None if data is None else json.dumps(data).encode()
        req = urllib.request.Request(f'http://127.0.0.1:{cls.port}/api{path}', data=body,
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.load(response)

    def test_kernel_evidence_and_restore_metadata(self):
        job = f'workbench-metadata-{time.time_ns()}'
        self.request('/run', {'job_id': job, 'command': 'sleep 5', 'cpu_limit': 75,
            'memory_limit': 128, 'pids_limit': 16, 'timeout': 8, 'adaptive': False})
        try:
            for _ in range(50):
                state = self.request('/job/' + job)
                if state.get('pid_attached') == 'YES':
                    break
                time.sleep(.05)
            self.assertEqual(state['command'], ['sleep', '5'])
            self.assertEqual(state['config']['cpu_limit'], 75)
            self.assertFalse(state['config']['adaptive'])
            self.assertEqual(state['kernel_controls']['cpu.max'], '75000 100000')
            self.assertEqual(state['kernel_controls']['memory.max'], str(128 * 1024 * 1024))
            self.assertIn(str(state['pid']), state['kernel_controls']['cgroup.procs'].splitlines())
        finally:
            self.request('/job/' + job + '/stop', {})

    def test_utf8_chunk_boundary_is_lossless(self):
        job = f'workbench-utf8-{time.time_ns()}'
        path = ROOT / 'reports' / (job + '_output.log')
        content = 'a' * 65535 + '\u20ac' + '終\n'
        path.write_bytes(content.encode())
        try:
            first = self.request('/job/' + job + '/output?offset=0&limit=65536')
            self.assertEqual(first['next_offset'], 65535)
            second = self.request('/job/' + job + '/output?offset=' + str(first['next_offset']))
            self.assertEqual(first['output'] + second['output'], content)
            self.assertTrue(second['eof'])
        finally:
            path.unlink()

    def test_stop_finishes_supervisor_and_descendants(self):
        job = f'workbench-stop-{time.time_ns()}'
        self.request('/run', {'job_id': job, 'command': "sh -c 'sleep 30 & wait'", 'timeout': 10})
        for _ in range(50):
            state = self.request('/job/' + job)
            if state.get('pid_attached') == 'YES':
                break
            time.sleep(.05)
        self.request('/job/' + job + '/stop', {})
        for _ in range(100):
            state = self.request('/job/' + job)
            if state['status'] not in ('STARTING', 'RUNNING'):
                break
            time.sleep(.05)
        self.assertEqual(state['status'], 'CANCELLED')
        self.assertIsNotNone(state['exit_code'])
        self.assertIsNotNone(state['report_data'])
        procs = Path('/sys/fs/cgroup/axes') / job / 'cgroup.procs'
        self.assertTrue(not procs.exists() or not procs.read_text().strip())

if __name__ == '__main__':
    unittest.main(verbosity=2)
