"""Safe behavioral isolation tests; requires Linux x86-64, bwrap and delegated cgroups."""
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / 'build/axes'

PROBE = r'''
import os, json, ctypes, socket
status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
libc = ctypes.CDLL(None, use_errno=True)
def syscall_result(n, *args):
    ctypes.set_errno(0)
    result = libc.syscall(n, *args)
    return [result, ctypes.get_errno()]
result = {
 'uid': os.getuid(), 'nnp': status['NoNewPrivs'].strip(), 'caps': status['CapEff'].strip(),
 'seccomp': status['Seccomp'].strip(),
 'namespaces': {name: os.readlink('/proc/self/ns/' + name) for name in ('pid','mnt','net','user','ipc','uts','cgroup')},
 'pids': [p for p in os.listdir('/proc') if p.isdigit()],
 'host_secret': os.path.exists(os.environ.get('HOST_SECRET', '/tmp/axes-host-secret')),
 'host_mount': os.path.exists('/mnt/c'), 'host_cgroup': os.path.exists('/sys/fs/cgroup'),
 'environment_secret': os.environ.get('AXES_TEST_SECRET'),
 'workspace': open('/workspace/probe-marker.txt').read(),
 'ptrace': syscall_result(101, 0, 0, 0, 0),
 'unshare': syscall_result(272, 0), 'mount': syscall_result(165, 0, 0, 0, 0, 0),
 'bpf': syscall_result(321, 0, 0, 0), 'clone3': syscall_result(435, 0, 0),
}
try:
 open('/workspace/probe-marker.txt','w').write('changed')
 result['workspace_write'] = 'allowed'
except OSError as e: result['workspace_write'] = e.errno
try:
 socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 result['socket'] = 'allowed'
except OSError as e: result['socket'] = e.errno
open('/tmp/scratch','w').write('ephemeral')
result['scratch'] = open('/tmp/scratch').read()
print(json.dumps(result))
'''

class Isolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='axes-security-')
        cls.workspace = Path(cls.temp.name)
        (cls.workspace/'probe-marker.txt').write_text('staged input')
        cls.fault = ROOT/'build/deny_setup'
        subprocess.run(['cc', str(ROOT/'tests/fixtures/deny_setup.c'), '-o', str(cls.fault)], check=True)
        cls.host_namespaces = {n: os.readlink('/proc/self/ns/'+n) for n in ('pid','mnt','net','user','ipc','uts','cgroup')}
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def execute(self, command, options=(), fault=None):
        job = 'security-' + str(time.time_ns())
        cmd = [str(BIN),'run','--job-id',job,'--isolation','isolated','--workspace',str(self.workspace),
            '--timeout','5','--sample-interval','.1',*options,'--',*command]
        if fault: cmd = [str(self.fault),fault,*cmd]
        run = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=12,
            env={**os.environ, 'AXES_TEST_SECRET':'must-not-leak'})
        output_path = ROOT/'reports'/f'{job}_output.log'
        output = output_path.read_text() if output_path.exists() else ''
        report_path = ROOT/'reports'/f'{job}_report.json'
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
        self.assertFalse((Path('/sys/fs/cgroup/axes')/job).exists(), run.stdout+run.stderr)
        return run, output, report

    def test_namespace_filesystem_network_and_privileges(self):
        run, output, report = self.execute(['python3','-c', PROBE])
        self.assertEqual(run.returncode, 0, output+run.stderr)
        d = json.loads(output)
        for name, value in self.host_namespaces.items(): self.assertNotEqual(d['namespaces'][name], value, name)
        self.assertNotEqual(d['uid'],0)
        self.assertEqual(d['nnp'],'1'); self.assertEqual(int(d['caps'],16),0); self.assertEqual(d['seccomp'],'2')
        self.assertLess(len(d['pids']),8)
        self.assertFalse(d['host_mount']); self.assertFalse(d['host_cgroup']); self.assertIsNone(d['environment_secret'])
        self.assertEqual(d['workspace'],'staged input'); self.assertEqual(d['workspace_write'],30)
        self.assertEqual(d['scratch'],'ephemeral'); self.assertEqual(d['socket'],1)
        for name in ('ptrace','unshare','mount','bpf'): self.assertEqual(d[name],[-1,1],name)
        self.assertEqual(d['clone3'],[-1,38]); self.assertEqual(report['isolation'],'isolated')

    def test_host_file_not_visible_even_through_proc_root(self):
        marker = self.workspace/'host-private.txt'; marker.write_text('private')
        # Workspace exposes this file at a deliberate staging path, never its host path.
        code = f"import os; assert not os.path.exists({str(marker)!r}); assert not os.path.exists('/proc/1/root'+{str(marker)!r}); print('restricted')"
        run, output, _ = self.execute(['python3','-c',code]); self.assertEqual(run.returncode,0,output)

    def test_representative_benign_workloads(self):
        for command in (['sh','-c','echo shell; sleep 0.05'], ['python3','-c','import threading; t=threading.Thread(target=lambda: print(42)); t.start(); t.join()']):
            run, output, _ = self.execute(command); self.assertEqual(run.returncode,0,output)
        binary = self.workspace/'hello.bin'
        subprocess.run(['cc',str(ROOT/'tests/fixtures/workbench_compile.c'),'-o',str(binary)],check=True)
        run, output, _ = self.execute(['/workspace/hello.bin']); self.assertEqual(run.returncode,0,output)

    def test_namespace_failure_never_executes_payload(self):
        run, output, report = self.execute(['echo','PAYLOAD_MUST_NOT_RUN'], fault='namespace')
        self.assertNotEqual(run.returncode,0); self.assertNotIn('PAYLOAD_MUST_NOT_RUN',output)
        self.assertEqual(report['status'],'FAILED')

    def test_seccomp_failure_never_executes_payload(self):
        run, output, report = self.execute(['echo','PAYLOAD_MUST_NOT_RUN'], fault='seccomp')
        self.assertNotEqual(run.returncode,0); self.assertNotIn('PAYLOAD_MUST_NOT_RUN',output)
        self.assertEqual(report['status'],'FAILED')

    def test_invalid_workspace_fails_closed(self):
        run, output, report = self.execute(['echo','PAYLOAD_MUST_NOT_RUN'],options=['--workspace','/does-not-exist-axes'])
        self.assertEqual(run.returncode,126); self.assertNotIn('PAYLOAD_MUST_NOT_RUN',output)
        self.assertIn('no host fallback',output)

    def test_nonzero_exit_and_normal_background_cleanup(self):
        run, _, report = self.execute(['sh','-c','exit 7'])
        self.assertEqual(run.returncode,7); self.assertEqual(report['status'],'FAILED')
        run, output, _ = self.execute(['sh','-c','sleep 30 & echo done'])
        self.assertEqual(run.returncode,0,output)

    def test_continuous_output_cannot_starve_timeout(self):
        run, _, report = self.execute(['python3','-c',"import os\nwhile True: os.write(1,b'x'*65536)"],options=['--timeout','.4','--max-output','1'])
        self.assertEqual(run.returncode,124); self.assertTrue(report['output_truncated']); self.assertLess(report['runtime_sec'],2)

    def test_policy_reduction_and_latch(self):
        run, output, report = self.execute(['python3','-c','while True: pass'],options=['--timeout','1.5','--cpu-threshold','1','--consecutive','2','--reduced-cpu','25'])
        self.assertEqual(run.returncode,124,output)
        self.assertEqual(report['adaptive']['final_cpu'],25)
        self.assertEqual(sum('ADAPTIVE TRIGGER' in event for event in report['event_timeline']),1)

if __name__ == '__main__': unittest.main(verbosity=2)
