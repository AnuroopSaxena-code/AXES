# AXES Security Architecture & Threat Model

**Document Version:** 1.0

**Target System:** AXES (Adaptive eXecution Environment Sandbox)

**Kernel Requirements:** Linux >= 5.14, unified cgroups v2 with delegated `cpu`, `memory`, and `pids` controllers, user/PID/mount/network/IPC/UTS/cgroup namespaces, and Seccomp-BPF

**Runtime Requirements:** x86_64, Bubblewrap (`/usr/bin/bwrap`), and an ordinary user account

**Verified Environment:** Ubuntu on WSL2, kernel 6.18.33-microsoft-standard-WSL2

---

## 1. Executive Summary

AXES applies resource bounds and defense-in-depth isolation to staged workloads. The current profile is verified against representative shell, Python/threading, and compiled C programs. It is not a complete boundary against kernel vulnerabilities or an assurance that every language runtime is compatible.

The security model is built on three core tenets:
1. **Separation of Privilege:** The execution supervisor and untrusted workloads **never run as root**. Privileged cgroup delegation is performed once by an administrator; all runtime operations run as an unprivileged user.
2. **Defense-in-Depth Isolation:** Workload isolation is established using Linux cgroups v2 (resource containment), Linux namespaces (process, filesystem, and network virtualization), process credential stripping (`PR_SET_NO_NEW_PRIVS`, zero capabilities), and Seccomp-BPF syscall filtering.
3. **Fail-Closed Guarantee (No Host Fallback):** If any stage of namespace, cgroup, or seccomp initialization fails, the child process is terminated immediately prior to executing any untrusted payload (`_exit(126)`). AXES never falls back to uncontained host execution.

---

## 2. Threat Model & Adversary Capabilities

### 2.1 In-Scope Threats
AXES is designed to defend against malicious or buggy workloads attempting:

| Threat Category | Adversarial Action | AXES Mitigation |
| :--- | :--- | :--- |
| **CPU Denial of Service** | Infinite loops, multi-threaded CPU burning (`cpu_burn.py`) | cgroups v2 `cpu.max` quota enforcement; deterministic one-way adaptive reduction; supervisor wall-clock timeout. |
| **Memory Exhaustion** | Unbounded heap allocation, memory leaks (`memory_stress.py`) | cgroups v2 `memory.max` enforcement; `memory.swap.max = 0` (swap disabled); kernel OOM killer terminates rogue process without host disruption. |
| **Process / Fork Bombs** | Recursive process spawning, zombie generation (`process_stress.c`) | cgroups v2 `pids.max` limits total processes; supervisor process subreaper (`PR_SET_CHILD_SUBREAPER`) reaps descendants; atomic cleanup via `cgroup.kill`. |
| **Filesystem Tampering** | Writing to host filesystem, traversing paths (`../../`), overwriting binaries | Staged workspace mounted read-only (`/workspace`); `/tmp` backed by isolated `tmpfs`; host roots (`/mnt/c`, `/sys/fs/cgroup`) unmapped; strict path traversal sanitization in supervisor and API. |
| **Network Abuse** | C2 beaconing, port scanning, exfiltration, lateral network attacks | Complete network namespace isolation (`CLONE_NEWNET` / `--unshare-net`); no network interfaces except unconfigured loopback (`lo`). Socket creation denied. |
| **Privilege Escalation** | Executing `sudo`, setuid binaries, gaining root capabilities | `PR_SET_NO_NEW_PRIVS` prevents setuid transitions; `cap-drop ALL` strips all effective, permitted, and inheritable Linux capabilities; root execution refused by supervisor. |
| **Escape via Kernel Calls** | Debugging parent via `ptrace`, altering namespaces via `unshare`/`setns`, loading BPF | Seccomp-BPF positive allowlist blocks `ptrace`, `unshare`, `setns`, `mount`, `bpf`, `clone3`, `kexec_load`, kernel keyring, and module loading. |
| **Output Flooding** | Infinite stdout/stderr generation to exhaust server disk/memory | Supervisor output pipe drained non-blockingly; output strictly bounded by `max_output_bytes` (default 10 MB); excess output discarded with truncation marker. |

### 2.2 Out-of-Scope / Non-Mitigated Threats
- **Kernel Zero-Day Exploits:** Workloads share the host Linux kernel. A vulnerability within an allowed syscall in the host kernel could theoretically permit kernel privilege escalation.
- **Microarchitectural Side Channels:** Speculative execution timing attacks (Spectre/Meltdown) between co-located physical cores are not mitigated without dedicated CPU core pinning and kernel thread isolation.
- **Hardware Fault Injection:** Physical attacks or hardware-level fault injection are outside the software sandbox model.
- **Trusted Control Plane:** The repository, AXES binary, Python API, Bubblewrap binary, host kernel, administrator setup, and staged-workspace owner are trusted. Compiling C/C++ in the workbench invokes the host compiler outside the sandbox and must be limited to trusted source.
- **Resource-Only Mode:** `--isolation resource` enforces cgroup limits but deliberately retains host filesystem, process, and network visibility. It is not an isolation mode for hostile code.

---

## 3. Trust Boundaries & Privilege Model

```
+--------------------------------------------------------------------------+
| ADMIN PRIVILEGED SETUP (One-Time Execution via sudo)                     |
| - setup_cgroups.sh creates /sys/fs/cgroup/axes                           |
| - Delegates ownership to unprivileged user (UID: 1000)                   |
| - Enables cpu, memory, pids controllers in parent subtree_control        |
+--------------------------------------------------------------------------+
                                  |
                                  v
+--------------------------------------------------------------------------+
| AXES SUPERVISOR & BENCHMARK API (Unprivileged User, UID 1000)            |
| - Runs web/server.py and build/axes                                      |
| - Validates input bounds, Job IDs, file paths                            |
| - Initializes /sys/fs/cgroup/axes/<job_id>                              |
| - Creates sync pipe barrier and non-blocking output pipes                |
| - Monitored via subreaper (PR_SET_CHILD_SUBREAPER)                       |
+--------------------------------------------------------------------------+
         |                                           |
         v (Barrier Verification)                    v (Output Draining)
+-----------------------------------+     +--------------------------------+
| UNTRUSTED WORKLOAD ISOLATION      |     | STREAMED METRICS & LOGS        |
| - Namespaces: USER, PID, MNT,     |     | - Workload stdout/stderr pipe  |
|   NET, IPC, UTS, CGROUP           |     | - Separated from supervisor log|
| - PR_SET_NO_NEW_PRIVS             |     | - Bounded at 10 MB cap         |
| - Cap-drop: ALL (CapEff = 0)      |     | - JSON report generation       |
| - Seccomp-BPF positive allowlist  |     +--------------------------------+
| - Read-only /workspace            |
| - Ephemeral /tmp (tmpfs)          |
| - No network interfaces           |
+-----------------------------------+
```

### 3.1 Strict Prohibition of Root Execution
Neither the supervisor binary (`build/axes`) nor the web server (`web/server.py`) may run as `root` (UID 0 or EUID 0):
- If `getuid() == 0 || geteuid() == 0`, `ExecutionLauncher::run()` and `exec_isolated()` immediately abort with exit code `126`:
  ```text
  [AXES] Refusing privileged workload execution. Delegate cgroups with setup, then run as an ordinary user.
  ```
- Similarly, `web/server.py` enforces `if os.getuid() == 0 or os.geteuid() == 0: raise SystemExit(...)`.

---

## 4. Linux Namespaces & Filesystem Boundaries

Isolation mode (`--isolation isolated`) establishes an unshared environment using Bubblewrap (`bwrap`):

1. **PID Namespace (`CLONE_NEWPID`):**
   - The workload cannot see or signal host processes.
   - Inside `/proc`, only the workload and its direct children are visible (typically 1 to 3 PIDs). Host PIDs are completely hidden.
2. **Mount Namespace (`CLONE_NEWNS`):**
   - Read-only binds for system runtime dependencies: `/usr`, `/bin`, `/lib`, `/lib64`, and `/etc/ld.so.cache`.
   - Staged workspace directory is mounted read-only at `/workspace`. Attempts to write return `EROFS` (Errno 30).
   - Private, isolated `tmpfs` mounted at `/tmp` for temporary scratch space. Files created in `/tmp` are ephemeral and destroyed upon workload termination.
   - Host mounts (such as `/mnt/c` in WSL2 or user home directories) are unmapped and inaccessible.
3. **Network Namespace (`CLONE_NEWNET`):**
   - Unshares the network stack. No physical or virtual network interfaces are inherited.
   - Outbound connections and socket creation fail with `EPERM` or `ENETUNREACH`.
4. **IPC & UTS Namespaces (`CLONE_NEWIPC`, `CLONE_NEWUTS`):**
   - Workload cannot access host shared memory, message queues, or host hostname.
5. **Cgroup Namespace (`CLONE_NEWCGROUP`):**
   - Workload cannot view or navigate parent cgroup hierarchies.

---

## 5. Seccomp-BPF Syscall Filtering

AXES installs a classic BPF seccomp filter sealed into a memory file descriptor (`memfd_create` with `F_SEAL_SEAL`) prior to payload execution.

### 5.1 Architecture & ABI Enforcement
- **Native Architecture Only:** Enforces `AUDIT_ARCH_X86_64`. Any attempt to invoke syscalls via 32-bit x86 or foreign ABIs results in immediate `SECCOMP_RET_KILL_PROCESS`.
- **Positive Allowlist:** Only syscalls explicitly required for compute, memory management, process lifecycle, signal handling, and standard file I/O are permitted (`SECCOMP_RET_ALLOW`).
- **Default Action:** Unrecognized syscalls return `SECCOMP_RET_ERRNO | EPERM` (or `ENOSYS` for `clone3`), preventing unauthorized kernel interaction.

### 5.2 Critical Filtered Syscalls

| Syscall | Action | Rationale |
| :--- | :--- | :--- |
| `ptrace` (101) | Blocked (`EPERM`) | Prevents inspecting or attaching to other processes or the supervisor. |
| `unshare` (272), `setns` (308) | Blocked (`EPERM`) | Prevents escaping or altering established namespaces. |
| `mount` (165), `umount2` (166) | Blocked (`EPERM`) | Prevents remounting filesystems or changing mount flags. |
| `bpf` (321) | Blocked (`EPERM`) | Prevents loading kernel BPF programs or inspecting kernel tracepoints. |
| `clone3` (435) | Blocked (`ENOSYS`) | Forces glibc to fall back to `clone()`, where namespace flags are verified. |
| `clone` (56) with namespace flags | Blocked (`EPERM`) | Prevents creating nested user/network/pid namespaces from inside the sandbox. |
| `reboot` (169), `kexec_load` (246) | Blocked (`EPERM`) | Prevents system reboot or kernel replacement. |
| `init_module` (175), `delete_module` (176) | Blocked (`EPERM`) | Prevents loading kernel drivers or rootkits. |
| `keyctl` (250), `add_key` (248) | Blocked (`EPERM`) | Prevents accessing kernel security keyring. |

---

## 6. Adaptive Resource Policy

AXES features a deterministic resource policy governing CPU usage:
1. **Consecutive-Sample Threshold:** Adaptation is triggered only when measured CPU utilization exceeds `cpu_threshold_pct` for `consecutive_samples_required` consecutive monitoring cycles (preventing false alarms on transient spikes).
2. **One-Way Hysteresis Latching:** Once a workload is adapted (throttled from `initial_cpu_limit_pct` down to `reduced_cpu_limit_pct`), the limit remains latched until workload termination.
   - *Rationale:* Throttled workloads are artificially capped by `cpu.max`; their measured CPU usage reflects the reduced quota, not their true computational demand. Raising limits automatically would risk rapid oscillation and defeat containment.
3. **Validated Cgroup Control:** Limit changes are written directly to `/sys/fs/cgroup/axes/<job_id>/cpu.max` and verified via readback before logging an `ADAPTIVE TRIGGER` event.

---

## 7. Audit & Verification Summary

| Security Property | Implementation Mechanism | Verification Test | Result |
| :--- | :--- | :--- | :---: |
| **Non-Root Execution** | UID/EUID validation in C++ and Python | Direct root invocation plus isolated UID/capability probe | **PASS** |
| **Namespace Isolation** | `bwrap` with 7 unshared namespaces | `test_namespace_filesystem_network_and_privileges` | **PASS** |
| **Read-Only Workspace** | Read-only bind mount at `/workspace` | `test_host_file_not_visible_even_through_proc_root` | **PASS** |
| **Network Block** | `CLONE_NEWNET`, unmapped loopback | Socket creation blocked with `EPERM` | **PASS** |
| **Seccomp Protection** | BPF allowlist sealed in memfd | Blocked syscall probe (`ptrace`, `bpf`, `unshare`) | **PASS** |
| **Fail-Closed Guarantee** | Launch barrier aborts on any failure | `test_namespace_failure_never_executes_payload` | **PASS** |
| **Seccomp Fail-Closed** | Launch barrier aborts on filter error | `test_seccomp_failure_never_executes_payload` | **PASS** |
| **Output Bounding** | Non-blocking drain with 10 MB cap | `test_continuous_output_cannot_starve_timeout` | **PASS** |
| **Atomic Cleanup** | `cgroup.kill` + SIGKILL loop | `test_stop_finishes_supervisor_and_descendants` | **PASS** |
