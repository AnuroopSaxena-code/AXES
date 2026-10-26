#include "security.hpp"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <vector>

namespace axes {
namespace {
[[noreturn]] void fail(const char* stage) {
    dprintf(2, "[AXES isolation] %s: %s. Workload was not executed; no host fallback.\n", stage, strerror(errno));
    _exit(126);
}
int profile_fd() {
#if !defined(__x86_64__)
    errno = ENOTSUP; fail("Seccomp profile supports native x86-64 only");
#else
    // Positive allowlist. Unknown syscalls return EPERM; foreign ABIs are killed.
    std::vector<sock_filter> filter = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        // clone3 cannot have its pointed-to flags inspected by classic BPF.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
            CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP | CLONE_UNTRACED, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    const int allowed[] = {
        __NR_read, __NR_write, __NR_readv, __NR_writev, __NR_pread64, __NR_pwrite64,
        __NR_close, __NR_close_range, __NR_lseek, __NR_open, __NR_openat, __NR_openat2,
        __NR_stat, __NR_fstat, __NR_lstat, __NR_newfstatat, __NR_statx,
        __NR_access, __NR_faccessat, __NR_faccessat2, __NR_readlink, __NR_readlinkat,
        __NR_getdents, __NR_getdents64, __NR_getcwd, __NR_chdir, __NR_fchdir,
        __NR_mmap, __NR_mprotect, __NR_munmap, __NR_mremap, __NR_madvise, __NR_brk,
        __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn, __NR_sigaltstack,
        __NR_rt_sigsuspend, __NR_rt_sigtimedwait, __NR_restart_syscall,
        __NR_futex, __NR_set_tid_address, __NR_set_robust_list, __NR_rseq,
        __NR_arch_prctl, __NR_getrandom, __NR_uname, __NR_sysinfo,
        __NR_clock_gettime, __NR_clock_getres, __NR_clock_nanosleep, __NR_nanosleep,
        __NR_gettimeofday, __NR_time, __NR_times, __NR_getrusage,
        __NR_getpid, __NR_getppid, __NR_gettid, __NR_getuid, __NR_geteuid,
        __NR_getgid, __NR_getegid, __NR_getgroups, __NR_getresuid, __NR_getresgid,
        __NR_fork, __NR_vfork, __NR_execve, __NR_wait4, __NR_waitid,
        __NR_exit, __NR_exit_group, __NR_kill, __NR_tkill, __NR_tgkill,
        __NR_pipe, __NR_pipe2, __NR_dup, __NR_dup2, __NR_dup3, __NR_fcntl, __NR_ioctl,
        __NR_poll, __NR_ppoll, __NR_select, __NR_pselect6,
        __NR_epoll_create1, __NR_epoll_ctl, __NR_epoll_wait, __NR_epoll_pwait, __NR_eventfd2,
        __NR_getrlimit, __NR_prlimit64, __NR_sched_yield, __NR_sched_getaffinity,
        __NR_sched_getparam, __NR_sched_getscheduler, __NR_getpriority,
        __NR_setpgid, __NR_getpgid, __NR_getpgrp, __NR_setsid, __NR_getsid,
        __NR_umask, __NR_fsync, __NR_fdatasync, __NR_ftruncate, __NR_truncate,
        __NR_mkdir, __NR_mkdirat, __NR_rmdir, __NR_unlink, __NR_unlinkat,
        __NR_rename, __NR_renameat, __NR_renameat2, __NR_link, __NR_linkat,
        __NR_symlink, __NR_symlinkat, __NR_chmod, __NR_fchmod, __NR_fchmodat,
        __NR_utimensat, __NR_statfs, __NR_fstatfs, __NR_sendfile, __NR_copy_file_range,
        __NR_capget
    };
    for (int syscall_number : allowed) {
        filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned>(syscall_number), 0, 1));
        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
    int fd = memfd_create("axes-seccomp-v1", MFD_ALLOW_SEALING);
    if (fd < 0) fail("create seccomp profile");
    const auto size = filter.size() * sizeof(sock_filter);
    if (write(fd, filter.data(), size) != static_cast<ssize_t>(size) || lseek(fd, 0, SEEK_SET) < 0 ||
        fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) < 0)
        fail("seal seccomp profile");
    return fd;
#endif
}
}
[[noreturn]] void exec_isolated(const std::vector<std::string>& command, const std::string& workspace,
                                int info_fd) {
    if (getuid() == 0 || geteuid() == 0) { errno = EPERM; fail("root execution refused"); }
    std::error_code ec;
    auto root = std::filesystem::canonical(workspace, ec);
    if (ec || !std::filesystem::is_directory(root) || root == "/") { errno = EINVAL; fail("invalid staging workspace"); }
    int fd = profile_fd();
    std::vector<std::string> args = {"/usr/bin/bwrap",
        "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
        "--disable-userns", "--assert-userns-disabled", "--die-with-parent", "--new-session",
        "--uid", std::to_string(getuid()), "--gid", std::to_string(getgid()), "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64", "--dir", "/etc",
        "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"};
    if (std::filesystem::exists("/etc/alternatives")) {
        args.push_back("--ro-bind");
        args.push_back("/etc/alternatives");
        args.push_back("/etc/alternatives");
    }
    std::vector<std::string> tail = {
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--ro-bind", root.string(), "/workspace", "--chdir", "/workspace",
        "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
        "--setenv", "LANG", "C.UTF-8", "--setenv", "PYTHONUNBUFFERED", "1",
        "--seccomp", std::to_string(fd), "--info-fd", std::to_string(info_fd), "--"};
    args.insert(args.end(), tail.begin(), tail.end());
    args.insert(args.end(), command.begin(), command.end());
    std::vector<char*> argv;
    for (auto& arg : args) argv.push_back(arg.data());
    argv.push_back(nullptr);
    execv(argv[0], argv.data());
    fail("exec /usr/bin/bwrap");
}
}
