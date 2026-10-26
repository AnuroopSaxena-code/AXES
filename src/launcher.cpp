#include "launcher.hpp"
#include "security.hpp"
#include "policy.hpp"
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <climits>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <thread>
#include <cstring>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>
#include <csignal>

namespace axes {

namespace fs = std::filesystem;

static volatile std::sig_atomic_t g_stop_requested = 0;
static volatile std::sig_atomic_t g_signal_received = 0;

static void supervisor_signal_handler(int sig) {
    g_stop_requested = 1;
    g_signal_received = sig;
}

static std::string json_escape(const std::string& str) {
    std::ostringstream o;
    for (char c : str) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if (static_cast<unsigned char>(c) < 32) {
            o << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
        } else {
            o << c;
        }
    }
    return o.str();
}

ExecutionLauncher::ExecutionLauncher(const Config& config)
    : config_(config) {}

void ExecutionLauncher::log_event(ExecutionResult& result, double runtime_sec, const std::string& message) {
    std::ostringstream ss;
    ss << "[" << std::fixed << std::setprecision(1) << runtime_sec << "s] " << message;
    std::string formatted = ss.str();
    result.event_log.push_back(formatted);
    if (config_.verbose_logging) {
        std::cout << formatted << std::endl;
    }
}

static std::string get_current_timestamp_str() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    localtime_r(&now_c, &tm_buf);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}

void ExecutionLauncher::write_execution_report(const ExecutionResult& result) {
    if (config_.report_dir.empty()) return;
    if (!is_valid_job_id(config_.job_id)) {
        std::cerr << "[AXES] Skipping report generation: invalid job ID '" << config_.job_id << "'" << std::endl;
        return;
    }

    std::error_code ec;
    fs::create_directories(config_.report_dir, ec);

    // 1. Write human-readable text report
    fs::path report_path = fs::path(config_.report_dir) / (config_.job_id + "_report.txt");
    std::ofstream ofs(report_path);
    if (ofs.is_open()) {
        ofs << "==================================================\n";
        ofs << "AXES EXECUTION REPORT\n";
        ofs << "==================================================\n\n";

        ofs << "Job ID:             " << result.job_id << "\n";
        ofs << "Command:            ";
        for (const auto& arg : config_.command) ofs << arg << " ";
        ofs << "\n";
        ofs << "Start time:         " << result.start_time_str << "\n";
        ofs << "End time:           " << result.end_time_str << "\n";
        ofs << "Runtime:            " << std::fixed << std::setprecision(2) << result.total_runtime_sec << " s\n";
        ofs << "Status:             " << result.final_status << "\n";
        ofs << "Isolation mode:     " << config_.isolation << "\n";
        ofs << "Security profile:   " << (config_.isolation == "isolated" ? "bwrap + axes-native-x86_64-v1 (required; setup failure prevents exec)" : "resource-only; trusted workloads") << "\n";
        ofs << "Isolation verified: " << (result.isolation_established ? "YES" : "NO") << "\n";
        if (!result.isolation_evidence.empty()) ofs << "Isolation evidence: " << result.isolation_evidence << "\n";
        ofs << "Exit code / Signal: ";
        if (result.terminated_by_signal) {
            ofs << "Signal " << result.signal_number << "\n";
        } else {
            ofs << "Code " << result.exit_code << "\n";
        }
        ofs << "Timed out:          " << (result.timed_out ? "YES" : "NO") << "\n";
        ofs << "Cancelled:          " << (result.cancelled ? "YES" : "NO") << "\n";
        ofs << "Output file:        " << result.output_file << "\n";
        ofs << "Output captured:    " << result.output_bytes_captured << " bytes" 
            << (result.output_truncated ? " (TRUNCATED)" : "") << "\n";

        ofs << "\nCGROUP\n";
        ofs << "Path:         " << result.cgroup_path << "\n";
        ofs << "PID Attached: " << (result.process_attached_verified ? "YES" : "NO") << "\n";

        ofs << "\nRESOURCE LIMITS\n";
        ofs << "CPU:     " << config_.initial_cpu_limit_pct << " %\n";
        ofs << "Memory:  " << config_.memory_limit_mb << " MB\n";
        ofs << "Swap:    Disabled (0 MB)\n";
        ofs << "PIDs:    " << config_.pids_limit << "\n";

        ofs << "\nPEAK USAGE\n";
        ofs << "CPU:       " << std::fixed << std::setprecision(1) << result.peak_cpu_pct << " %\n";
        ofs << "Memory:    " << std::fixed << std::setprecision(1) << result.peak_memory_mb << " MB\n";
        ofs << "Processes: " << result.peak_pids << "\n";

        ofs << "\nADAPTIVE POLICY\n";
        ofs << "Initial CPU:         " << result.initial_cpu_limit << " %\n";
        ofs << "Final CPU:           " << result.final_cpu_limit << " %\n";
        ofs << "Threshold:           " << config_.cpu_threshold_pct << " %\n";
        ofs << "Consecutive Samples: " << config_.consecutive_samples_required << "\n";
        ofs << "Triggered:           " << (result.cpu_adaptation_triggered ? "TRIGGERED (Reduced)" : "NOT TRIGGERED") << "\n";

        ofs << "\nEVENT TIMELINE\n";
        for (const auto& ev : result.event_log) {
            ofs << ev << "\n";
        }

        ofs << "\nRAW KERNEL VALUES\n";
        ofs << "cpu.max:         " << result.cpu_max_final << "\n";
        ofs << "memory.max:      " << result.memory_max_evidence << "\n";
        ofs << "memory.swap.max: " << result.memory_swap_max_evidence << "\n";
        ofs << "pids.max:        " << result.pids_max_evidence << "\n";
        ofs << "==================================================\n";
        ofs.close();
        std::cout << "\n[AXES] Text report generated: " << report_path.string() << std::endl;
    }

    // 2. Write structured JSON report
    fs::path json_path = fs::path(config_.report_dir) / (config_.job_id + "_report.json");
    std::ofstream jfs(json_path);
    if (jfs.is_open()) {
        jfs << "{\n";
        jfs << "  \"job_id\": \"" << json_escape(result.job_id) << "\",\n";
        jfs << "  \"command\": [";
        for (size_t i = 0; i < config_.command.size(); ++i) {
            jfs << "\"" << json_escape(config_.command[i]) << "\"" << (i + 1 < config_.command.size() ? ", " : "");
        }
        jfs << "],\n";
        jfs << "  \"start_time\": \"" << json_escape(result.start_time_str) << "\",\n";
        jfs << "  \"end_time\": \"" << json_escape(result.end_time_str) << "\",\n";
        jfs << "  \"runtime_sec\": " << std::fixed << std::setprecision(3) << result.total_runtime_sec << ",\n";
        jfs << "  \"status\": \"" << json_escape(result.final_status) << "\",\n";
        jfs << "  \"final_status\": \"" << json_escape(result.final_status) << "\",\n";
        jfs << "  \"exit_code\": " << result.exit_code << ",\n";
        jfs << "  \"isolation\": \"" << config_.isolation << "\",\n";
        jfs << "  \"security_profile\": \"" << (config_.isolation == "isolated" ? "axes-native-x86_64-v1" : "resource-only") << "\",\n";
        jfs << "  \"isolation_established\": " << (result.isolation_established ? "true" : "false") << ",\n";
        jfs << "  \"isolation_evidence\": \"" << json_escape(result.isolation_evidence) << "\",\n";
        jfs << "  \"terminated_by_signal\": " << (result.terminated_by_signal ? "true" : "false") << ",\n";
        jfs << "  \"signal_number\": " << result.signal_number << ",\n";
        jfs << "  \"timed_out\": " << (result.timed_out ? "true" : "false") << ",\n";
        jfs << "  \"cancelled\": " << (result.cancelled ? "true" : "false") << ",\n";
        jfs << "  \"cgroup_path\": \"" << json_escape(result.cgroup_path) << "\",\n";
        jfs << "  \"pid_attached\": \"" << (result.process_attached_verified ? "YES" : "NO") << "\",\n";
        jfs << "  \"output_file\": \"" << json_escape(result.output_file) << "\",\n";
        jfs << "  \"output_bytes_captured\": " << result.output_bytes_captured << ",\n";
        jfs << "  \"output_truncated\": " << (result.output_truncated ? "true" : "false") << ",\n";
        jfs << "  \"limits\": {\n";
        jfs << "    \"cpu_pct\": " << config_.initial_cpu_limit_pct << ",\n";
        jfs << "    \"memory_mb\": " << config_.memory_limit_mb << ",\n";
        jfs << "    \"pids\": " << config_.pids_limit << "\n";
        jfs << "  },\n";
        jfs << "  \"peaks\": {\n";
        jfs << "    \"cpu_pct\": " << std::fixed << std::setprecision(1) << result.peak_cpu_pct << ",\n";
        jfs << "    \"memory_mb\": " << std::fixed << std::setprecision(1) << result.peak_memory_mb << ",\n";
        jfs << "    \"pids\": " << result.peak_pids << "\n";
        jfs << "  },\n";
        jfs << "  \"adaptive\": {\n";
        jfs << "    \"triggered\": " << (result.cpu_adaptation_triggered ? "true" : "false") << ",\n";
        jfs << "    \"initial_cpu\": " << result.initial_cpu_limit << ",\n";
        jfs << "    \"final_cpu\": " << result.final_cpu_limit << ",\n";
        jfs << "    \"threshold_pct\": " << config_.cpu_threshold_pct << ",\n";
        jfs << "    \"consecutive_samples\": " << config_.consecutive_samples_required << "\n";
        jfs << "  },\n";
        jfs << "  \"raw_kernel\": {\n";
        jfs << "    \"cpu_max\": \"" << json_escape(result.cpu_max_final) << "\",\n";
        jfs << "    \"memory_max\": \"" << json_escape(result.memory_max_evidence) << "\",\n";
        jfs << "    \"memory_swap_max\": \"" << json_escape(result.memory_swap_max_evidence) << "\",\n";
        jfs << "    \"pids_max\": \"" << json_escape(result.pids_max_evidence) << "\"\n";
        jfs << "  },\n";
        jfs << "  \"event_timeline\": [\n";
        for (size_t i = 0; i < result.event_log.size(); ++i) {
            jfs << "    \"" << json_escape(result.event_log[i]) << "\"" << (i + 1 < result.event_log.size() ? "," : "") << "\n";
        }
        jfs << "  ]\n";
        jfs << "}\n";
        jfs.close();
        std::cout << "[AXES] JSON report generated: " << json_path.string() << std::endl;
    }
}

ExecutionResult ExecutionLauncher::run() {
    ExecutionResult result;
    result.job_id = config_.job_id;
    result.initial_cpu_limit = config_.initial_cpu_limit_pct;
    result.final_cpu_limit = config_.initial_cpu_limit_pct;
    result.start_time_str = get_current_timestamp_str();
    if (getuid() == 0 || geteuid() == 0 || getuid() != geteuid() || getgid() != getegid()) {
        std::cerr << "[AXES] Refusing privileged workload execution. Delegate cgroups with setup, then run as an ordinary user.\n";
        result.exit_code = 126;
        result.final_status = "FAILED";
        return result;
    }
    if (config_.isolation != "resource" && config_.isolation != "isolated") {
        result.exit_code = 126; result.final_status = "FAILED"; return result;
    }
    // Reap orphaned workload descendants after killing the cgroup.
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0) {
        std::perror("[AXES] subreaper setup failed");
        result.exit_code = 126; result.final_status = "FAILED"; return result;
    }

    // Default output file if not set
    if (config_.output_file.empty()) {
        config_.output_file = (fs::path(config_.report_dir) / (config_.job_id + "_output.log")).string();
    }
    result.output_file = config_.output_file;

    if (config_.command.empty()) {
        std::cerr << "[AXES] Error: No command provided to launcher." << std::endl;
        result.exit_code = -1;
        result.final_status = "FAILED";
        return result;
    }

    if (!is_valid_job_id(config_.job_id)) {
        std::cerr << "\n[AXES FATAL ERROR] Invalid job ID '" << config_.job_id 
                  << "'. Must be 1-64 characters matching [a-zA-Z0-9_-] and start with alphanumeric or underscore." << std::endl;
        result.exit_code = 1;
        result.cgroup_setup_failed = true;
        result.final_status = "FAILED";
        return result;
    }

    std::cout << "\nAXES Sandbox Launcher\n";
    std::cout << "----------------------------------------------\n";
    std::cout << "Job ID:        " << config_.job_id << "\n";
    std::cout << "Command:       ";
    for (const auto& arg : config_.command) std::cout << arg << " ";
    std::cout << "\nLimits:        CPU " << config_.initial_cpu_limit_pct << "%, Memory " 
              << config_.memory_limit_mb << " MB, Processes " << config_.pids_limit << "\n";
    if (config_.timeout_sec > 0.0) {
        std::cout << "Timeout:       " << config_.timeout_sec << " s\n";
    } else {
        std::cout << "Timeout:       Disabled\n";
    }
    std::cout << "Output File:   " << config_.output_file << " (Max: " 
              << (config_.max_output_bytes / (1024 * 1024)) << " MB)\n";
    std::cout << "Adaptive Rule: CPU Threshold > " << config_.cpu_threshold_pct << "% for " 
              << config_.consecutive_samples_required << " consecutive samples -> Limit " 
              << config_.reduced_cpu_limit_pct << "%\n";
    std::cout << "----------------------------------------------\n" << std::endl;

    // Create report and output directory
    std::error_code ec;
    fs::path out_file_path(config_.output_file);
    if (out_file_path.has_parent_path()) {
        fs::create_directories(out_file_path.parent_path(), ec);
    }
    if (!config_.report_dir.empty()) {
        fs::create_directories(config_.report_dir, ec);
    }

    // Open target output file
    int out_fd = open(config_.output_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        std::perror("[AXES] Failed to open target output log file");
        result.exit_code = 126; result.final_status = "FAILED";
        write_execution_report(result);
        return result;
    }

    // Create and initialize cgroup - STRICT FATAL CHECK!
    CGroupController cgroup(config_.job_id);
    if (!cgroup.init(config_.initial_cpu_limit_pct, config_.memory_limit_mb, config_.pids_limit)) {
        std::cerr << "\n[AXES FATAL ERROR] Cgroup initialization failed!" << std::endl;
        std::cerr << "[AXES FATAL ERROR] Execution ABORTED. Target program was NOT launched uncontained." << std::endl;
        std::cerr << "[AXES FATAL ERROR] Please run 'sudo ./scripts/setup_cgroups.sh' or './axes check'." << std::endl;
        if (out_fd >= 0) close(out_fd);
        result.exit_code = 1;
        result.cgroup_setup_failed = true;
        result.final_status = "FAILED";
        result.end_time_str = get_current_timestamp_str();
        log_event(result, 0, "SETUP FAILED: cgroup initialization; workload not executed.");
        write_execution_report(result);
        return result;
    }

    result.cgroup_path = cgroup.get_cgroup_path();
    result.cpu_max_initial = cgroup.get_control_file("cpu.max");
    result.cpu_max_final = result.cpu_max_initial;
    result.memory_max_evidence = cgroup.get_control_file("memory.max");
    result.memory_swap_max_evidence = cgroup.get_control_file("memory.swap.max");
    if (result.memory_swap_max_evidence.empty()) result.memory_swap_max_evidence = "0";
    result.pids_max_evidence = cgroup.get_control_file("pids.max");

    // Create sync pipe for child launch barrier
    int sync_pipe[2];
    if (pipe(sync_pipe) < 0) {
        std::perror("[AXES] pipe creation failed");
        if (out_fd >= 0) close(out_fd);
        cgroup.cleanup();
        result.exit_code = -1;
        result.final_status = "FAILED";
        return result;
    }

    // Create output pipe for capturing workload stdout & stderr
    int out_pipe[2];
    if (pipe(out_pipe) < 0) {
        std::perror("[AXES] output pipe creation failed");
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        if (out_fd >= 0) close(out_fd);
        cgroup.cleanup();
        result.exit_code = -1;
        result.final_status = "FAILED";
        return result;
    }

    int isolation_pipe[2] = {-1, -1};
    if (config_.isolation == "isolated" && pipe(isolation_pipe) < 0) {
        std::perror("[AXES] isolation evidence pipe failed");
        close(sync_pipe[0]); close(sync_pipe[1]); close(out_pipe[0]); close(out_pipe[1]);
        if (out_fd >= 0) close(out_fd);
        cgroup.cleanup(); result.exit_code = 126; result.final_status = "FAILED";
        return result;
    }

    // Set read end of output pipe to non-blocking
    int fl = fcntl(out_pipe[0], F_GETFL, 0);
    fcntl(out_pipe[0], F_SETFL, fl | O_NONBLOCK);

    // Setup graceful supervisor signal handling
    g_stop_requested = 0;
    g_signal_received = 0;
    struct sigaction sa, old_int, old_term, old_hup;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = supervisor_signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, &old_int);
    sigaction(SIGTERM, &sa, &old_term);
    sigaction(SIGHUP, &sa, &old_hup);

    pid_t pid = fork();
    if (pid < 0) {
        std::perror("[AXES] fork failed");
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);
        if (isolation_pipe[0] >= 0) close(isolation_pipe[0]);
        if (isolation_pipe[1] >= 0) close(isolation_pipe[1]);
        if (out_fd >= 0) close(out_fd);
        sigaction(SIGINT, &old_int, nullptr);
        sigaction(SIGTERM, &old_term, nullptr);
        sigaction(SIGHUP, &old_hup, nullptr);
        cgroup.cleanup();
        result.exit_code = -1;
        result.final_status = "FAILED";
        return result;
    }

    if (pid == 0) {
        // Child Process: restore default signal handling
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);

        close(sync_pipe[1]); // Close write end of barrier
        close(out_pipe[0]);  // Close read end of output pipe
        if (isolation_pipe[0] >= 0) close(isolation_pipe[0]);

        // Redirect stdout and stderr to out_pipe[1]
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(out_pipe[1], STDERR_FILENO);
        close(out_pipe[1]);

        // Wait for parent to attach PID to cgroup and verify
        char buf = 0;
        ssize_t n = read(sync_pipe[0], &buf, 1);
        close(sync_pipe[0]);

        if (n != 1 || buf != 'G') {
            std::cerr << "[AXES Child] Launch barrier aborted or sync failed. Exiting immediately without exec." << std::endl;
            _exit(126);
        }

        // Close every inherited descriptor except output streams. Workloads must not
        // inherit host directory, socket, terminal or writable report descriptors.
        int info_fd = -1;
        if (isolation_pipe[1] >= 0) {
            info_fd = 3;
            if (dup2(isolation_pipe[1], info_fd) < 0) _exit(126);
        }
        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 ||
            syscall(SYS_close_range, static_cast<unsigned>(info_fd >= 0 ? 4 : 3), UINT_MAX, 0) < 0 ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            std::perror("[AXES Child] descriptor/privilege setup failed; no execution");
            _exit(126);
        }
        if (config_.isolation == "isolated") exec_isolated(config_.command, config_.workspace, info_fd);

        // Build argv array
        std::vector<char*> argv;
        for (const auto& arg : config_.command) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        execvp(argv[0], argv.data());

        // If execvp returns, error occurred
        std::cerr << "[AXES Child] Failed to execvp command: " << argv[0] << std::endl;
        _exit(127);
    }

    // Parent Process
    close(sync_pipe[0]); // Close read end of barrier
    close(out_pipe[1]);  // Close write end of output pipe
    if (isolation_pipe[1] >= 0) close(isolation_pipe[1]);

    std::cout << "PID:         " << pid << "\n";
    std::cout << "Cgroup Path: " << cgroup.get_cgroup_path() << "\n";

    // Attach child process PID to cgroup in parent
    if (!cgroup.add_process(pid)) {
        std::cerr << "\n[AXES FATAL ERROR] Failed to attach PID " << pid << " to cgroup.procs!" << std::endl;
        kill(pid, SIGKILL);
        close(sync_pipe[1]);
        close(out_pipe[0]);
        if (isolation_pipe[0] >= 0) close(isolation_pipe[0]);
        if (out_fd >= 0) close(out_fd);
        int status = 0;
        waitpid(pid, &status, 0); // reap child
        sigaction(SIGINT, &old_int, nullptr);
        sigaction(SIGTERM, &old_term, nullptr);
        sigaction(SIGHUP, &old_hup, nullptr);
        cgroup.cleanup();
        result.exit_code = 1;
        result.cgroup_setup_failed = true;
        result.final_status = "FAILED";
        return result;
    }

    // Verify PID presence in cgroup.procs
    result.process_attached_verified = cgroup.verify_process_attached(pid);
    if (!result.process_attached_verified) {
        std::cerr << "\n[AXES FATAL ERROR] PID " << pid << " was NOT verified in cgroup.procs!" << std::endl;
        std::cerr << "[AXES FATAL ERROR] Execution ABORTED. Target program was NOT launched." << std::endl;
        kill(pid, SIGKILL);
        close(sync_pipe[1]);
        close(out_pipe[0]);
        if (isolation_pipe[0] >= 0) close(isolation_pipe[0]);
        if (out_fd >= 0) close(out_fd);
        int status = 0;
        waitpid(pid, &status, 0); // reap child
        sigaction(SIGINT, &old_int, nullptr);
        sigaction(SIGTERM, &old_term, nullptr);
        sigaction(SIGHUP, &old_hup, nullptr);
        cgroup.cleanup();
        result.exit_code = 1;
        result.cgroup_setup_failed = true;
        result.final_status = "FAILED";
        return result;
    }

    std::cout << "Cgroup PID:  VERIFIED (Present in cgroup.procs)\n";

    // Unblock child process to proceed with execvp
    if (write(sync_pipe[1], "G", 1) != 1) {
        std::cerr << "\n[AXES FATAL ERROR] Failed to write go-signal to sync pipe!" << std::endl;
        kill(pid, SIGKILL);
        close(sync_pipe[1]);
        close(out_pipe[0]);
        if (isolation_pipe[0] >= 0) close(isolation_pipe[0]);
        if (out_fd >= 0) close(out_fd);
        int status = 0;
        waitpid(pid, &status, 0); // reap child
        sigaction(SIGINT, &old_int, nullptr);
        sigaction(SIGTERM, &old_term, nullptr);
        sigaction(SIGHUP, &old_hup, nullptr);
        cgroup.cleanup();
        result.exit_code = 1;
        result.cgroup_setup_failed = true;
        result.final_status = "FAILED";
        return result;
    }
    close(sync_pipe[1]);
    if (isolation_pipe[0] >= 0) {
        pollfd evidence_poll{isolation_pipe[0], POLLIN | POLLHUP, 0};
        if (poll(&evidence_poll, 1, 3000) > 0) {
            char evidence[4096]{};
            ssize_t count = read(isolation_pipe[0], evidence, sizeof(evidence) - 1);
            if (count > 0) {
                result.isolation_evidence.assign(evidence, static_cast<size_t>(count));
                result.isolation_established = result.isolation_evidence.find("pid-namespace") != std::string::npos &&
                    result.isolation_evidence.find("net-namespace") != std::string::npos &&
                    result.isolation_evidence.find("mnt-namespace") != std::string::npos;
            }
        }
        close(isolation_pipe[0]);
        if (!result.isolation_established) {
            std::cout << "Isolation:   FAILED (namespace setup not confirmed; workload cannot run on host)\n";
        } else {
            std::cout << "Isolation:   VERIFIED (mount, PID, network namespaces; Seccomp requested)\n";
        }
    }
    std::cout << "Status:      RUNNING\n" << std::endl;

    // Helper lambda to drain child output from pipe
    auto drain_output = [&](bool flush_sync) {
        char buf[8192];
        // Bound work per iteration so a continuous writer cannot starve timeout/Stop.
        for (int batch = 0; batch < 32; ++batch) {
            ssize_t n = read(out_pipe[0], buf, sizeof(buf));
            if (n > 0) {
                if (result.output_bytes_captured < config_.max_output_bytes) {
                    uint64_t to_write = std::min(static_cast<uint64_t>(n), config_.max_output_bytes - result.output_bytes_captured);
                    if (out_fd >= 0) {
                        ssize_t written = write(out_fd, buf, to_write);
                        (void)written;
                        if (flush_sync) fdatasync(out_fd);
                    }
                    result.output_bytes_captured += to_write;
                    if (result.output_bytes_captured >= config_.max_output_bytes && !result.output_truncated) {
                        result.output_truncated = true;
                        const char* trunc_msg = "\n[AXES] Output limit reached. Further output truncated.\n";
                        if (out_fd >= 0) {
                            ssize_t written = write(out_fd, trunc_msg, strlen(trunc_msg));
                            (void)written;
                            if (flush_sync) fdatasync(out_fd);
                        }
                    }
                }
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            } else {
                // EOF or error
                break;
            }
        }
    };

    // Initialize Monitor
    Monitor monitor(config_.job_id, pid);
    
    CpuPolicy policy(config_.initial_cpu_limit_pct, config_.cpu_threshold_pct,
        config_.consecutive_samples_required, config_.reduced_cpu_limit_pct);
    int status = 0;
    bool child_exited = false;
    auto wall_start = std::chrono::steady_clock::now();
    auto next_sample_time = wall_start;

    // Monitoring loop
    while (!child_exited) {
        // 1. Drain output incrementally
        drain_output(true);

        // 2. Check for supervisor cancellation signal
        if (g_stop_requested) {
            auto now = std::chrono::steady_clock::now();
            double cur_elapsed = std::chrono::duration<double>(now - wall_start).count();
            result.cancelled = true;
            result.final_status = "CANCELLED";
            result.terminated_by_signal = true;
            result.signal_number = g_signal_received;
            result.exit_code = 128 + g_signal_received;
            log_event(result, cur_elapsed, "CANCELLED: Supervisor received signal " + std::to_string(g_signal_received) + ". Terminating workload process tree.");
            cgroup.cleanup();
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            child_exited = true;
            break;
        }

        // 3. Check for wall-clock timeout
        auto now = std::chrono::steady_clock::now();
        double cur_elapsed = std::chrono::duration<double>(now - wall_start).count();
        if (config_.timeout_sec > 0.0 && cur_elapsed >= config_.timeout_sec) {
            result.timed_out = true;
            result.final_status = "TIMED_OUT";
            result.exit_code = 124;
            log_event(result, cur_elapsed, "TIMEOUT: Wall-clock timeout of " + std::to_string(config_.timeout_sec) + "s exceeded. Terminating workload process tree.");
            cgroup.cleanup();
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            child_exited = true;
            break;
        }

        // 4. Poll child process status
        pid_t wait_res = waitpid(pid, &status, WNOHANG);

        if (wait_res == pid) {
            // Child terminated
            child_exited = true;
            if (WIFEXITED(status)) {
                result.exit_code = WEXITSTATUS(status);
                result.terminated_by_signal = false;
                result.final_status = (result.exit_code == 0) ? "COMPLETED" : "FAILED";
            } else if (WIFSIGNALED(status)) {
                result.terminated_by_signal = true;
                result.signal_number = WTERMSIG(status);
                result.exit_code = 128 + result.signal_number;
                result.final_status = "KILLED";
            }
            break;
        } else if (wait_res < 0) {
            std::perror("[AXES] waitpid error");
            child_exited = true;
            result.final_status = "FAILED";
            break;
        }

        // 5. Sample metrics if sample interval has elapsed
        if (now >= next_sample_time) {
            next_sample_time = now + std::chrono::milliseconds(static_cast<int>(config_.sample_interval_sec * 1000));
            ProcessMetrics m = monitor.sample(cgroup);
            
            // Track peaks
            if (m.cpu_usage_pct > result.peak_cpu_pct) result.peak_cpu_pct = m.cpu_usage_pct;
            if (m.memory_usage_mb > result.peak_memory_mb) result.peak_memory_mb = m.memory_usage_mb;
            if (m.process_count > result.peak_pids) result.peak_pids = m.process_count;

            monitor.print_snapshot(m, "RUNNING");

            // One-way latch prevents oscillation and never raises the initial ceiling.
            if (config_.adaptive_enabled && policy.observe(m.cpu_usage_pct, m.valid)) {
                const double old_limit = cgroup.get_current_cpu_limit();
                if (policy.target() < old_limit && cgroup.update_cpu_limit(policy.target())) {
                    policy.applied();
                    result.cpu_adaptation_triggered = true;
                    result.final_cpu_limit = policy.target();
                    result.cpu_max_final = cgroup.get_control_file("cpu.max");
                    std::ostringstream event;
                    event << "ADAPTIVE TRIGGER: CPU limit changed: " << old_limit << "% -> " << policy.target()
                        << "% (usage=" << m.cpu_usage_pct << "%, threshold=" << config_.cpu_threshold_pct
                        << "%, consecutive=" << policy.samples() << ", cpu.max: " << result.cpu_max_final
                        << "). Latched until job exit; no automatic recovery.";
                    log_event(result, m.runtime_seconds, event.str());
                } else {
                    policy.failed();
                    log_event(result, m.runtime_seconds, policy.target() >= old_limit
                        ? "POLICY UNCHANGED: requested reduction is not below current quota; ceiling preserved."
                        : "POLICY ERROR: cpu.max write/readback failed; reduction not confirmed.");
                }
            }
        }

        // Responsive sub-interval sleep (50ms) to rapidly detect timeout, cancellation, or output
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    ProcessMetrics final_m = monitor.sample(cgroup);
    // Normal exit must also terminate background descendants before draining pipes.
    cgroup.cleanup();
    for (int attempt = 0; attempt < 20; ++attempt) {
        int descendant_status;
        pid_t reaped = waitpid(-1, &descendant_status, WNOHANG);
        if (reaped < 0 && errno == ECHILD) break;
        if (reaped == 0) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Final drain of remaining child output
    drain_output(true);
    close(out_pipe[0]);
    if (out_fd >= 0) {
        close(out_fd);
    }

    // Restore original signal handlers
    sigaction(SIGINT, &old_int, nullptr);
    sigaction(SIGTERM, &old_term, nullptr);
    sigaction(SIGHUP, &old_hup, nullptr);

    // Final sample
    auto wall_end = std::chrono::steady_clock::now();
    result.total_runtime_sec = std::chrono::duration<double>(wall_end - wall_start).count();
    result.end_time_str = get_current_timestamp_str();
    if (final_m.cpu_usage_pct > result.peak_cpu_pct) result.peak_cpu_pct = final_m.cpu_usage_pct;
    if (final_m.memory_usage_mb > result.peak_memory_mb) result.peak_memory_mb = final_m.memory_usage_mb;
    if (final_m.process_count > result.peak_pids) result.peak_pids = final_m.process_count;

    monitor.print_snapshot(final_m, result.final_status);

    std::cout << "\n----------------------------------------------\n";
    std::cout << "Job ID: " << config_.job_id << " Execution Summary\n";
    std::cout << "Status: " << result.final_status << " (Exit Code: " << result.exit_code << ")\n";
    std::cout << "Runtime: " << std::fixed << std::setprecision(2) << result.total_runtime_sec << " s\n";
    std::cout << "Output:  " << result.output_bytes_captured << " bytes captured -> " << result.output_file << "\n";
    std::cout << "CGroup:  " << result.cgroup_path << " (Verified attached: " << (result.process_attached_verified ? "YES" : "NO") << ")\n";
    std::cout << "----------------------------------------------\n" << std::endl;

    write_execution_report(result);

    // Clean up cgroup directory
    cgroup.cleanup();

    return result;
}

} // namespace axes

