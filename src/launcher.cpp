#include "launcher.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <thread>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <csignal>

namespace axes {

namespace fs = std::filesystem;

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

    std::error_code ec;
    fs::create_directories(config_.report_dir, ec);

    fs::path report_path = fs::path(config_.report_dir) / (config_.job_id + "_report.txt");
    std::ofstream ofs(report_path);
    if (!ofs.is_open()) return;

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
    ofs << "Status:             " << (result.terminated_by_signal ? "KILLED (Signal Termination)" : "EXITED") << "\n";
    ofs << "Exit code / Signal: ";
    if (result.terminated_by_signal) {
        ofs << "Signal " << result.signal_number << "\n";
    } else {
        ofs << "Code " << result.exit_code << "\n";
    }

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

    std::cout << "\n[AXES] Report generated: " << report_path.string() << std::endl;
}

ExecutionResult ExecutionLauncher::run() {
    ExecutionResult result;
    result.job_id = config_.job_id;
    result.initial_cpu_limit = config_.initial_cpu_limit_pct;
    result.final_cpu_limit = config_.initial_cpu_limit_pct;
    result.start_time_str = get_current_timestamp_str();

    if (config_.command.empty()) {
        std::cerr << "[AXES] Error: No command provided to launcher." << std::endl;
        result.exit_code = -1;
        return result;
    }

    std::cout << "\nAXES Sandbox Launcher\n";
    std::cout << "----------------------------------------------\n";
    std::cout << "Job ID:        " << config_.job_id << "\n";
    std::cout << "Command:       ";
    for (const auto& arg : config_.command) std::cout << arg << " ";
    std::cout << "\nLimits:        CPU " << config_.initial_cpu_limit_pct << "%, Memory " 
              << config_.memory_limit_mb << " MB, Processes " << config_.pids_limit << "\n";
    std::cout << "Adaptive Rule: CPU Threshold > " << config_.cpu_threshold_pct << "% for " 
              << config_.consecutive_samples_required << " consecutive samples -> Limit " 
              << config_.reduced_cpu_limit_pct << "%\n";
    std::cout << "----------------------------------------------\n" << std::endl;

    // Create and initialize cgroup - STRICT FATAL CHECK!
    CGroupController cgroup(config_.job_id);
    if (!cgroup.init(config_.initial_cpu_limit_pct, config_.memory_limit_mb, config_.pids_limit)) {
        std::cerr << "\n[AXES FATAL ERROR] Cgroup initialization failed!" << std::endl;
        std::cerr << "[AXES FATAL ERROR] Execution ABORTED. Target program was NOT launched uncontained." << std::endl;
        std::cerr << "[AXES FATAL ERROR] Please run 'sudo ./scripts/setup_cgroups.sh' or './axes check'." << std::endl;
        result.exit_code = 1;
        result.cgroup_setup_failed = true;
        return result;
    }

    result.cgroup_path = cgroup.get_cgroup_path();
    result.cpu_max_initial = cgroup.get_control_file("cpu.max");
    result.cpu_max_final = result.cpu_max_initial;
    result.memory_max_evidence = cgroup.get_control_file("memory.max");
    result.memory_swap_max_evidence = cgroup.get_control_file("memory.swap.max");
    if (result.memory_swap_max_evidence.empty()) result.memory_swap_max_evidence = "0";
    result.pids_max_evidence = cgroup.get_control_file("pids.max");

    // Create sync pipe for child launch
    int sync_pipe[2];
    if (pipe(sync_pipe) < 0) {
        std::perror("[AXES] pipe creation failed");
        cgroup.cleanup();
        result.exit_code = -1;
        return result;
    }

    pid_t pid = fork();
    if (pid < 0) {
        std::perror("[AXES] fork failed");
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        cgroup.cleanup();
        result.exit_code = -1;
        return result;
    }

    if (pid == 0) {
        // Child Process
        close(sync_pipe[1]); // Close write end
        
        // Wait for parent to attach PID to cgroup
        char buf;
        ssize_t n = read(sync_pipe[0], &buf, 1);
        (void)n;
        close(sync_pipe[0]);

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
    close(sync_pipe[0]); // Close read end

    std::cout << "PID:         " << pid << "\n";
    std::cout << "Cgroup Path: " << cgroup.get_cgroup_path() << "\n";

    // Attach child process PID to cgroup in parent
    if (!cgroup.add_process(pid)) {
        std::cerr << "\n[AXES FATAL ERROR] Failed to attach PID " << pid << " to cgroup.procs!" << std::endl;
        kill(pid, SIGKILL);
        close(sync_pipe[1]);
        cgroup.cleanup();
        result.exit_code = 1;
        result.cgroup_setup_failed = true;
        return result;
    }

    // Verify PID presence in cgroup.procs
    result.process_attached_verified = cgroup.verify_process_attached(pid);
    std::cout << "Cgroup PID:  " << (result.process_attached_verified ? "VERIFIED (Present in cgroup.procs)" : "WARNING (Pending)") << "\n";

    // Unblock child process to proceed with execvp
    write(sync_pipe[1], "G", 1);
    close(sync_pipe[1]);
    std::cout << "Status:      RUNNING\n" << std::endl;

    // Initialize Monitor
    Monitor monitor(config_.job_id, pid);
    
    int consecutive_high_cpu = 0;
    int status = 0;
    bool child_exited = false;

    // Monitoring loop
    while (!child_exited) {
        pid_t wait_res = waitpid(pid, &status, WNOHANG);

        if (wait_res == pid) {
            // Child terminated
            child_exited = true;
            if (WIFEXITED(status)) {
                result.exit_code = WEXITSTATUS(status);
                result.terminated_by_signal = false;
            } else if (WIFSIGNALED(status)) {
                result.terminated_by_signal = true;
                result.signal_number = WTERMSIG(status);
                result.exit_code = 128 + result.signal_number;
            }
        } else if (wait_res < 0) {
            std::perror("[AXES] waitpid error");
            child_exited = true;
        } else {
            // Child still running: sample metrics
            ProcessMetrics m = monitor.sample(cgroup);
            
            // Track peaks
            if (m.cpu_usage_pct > result.peak_cpu_pct) result.peak_cpu_pct = m.cpu_usage_pct;
            if (m.memory_usage_mb > result.peak_memory_mb) result.peak_memory_mb = m.memory_usage_mb;
            if (m.process_count > result.peak_pids) result.peak_pids = m.process_count;

            monitor.print_snapshot(m, "RUNNING");

            // Adaptive Control Logic
            if (config_.adaptive_enabled) {
                if (m.cpu_usage_pct >= config_.cpu_threshold_pct) {
                    consecutive_high_cpu++;
                    std::ostringstream msg;
                    msg << "High CPU detected (" << std::fixed << std::setprecision(1) << m.cpu_usage_pct 
                        << "% >= " << config_.cpu_threshold_pct << "%) [" << consecutive_high_cpu 
                        << "/" << config_.consecutive_samples_required << "]";
                    log_event(result, m.runtime_seconds, msg.str());

                    if (consecutive_high_cpu >= config_.consecutive_samples_required && !result.cpu_adaptation_triggered) {
                        result.cpu_adaptation_triggered = true;
                        result.final_cpu_limit = config_.reduced_cpu_limit_pct;
                        cgroup.update_cpu_limit(config_.reduced_cpu_limit_pct);

                        result.cpu_max_final = cgroup.get_control_file("cpu.max");

                        std::ostringstream adapt_msg;
                        adapt_msg << "ADAPTIVE TRIGGER: CPU limit changed: " << config_.initial_cpu_limit_pct 
                                  << "% -> " << config_.reduced_cpu_limit_pct << "% (cpu.max: " << result.cpu_max_final << ")";
                        log_event(result, m.runtime_seconds, adapt_msg.str());
                    }
                } else {
                    if (consecutive_high_cpu > 0) {
                        consecutive_high_cpu = 0;
                    }
                    log_event(result, m.runtime_seconds, "NORMAL");
                }
            } else {
                log_event(result, m.runtime_seconds, "NORMAL");
            }

            // Sleep sample interval
            int sleep_ms = static_cast<int>(config_.sample_interval_sec * 1000);
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
        }
    }

    // Final sample
    ProcessMetrics final_m = monitor.sample(cgroup);
    result.total_runtime_sec = final_m.runtime_seconds;
    result.end_time_str = get_current_timestamp_str();
    if (final_m.cpu_usage_pct > result.peak_cpu_pct) result.peak_cpu_pct = final_m.cpu_usage_pct;
    if (final_m.memory_usage_mb > result.peak_memory_mb) result.peak_memory_mb = final_m.memory_usage_mb;
    if (final_m.process_count > result.peak_pids) result.peak_pids = final_m.process_count;

    monitor.print_snapshot(final_m, result.terminated_by_signal ? "KILLED" : "FINISHED");

    std::cout << "\n----------------------------------------------\n";
    std::cout << "Job ID: " << config_.job_id << " Execution Summary\n";
    if (result.terminated_by_signal) {
        std::cout << "Status: COMPLETED WITH SIGNAL " << result.signal_number << " (e.g. SIGKILL/OOM)\n";
    } else {
        std::cout << "Status: COMPLETED (Exit Code: " << result.exit_code << ")\n";
    }
    std::cout << "Runtime: " << std::fixed << std::setprecision(2) << result.total_runtime_sec << " s\n";
    std::cout << "CGroup:  " << result.cgroup_path << " (Verified attached: " << (result.process_attached_verified ? "YES" : "NO") << ")\n";
    std::cout << "----------------------------------------------\n" << std::endl;

    write_execution_report(result);

    // Clean up cgroup directory
    cgroup.cleanup();

    return result;
}

} // namespace axes
