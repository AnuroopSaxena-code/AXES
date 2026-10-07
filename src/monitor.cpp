#include "monitor.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unistd.h>
#include <sys/types.h>

namespace axes {

Monitor::Monitor(const std::string& job_id, pid_t pid)
    : job_id_(job_id), target_pid_(pid) {
    start_time_ = std::chrono::steady_clock::now();
    last_sample_time_ = start_time_;
    start_time_sec_ = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

ProcessMetrics Monitor::sample(CGroupController& cgroup) {
    ProcessMetrics metrics;
    metrics.timestamp = std::chrono::system_clock::now();

    auto now = std::chrono::steady_clock::now();
    double runtime_sec = std::chrono::duration<double>(now - start_time_).count();
    metrics.runtime_seconds = runtime_sec;

    uint64_t cpu_usec = 0;
    uint64_t mem_bytes = 0;
    int64_t pids_count = 0;

    bool cgroup_ok = cgroup.get_stats(cpu_usec, mem_bytes, pids_count);

    if (cgroup_ok && (cpu_usec > 0 || mem_bytes > 0 || pids_count > 0)) {
        double elapsed_sec = std::chrono::duration<double>(now - last_sample_time_).count();
        if (elapsed_sec > 0.0 && !first_sample_) {
            uint64_t cpu_delta = (cpu_usec >= last_cpu_usec_) ? (cpu_usec - last_cpu_usec_) : 0;
            double cpu_used_sec = static_cast<double>(cpu_delta) / 1000000.0;
            metrics.cpu_usage_pct = (cpu_used_sec / elapsed_sec) * 100.0;
        } else {
            metrics.cpu_usage_pct = 0.0;
        }

        metrics.memory_usage_mb = static_cast<double>(mem_bytes) / (1024.0 * 1024.0);
        metrics.process_count = (pids_count > 0) ? pids_count : 1;
    } else {
        // Fallback to /proc if cgroup stats aren't readable
        metrics = sample_fallback_proc(target_pid_, runtime_sec);
    }

    last_sample_time_ = now;
    last_cpu_usec_ = cpu_usec;
    first_sample_ = false;

    history_.push_back(metrics);
    return metrics;
}

ProcessMetrics Monitor::sample_fallback_proc(pid_t pid, double runtime_sec) {
    ProcessMetrics m;
    m.runtime_seconds = runtime_sec;
    m.timestamp = std::chrono::system_clock::now();
    m.process_count = 1;

    // Read /proc/<pid>/status for VmRSS
    std::string status_path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream ifs(status_path);
    if (ifs.is_open()) {
        std::string line;
        while (std::getline(ifs, line)) {
            if (line.rfind("VmRSS:", 0) == 0) {
                std::istringstream iss(line.substr(6));
                uint64_t kb;
                iss >> kb;
                m.memory_usage_mb = static_cast<double>(kb) / 1024.0;
                break;
            }
        }
    }
    m.cpu_usage_pct = 0.0;
    return m;
}

void Monitor::print_snapshot(const ProcessMetrics& metrics, const std::string& status_label) {
    std::cout << "\n----------------------------------------\n";
    std::cout << "Job: " << job_id_ << " | Status: " << status_label << "\n";
    std::cout << std::fixed << std::setprecision(1);
    std::cout << "CPU Usage:       " << metrics.cpu_usage_pct << "%\n";
    std::cout << "Memory Usage:    " << metrics.memory_usage_mb << " MB\n";
    std::cout << "Processes:       " << metrics.process_count << "\n";
    std::cout << "Runtime:         " << metrics.runtime_seconds << " s\n";
    std::cout << "----------------------------------------\n" << std::flush;
}

} // namespace axes
