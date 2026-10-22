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

    metrics.valid = cgroup_ok && !first_sample_;
    if (cgroup_ok) {
        double elapsed = std::chrono::duration<double>(now - last_sample_time_).count();
        if (elapsed > 0 && !first_sample_ && cpu_usec >= last_cpu_usec_)
            metrics.cpu_usage_pct = (cpu_usec - last_cpu_usec_) / (elapsed * 10000.0);
        metrics.memory_usage_mb = static_cast<double>(mem_bytes) / (1024.0 * 1024.0);
        metrics.process_count = pids_count;
    }

    last_sample_time_ = now;
    last_cpu_usec_ = cpu_usec;
    first_sample_ = false;

    if (history_.size() >= 512) history_.erase(history_.begin());
    history_.push_back(metrics);
    return metrics;
}

void Monitor::print_snapshot(const ProcessMetrics& metrics, const std::string& status_label) {
    std::cout << "\n----------------------------------------\n";
    std::cout << "Job: " << job_id_ << " | Status: " << status_label << "\n";
    std::cout << std::fixed << std::setprecision(1);
    std::cout << "Metrics Valid: " << (metrics.valid ? "YES" : "NO") << "\n";
    std::cout << "CPU Usage:       " << metrics.cpu_usage_pct << "%\n";
    std::cout << "Memory Usage:    " << metrics.memory_usage_mb << " MB\n";
    std::cout << "Processes:       " << metrics.process_count << "\n";
    std::cout << "Runtime:         " << metrics.runtime_seconds << " s\n";
    std::cout << "----------------------------------------\n" << std::flush;
}

} // namespace axes
