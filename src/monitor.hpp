#ifndef AXES_MONITOR_HPP
#define AXES_MONITOR_HPP

#include "cgroup.hpp"
#include <chrono>
#include <vector>
#include <string>

namespace axes {

struct ProcessMetrics {
    double cpu_usage_pct{0.0};
    double memory_usage_mb{0.0};
    int64_t process_count{0};
    double runtime_seconds{0.0};
    std::chrono::system_clock::time_point timestamp;
};

class Monitor {
public:
    Monitor(const std::string& job_id, pid_t pid);

    // Take a snapshot measurement
    ProcessMetrics sample(CGroupController& cgroup);

    // Display formatted runtime snapshot to console
    void print_snapshot(const ProcessMetrics& metrics, const std::string& status_label = "RUNNING");

    // Getters
    const std::vector<ProcessMetrics>& get_history() const { return history_; }
    double get_start_time() const { return start_time_sec_; }
    
private:
    std::string job_id_;
    pid_t target_pid_;
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point last_sample_time_;
    uint64_t last_cpu_usec_{0};
    bool first_sample_{true};
    double start_time_sec_{0.0};

    std::vector<ProcessMetrics> history_;

    ProcessMetrics sample_fallback_proc(pid_t pid, double runtime_sec);
};

} // namespace axes

#endif // AXES_MONITOR_HPP
