#ifndef AXES_LAUNCHER_HPP
#define AXES_LAUNCHER_HPP

#include "cgroup.hpp"
#include "monitor.hpp"
#include <string>
#include <vector>
#include <memory>
#include <chrono>

namespace axes {

struct Config {
    std::string job_id;
    std::vector<std::string> command;
    std::string isolation{"resource"}; // Legacy trusted-workload mode; isolated requires Bubblewrap + seccomp.
    std::string workspace{"staging"};
    
    // Resource limits
    double initial_cpu_limit_pct{200.0};
    uint64_t memory_limit_mb{512};
    int64_t pids_limit{64};

    // Adaptive control parameters
    double cpu_threshold_pct{150.0};
    int consecutive_samples_required{3};
    double reduced_cpu_limit_pct{100.0};
    bool adaptive_enabled{true};

    // Monitoring options
    double sample_interval_sec{1.0};
    bool verbose_logging{true};
    std::string report_dir{"reports"};

    // Execution lifecycle & output capture options
    double timeout_sec{0.0};                      // Wall-clock timeout in seconds (0 = disabled)
    std::string output_file;                      // Output file path for child stdout/stderr
    uint64_t max_output_bytes{10 * 1024 * 1024};  // Maximum output bytes captured (default: 10MB)
};

struct ExecutionResult {
    std::string job_id;
    int exit_code{-1};
    bool terminated_by_signal{false};
    int signal_number{0};
    double total_runtime_sec{0.0};
    double peak_cpu_pct{0.0};
    double peak_memory_mb{0.0};
    int64_t peak_pids{0};
    bool cpu_adaptation_triggered{false};
    double initial_cpu_limit{200.0};
    double final_cpu_limit{200.0};
    std::string start_time_str;
    std::string end_time_str;

    // CGroup verification evidence fields
    bool cgroup_setup_failed{false};
    bool process_attached_verified{false};
    bool isolation_established{false};
    std::string isolation_evidence;
    std::string cgroup_path;
    std::string cpu_max_initial;
    std::string cpu_max_final;
    std::string memory_max_evidence;
    std::string memory_swap_max_evidence;
    std::string pids_max_evidence;

    std::vector<std::string> event_log;

    // Execution status & output metrics
    bool timed_out{false};
    bool cancelled{false};
    std::string final_status{"UNKNOWN"}; // "COMPLETED", "KILLED", "TIMED_OUT", "CANCELLED", "FAILED"
    std::string output_file;
    uint64_t output_bytes_captured{0};
    bool output_truncated{false};
};

class ExecutionLauncher {
public:
    explicit ExecutionLauncher(const Config& config);
    ~ExecutionLauncher() = default;

    ExecutionResult run();

private:
    Config config_;
    
    void log_event(ExecutionResult& result, double runtime_sec, const std::string& message);
    void write_execution_report(const ExecutionResult& result);
};

} // namespace axes

#endif // AXES_LAUNCHER_HPP
