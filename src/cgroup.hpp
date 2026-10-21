#ifndef AXES_CGROUP_HPP
#define AXES_CGROUP_HPP

#include <string>
#include <cstdint>
#include <sys/types.h>

namespace axes {

struct EnvironmentCheckResult {
    bool cgroups_v2_mounted{false};
    bool cpu_controller_available{false};
    bool memory_controller_available{false};
    bool pids_controller_available{false};
    bool axes_dir_writable{false};
    std::string resolved_cgroup_root;
    std::string details;

    bool is_ready() const {
        return cgroups_v2_mounted && cpu_controller_available && 
               memory_controller_available && pids_controller_available && 
               axes_dir_writable;
    }
};

// Validates that job_id is 1-64 characters, starts with alphanumeric or '_',
// contains only [a-zA-Z0-9_-], and contains no directory separators or traversal characters.
bool is_valid_job_id(const std::string& job_id);

class CGroupController {
public:
    CGroupController(const std::string& job_id, 
                     const std::string& base_path = "/sys/fs/cgroup");
    ~CGroupController();

    // Disable copy
    CGroupController(const CGroupController&) = delete;
    CGroupController& operator=(const CGroupController&) = delete;

    // Enable move
    CGroupController(CGroupController&&) noexcept;
    CGroupController& operator=(CGroupController&&) noexcept;

    // Initialize cgroup directory and set initial resource limits
    // Returns false if cgroup creation or limit application fails.
    bool init(double cpu_limit_pct, uint64_t memory_limit_mb, int64_t pids_limit);

    // Add process PID to cgroup
    bool add_process(pid_t pid);

    // Verify if PID is present in cgroup.procs
    bool verify_process_attached(pid_t pid);

    // Dynamically update CPU quota limit (%)
    bool update_cpu_limit(double cpu_limit_pct);

    // Read current stats from cgroup files
    bool get_stats(uint64_t& cpu_usage_usec, uint64_t& memory_bytes, int64_t& pids_count);

    // Read raw file content for evidence inspection (e.g. cpu.max, memory.max, pids.max)
    std::string get_control_file(const std::string& filename);

    // Clean up cgroup directory
    void cleanup();

    // Environment diagnostic tool
    static EnvironmentCheckResult check_environment(const std::string& base_path = "/sys/fs/cgroup");

    // Getters
    const std::string& get_cgroup_path() const { return cgroup_path_; }
    const std::string& get_job_id() const { return job_id_; }
    bool is_initialized() const { return initialized_; }
    double get_current_cpu_limit() const { return current_cpu_limit_; }

private:
    std::string job_id_;
    std::string base_path_;
    std::string cgroup_path_;
    bool initialized_{false};
    double current_cpu_limit_{200.0};

    bool write_file(const std::string& rel_path, const std::string& content);
    bool read_file(const std::string& rel_path, std::string& content);
    void ensure_parent_controllers();
    static std::string resolve_writable_base_path(const std::string& default_base);
};

} // namespace axes

#endif // AXES_CGROUP_HPP
