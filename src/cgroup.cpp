#include "cgroup.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <cmath>
#include <cstring>
#include <vector>
#include <cctype>
#include <csignal>
#include <thread>
#include <chrono>

namespace axes {

bool is_valid_job_id(const std::string& job_id) {
    if (job_id.empty() || job_id.length() > 64) {
        return false;
    }
    // Must begin with an alphanumeric character or underscore
    char first = job_id[0];
    if (!std::isalnum(static_cast<unsigned char>(first)) && first != '_') {
        return false;
    }
    for (char c : job_id) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
            return false;
        }
    }
    return true;
}

namespace fs = std::filesystem;

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

std::string CGroupController::resolve_writable_base_path(const std::string& default_base) {
    // 1. Check primary path /sys/fs/cgroup/axes
    fs::path primary_axes = fs::path(default_base) / "axes";
    std::error_code ec;
    
    if (!fs::exists(primary_axes)) {
        fs::create_directories(primary_axes, ec);
    }
    
    if (access(primary_axes.c_str(), W_OK | X_OK) == 0) {
        return primary_axes.string();
    }

    // 2. Check user slice path if unprivileged and primary failed
    uid_t uid = getuid();
    if (uid != 0) {
        std::string proc_cgroup;
        std::ifstream ifs("/proc/self/cgroup");
        if (ifs.is_open() && std::getline(ifs, proc_cgroup)) {
            // Format: 0::<path>
            size_t pos = proc_cgroup.find("::");
            if (pos != std::string::npos) {
                std::string user_rel = proc_cgroup.substr(pos + 2);
                fs::path user_cgroup = fs::path(default_base) / (user_rel.empty() ? "." : user_rel.substr(1)) / "axes";
                fs::create_directories(user_cgroup, ec);
                if (access(user_cgroup.c_str(), W_OK | X_OK) == 0) {
                    return user_cgroup.string();
                }
            }
        }
    }

    return primary_axes.string();
}

CGroupController::CGroupController(const std::string& job_id, const std::string& base_path)
    : job_id_(job_id), base_path_(base_path) {
    if (!is_valid_job_id(job_id_)) {
        cgroup_path_ = "";
        return;
    }
    std::string writable_axes = resolve_writable_base_path(base_path_);
    cgroup_path_ = (fs::path(writable_axes) / job_id_).string();
}

CGroupController::~CGroupController() {
    if (initialized_) {
        cleanup();
    }
}

CGroupController::CGroupController(CGroupController&& other) noexcept
    : job_id_(std::move(other.job_id_)),
      base_path_(std::move(other.base_path_)),
      cgroup_path_(std::move(other.cgroup_path_)),
      initialized_(other.initialized_),
      current_cpu_limit_(other.current_cpu_limit_) {
    other.initialized_ = false;
}

CGroupController& CGroupController::operator=(CGroupController&& other) noexcept {
    if (this != &other) {
        if (initialized_) {
            cleanup();
        }
        job_id_ = std::move(other.job_id_);
        base_path_ = std::move(other.base_path_);
        cgroup_path_ = std::move(other.cgroup_path_);
        initialized_ = other.initialized_;
        current_cpu_limit_ = other.current_cpu_limit_;
        other.initialized_ = false;
    }
    return *this;
}

void CGroupController::ensure_parent_controllers() {
    fs::path parent_dir = fs::path(cgroup_path_).parent_path();
    std::error_code ec;
    fs::create_directories(parent_dir, ec);

    // 1. Enable controllers at root level /sys/fs/cgroup/cgroup.subtree_control
    fs::path root_subtree = fs::path(base_path_) / "cgroup.subtree_control";
    if (fs::exists(root_subtree)) {
        std::ofstream ofs(root_subtree);
        if (ofs.is_open()) {
            ofs << "+cpu +memory +pids" << std::endl;
            ofs.flush();
        }
    }

    // 2. Enable controllers in parent directory (e.g. /sys/fs/cgroup/axes/cgroup.subtree_control)
    fs::path parent_subtree = parent_dir / "cgroup.subtree_control";
    if (fs::exists(parent_subtree)) {
        std::ofstream ofs(parent_subtree);
        if (ofs.is_open()) {
            ofs << "+cpu +memory +pids" << std::endl;
            ofs.flush();
        }
    }
}

bool CGroupController::init(double cpu_limit_pct, uint64_t memory_limit_mb, int64_t pids_limit) {
    if (!is_valid_job_id(job_id_) || cgroup_path_.empty()) {
        std::cerr << "[CGroup FATAL] Invalid job ID '" << job_id_ 
                  << "'. Must be 1-64 characters matching [a-zA-Z0-9_-] and start with alphanumeric or underscore." << std::endl;
        return false;
    }

    // Check for collision with an actively running job
    if (fs::exists(cgroup_path_)) {
        std::string existing_procs;
        if (read_file("cgroup.procs", existing_procs)) {
            std::istringstream iss(existing_procs);
            pid_t existing_pid;
            if (iss >> existing_pid) {
                std::cerr << "[CGroup FATAL] Cgroup path '" << cgroup_path_ 
                          << "' already exists and contains active processes. Collision with job ID '" 
                          << job_id_ << "'!" << std::endl;
                return false;
            }
        }
    }

    ensure_parent_controllers();

    std::error_code ec;
    fs::create_directories(cgroup_path_, ec);
    if (ec) {
        std::cerr << "[CGroup FATAL] Failed to create cgroup directory '" << cgroup_path_ 
                  << "': " << ec.message() << std::endl;
        std::cerr << "[CGroup FATAL] Reason: Permission denied or missing cgroup delegation. Run 'sudo ./scripts/setup_cgroups.sh' first!" << std::endl;
        return false;
    }

    current_cpu_limit_ = cpu_limit_pct;

    // Set CPU Limit
    if (!update_cpu_limit(cpu_limit_pct)) {
        std::cerr << "[CGroup FATAL] Failed to write initial CPU limit (cpu.max) to " << cgroup_path_ << std::endl;
        cleanup();
        return false;
    }

    // Set Memory Limit (in bytes)
    uint64_t memory_bytes = memory_limit_mb * 1024 * 1024;
    if (!write_file("memory.max", std::to_string(memory_bytes))) {
        std::cerr << "[CGroup FATAL] Failed to write memory limit (memory.max) to " << cgroup_path_ << std::endl;
        cleanup();
        return false;
    }
    // Disable swap to enforce strict memory ceiling
    write_file("memory.swap.max", "0");

    // Set PIDs Limit
    std::string pids_str = (pids_limit > 0) ? std::to_string(pids_limit) : "max";
    if (!write_file("pids.max", pids_str)) {
        std::cerr << "[CGroup FATAL] Failed to write process limit (pids.max) to " << cgroup_path_ << std::endl;
        cleanup();
        return false;
    }

    initialized_ = true;
    return true;
}

bool CGroupController::add_process(pid_t pid) {
    if (!initialized_ || !fs::exists(cgroup_path_)) {
        std::cerr << "[CGroup FATAL] Cannot attach PID " << pid << ": Cgroup directory does not exist: " << cgroup_path_ << std::endl;
        return false;
    }
    std::string p_str = (pid == 0) ? "0" : std::to_string(pid);
    if (!write_file("cgroup.procs", p_str)) {
        std::cerr << "[CGroup FATAL] Failed to write PID " << p_str << " to " << cgroup_path_ << "/cgroup.procs" << std::endl;
        return false;
    }
    return true;
}

bool CGroupController::verify_process_attached(pid_t pid) {
    std::string content;
    if (!read_file("cgroup.procs", content)) return false;
    std::istringstream iss(content);
    pid_t p;
    while (iss >> p) {
        if (p == pid) return true;
    }
    return false;
}

bool CGroupController::update_cpu_limit(double cpu_limit_pct) {
    if (cpu_limit_pct <= 0) return false;

    // Period is 100ms (100,000 us)
    const uint64_t period_usec = 100000;
    uint64_t quota_usec = static_cast<uint64_t>(std::round((cpu_limit_pct / 100.0) * period_usec));
    
    std::string val = std::to_string(quota_usec) + " " + std::to_string(period_usec);
    if (write_file("cpu.max", val)) {
        current_cpu_limit_ = cpu_limit_pct;
        return true;
    }
    return false;
}

bool CGroupController::get_stats(uint64_t& cpu_usage_usec, uint64_t& memory_bytes, int64_t& pids_count) {
    cpu_usage_usec = 0;
    memory_bytes = 0;
    pids_count = 0;

    if (!initialized_) return false;

    // Read CPU usage from cpu.stat
    std::string cpu_stat_content;
    if (read_file("cpu.stat", cpu_stat_content)) {
        std::istringstream iss(cpu_stat_content);
        std::string key;
        uint64_t val;
        while (iss >> key >> val) {
            if (key == "usage_usec") {
                cpu_usage_usec = val;
                break;
            }
        }
    }

    // Read Memory usage from memory.current
    std::string mem_content;
    if (read_file("memory.current", mem_content)) {
        try {
            memory_bytes = std::stoull(mem_content);
        } catch (...) {
            memory_bytes = 0;
        }
    }

    // Read Process count from pids.current
    std::string pids_content;
    if (read_file("pids.current", pids_content)) {
        try {
            pids_count = std::stoll(pids_content);
        } catch (...) {
            pids_count = 0;
        }
    }

    return true;
}

std::string CGroupController::get_control_file(const std::string& filename) {
    std::string content;
    read_file(filename, content);
    // Trim trailing newlines
    while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) {
        content.pop_back();
    }
    return content;
}

void CGroupController::cleanup() {
    if (!initialized_ || cgroup_path_.empty()) return;

    if (fs::exists(cgroup_path_)) {
        // 1. Attempt atomic cgroup.kill (Linux kernel >= 5.14)
        fs::path kill_path = fs::path(cgroup_path_) / "cgroup.kill";
        if (fs::exists(kill_path)) {
            std::ofstream kfs(kill_path);
            if (kfs.is_open()) {
                kfs << "1" << std::endl;
                kfs.flush();
            }
        }

        // 2. Fallback / guarantee: read cgroup.procs and send SIGKILL to all active PIDs
        // Never migrate surviving untrusted descendants into an unrestricted parent!
        for (int attempt = 0; attempt < 5; ++attempt) {
            std::string procs_content;
            std::vector<pid_t> pids_to_kill;
            if (read_file("cgroup.procs", procs_content)) {
                std::istringstream iss(procs_content);
                pid_t p;
                while (iss >> p) {
                    if (p > 1) { // Safety: never signal PID 0 or PID 1
                        pids_to_kill.push_back(p);
                    }
                }
            }

            if (pids_to_kill.empty()) {
                break;
            }

            for (pid_t p : pids_to_kill) {
                kill(p, SIGKILL);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        // 3. Remove the cgroup directory with retries to allow kernel cleanup
        for (int rmdir_attempt = 0; rmdir_attempt < 5; ++rmdir_attempt) {
            if (rmdir(cgroup_path_.c_str()) == 0) {
                break;
            }
            if (errno == ENOENT) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    initialized_ = false;
}

EnvironmentCheckResult CGroupController::check_environment(const std::string& base_path) {
    EnvironmentCheckResult res;
    
    // 1. Check filesystem type
    struct statfs sfs;
    if (statfs(base_path.c_str(), &sfs) == 0) {
        if (sfs.f_type == CGROUP2_SUPER_MAGIC) {
            res.cgroups_v2_mounted = true;
        }
    }

    // 2. Check available controllers from cgroup.controllers
    fs::path controllers_path = fs::path(base_path) / "cgroup.controllers";
    std::ifstream c_ifs(controllers_path);
    if (c_ifs.is_open()) {
        std::string line;
        std::getline(c_ifs, line);
        if (line.find("cpu") != std::string::npos) res.cpu_controller_available = true;
        if (line.find("memory") != std::string::npos) res.memory_controller_available = true;
        if (line.find("pids") != std::string::npos) res.pids_controller_available = true;
    }

    // 3. Resolve writable cgroup root and test directory creation
    std::string writable_base = resolve_writable_base_path(base_path);
    res.resolved_cgroup_root = writable_base;

    fs::path test_dir = fs::path(writable_base) / "axes_check_tmp";
    std::error_code ec;
    fs::create_directories(test_dir, ec);
    if (!ec && fs::exists(test_dir)) {
        // Test writability via access() on the created cgroup directory
        if (access(test_dir.c_str(), W_OK | X_OK) == 0) {
            res.axes_dir_writable = true;
        } else {
            res.details = "Write access check failed on '" + test_dir.string() + "'";
        }
        fs::remove(test_dir, ec);
    } else {
        res.details = "Directory creation failed at '" + writable_base + "': " + ec.message();
    }

    return res;
}

bool CGroupController::write_file(const std::string& rel_path, const std::string& content) {
    fs::path full_path = fs::path(cgroup_path_) / rel_path;
    std::ofstream ofs(full_path);
    if (!ofs.is_open()) {
        return false;
    }
    ofs << content << std::endl;
    ofs.flush();
    return ofs.good();
}

bool CGroupController::read_file(const std::string& rel_path, std::string& content) {
    fs::path full_path = fs::path(cgroup_path_) / rel_path;
    std::ifstream ifs(full_path);
    if (!ifs.is_open()) {
        return false;
    }
    std::ostringstream ss;
    ss << ifs.rdbuf();
    content = ss.str();
    return true;
}

} // namespace axes
