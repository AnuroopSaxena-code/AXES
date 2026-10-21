#include "launcher.hpp"
#include "cgroup.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>

void print_help(const char* prog_name) {
    std::cout << "AXES: Adaptive eXecution Environment Sandbox (Initial Working Prototype)\n";
    std::cout << "Usage:\n";
    std::cout << "  " << prog_name << " run [options] <program> [args...]\n";
    std::cout << "  " << prog_name << " check\n\n";
    std::cout << "Commands:\n";
    std::cout << "  run                     Execute target program inside isolated sandbox\n";
    std::cout << "  check                   Verify Linux cgroups v2 environment & subtree permissions\n\n";
    std::cout << "Options for 'run':\n";
    std::cout << "  --job-id <id>           Unique identifier for execution job (default: job-XXX)\n";
    std::cout << "  --cpu-limit <pct>       Initial CPU limit percentage (default: 200%)\n";
    std::cout << "  --memory-limit <mb>     Memory limit in MB (default: 512 MB)\n";
    std::cout << "  --pids-limit <count>    Max number of processes (default: 64)\n";
    std::cout << "  --cpu-threshold <pct>   CPU % threshold to trigger adaptation (default: 150%)\n";
    std::cout << "  --consecutive <n>       Consecutive samples above threshold to adapt (default: 3)\n";
    std::cout << "  --reduced-cpu <pct>     CPU % limit after adaptation (default: 100%)\n";
    std::cout << "  --sample-interval <sec> Monitoring sampling interval in seconds (default: 1.0s)\n";
    std::cout << "  --no-adaptive           Disable adaptive CPU limit adjustments\n";
    std::cout << "  --help                  Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << prog_name << " check\n";
    std::cout << "  " << prog_name << " run python3 workloads/cpu_burn.py\n";
    std::cout << "  " << prog_name << " run --job-id job-001 --cpu-limit 200 --memory-limit 256 python3 workloads/memory_stress.py\n";
}

int do_check() {
    std::cout << "\n==================================================\n";
    std::cout << " AXES Sandbox - Environment & CGroup v2 Diagnostic\n";
    std::cout << "==================================================\n";

    auto check = axes::CGroupController::check_environment("/sys/fs/cgroup");

    std::cout << "1. Linux cgroups v2 mounted:   " << (check.cgroups_v2_mounted ? "[PASS]" : "[FAIL]") << "\n";
    std::cout << "2. CPU controller available:   " << (check.cpu_controller_available ? "[PASS]" : "[FAIL]") << "\n";
    std::cout << "3. Memory controller available:" << (check.memory_controller_available ? "[PASS]" : "[FAIL]") << "\n";
    std::cout << "4. PIDs controller available:  " << (check.pids_controller_available ? "[PASS]" : "[FAIL]") << "\n";
    std::cout << "5. AXES subtree writable:      " << (check.axes_dir_writable ? "[PASS]" : "[FAIL]") << "\n";
    std::cout << "   Resolved CGroup Root:      " << check.resolved_cgroup_root << "\n";

    if (!check.details.empty()) {
        std::cout << "   Details:                   " << check.details << "\n";
    }

    std::cout << "--------------------------------------------------\n";
    if (check.is_ready()) {
        std::cout << "RESULT: SYSTEM READY FOR CONTAINMENT EXECUTION [PASS]\n";
        std::cout << "==================================================\n\n";
        return 0;
    } else {
        std::cout << "RESULT: SYSTEM ENVIRONMENT INCOMPLETE OR NOT DELEGATED [FAIL]\n";
        std::cout << "Fix suggestion: Run 'sudo ./scripts/setup_cgroups.sh' to delegate cgroup permissions.\n";
        std::cout << "==================================================\n\n";
        return 1;
    }
}

#include <cmath>
#include <cstdlib>
#include <cerrno>
#include <cctype>
#include <unistd.h>

static bool safe_parse_double(const std::string& str, double& out, double min_val, double max_val, const std::string& opt_name) {
    if (str.empty()) {
        std::cerr << "[AXES Error] Option " << opt_name << " has empty value.\n";
        return false;
    }
    char* endptr = nullptr;
    errno = 0;
    double val = std::strtod(str.c_str(), &endptr);
    if (errno == ERANGE) {
        std::cerr << "[AXES Error] Value out of range for " << opt_name << ": '" << str << "'.\n";
        return false;
    }
    if (endptr == str.c_str() || *endptr != '\0') {
        std::cerr << "[AXES Error] Invalid numeric value for " << opt_name << ": '" << str << "'. Expected a valid number.\n";
        return false;
    }
    if (std::isnan(val) || std::isinf(val)) {
        std::cerr << "[AXES Error] Value for " << opt_name << " must be a finite number.\n";
        return false;
    }
    if (val < min_val || val > max_val) {
        std::cerr << "[AXES Error] Value for " << opt_name << " (" << val 
                  << ") is outside acceptable range [" << min_val << ", " << max_val << "].\n";
        return false;
    }
    out = val;
    return true;
}

static bool safe_parse_uint64(const std::string& str, uint64_t& out, uint64_t min_val, uint64_t max_val, const std::string& opt_name) {
    if (str.empty()) {
        std::cerr << "[AXES Error] Option " << opt_name << " has empty value.\n";
        return false;
    }
    for (char c : str) {
        if (c == '-') {
            std::cerr << "[AXES Error] Negative value not allowed for " << opt_name << ": '" << str << "'.\n";
            return false;
        }
    }
    char* endptr = nullptr;
    errno = 0;
    unsigned long long val = std::strtoull(str.c_str(), &endptr, 10);
    if (errno == ERANGE) {
        std::cerr << "[AXES Error] Value out of range for " << opt_name << ": '" << str << "'.\n";
        return false;
    }
    if (endptr == str.c_str() || *endptr != '\0') {
        std::cerr << "[AXES Error] Invalid integer value for " << opt_name << ": '" << str << "'. Expected an integer.\n";
        return false;
    }
    if (val < min_val || val > max_val) {
        std::cerr << "[AXES Error] Value for " << opt_name << " (" << val 
                  << ") is outside acceptable range [" << min_val << ", " << max_val << "].\n";
        return false;
    }
    out = static_cast<uint64_t>(val);
    return true;
}

static bool safe_parse_int64(const std::string& str, int64_t& out, int64_t min_val, int64_t max_val, const std::string& opt_name) {
    if (str.empty()) {
        std::cerr << "[AXES Error] Option " << opt_name << " has empty value.\n";
        return false;
    }
    char* endptr = nullptr;
    errno = 0;
    long long val = std::strtoll(str.c_str(), &endptr, 10);
    if (errno == ERANGE) {
        std::cerr << "[AXES Error] Value out of range for " << opt_name << ": '" << str << "'.\n";
        return false;
    }
    if (endptr == str.c_str() || *endptr != '\0') {
        std::cerr << "[AXES Error] Invalid integer value for " << opt_name << ": '" << str << "'. Expected an integer.\n";
        return false;
    }
    if (val < min_val || val > max_val) {
        std::cerr << "[AXES Error] Value for " << opt_name << " (" << val 
                  << ") is outside acceptable range [" << min_val << ", " << max_val << "].\n";
        return false;
    }
    out = static_cast<int64_t>(val);
    return true;
}

static bool safe_parse_int(const std::string& str, int& out, int min_val, int max_val, const std::string& opt_name) {
    int64_t val64 = 0;
    if (!safe_parse_int64(str, val64, min_val, max_val, opt_name)) {
        return false;
    }
    out = static_cast<int>(val64);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    std::string command_mode = argv[1];
    if (command_mode == "--help" || command_mode == "-h") {
        print_help(argv[0]);
        return 0;
    }

    if (command_mode == "check") {
        return do_check();
    }

    if (command_mode != "run") {
        std::cerr << "[AXES Error] Unknown command mode: " << command_mode << "\n";
        print_help(argv[0]);
        return 1;
    }

    axes::Config config;
    std::string explicit_job_id;

    int i = 2;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "--job-id") {
            if (i + 1 >= argc) {
                std::cerr << "[AXES Error] Option --job-id requires a value.\n";
                return 1;
            }
            std::string jid = argv[++i];
            if (!axes::is_valid_job_id(jid)) {
                std::cerr << "[AXES Error] Invalid job ID '" << jid 
                          << "'. Must be 1-64 characters matching [a-zA-Z0-9_-] and start with alphanumeric or underscore.\n";
                return 1;
            }
            explicit_job_id = jid;
        } else if (arg == "--cpu-limit") {
            if (i + 1 >= argc) {
                std::cerr << "[AXES Error] Option --cpu-limit requires a value.\n";
                return 1;
            }
            if (!safe_parse_double(argv[++i], config.initial_cpu_limit_pct, 1.0, 10000.0, "--cpu-limit")) {
                return 1;
            }
        } else if (arg == "--memory-limit") {
            if (i + 1 >= argc) {
                std::cerr << "[AXES Error] Option --memory-limit requires a value.\n";
                return 1;
            }
            if (!safe_parse_uint64(argv[++i], config.memory_limit_mb, 1, 1048576, "--memory-limit")) {
                return 1;
            }
        } else if (arg == "--pids-limit") {
            if (i + 1 >= argc) {
                std::cerr << "[AXES Error] Option --pids-limit requires a value.\n";
                return 1;
            }
            if (!safe_parse_int64(argv[++i], config.pids_limit, 1, 4194304, "--pids-limit")) {
                return 1;
            }
        } else if (arg == "--cpu-threshold") {
            if (i + 1 >= argc) {
                std::cerr << "[AXES Error] Option --cpu-threshold requires a value.\n";
                return 1;
            }
            if (!safe_parse_double(argv[++i], config.cpu_threshold_pct, 1.0, 10000.0, "--cpu-threshold")) {
                return 1;
            }
        } else if (arg == "--consecutive") {
            if (i + 1 >= argc) {
                std::cerr << "[AXES Error] Option --consecutive requires a value.\n";
                return 1;
            }
            if (!safe_parse_int(argv[++i], config.consecutive_samples_required, 1, 1000, "--consecutive")) {
                return 1;
            }
        } else if (arg == "--reduced-cpu") {
            if (i + 1 >= argc) {
                std::cerr << "[AXES Error] Option --reduced-cpu requires a value.\n";
                return 1;
            }
            if (!safe_parse_double(argv[++i], config.reduced_cpu_limit_pct, 1.0, 10000.0, "--reduced-cpu")) {
                return 1;
            }
        } else if (arg == "--sample-interval") {
            if (i + 1 >= argc) {
                std::cerr << "[AXES Error] Option --sample-interval requires a value.\n";
                return 1;
            }
            if (!safe_parse_double(argv[++i], config.sample_interval_sec, 0.05, 3600.0, "--sample-interval")) {
                return 1;
            }
        } else if (arg == "--no-adaptive") {
            config.adaptive_enabled = false;
        } else if (arg.rfind("--", 0) == 0 || (arg.rfind("-", 0) == 0 && arg.length() > 1 && !std::isdigit(static_cast<unsigned char>(arg[1])))) {
            std::cerr << "[AXES Error] Unknown option: " << arg << "\n";
            print_help(argv[0]);
            return 1;
        } else {
            // Reached start of command and its arguments
            break;
        }
        i++;
    }

    if (!explicit_job_id.empty()) {
        config.job_id = explicit_job_id;
    } else {
        auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        config.job_id = "job-" + std::to_string(now_us % 1000000) + "-" + std::to_string(getpid());
    }

    while (i < argc) {
        config.command.push_back(argv[i++]);
    }

    if (config.command.empty()) {
        std::cerr << "[AXES Error] No command specified to run.\n";
        print_help(argv[0]);
        return 1;
    }

    axes::ExecutionLauncher launcher(config);
    axes::ExecutionResult result = launcher.run();

    if (result.cgroup_setup_failed) {
        return 1;
    }

    return (result.exit_code >= 0 && result.exit_code != 127) ? result.exit_code : 1;
}
