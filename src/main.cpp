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
    
    // Auto-generate job ID if not explicitly specified
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    config.job_id = "job-" + std::to_string(now_ms % 10000);

    int i = 2;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "--job-id" && i + 1 < argc) {
            config.job_id = argv[++i];
        } else if (arg == "--cpu-limit" && i + 1 < argc) {
            config.initial_cpu_limit_pct = std::stod(argv[++i]);
        } else if (arg == "--memory-limit" && i + 1 < argc) {
            config.memory_limit_mb = std::stoull(argv[++i]);
        } else if (arg == "--pids-limit" && i + 1 < argc) {
            config.pids_limit = std::stoll(argv[++i]);
        } else if (arg == "--cpu-threshold" && i + 1 < argc) {
            config.cpu_threshold_pct = std::stod(argv[++i]);
        } else if (arg == "--consecutive" && i + 1 < argc) {
            config.consecutive_samples_required = std::stoi(argv[++i]);
        } else if (arg == "--reduced-cpu" && i + 1 < argc) {
            config.reduced_cpu_limit_pct = std::stod(argv[++i]);
        } else if (arg == "--sample-interval" && i + 1 < argc) {
            config.sample_interval_sec = std::stod(argv[++i]);
        } else if (arg == "--no-adaptive") {
            config.adaptive_enabled = false;
        } else if (arg.rfind("--", 0) == 0) {
            std::cerr << "[AXES Error] Unknown option: " << arg << "\n";
            return 1;
        } else {
            // Reached start of command and its arguments
            break;
        }
        i++;
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
