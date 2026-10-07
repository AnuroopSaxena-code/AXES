#include "../src/cgroup.hpp"
#include "../src/monitor.hpp"
#include "../src/launcher.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include <filesystem>
#include <unistd.h>

namespace fs = std::filesystem;

void test_cgroup_lifecycle() {
    std::cout << "[Test 1] Testing CGroupController Lifecycle..." << std::endl;
    axes::CGroupController cgroup("test-job-001");
    bool init_ok = cgroup.init(200.0, 512, 32);
    std::cout << "  Cgroup Init Result: " << (init_ok ? "SUCCESS" : "FAIL") << std::endl;

    // STRICT TEST REQUIREMENT: Cgroup creation MUST succeed
    if (!init_ok) {
        std::cerr << "[TEST FAIL FATAL] CGroupController::init failed! Run 'sudo ./scripts/setup_cgroups.sh' first." << std::endl;
        exit(1);
    }

    assert(cgroup.is_initialized());
    assert(cgroup.get_current_cpu_limit() == 200.0);

    bool update_ok = cgroup.update_cpu_limit(100.0);
    std::cout << "  Dynamic CPU Limit Update: " << (update_ok ? "SUCCESS" : "FAIL") << std::endl;
    assert(update_ok);
    assert(cgroup.get_current_cpu_limit() == 100.0);

    uint64_t cpu_usec = 0;
    uint64_t mem_bytes = 0;
    int64_t pids = 0;
    bool stats_ok = cgroup.get_stats(cpu_usec, mem_bytes, pids);
    std::cout << "  Stats Query Result: " << (stats_ok ? "SUCCESS" : "FAIL") << std::endl;
    assert(stats_ok);

    cgroup.cleanup();
    assert(!cgroup.is_initialized());
    std::cout << "[Test 1] Passed!\n" << std::endl;
}

void test_monitor_sampling() {
    std::cout << "[Test 2] Testing Monitor Sampling & PID Attachment..." << std::endl;
    axes::CGroupController cgroup("test-job-002");
    bool init_ok = cgroup.init(200.0, 256, 16);
    assert(init_ok);

    bool add_ok = cgroup.add_process(0);
    assert(add_ok);

    bool verify_ok = cgroup.verify_process_attached(getpid());
    std::cout << "  PID Attached to cgroup.procs: " << (verify_ok ? "YES" : "NO") << std::endl;
    assert(verify_ok);

    axes::Monitor monitor("test-job-002", getpid());
    auto m1 = monitor.sample(cgroup);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto m2 = monitor.sample(cgroup);

    assert(m2.runtime_seconds > 0.0);
    assert(m2.process_count >= 1);
    std::cout << "  Sampled Runtime: " << m2.runtime_seconds << "s, Memory: " << m2.memory_usage_mb << " MB\n";

    cgroup.cleanup();
    std::cout << "[Test 2] Passed!\n" << std::endl;
}

void test_normal_launcher_run() {
    std::cout << "[Test 3] Testing ExecutionLauncher Normal Run..." << std::endl;
    axes::Config config;
    config.job_id = "test-job-normal";
    config.command = {"echo", "AXES Sandbox Test Success"};
    config.verbose_logging = false;

    axes::ExecutionLauncher launcher(config);
    axes::ExecutionResult res = launcher.run();

    assert(!res.cgroup_setup_failed);
    assert(res.process_attached_verified);
    assert(res.exit_code == 0);
    assert(!res.terminated_by_signal);
    std::cout << "  Normal launcher run exit code: " << res.exit_code << "\n";
    std::cout << "  CGroup Evidence Path: " << res.cgroup_path << "\n";
    std::cout << "[Test 3] Passed!\n" << std::endl;
}

int main() {
    std::cout << "========================================\n";
    std::cout << " AXES Sandbox - C++ Unit Test Suite\n";
    std::cout << "========================================\n" << std::endl;

    test_cgroup_lifecycle();
    test_monitor_sampling();
    test_normal_launcher_run();

    std::cout << "All C++ Unit Tests Passed Successfully!" << std::endl;
    return 0;
}
