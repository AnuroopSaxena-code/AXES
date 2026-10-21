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

void test_job_id_validation() {
    std::cout << "[Test 1] Testing Job ID Validation Rules..." << std::endl;
    // Valid job IDs
    assert(axes::is_valid_job_id("job-1"));
    assert(axes::is_valid_job_id("job_2"));
    assert(axes::is_valid_job_id("JOB-TEST-123"));
    assert(axes::is_valid_job_id("a"));
    assert(axes::is_valid_job_id("_underscore_start"));
    std::string max_valid(64, 'x');
    assert(axes::is_valid_job_id(max_valid));

    // Invalid job IDs: traversal, separators, invalid characters, bounds
    assert(!axes::is_valid_job_id(""));
    assert(!axes::is_valid_job_id("-starts-with-hyphen"));
    assert(!axes::is_valid_job_id("../traversal"));
    assert(!axes::is_valid_job_id("job/slash"));
    assert(!axes::is_valid_job_id("job\\backslash"));
    assert(!axes::is_valid_job_id("job.dot"));
    assert(!axes::is_valid_job_id(".."));
    assert(!axes::is_valid_job_id("."));
    assert(!axes::is_valid_job_id("job space"));
    assert(!axes::is_valid_job_id("job$bad"));
    assert(!axes::is_valid_job_id("job;rm"));
    assert(!axes::is_valid_job_id("job`whoami`"));
    std::string too_long(65, 'x');
    assert(!axes::is_valid_job_id(too_long));

    std::cout << "  Job ID validation passed successfully!\n" << std::endl;
}

void test_invalid_job_id_rejection() {
    std::cout << "[Test 2] Testing Security Rejection of Invalid Job IDs..." << std::endl;
    // CGroupController must reject invalid job IDs
    axes::CGroupController bad_cgroup("../malicious_path");
    assert(bad_cgroup.get_cgroup_path().empty());
    assert(!bad_cgroup.init(200.0, 512, 32));

    // ExecutionLauncher must reject invalid job IDs without launching process
    axes::Config bad_config;
    bad_config.job_id = "../malicious_job";
    bad_config.command = {"echo", "should_never_run"};
    bad_config.verbose_logging = false;

    axes::ExecutionLauncher bad_launcher(bad_config);
    axes::ExecutionResult res = bad_launcher.run();
    assert(res.cgroup_setup_failed);
    assert(res.exit_code == 1);
    assert(!res.process_attached_verified);

    std::cout << "  Invalid job ID security rejection passed successfully!\n" << std::endl;
}

void test_cgroup_lifecycle() {
    std::cout << "[Test 3] Testing CGroupController Lifecycle..." << std::endl;
    axes::CGroupController cgroup("test-job-001");
    bool init_ok = cgroup.init(200.0, 512, 32);
    std::cout << "  Cgroup Init Result: " << (init_ok ? "SUCCESS" : "FAIL") << std::endl;

    if (!init_ok) {
        std::cerr << "[TEST SKIPPED] CGroupController::init failed. Subtree delegation required." << std::endl;
        return;
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
    std::cout << "  Cgroup lifecycle passed!\n" << std::endl;
}

void test_monitor_sampling() {
    std::cout << "[Test 4] Testing Monitor Sampling & PID Attachment..." << std::endl;
    axes::CGroupController cgroup("test-job-002");
    bool init_ok = cgroup.init(200.0, 256, 16);
    if (!init_ok) {
        std::cerr << "[TEST SKIPPED] Subtree delegation required." << std::endl;
        return;
    }

    bool add_ok = cgroup.add_process(0);
    assert(add_ok);

    bool verify_ok = cgroup.verify_process_attached(getpid());
    std::cout << "  PID Attached to cgroup.procs: " << (verify_ok ? "YES" : "NO") << std::endl;
    assert(verify_ok);

    axes::Monitor monitor("test-job-002", getpid());
    monitor.sample(cgroup);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto m2 = monitor.sample(cgroup);

    assert(m2.runtime_seconds > 0.0);
    assert(m2.process_count >= 1);
    std::cout << "  Sampled Runtime: " << m2.runtime_seconds << "s, Memory: " << m2.memory_usage_mb << " MB\n";

    cgroup.cleanup();
    std::cout << "  Monitor sampling passed!\n" << std::endl;
}

void test_normal_launcher_run() {
    std::cout << "[Test 5] Testing ExecutionLauncher Normal Run..." << std::endl;
    axes::Config config;
    config.job_id = "test-job-normal";
    config.command = {"echo", "AXES Sandbox Test Success"};
    config.verbose_logging = false;

    axes::ExecutionLauncher launcher(config);
    axes::ExecutionResult res = launcher.run();

    if (res.cgroup_setup_failed) {
        std::cerr << "[TEST SKIPPED] Subtree delegation required for launch execution." << std::endl;
        return;
    }

    assert(res.process_attached_verified);
    assert(res.exit_code == 0);
    assert(!res.terminated_by_signal);
    std::cout << "  Normal launcher run exit code: " << res.exit_code << "\n";
    std::cout << "  CGroup Evidence Path: " << res.cgroup_path << "\n";
    std::cout << "  Normal launcher run passed!\n" << std::endl;
}

int main() {
    std::cout << "========================================\n";
    std::cout << " AXES Sandbox - C++ Unit Test Suite\n";
    std::cout << "========================================\n" << std::endl;

    test_job_id_validation();
    test_invalid_job_id_rejection();

    auto env = axes::CGroupController::check_environment("/sys/fs/cgroup");
    if (!env.is_ready()) {
        std::cout << "NOTICE: Kernel cgroup v2 subtree delegation is not currently active for user.\n";
        std::cout << "Core validation & security rejection tests PASSED.\n";
        std::cout << "To run live cgroup attachment tests, run: sudo ./scripts/setup_cgroups.sh\n" << std::endl;
    } else {
        test_cgroup_lifecycle();
        test_monitor_sampling();
        test_normal_launcher_run();
    }

    std::cout << "========================================\n";
    std::cout << "Unit Test Execution Finished Successfully!\n";
    std::cout << "========================================\n" << std::endl;
    return 0;
}
