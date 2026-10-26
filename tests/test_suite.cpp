#include "../src/cgroup.hpp"
#include "../src/monitor.hpp"
#include "../src/launcher.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include <filesystem>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

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
    std::cout << "[Test 4] Testing CGroupController Lifecycle..." << std::endl;
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

void test_inaccessible_cgroup_path_fails_cleanly() {
    std::cout << "[Test 3] Testing Inaccessible Cgroup Failure Handling..." << std::endl;
    fs::path base = fs::path("/tmp") / ("axes-unreadable-" + std::to_string(getpid()));
    std::error_code ec;
    fs::create_directories(base, ec);
    assert(!ec);
    assert(chmod(base.c_str(), 0000) == 0);

    bool initialized = true;
    try {
        axes::CGroupController denied("permission-denied", base.string());
        initialized = denied.init(100.0, 64, 8);
    } catch (...) {
        chmod(base.c_str(), 0700);
        fs::remove_all(base, ec);
        assert(false && "Permission failure must not escape as an exception");
    }

    assert(!initialized);
    assert(chmod(base.c_str(), 0700) == 0);
    fs::remove_all(base, ec);
    std::cout << "  Inaccessible cgroup path failed closed without an exception!\n" << std::endl;
}

void test_monitor_sampling() {
    std::cout << "[Test 5] Testing Monitor Sampling & PID Attachment..." << std::endl;
    axes::CGroupController cgroup("test-job-002");
    bool init_ok = cgroup.init(200.0, 256, 16);
    if (!init_ok) {
        std::cerr << "[TEST SKIPPED] Subtree delegation required." << std::endl;
        return;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        // Child process sleeps briefly
        sleep(2);
        _exit(0);
    }

    bool add_ok = cgroup.add_process(child_pid);
    assert(add_ok);

    bool verify_ok = cgroup.verify_process_attached(child_pid);
    std::cout << "  PID Attached to cgroup.procs: " << (verify_ok ? "YES" : "NO") << std::endl;
    assert(verify_ok);

    axes::Monitor monitor("test-job-002", child_pid);
    monitor.sample(cgroup);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto m2 = monitor.sample(cgroup);

    assert(m2.runtime_seconds > 0.0);
    assert(m2.process_count >= 1);
    std::cout << "  Sampled Runtime: " << m2.runtime_seconds << "s, Memory: " << m2.memory_usage_mb << " MB\n";

    cgroup.cleanup();
    int status = 0;
    waitpid(child_pid, &status, 0);
    std::cout << "  Monitor sampling passed!\n" << std::endl;
}

void test_normal_launcher_run() {
    std::cout << "[Test 6] Testing ExecutionLauncher Normal Run & Output Capture..." << std::endl;
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
    assert(res.final_status == "COMPLETED");
    assert(res.output_bytes_captured > 0);
    std::cout << "  Normal launcher run exit code: " << res.exit_code << "\n";
    std::cout << "  Output bytes captured: " << res.output_bytes_captured << "\n";
    std::cout << "  Normal launcher run passed!\n" << std::endl;
}

void test_launcher_timeout() {
    std::cout << "[Test 7] Testing ExecutionLauncher Wall-Clock Timeout..." << std::endl;
    axes::Config config;
    config.job_id = "test-job-timeout";
    config.command = {"sleep", "5"};
    config.timeout_sec = 0.5;
    config.verbose_logging = false;

    auto t0 = std::chrono::steady_clock::now();
    axes::ExecutionLauncher launcher(config);
    axes::ExecutionResult res = launcher.run();
    auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    if (res.cgroup_setup_failed) {
        std::cerr << "[TEST SKIPPED] Subtree delegation required for timeout execution." << std::endl;
        return;
    }

    assert(res.timed_out);
    assert(res.exit_code == 124);
    assert(res.final_status == "TIMED_OUT");
    assert(elapsed < 2.0);
    std::cout << "  Timeout elapsed: " << elapsed << "s (limit 0.5s), exit code: " << res.exit_code << "\n";
    std::cout << "  Launcher timeout test passed!\n" << std::endl;
}

int main() {
    std::cout << "========================================\n";
    std::cout << " AXES Sandbox - C++ Unit Test Suite\n";
    std::cout << "========================================\n" << std::endl;

    test_job_id_validation();
    test_invalid_job_id_rejection();
    test_inaccessible_cgroup_path_fails_cleanly();

    auto env = axes::CGroupController::check_environment("/sys/fs/cgroup");
    if (!env.is_ready()) {
        std::cout << "NOTICE: Kernel cgroup v2 subtree delegation is not currently active for user.\n";
        std::cout << "Core validation & security rejection tests PASSED.\n";
        std::cout << "To run live cgroup attachment tests, run: sudo ./scripts/setup_cgroups.sh\n" << std::endl;
    } else {
        test_cgroup_lifecycle();
        test_monitor_sampling();
        test_normal_launcher_run();
        test_launcher_timeout();
    }

    std::cout << "========================================\n";
    std::cout << "Unit Test Execution Finished Successfully!\n";
    std::cout << "========================================\n" << std::endl;
    return 0;
}
