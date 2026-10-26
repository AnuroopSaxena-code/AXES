#ifndef AXES_SECURITY_HPP
#define AXES_SECURITY_HPP
#include <string>
#include <vector>
namespace axes {
// This trusted setup runs only after cgroup attachment; it never falls back to exec.
[[noreturn]] void exec_isolated(const std::vector<std::string>& command, const std::string& workspace,
                                int info_fd);
}
#endif
