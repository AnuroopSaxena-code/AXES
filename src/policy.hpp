#ifndef AXES_POLICY_HPP
#define AXES_POLICY_HPP
#include <algorithm>
#include <cmath>
namespace axes {
// Deliberately one-way hysteresis: once reduced, stay reduced until this job ends.
// Recovery is not inferred from throttled usage, which cannot reveal CPU demand.
class CpuPolicy {
public:
    CpuPolicy(double initial, double threshold, int required, double reduced)
        : threshold_(threshold), target_(std::min(initial, reduced)), required_(required) {}
    bool observe(double usage, bool valid) {
        if (latched_ || failed_) return false;
        if (!valid || !std::isfinite(usage) || usage < threshold_) { consecutive_ = 0; return false; }
        return ++consecutive_ >= required_;
    }
    void applied() { latched_ = true; }
    void failed() { failed_ = true; }
    double target() const { return target_; }
    int samples() const { return consecutive_; }
private:
    double threshold_, target_;
    int required_, consecutive_{0};
    bool latched_{false}, failed_{false};
};
}
#endif
