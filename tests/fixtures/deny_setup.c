// Safe fault injector: prevents namespace or seccomp setup before execing AXES.
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    };
    if (!strcmp(argv[1], "namespace")) filter[1].k = SYS_unshare;
    else {
        // bwrap applies the filter through prctl. AXES' other prctl calls remain allowed.
        struct sock_filter sec[] = {
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_seccomp, 0, 1),
            BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_prctl, 0, 3),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, PR_SET_SECCOMP, 0, 1),
            BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
            BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog p = {8, sec};
        if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p)) return 3;
        execv(argv[2], argv+2); return 4;
    }
    struct sock_fprog p = {4, filter};
    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p)) return 3;
    execv(argv[2], argv+2); return 4;
}
