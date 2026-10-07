#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

int main() {
    printf("[process_stress] Starting process spawn workload (PID %d)...\n", getpid());
    int max_attempts = 100;
    int spawned_count = 0;
    pid_t pids[150];

    for (int i = 0; i < max_attempts; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            printf("[process_stress] Fork #%d failed! Error: %s (errno %d)\n", 
                   i + 1, strerror(errno), errno);
            printf("[process_stress] SUCCESS: PID / Process limit enforced by cgroup at %d active processes!\n", 
                   spawned_count + 1);
            break;
        } else if (pid == 0) {
            // Child process sleeps briefly then exits
            sleep(4);
            _exit(0);
        } else {
            pids[spawned_count++] = pid;
            printf("[process_stress] Spawned child process #%d (PID %d)\n", spawned_count, pid);
            usleep(100000); // 100ms pause
        }
    }

    printf("[process_stress] Waiting for %d spawned child processes to finish...\n", spawned_count);
    for (int i = 0; i < spawned_count; i++) {
        int status;
        waitpid(pids[i], &status, 0);
    }

    printf("[process_stress] Process stress workload completed.\n");
    return 0;
}
