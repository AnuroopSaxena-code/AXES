#!/usr/bin/env bash
set -euo pipefail
# Privileged provisioning only. Never launch workloads from this script.
CGROUP_ROOT=/sys/fs/cgroup
AXES_CGROUP_DIR="$CGROUP_ROOT/axes"
TARGET_USER="${TARGET_USER:-${SUDO_USER:-}}"
if [ "$EUID" -ne 0 ] || [ -z "$TARGET_USER" ] || [ "$(id -u "$TARGET_USER")" -eq 0 ]; then
    echo 'Use sudo TARGET_USER=<ordinary-user> ./scripts/setup_cgroups.sh; root must not be the workload user.' >&2
    exit 1
fi
TARGET_GROUP=$(id -gn "$TARGET_USER")
[ "$(stat -fc %T "$CGROUP_ROOT")" = cgroup2fs ] || { echo 'cgroups v2 required' >&2; exit 1; }
printf '+cpu +memory +pids\n' > "$CGROUP_ROOT/cgroup.subtree_control"
mkdir -p "$AXES_CGROUP_DIR"
printf '+cpu +memory +pids\n' > "$AXES_CGROUP_DIR/cgroup.subtree_control"
chown "$TARGET_USER:$TARGET_GROUP" "$AXES_CGROUP_DIR" "$AXES_CGROUP_DIR/cgroup.procs" "$AXES_CGROUP_DIR/cgroup.subtree_control" "$AXES_CGROUP_DIR/cgroup.threads"
chmod 0750 "$AXES_CGROUP_DIR"
# Migration requires write access on the common ancestor. Scope it to the
# operator's primary group; never make host cgroup.procs world-writable.
for migration in "$CGROUP_ROOT/cgroup.procs" "$CGROUP_ROOT/init.scope/cgroup.procs" "$CGROUP_ROOT/user.slice/cgroup.procs"; do
    if [ -f "$migration" ]; then
        chown "root:$TARGET_GROUP" "$migration"
        chmod 0620 "$migration"
    fi
done
printf 'Delegated %s to %s. Run AXES without sudo.\n' "$AXES_CGROUP_DIR" "$TARGET_USER"
