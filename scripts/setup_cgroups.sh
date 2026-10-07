#!/usr/bin/env bash
set -e

# Setup script to delegate cgroups v2 control for AXES sandbox

CGROUP_ROOT="/sys/fs/cgroup"
AXES_CGROUP_DIR="$CGROUP_ROOT/axes"
TARGET_USER="${SUDO_USER:-$USER}"

if [ "$EUID" -ne 0 ]; then
    echo "[setup_cgroups] Error: This script must be run with sudo to configure cgroup delegation."
    echo "Usage: sudo ./scripts/setup_cgroups.sh"
    exit 1
fi

echo "[setup_cgroups] Configuring cgroups v2 delegation for user: $TARGET_USER"

# 1. Enable controllers at root level
if [ -f "$CGROUP_ROOT/cgroup.subtree_control" ]; then
    echo "+cpu +memory +pids" > "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
fi

# 2. Create /sys/fs/cgroup/axes directory
mkdir -p "$AXES_CGROUP_DIR"

# 3. Enable controllers for subtrees under axes
if [ -f "$AXES_CGROUP_DIR/cgroup.subtree_control" ]; then
    echo "+cpu +memory +pids" > "$AXES_CGROUP_DIR/cgroup.subtree_control" 2>/dev/null || true
fi

# 4. Delegate ownership of /sys/fs/cgroup/axes to the target unprivileged user
chown -R "$TARGET_USER:$TARGET_USER" "$AXES_CGROUP_DIR"
chmod 775 "$AXES_CGROUP_DIR"

echo "[setup_cgroups] SUCCESS: $AXES_CGROUP_DIR delegated to user '$TARGET_USER'."
echo "[setup_cgroups] User '$TARGET_USER' can now run AXES without sudo!"
