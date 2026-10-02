#!/bin/sh
# Install watchdog as a background agent on macOS.
#
# Two pieces are installed:
#   1. a boot-time root job that grants the access_bpf group access to /dev/bpf*
#   2. a user agent that runs watchdog itself with no elevated privileges
#
# Safe to re-run. Run from the repository root after building the release preset.
set -eu

binary=build/release/watchdog
prefix=/usr/local
packaging=packaging/macos
group=access_bpf
agent_label=org.watchdog.agent
chmodbpf_label=org.watchdog.chmodbpf

if [ ! -x "$binary" ]; then
    echo "build it first: cmake --preset release && cmake --build --preset release" >&2
    exit 1
fi

echo "installing binaries to $prefix (requires sudo)"
sudo install -d "$prefix/bin" "$prefix/libexec"
sudo install -m 0755 "$binary" "$prefix/bin/watchdog"
sudo install -m 0755 "$packaging/watchdog-chmodbpf" "$prefix/libexec/watchdog-chmodbpf"

# The group is created here rather than left to the boot job, because launchctl
# bootstrap returns before the job has run and the membership edit below would
# then race against it.
if dseditgroup -o read "$group" >/dev/null 2>&1; then
    echo "group $group already exists"
else
    echo "creating the $group group"
    sudo dseditgroup -o create "$group"
fi

echo "adding $USER to $group"
sudo dseditgroup -o edit -a "$USER" -t user "$group"

echo "installing the BPF permission job"
sudo install -m 0644 "$packaging/$chmodbpf_label.plist" \
    "/Library/LaunchDaemons/$chmodbpf_label.plist"
sudo launchctl bootout "system/$chmodbpf_label" 2>/dev/null || true
sudo launchctl bootstrap system "/Library/LaunchDaemons/$chmodbpf_label.plist"
sudo "$prefix/libexec/watchdog-chmodbpf"

if [ "$(stat -f '%Sg' /dev/bpf0)" != "$group" ]; then
    echo "error: /dev/bpf0 is still owned by $(stat -f '%Sg' /dev/bpf0), not $group" >&2
    exit 1
fi
echo "capture devices are readable by the $group group"

mkdir -p "$HOME/Library/LaunchAgents" "$HOME/.config/watchdog"
if [ ! -f "$HOME/.config/watchdog/watchdog.conf" ]; then
    cp packaging/watchdog.conf.example "$HOME/.config/watchdog/watchdog.conf"
    echo "wrote a starter config to ~/.config/watchdog/watchdog.conf"
fi

echo "installing the user agent"
sed "s#/usr/local/bin/watchdog#$prefix/bin/watchdog#" \
    "$packaging/$agent_label.plist" > "$HOME/Library/LaunchAgents/$agent_label.plist"
launchctl bootout "gui/$(id -u)/$agent_label" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$agent_label.plist"

echo
if id -Gn | tr ' ' '\n' | grep -qx "$group"; then
    echo "installed and running. Check on it with:  watchdog top"
else
    cat <<EOF
installed, but this login session predates your $group membership, so the agent
cannot open /dev/bpf yet and will retry every 30 seconds. Log out and back in to
finish, then check on it with:  watchdog top

To confirm without logging out:  sudo $prefix/bin/watchdog run
EOF
fi

cat <<EOF

To remove:
  launchctl bootout gui/\$(id -u)/$agent_label
  sudo launchctl bootout system/$chmodbpf_label
  sudo rm $prefix/bin/watchdog $prefix/libexec/watchdog-chmodbpf
  sudo rm /Library/LaunchDaemons/$chmodbpf_label.plist
  rm ~/Library/LaunchAgents/$agent_label.plist
EOF
