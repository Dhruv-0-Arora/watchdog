# watchdog

A resident network anomaly detector for macOS and Linux.
It captures packet headers, learns what your normal traffic looks like online with a KitNET-style autoencoder ensemble, and tells you when something new or suspicious appears.

It is one small C++ binary with libpcap as its only dependency, holds flat memory for months, and has no interface beyond a one-line-per-source checkin.

Design documents: [PLAN.md](PLAN.md), [ARCHITECTURE.md](ARCHITECTURE.md), [ML-DESIGN.md](ML-DESIGN.md), [PHASES.md](PHASES.md), [docs/eval.md](docs/eval.md).

## Install (macOS)

```sh
cmake --preset release && cmake --build --preset release
./packaging/install-macos.sh
```

This installs two things: a boot-time root job that grants the `access_bpf` group access to `/dev/bpf*`, and a user agent that runs watchdog with **no elevated privileges at all**.
Group membership applies at your next login, so log out and back in once; until then the agent retries every 30 seconds and `watchdog top` reports no daemon.
The script is safe to re-run.

macOS keeps a small fixed set of `/dev/bpf*` devices and creates more on demand with root-only permissions, so if several capture tools are running at once watchdog may find none it can open.
Re-running `sudo /usr/local/libexec/watchdog-chmodbpf` re-applies the group to every device that exists.

## Install (Linux)

```sh
cmake --preset release && cmake --build --preset release
sudo install -m 0755 build/release/watchdog /usr/local/bin/watchdog
sudo useradd --system --no-create-home watchdog
sudo install -m 0644 packaging/linux/watchdog.service /etc/systemd/system/
sudo systemctl enable --now watchdog
sudo usermod -aG watchdog "$USER"        # so you may read its status socket
```

The unit grants only `CAP_NET_RAW` with `NoNewPrivileges`, so the daemon never runs as root.
Its status socket is owner-and-group only, which is why your account joins the `watchdog` group; that takes effect at your next login.
The system service keeps its state under `/var/lib/watchdog` and its socket at `/run/watchdog/watchdog.sock`, so point the client at it:

```sh
alias wtop='watchdog top --socket /run/watchdog/watchdog.sock'
```

## Using it

```sh
watchdog top            # what has happened since your last checkin, then mark it seen
watchdog top --peek     # same, without marking it seen
watchdog top --watch    # live view; 'a' acknowledges, 'q' quits
```

A checkin looks like this:

```
watchdog  detecting  up 6h12m  41.7M packets  0 drops  23 MB  9 fds

1 new incident from 1 host since your last checkin:
    48x 10.0.0.99 -> 10.0.1.5              200.0k pkts  2m14s ago  mac-ip+host+channel, new socket

first seen: 82 hosts, 3.2k channels   alert threshold 0.367
```

The multiplier is how far over the alert threshold the worst packet scored, and the trailing labels say which statistics looked wrong and whether the host, channel, or port had ever been seen before.
Every incident is also appended to `~/.local/state/watchdog/alerts.jsonl` (rotated, two files, so disk stays flat).

The daemon spends its first million packets learning and will not alert during that time; `watchdog top` says so while it happens.
That first window assumes your network is healthy, so run it somewhere you trust.

## Configuring

Settings live in `~/.config/watchdog/watchdog.conf`; see [packaging/watchdog.conf.example](packaging/watchdog.conf.example) for every key with its default.
Invalid values are reported with a line number and the daemon refuses to start rather than guessing.
Command line flags override the file, and `--config none` skips it.

If a quiet network still produces alerts you do not care about, raise `alert_factor`.

## Running it by hand

```sh
sudo watchdog run                 # drops back to your user once /dev/bpf is open
watchdog run en0 --grace 200000   # if you already have BPF access
watchdog replay capture.pcap      # same pipeline over a file; the test harness
```

## Build and test

Requires CMake >= 3.25, ninja, clang, and libpcap.

```sh
cmake --preset debug && cmake --build --preset debug && ctest --preset debug
```

Presets: `debug` (ASan + UBSan + allocation counting), `tsan`, `release` (`-O3 -flto`), `fuzz`, `tidy`.

## Status

All five phases of [PHASES.md](PHASES.md) are complete.
Measured on Apple Silicon: ~500k packets/s single-threaded, ~23 MB resident, flat across a billion packets, zero leaks.
Detection quality and the defects found while measuring it are documented in [docs/eval.md](docs/eval.md).
