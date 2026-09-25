# Architecture

One daemon binary, one optional TUI client binary, one shared header-only core library.

```
                 daemon (watchdog run / replay)
┌─────────────────────────────────────────────────────────────┐
│ capture thread                processing thread             │
│ ┌───────────┐   SPSC ring    ┌─────────┐ ┌────────┐ ┌─────┐ │
│ │ libpcap   │──packet recs──▶│ decoder │▶│features│▶│model│ │
│ │ (BPF/AF_  │   (fixed size) └─────────┘ └────────┘ └──┬──┘ │
│ │  PACKET)  │                                          ▼    │
│ └───────────┘                              ┌───────────────┐│
│                                            │ alert sink +  ││
│                                            │ stats snapshot││
│                                            └───────┬───────┘│
└────────────────────────────────────────────────────┼────────┘
                       unix domain socket ───────────┘
                              │
                      ┌───────▼───────┐
                      │ watchdog top  │  (separate process, exits when done)
                      └───────────────┘
```

## Module layout

```
src/
  core/            header-only, no I/O, no platform code, fully unit-testable
    decode.hpp     L2/L3/L4 header parsing into PacketMeta
    stats.hpp      damped incremental statistics (see ML-DESIGN.md)
    table.hpp      fixed-slot open-addressing entity table with decay eviction
    features.hpp   PacketMeta -> feature vector
    quantile.hpp   P2 streaming quantile estimator for adaptive thresholds
    autoencoder.hpp  one tiny dense autoencoder over an external parameter arena
    mapper.hpp     correlation clustering of features into small groups
    model.hpp      feature mapper + autoencoder ensemble + threshold
    incident.hpp   folds repeated alerts into per-channel incidents
    ring.hpp       lock-free SPSC ring buffer
    config.hpp     settings text -> validated struct
    snapshot.hpp   the wire format shared by daemon and client
    format.hpp     address and label rendering
  platform/
    capture.hpp          Capture interface
    capture_pcap.cpp     live and pcap-file sources behind one handle
    ipc.cpp              unix socket snapshot server and client
    alert_log.cpp        JSONL incident log with size rotation
    checkpoint.cpp       atomic model file write
    privilege.cpp        drop root once the capture device is open
    resources.cpp        RSS and file-descriptor self-probes
    settings_file.cpp    read the config file
    paths.cpp            XDG-aware state, config, and socket locations
  app/
    daemon.cpp     argument parsing, config precedence, command dispatch
    pipeline.cpp   capture -> ring -> decode -> features -> model -> alerts
    tui.cpp        the checkin client
```

`core/` is the bulk of the value and compiles with zero dependencies, so every algorithm is testable and benchmarkable without touching the network.

## Data flow and threading

**Capture thread** owns the pcap handle exclusively.
Snaplen is 128 bytes: enough for Ethernet + IPv6 + TCP with options, and a hard privacy/perf cap on payload copying.
For each packet it writes a fixed-size record (timestamp, lengths, copied header bytes) into the SPSC ring and increments a drop counter if the ring is full.
Dropping under overload is deliberate: an anomaly detector that samples under load stays useful; one that buffers unboundedly violates the flat-memory guarantee.

**Processing thread** drains the ring in batches, decodes, extracts features, scores, trains, and emits alerts.
Batching amortizes cache misses on the entity tables and lets the thread sleep on an eventfd/kqueue-style wakeup when traffic is idle, so idle CPU cost is near zero.

**IPC** is served from the processing thread's event loop between batches (single-threaded accept + non-blocking writes), avoiding any locking of the stats structures.
The daemon publishes a versioned snapshot struct: counters, score distribution summary, ring of the last 256 alerts, and a monotonically increasing alert sequence number.
`watchdog top` stores the last acknowledged sequence number in `$XDG_STATE_HOME`, so "since last checkin" is computed client-side and the daemon stays stateless about viewers.

## Memory discipline (the top priority)

Rules, enforced by review and tooling:

1. All hot-path capacity is fixed at startup from config: ring slots, table slots, alert ring, feature buffers.
   The per-packet path - decode, feature extraction, scoring, training - performs no heap allocation at all.
   Rendering an incident into the JSONL log allocates a couple of short-lived strings, but that happens once per incident rather than per packet and every one is freed immediately.
   The invariant the soak asserts is therefore the one that actually matters for a daemon running for months: the *live* allocation count is constant once warm, verified by interposing the allocator in debug builds.
2. Entity state (per source, per channel, per socket) lives in open-addressing hash tables with a fixed slot count (default 65,536 per context, ~13 MB total).
   Eviction is by staleness: each lookup that collides may reclaim a slot whose decayed weight has fallen below epsilon, and an incremental scan retires a few stale slots per batch.
   Tables therefore never grow, never rehash, and old hosts fade out automatically.
3. RAII for every resource (pcap handles, fds, mmaps); no naked new/delete anywhere; ownership is `unique_ptr` or by-value.
4. The alert log on disk is JSONL with size-based rotation (default keep 2 x 8 MB), so disk usage is also flat.
5. No third-party code on the hot path; libpcap is the only link-time dependency and it is invoked only on the capture thread.

Verification is continuous, not one-time:

- Debug CI runs unit + replay tests under ASan + LSan + UBSan (both OSes) and TSan (ring buffer tests).
- Soak test: `watchdog replay <pcap> --loop N` reports RSS, file-descriptor count, and allocation counters every pass, so growth of any of the three is visible without external tooling.
  RSS comes from `mach_task_basic_info` on macOS and `/proc/self/statm` on Linux; the descriptor count from `proc_pidinfo` and `/proc/self/fd`.
  Both are also published in the status snapshot, so a live daemon can be checked the same way.
- macOS `leaks --atExit` and Linux valgrind run against the replay mode in CI on every merge.

## Platform layer

macOS first.

| Concern | macOS | Linux |
|---|---|---|
| Capture | libpcap over `/dev/bpf` | libpcap over `AF_PACKET` |
| Privilege | `access_bpf` group, granted by a boot-time root job | `CAP_NET_RAW` via the systemd unit |
| Idle wakeup | `std::atomic::wait` on a ring wake epoch | same |
| Service | launchd agent (runs as the user) | systemd unit (runs as `watchdog`) |
| RSS probe | `task_info` | `/proc/self/statm` |
| FD probe | `proc_pidinfo` into a fixed buffer | `/proc/self/fd` |

Idle wakeup needed no platform code: C++20's `atomic::wait` on the ring's wake epoch is portable and lets the processing thread sleep at zero cost when traffic stops, so the planned kqueue/epoll split was dropped.

The daemon opens the capture handle first and drops privileges immediately afterwards, before it touches any config or writes any file.
If it was started with `sudo` it returns to the invoking user (`SUDO_UID`), verifies that root cannot be regained, and refuses to continue if the drop fails.
The packaged installs avoid privileges altogether: on macOS a root job grants the `access_bpf` group access to `/dev/bpf*` at boot and the agent then runs entirely unprivileged, and on Linux the unit grants only `CAP_NET_RAW` with `NoNewPrivileges`.

## Configuration

Settings come from `~/.config/watchdog/watchdog.conf` (`XDG_CONFIG_HOME` honoured), and command line flags override the file.
Parsing lives in `core/config.hpp` as a pure text-to-struct function so it is unit-testable without touching a filesystem; only `platform/settings_file.cpp` reads the file.
Every value is range-checked, table sizes must be powers of two, and contradictory windows are rejected: the daemon reports each problem with its line number and refuses to start rather than silently substituting a default.

## Build and quality gates

- CMake + C++20, clang on both platforms; universal (arm64 + x86_64) build on macOS.
- `-Wall -Wextra -Wconversion -Werror`; clang-tidy and clang-format enforced in CI.
- CMake presets: `debug` (sanitizers), `release` (`-O3 -flto`), `bench`.
- Unit tests with doctest (single vendored header, test-only, keeps the zero-dependency property of shipped code).
- Benchmarks replay canonical pcaps and report packets/sec and ns/packet per pipeline stage, tracked over time so hot-path regressions fail CI.
