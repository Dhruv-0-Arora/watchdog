# Phases

Each phase ends with working, tested, sanitizer-clean software.
Memory verification is not a final phase; it is an exit criterion of every phase, because leak-freedom is the top priority and retrofitting it is how projects fail at it.

## Phase 0: Skeleton and quality rails

- CMake project, C++20, clang, presets for debug (ASan/LSan/UBSan), release (`-O3 -flto`), bench.
- clang-format, clang-tidy configs; `-Werror` on.
- doctest vendored; CI (GitHub Actions: macos-latest, ubuntu-latest) running tests under sanitizers.
- Debug-build allocation counter to later assert zero steady-state allocations.

**Exit**: `ctest` green under sanitizers on both platforms from a clean clone.

## Phase 1: Capture and decode

- SPSC ring (`ring.hpp`) with TSan-verified tests.
- `Capture` interface with libpcap live source and pcap-file replay source.
- `decode.hpp`: Ethernet, IPv4/IPv6, TCP/UDP/ICMP into `PacketMeta`; fuzz the decoder (libFuzzer) since it parses untrusted bytes.
- Daemon skeleton: capture thread -> ring -> processing thread that just counts; clean SIGINT/SIGTERM shutdown; drop counters.
- `watchdog replay` prints per-stage packets/sec and ns/packet.

**Exit**: replay of a 1 GB pcap is leak-clean (`leaks --atExit`, valgrind), decoder fuzzed for 1 h without findings, live capture works on macOS en0.

## Phase 2: Feature extraction

- `stats.hpp`: damped (w, LS, SS) tuples and damped covariance, lazily decayed; property tests against a naive reference implementation.
- `table.hpp`: fixed-slot open-addressing table with epsilon-decay eviction; tests prove bounded memory under adversarial key churn (millions of unique keys, zero growth).
- `features.hpp`: four contexts, five windows, ~100-dim vector; first-sight detection of new MAC/IP/port.

**Exit**: 24 h looped replay shows flat RSS and zero steady-state allocations; feature values match the reference implementation within float tolerance.

## Phase 3: Model

- `quantile.hpp` (P2 estimator), `model.hpp` (mapper, AE ensemble, output AE, thresholds) per ML-DESIGN.md.
- Gradient check against numerical differentiation in tests.
- Checkpoint save/load with atomic rename and version gate.
- Evaluate on Kitsune public datasets; record detection/FP numbers in `docs/eval.md`.

**Exit**: Mirai replay detected at paper-comparable FP rate; a quiet-day personal-traffic replay produces zero alerts after grace; throughput >= 200k packets/sec on Apple Silicon in release mode.

## Phase 4: Alerts, IPC, TUI

- Incident folding, JSONL alert log with rotation.
- Unix-socket stats snapshot served from the processing thread.
- `watchdog top`: single screen, plain ANSI (no ncurses): alerts since last checkin, new entities seen, traffic/drop counters, model state (grace/active, threshold, score p99); `a` acknowledges, `q` quits.

**Exit**: end-to-end: run the daemon, drive a port scan at it, see the incident in `watchdog top`, acknowledge it, confirm the ack persists across TUI restarts.
Verified against a replayed synthetic scan rather than a live `nmap` from a second host; the live capture path itself is exercised separately in phase 5's soak.

## Phase 5: Hardening and packaging

- Soak asserting flat RSS, no fd growth, and no allocation growth, measured from the daemon's own self-probes.
- Perf pass guided by benchmarks; SIMD only where measured.
- launchd agent + systemd unit, privilege-drop path, `README` covering BPF permissions on macOS and CAP_NET_RAW on Linux.
- Config file (capacities, windows, thresholds, interface) with validated defaults.

**Exit**: install via launchd on a Mac, run for three days, and the only interaction needed is `watchdog top`.

Done, with one caveat: the three-day wall-clock run has to happen on the user's own machine, so it is the one criterion this repository cannot self-certify.
What was verified instead is a replay soak over hundreds of millions of packets showing byte-identical RSS, a constant file-descriptor count, zero steady-state allocations, and bounded log growth through rotation.
The perf pass found one structural win (reusing the forward pass for backpropagation, 303k -> 500k packets/s) and no case for SIMD.

## Deferred ideas (explicitly out of scope for v1)

- Mini-batch k-means as a second-opinion detector.
- Per-process attribution (macOS NetworkExtension / Linux eBPF) - powerful but a large platform-permission project on its own.
- Alert push channels (notification center, webhook).
