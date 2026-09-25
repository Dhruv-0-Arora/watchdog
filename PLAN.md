# Watchdog: Plan Overview

A resident network anomaly detector for macOS (primary) and Linux.
It captures packet headers, learns what "normal" traffic looks like online, and alerts when something new or suspicious appears.
It is a single small C++ binary designed to run for months without growing.

## Documents

- [ARCHITECTURE.md](ARCHITECTURE.md) - processes, threads, data flow, memory strategy, platform layer.
- [ML-DESIGN.md](ML-DESIGN.md) - feature extraction, the online anomaly detection model, thresholds, continual learning.
- [PHASES.md](PHASES.md) - implementation phases with concrete exit criteria.

## Goals

1. Detect novel or suspicious network behavior on the local machine, unsupervised, with no labeled data and no cloud dependency.
2. Learn continuously so the model tracks slow drift in normal behavior.
3. Run indefinitely with flat memory: every data structure is fixed-capacity, allocated at startup, with decay-based eviction.
4. Stay cheap: target under 5% of one core at typical home/office traffic and under 50 MB resident memory.
5. Code quality that reads without comments: small components, single-purpose lines, no cleverness that needs explaining.

## Non-goals

- No deep packet inspection or payload analysis; headers only (snaplen-limited capture, which is also a privacy property).
- No signature database, threat intel feeds, or rule language.
- No GUI; the only interface is a thin TUI client showing "what happened since you last looked" plus a JSONL alert log.
- No Windows support.

## Key decisions (summary)

Full rationale lives in the linked documents.

- **Capture**: libpcap, the only external dependency.
  It is preinstalled on macOS, universally packaged on Linux, and wraps the fast native mechanisms (BPF on macOS, AF_PACKET on Linux).
- **ML**: a KitNET-style ensemble of tiny autoencoders over damped incremental statistics, implemented in-house as a header-only module (~1k lines).
  mlpack and Shark were rejected: both drag in large dependency trees (Armadillo, Boost) for matrix sizes here that are at most 10x10, and neither gives us allocation control.
  Everything the model needs is dense loops over small fixed arrays, which plain C++ does optimally.
- **Concurrency**: two threads in the daemon (capture, processing) joined by a fixed-size lock-free SPSC ring; the TUI is a separate short-lived client process.
- **Memory**: no heap allocation on the hot path after warmup; entity state lives in fixed-slot open-addressing tables where stale entries are reclaimed by time-decay eviction, never by growth.
- **Learning safety**: the model keeps training forever at a low rate, but never trains on packets it just flagged anomalous, so attacks cannot teach themselves into the baseline.

## Operating modes

- `watchdog run` - live capture daemon (requires BPF device access on macOS, CAP_NET_RAW on Linux).
- `watchdog replay <file.pcap>` - identical pipeline fed from a file; this is the test and benchmark harness, not a bolt-on.
- `watchdog top` - the TUI client; connects to the daemon over a unix socket, shows deltas since last checkin, and acknowledges them.
