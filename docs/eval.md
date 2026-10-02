# Detection Evaluation

Results for the model on synthetic scenarios.
All pcaps come from `tools/make_test_pcap.py` (deterministic, seed 7), 2M packets each, replayed with `--grace 1000000` on the release build (Apple Silicon).

## Scenarios

- **benign**: the standard mixed-traffic generator (TCP/UDP/IPv6/VLAN/ICMP/ARP, ~40 hosts, randomized ports and sizes).
- **scan**: same, but the last 400k packets interleave a TCP SYN port sweep (200k packets, ports 1-2000, from a never-before-seen host) 1:1 with normal traffic.
- **exfil**: same shape, but the attack is a sudden large one-sided upload (1454-byte packets) from a known host to a new server.

Reproduce with:

```sh
python3 tools/make_test_pcap.py build/test_traffic.pcap 2000000
python3 tools/make_test_pcap.py build/attack_scan.pcap 2000000 scan
python3 tools/make_test_pcap.py build/attack_exfil.pcap 2000000 exfil
./build/release/watchdog replay build/attack_scan.pcap --grace 1000000 --alerts build/alerts.jsonl
```

## Results (2026-07-29)

| Scenario | Attack packets | Alerting packets | Incidents | False positives |
|---|---|---|---|---|
| benign | 0 | 0 | 0 | 0 |
| benign, 10x looped (20M packets) | 0 | 0 | 0 | 0 |
| scan | 200,000 | 199,974 | 4, all the scanner | 0 |
| exfil | 200,000 | 204,243 | 5,588, all from the compromised host | 0 |

Incident folding is what makes this usable: the scan's 199,974 alerting packets become 4 log lines (cut at the 60 s incident cap), and `watchdog top` collapses those to a single line naming the scanner.
The exfil case opens many incidents because the compromised host's *other* conversations also deviate once its host-level statistics are distorted - every one of the 5,588 is attributable to `10.0.0.7`, and the TUI shows it as one row with a peer count.

Median benign score after grace: 0.009; alert threshold settles near 0.33; scan scores reach 17.5 and exfil 19.7, so attack/normal separation is roughly two orders of magnitude.

Throughput with the full pipeline (decode + features + model + alerting): ~500k packets/s single-threaded, against the phase exit criterion of 200k.
Checkpoint resume (`--model path`) skips the grace period and detects identically; the serialized model is ~10 KB.

## Lessons encoded in the model

Each of these was a real defect found by evaluation, not a hypothetical.

1. **Normalization clamping hides anomalies.**
   Clamping normalized features to [0,1] caps exactly the out-of-range extremes the ensemble needs to see. Execution now normalizes without clamping.
2. **Normalizer ranges freeze after grace.**
   If min/max keep adapting during detection, the first below-threshold attack packets stretch the ranges and the attack normalizes itself into invisibility within a few packets.
3. **The threshold needs a training gate below it.**
   Attack scores ramp gradually as the attacker's damped statistics accumulate. If every below-threshold score feeds the threshold quantile, the extreme quantile ratchets upward just ahead of the ramp and never fires.
4. **An extreme quantile needs priming.**
   The 1-1e-5 quantile estimated from its first ~10k samples sits near the sample maximum, which caused a spurious alert the moment thresholding activated. Alerts stay disabled until 50k detecting-phase scores have been observed.
5. **Gating the quantile as well as training makes the threshold ratchet *down*.**
   Found by the phase 4 soak, not by any single-pass run: over a 40x looped replay (79M packets) the false-positive rate climbed from 6 incidents per pass to a steady ~2,000, all at 1.1x severity.
   Excluding above-gate scores from the estimator truncates its sample, so it converges below the true quantile; because the truncation point is the estimate itself, the drift compounds until the threshold grazes normal traffic.
   Fixed by feeding gated scores to the estimator capped at its current top marker: tail *counts* stay honest, anomaly *magnitudes* stay out. The same 20M-packet benign soak now yields zero false positives.

This last one is the argument for soak-testing detection quality and not just memory: a single 2M-packet pass looked healthy at 4 false positives while the model was quietly drifting toward unusability.

## Performance

Measured on Apple Silicon in the release preset, replaying the 2M-packet benign capture.

| Stage | ns/packet |
|---|---|
| decode | 10 |
| features | ~450 |
| model | ~1,500 |

The single optimisation worth making was structural rather than instruction-level.
The detecting path used to run a full forward pass to produce the score and then a second one inside training; splitting the autoencoder into `forward` and `backprop` so the backward pass reuses the activations already computed cut model time from 2,680 to ~1,500 ns/packet and took end-to-end throughput from 303k to ~500k packets/s.
Results are unchanged: the benign and attack replays reproduce their thresholds, alerting-packet counts, and peak scores exactly.
No SIMD was written, because at 500k packets/s against a home network's few hundred packets/s there is nothing left worth optimising.

Incident segmentation is also now deterministic.
Expiry used to be evaluated once per ring batch, so thread scheduling could shift an incident boundary and the same capture could yield 404 or 405 incidents; it is now evaluated at each packet's timestamp (free when nothing is open) and the same capture always yields the same incidents.

## Resource stability

Release soak, `replay attack_scan.pcap --loop 400` with alerting and the status socket active, sampled from the daemon's own probes:

| Passes | Packets | RSS | Open fds |
|---|---|---|---|
| 1 | 2M | 23.5 MB | 6 |
| 50 | 100M | 23.6 MB | 6 |
| 100 | 200M | 23.7 MB | 6 |
| 150 | 300M | 23.7 MB | 6 |

RSS rises 0.2 MB during warmup as the entity tables fill and the log buffer is allocated, then holds flat.
The descriptor count never moves off six (stdio, the capture handle, the alert log, the status socket).
Disk stays bounded at 16 MB by rotation: one full 8 MB file plus the live one.

A matching debug soak with the allocator interposed shows the live allocation count reaching 40 and staying there from the fourth pass onward, and `leaks --atExit` reports zero leaks against the full stack (model checkpointing, alert log, and socket server all active).
The per-packet path allocates nothing; the handful of transient allocations per pass come from formatting an incident into JSON and from reopening the capture file each loop, and all are freed immediately.

The 72-hour wall-clock criterion in [PHASES.md](../PHASES.md) still needs a real installation to certify, since a replay soak cannot exercise clock drift, sleep/wake, or interface changes.

## Pending: Kitsune public datasets

The exit criterion also calls for replaying the Kitsune datasets (Mirai, SSDP flood, ARP MitM).
Those captures are multi-GB downloads behind Kaggle/Google Drive authentication, so they are not fetched automatically.
To run one: download `Mirai_pcap.pcap` from the Kitsune dataset mirror, then `./build/release/watchdog replay Mirai_pcap.pcap --grace 1000000 --scores mirai_scores.bin` (the Mirai capture's first ~1.2M packets are benign; the infection begins around packet 1.5M).
