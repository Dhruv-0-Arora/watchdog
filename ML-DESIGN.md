# ML Design

The model is a KitNET-style online anomaly detector: an ensemble of tiny autoencoders over damped incremental traffic statistics.
KitNET (from the Kitsune NDSS 2018 paper) is an algorithm, not a library, and the reference implementation is Python.
We implement it as a header-only C++ module because the math is only dense loops over arrays of at most ~10x10, where hand-written code with fixed allocation beats any general-purpose library and carries zero dependencies.

Why this algorithm fits the requirements:

- Unsupervised: it learns "normal" from live traffic with no labels.
- Online: every packet both scores and (optionally) trains; there is no batch retraining, so it is "constantly learning" by construction.
- Tiny: total parameter count is a few thousand floats; inference plus training is a few microseconds per packet.
- Interpretable enough: the per-autoencoder reconstruction errors identify *which feature group* is anomalous, which makes alerts actionable.

Mini-batch k-means was considered as the detector and rejected as primary: it models cluster membership rather than reconstruction, handles correlated features poorly at this dimensionality, and offers weaker novelty scores.
It remains a candidate for a later, optional second opinion signal.

## Stage 1: Features (damped incremental statistics)

For each packet we update exponentially decayed statistics in four contexts, then read them back as the feature vector:

| Context | Key | Captures |
|---|---|---|
| Source | src IP | how much/how fast this host talks |
| Channel | src IP -> dst IP | the relationship between two hosts |
| Socket | src IP:port -> dst IP:port | the specific conversation |
| Jitter | src IP -> dst IP inter-arrival times | timing regularity |

Each context maintains, per key and per decay window, the damped tuple (weight w, linear sum LS, squared sum SS), from which mean, variance, and magnitude are read in O(1).
Channel contexts additionally maintain damped covariance between the two directions, yielding correlation and covariance features that expose one-sided behavior like scanning and exfiltration.
Decay uses five half-life windows (100 ms, 500 ms, 1.5 s, 10 s, 60 s), so the vector sees both bursts and slow drifts.
Decay is applied lazily at touch time from the stored last-update timestamp, so idle keys cost nothing.

This yields a fixed-length vector of ~100 floats per packet.
All state lives in the fixed-slot tables from ARCHITECTURE.md; a key whose weight decays below epsilon is reclaimable, which is what keeps memory flat forever.

New-entity signals are surfaced directly alongside the model: first-ever sight of a source MAC, source IP, or listening port is itself alert-worthy ("something new is appearing") and costs only a presence check in the tables.

## Stage 2: Feature mapper

During the grace period the mapper learns an incremental correlation distance between features and clusters the ~100 dimensions into small groups, each group capped at m = 10 features.
Implementation: maintain incremental sums to compute pairwise correlation, then single-linkage agglomerative clustering on 100x100 distances, run once at the end of the grace period (a one-off millisecond-scale computation, not hot path).
The mapping is then frozen; regrouping while autoencoders are training would invalidate their learned weights.

## Stage 3: Autoencoder ensemble

- One autoencoder per feature group: input d <= 10, one hidden layer of ceil(0.75 d), sigmoid activations, untied weights.
- Inputs are min-max normalized with per-feature running min/max, learned during grace and frozen afterwards.
- Normalization does not clamp: out-of-range values during detection are exactly the anomaly signal the ensemble must see, and frozen ranges prevent below-threshold attack traffic from stretching normalization until the attack looks normal.
- Each AE reports RMSE reconstruction error for its group.
- An output autoencoder takes the vector of normalized ensemble RMSEs and produces the final anomaly score (its own RMSE).
- Training is plain SGD, one sample at a time, learning rate decaying to a floor (never zero, so learning is continual).

All weights live in one contiguous, startup-allocated float arena; layer views are spans into it.
Loops are written flat over `float*` with sizes known at construction, which the compiler auto-vectorizes; explicit SIMD intrinsics only if benchmarks prove the need.

## Lifecycle: grace period, thresholding, alerts

1. **Grace period** (default: first 1M packets or 15 minutes, whichever is later): learn feature mapper, then train the ensemble; no alerts.
   The user is warned once that alerts assume the network was healthy during this window.
2. **Scoring**: after grace, every packet produces a score s.
   Scores are heavy-tailed, so the threshold is adaptive: log(s) feeds a P2 streaming quantile estimator, and the alert threshold is quantile(1 - 1e-3) times a configurable factor.
   The quantile is fed only from detecting-phase scores (training-phase scores carry the early convergence transient), and alerting stays disabled until it has seen 50k samples.
   The quantile is 1-in-1000, not the 1-in-100,000 this document originally specified.
   A five-marker P2 sketch cannot resolve a quantile that extreme: markers 2, 3 and 4 all want to sit at position n, they move at most one rank per observation, and they only move when a gap opens below the marker above them.
   The estimate then reports the order the first handful of samples arrived in rather than any property of the distribution.
   Replaying one real capture and varying only the grace length moved the resulting threshold across eight orders of magnitude, from 0.47 to 7.7e7.
   Resolving a tighter quantile needs a different sketch, not a different parameter.

   Normalization is also bounded, at ten times outside the learned range, which contradicts the "does not clamp" note in stage 3 above and supersedes it.
   Out-of-range readings are still unmistakably out of range at 10x, but unbounded ones are not: an unclamped score reached 1.4e7 in replay, and a log-score distribution spanning eight decades leaves the quantile sketch nothing meaningful to estimate.
3. **Alerting**: a threshold crossing opens an *incident* keyed by the offending context key; further crossings for the same key within a cooldown fold into that incident with an updated count.
   This turns a 10k-packet port scan into one alert, not 10k.
   Each alert records: timestamp, severity (score ratio over threshold), context key (who -> whom), top contributing feature groups, and packet counters.
4. **Continual learning with poisoning resistance**: packets whose score exceeds the *training gate* (the alert threshold, times a factor of at least one) are scored but not trained on.
   The gate must not sit below the alert threshold.
   A lower gate opens a band of traffic that neither alerts nor teaches the model anything, and that band is where the detector deadlocks: once it covers ordinary traffic the model stops learning, untrained scores stay high, high scores are all fed to the sketch capped, and capping pins the maximum marker so the threshold can never climb back out.
   The first deployment ran this way for 375 hours, alerting on 61% of every packet with a threshold frozen to seven identical digits throughout.
   This gray zone matters: attack scores ramp gradually as the attacker's damped statistics accumulate, and without the gate the extreme quantile ratchets upward just ahead of the ramp and never fires.
   Normal drift is absorbed; a sustained attack cannot gradually teach itself into the baseline.
5. **Gated packets still count as tail mass.** A gated score is fed to the quantile estimator *capped at the estimator's current maximum marker* rather than dropped.
   Dropping them entirely truncates the sample the estimator sees, so it converges to the extreme quantile of the truncated distribution, which is lower - and since the truncation point is itself the estimate, the threshold ratchets downward until it grazes normal traffic and emits a permanent trickle of false positives.
   Capping keeps the count of tail observations honest (no downward drift) while ensuring an anomaly's *magnitude* can never widen the scale and pull the threshold up to meet it.

## Persistence

Model state (mapper, weights, normalizers, quantile sketch) is checkpointed atomically (write temp, fsync, rename) every N minutes and on clean shutdown, so a restart resumes without a new grace period.
The checkpoint is versioned and a mismatched version triggers a fresh grace period rather than a risky migration.

## Evaluation plan

- Correctness: replay the public Kitsune datasets (Mirai, SSDP flood, ARP MitM, etc.) and confirm detection at false-positive rates comparable to the paper.
- Fitness for *this* machine: capture a day of the developer's own traffic, replay it, and tune default thresholds so a normal day is silent.
  This matters more than it sounds. The synthetic corpus in `tools/make_test_pcap.py` draws from 40 uniformly random hosts; a real machine on a real network showed 649 endpoints with constant CDN churn.
  The deadlock above does not reproduce on the synthetic corpus at all, which is why a green test suite and a clean scenario matrix said nothing about it.
- Held-out benign traffic: train on one real capture, then replay a *different* real capture taken later. Novel-but-harmless traffic is the case the detector has to stay quiet on, and it is the case stationary synthetic traffic never exercises.
- Adversarial checks in tests: port scan (nmap), new device joining, sudden large upload, DNS burst; each must alert with the right context key.
