# Xgress RTT Estimation: Experiments and Notes

## Original Design

The original RTT estimation uses a simple 2-sample average with a configurable multiplier:

```go
rtt = (rtt + lastRtt) >> 1
retxThreshold = uint32(float64(rtt) * retxScale) + RetxAddMs
```

`retxScale` starts at `RetxScale` (default 1.5) and is adjusted by duplicate ack feedback:
- Every `TxPortalDupAckThresh` (default 64) duplicate acks: `retxScale += 0.2`
- Every `TxPortalIncreaseThresh` (default 28) successful acks: `retxScale -= 0.01`

This is a simple system but has two problems:
1. A single RTT spike can double the estimate instantly (the 2-sample average gives 50% weight to each new sample)
2. The `retxScale` multiplier is coarse — it conflates RTT estimation quality with safety margin

## Experiment 1: RFC 6298 SRTT/RTTVAR + Spike Cap

Replaced the 2-sample average with TCP-style EWMA (RFC 6298):

```go
// First sample
smoothedRtt = sample
rttVariance = sample / 2

// Subsequent samples
diff = abs(smoothedRtt - sample)
rttVariance = 0.75*rttVariance + 0.25*diff
smoothedRtt = 0.875*smoothedRtt + 0.125*sample

retxThreshold = uint32(smoothedRtt + 4*rttVariance) + RetxAddMs
```

Added spike cap (`MaxRttScale`, default 4): before entering the EWMA, any sample is capped at
`smoothedRtt * MaxRttScale`. This prevents a single network hiccup from blowing up the estimate.
Setting `MaxRttScale` to 0 disables the cap. The minimum effective value is 2 (values of 1 are
bumped to 2, since 1 would freeze RTT at its current value).

Added hard cap (`RetxMaxMs`, default 10000): `retxThreshold` is clamped to this ceiling. Setting
`RetxMaxMs` to 0 disables the cap.

Removed `retxScale` and its dup-ack/success-ack feedback loop.

### Result

Initial testing showed ~2x retransmissions on the candidate vs baseline, causing ~15% throughput
regression on SDK (xgress) paths. The EWMA produced a tighter (lower) RTO than the old
`rtt * 1.5` approach, which was too aggressive — payloads were being retransmitted before their
acks arrived.

## Experiment 2: Synthetic RTT from Duplicate Acks

Added duplicate ack feedback back into the EWMA. When `TxPortalDupAckThresh` (changed to 5)
consecutive duplicate acks accumulated, a synthetic RTT sample was fed into the EWMA:

```go
sample := float64(retxThreshold) * DupAckRetxScale  // DupAckRetxScale default 1.25
buffer.updateRtt(sample)
```

This pushed `smoothedRtt` higher when the system detected too-aggressive retransmission.

### Result

8-hour A/B test (136 run pairs) showed **neutral results** across all metrics. Throughput deltas
were +0.5% to +3.1% (within noise). Latency mean/P50/P95 all within noise. P99 showed a
consistent +6-11% regression across all paths (including ERT-to-ERT which has no xgress segments),
suggesting an environmental factor rather than a code issue.

## Experiment 3: Adaptive Minimum Margin

Replaced the synthetic RTT sample with a cleaner approach. Instead of polluting the EWMA with
fake data, added a separate adaptive `minRetxMargin` floor:

```go
margin := max(minRetxMargin, 2*rttVariance)
retxThreshold = uint32(smoothedRtt + margin) + RetxAddMs
```

The margin adjusts based on dup ack / success ack feedback:
- Every `TxPortalDupAckThresh` (changed to 20) duplicate acks: `minRetxMargin++`
- Every `TxPortalIncreaseThresh` (28) successful acks: `minRetxMargin--` (floor at 0)

Also changed the variance multiplier from 4x to 2x, with the minimum margin providing the safety
floor instead.

### Result

6-hour A/B test (159 run pairs) showed **regression**. SDK hosting paths were consistently worse:
Peak M1 throughput "better" rate was 21% and 9% (should be ~50% if neutral). Latencies were
universally worse, especially P95/P99 on SDK paths (+41%, +44%).

The 1ms increment per 20 dup acks was far too weak compared to the synthetic RTT approach. The
margin barely moved while duplicate acks piled up. The synthetic RTT approach (experiment 2) fed
`retxThreshold * 1.25` every 5 dup acks — a much larger and more frequent adjustment.

## Current State

Reverting to the original design (simple 2-sample average + `retxScale`), keeping only the spike
cap (`MaxRttScale`) and hard cap (`RetxMaxMs`) as improvements.

## Ideas for Future Attempts

### Tune the Adaptive Margin (Experiment 3 Revisited)

The concept of a separate margin is cleaner than synthetic RTT samples. The failure was in
parameter tuning, not the mechanism. Options:
- Scale the increment relative to current threshold: `minRetxMargin += retxThreshold / N`
  instead of a fixed 1ms
- Lower the threshold back to 5 (the adjustment is weak, so it needs to trigger more often)
- Combine: moderate threshold (10) with proportional increment

### Hybrid: EWMA + Scaled retxScale

Keep SRTT/RTTVAR for accurate RTT tracking but compute the threshold using a dynamic multiplier
similar to the original `retxScale`:

```go
retxThreshold = uint32(smoothedRtt * retxScale) + RetxAddMs
```

This gets the benefit of smoother RTT estimation (EWMA + spike cap) while keeping the proven
dup-ack feedback mechanism that adjusts the safety multiplier.

### Investigate Asymmetric Behavior

The A/B tests consistently showed different behavior depending on which side hosts via SDK:
- SDK client -> ERT host: throughput improves with candidate
- SDK client -> SDK host: throughput regresses
- ERT client -> ERT host: neutral

The xgress send buffer on the host-side (router -> SDK host app) handles the receiving direction
for throughput tests. This segment might have different RTT characteristics (short intra-region
hops with very low variance) that interact poorly with tighter RTT estimation. Understanding why
the host-side xgress behaves differently could inform a better approach.

### Consider Separate Tuning for Low-RTT Paths

In-region xgress connections have ~1ms RTT. Cross-region fabric links have ~60ms RTT. The same
parameters may not work well for both. A minimum retx threshold floor (e.g., 10-20ms regardless
of measured RTT) could prevent overly aggressive retransmission on low-RTT paths without affecting
high-RTT paths.
