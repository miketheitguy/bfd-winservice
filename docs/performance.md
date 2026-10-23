# Windows service performance

Cowabunga, service maintainers. Use these version 6.0.1 measurements to assess
CPU, memory, context switches, and thread ready behavior. This section retains
only the most recent verified measurement set for version 6 and later. Release
history lives in the [release notes](README.md#release-notes).

Every metric has a “Better” interpretation in the tables or the [counter
reference](performance/counters.md). “Lower” assumes the same successful
workload and unchanged detection timers. The reference cites Microsoft
documentation and explains metrics that have no universal higher/lower ranking.

## Workload and build

| Setting | Measured value |
| --- | --- |
| Date | October 23, 2026 (UTC) |
| Version / source | 6.0.1 / `fc9a91f8c389478f0508e676ae44ebdaa0836df6` |
| Build | Local hardened release build installed from the 6.0.1 setup bundle |
| Windows VM | Windows Server 2025 Standard Evaluation, build 26100; two vCPUs; Hyper-V dynamic memory |
| Ubuntu peer | BIRD 2.18; one single-hop BFD/BGP peer |
| BFD | Meticulous keyed SHA-1; TX/RX 300 ms; multiplier 3; negotiated detection 900 ms |
| BGP | Windows AS 64513; BIRD AS 64512; peer `BirdLab` |
| Routes | Windows advertises `198.51.100.53/32`; BIRD advertises `203.0.113.54/32` |
| Engine | `BfdWinService` / `bfd-winservice.exe` / PID 4168 |
| Broker | `BfdBgpBroker` / `bfd-bgp-broker.exe` / PID 5256 |

The measured binaries match the local 6.0.1 lab installation receipt. These are
not the hosted CI executable files. Subsequent repository changes before this
test affect documentation only. Exact executable hashes, profiles, tools, and
capture metadata are in the [data
set](performance/6.0.1-2026-10-23/capture-metadata.json).

## Capture method and health

| Set | Purpose | UTC request window | Analysis |
| --- | --- | --- | --- |
| A | CPU and memory | 11:17:01–11:22:01 | 300 s |
| B | Thread-ready stacks | 11:22:11–11:27:11 | 300 s |

Windows Performance Recorder (WPR) records Event Tracing for Windows (ETW)
scheduler events, sampled CPU stacks, process counters, and memory snapshots.
Set B also records context-switch and ready-thread stacks. Both
profiles request 32 MiB of kernel buffers. Additional stacks affect recording
overhead, so interpret each set separately. Windows Performance Analyzer (WPA)
Exporter processes the traces after both recordings finish.

Each set contains 301 approximately one-second process samples per service and
300 one-second scheduler buckets. CPU intervals are clipped to trace seconds [0,
300); context switches count dispatches into service threads in that window. CPU
percentage uses both guest CPUs: scheduled ms / (300 × 2 × 1,000) × 100. It is
not host CPU utilization.

| Health / evidence | A | B | Better |
| --- | --- | --- | --- |
| Windows BGP and route checks | 11/11 | 11/11 | Higher pass fraction; target 100% |
| Ubuntu BFD/BGP/routes before and after | Pass | Pass | Healthy / present |
| BFD operational events during recording | 0 | 0 | Zero unexpected changes/errors |
| Service restarts / PID changes | 0 | 0 | Lower; target zero |
| Lost ETW events / buffers | 0 / 0 | 0 / 0 | Lower; target zero |

Both services retain the same PID, executable hash, start time, and BFD
configuration before and after each set. WPR is stopped after capture. Health
checks are periodic observations; they do not measure every packet or prove
continuous query latency.

## CPU usage

CPU totals measure scheduled execution; all distribution values are percentages
of total two-vCPU guest capacity. Lower is better for the same work. P50 is the
median; P95/P99 use nearest rank. Percentiles below describe one-second buckets,
not per-packet execution time.

| Set / service | Total CPU ms | Mean % | Min % | P50 % | P95 % | P99 % | Max % | Better |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A / Engine | 148.626 | 0.02477 | 0.01852 | 0.02479 | 0.02891 | 0.03034 | 0.03547 | Lower |
| A / Broker | 84.192 | 0.01403 | 0.00075 | 0.01412 | 0.01923 | 0.02164 | 0.02685 | Lower |
| B / Engine | 196.913 | 0.03282 | 0.02272 | 0.03275 | 0.03904 | 0.04116 | 0.04487 | Lower |
| B / Broker | 115.199 | 0.01920 | 0.00160 | 0.01952 | 0.02515 | 0.02845 | 0.03273 | Lower |

Process counters and sampled CPU provide supporting measurements. Counter deltas
use the first and last process samples, which are slightly offset from the trace
window; timer accounting and sparse sampling can differ from scheduler totals.
User plus kernel time equals process CPU time. CPU times are lower for equal
work; observation count has no independent performance direction.

| Set / service | Process ms | User ms | Kernel ms | Sampled ms | Observations |
| --- | --- | --- | --- | --- | --- |
| A / Engine | 125.000 | 78.125 | 46.875 | 20.634 | 21 |
| A / Broker | 125.000 | 62.500 | 62.500 | 33.479 | 34 |
| B / Engine | 203.125 | 93.750 | 109.375 | 18.723 | 19 |
| B / Broker | 109.375 | 46.875 | 62.500 | 110.000 | 112 |

## Context switches per second

Counts represent switch-ins into the service, not the sum of both switch-ins and
switch-outs. Generally lower is better at the same work and responsiveness; an
active service still needs to wake for traffic and timers.

| Set / service | Total | Mean/s | Min/s | P50/s | P95/s | P99/s | Max/s | Better |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A / Engine | 3487 | 11.623 | 8.000 | 11.500 | 14.000 | 15.000 | 16.000 | Generally lower |
| A / Broker | 1982 | 6.607 | 1.000 | 6.000 | 8.000 | 8.000 | 9.000 | Generally lower |
| B / Engine | 3507 | 11.690 | 8.000 | 12.000 | 14.000 | 16.000 | 19.000 | Generally lower |
| B / Broker | 2083 | 6.943 | 1.000 | 7.000 | 9.000 | 11.000 | 66.000 | Generally lower |

## Memory

Values below use MiB (1,048,576 bytes) and the 301 process samples. Private
bytes are private commit; working set is resident RAM including shared pages.
Lower private commit is desirable for equal work. Working set has no universal
direction because Windows can trim pages and cause later faults. Virtual bytes
measure address space, not RAM; their full distribution is in the CSV.

| Set / service / metric | Min MiB | Mean MiB | P50 MiB | P95 MiB | P99 MiB | Max MiB | Better |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A / Engine / private | 1.418 | 1.456 | 1.457 | 1.461 | 1.461 | 1.461 | Lower |
| A / Engine / working set | 7.180 | 7.288 | 7.305 | 7.340 | 7.340 | 7.340 | Context dependent |
| A / Broker / private | 2.320 | 2.349 | 2.355 | 2.359 | 2.359 | 2.359 | Lower |
| A / Broker / working set | 12.352 | 12.473 | 12.488 | 12.496 | 12.496 | 12.496 | Context dependent |
| B / Engine / private | 1.418 | 1.456 | 1.457 | 1.457 | 1.457 | 1.457 | Lower |
| B / Engine / working set | 7.340 | 7.427 | 7.438 | 7.457 | 7.457 | 7.457 | Context dependent |
| B / Broker / private | 2.320 | 2.350 | 2.359 | 2.359 | 2.359 | 2.359 | Lower |
| B / Broker / working set | 12.496 | 12.551 | 12.555 | 12.582 | 12.582 | 12.582 | Context dependent |

Raw first/last observations show the change over each five-minute window.
Stable, bounded use is desirable; a negative change alone is not an improvement.

| Set / service / metric | First bytes | Last bytes | Change bytes |
| --- | --- | --- | --- |
| A / Engine / private_memory | 1,531,904 | 1,523,712 | -8,192 |
| A / Engine / working_set | 7,528,448 | 7,696,384 | 167,936 |
| A / Broker / private_memory | 2,469,888 | 2,473,984 | 4,096 |
| A / Broker / working_set | 12,951,552 | 13,103,104 | 151,552 |
| B / Engine / private_memory | 1,523,712 | 1,527,808 | 4,096 |
| B / Engine / working_set | 7,696,384 | 7,819,264 | 122,880 |
| B / Broker / private_memory | 2,473,984 | 2,437,120 | -36,864 |
| B / Broker / working_set | 13,103,104 | 13,172,736 | 69,632 |

WPA snapshots independently report working set, private working set, and process
commit. Their minimum, mean, P50/P95/P99, maximum, and first/last/change values
are preserved in service-metrics.csv. Snapshot counts and times differ from the
process sampler; do not mix their populations.

## Handles and threads

Stable, bounded handles and an appropriate stable thread count are desirable.
Blindly minimizing either counter can impair useful work. Counts include threads
that are waiting.

| Set / service / resource | Min | Mean | P50 | P95 | P99 | Max | First → last | Better |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A / Engine / handles | 121.000 | 121.465 | 121.000 | 123.000 | 123.000 | 123.000 | 123 → 121 | Stable / appropriate |
| A / Engine / threads | 6.000 | 6.993 | 7.000 | 7.000 | 7.000 | 7.000 | 7 → 7 | Stable / appropriate |
| A / Broker / handles | 179.000 | 180.575 | 181.000 | 181.000 | 181.000 | 181.000 | 181 → 181 | Stable / appropriate |
| A / Broker / threads | 8.000 | 8.794 | 9.000 | 9.000 | 9.000 | 9.000 | 9 → 9 | Stable / appropriate |
| B / Engine / handles | 121.000 | 121.000 | 121.000 | 121.000 | 121.000 | 121.000 | 121 → 121 | Stable / appropriate |
| B / Engine / threads | 6.000 | 6.990 | 7.000 | 7.000 | 7.000 | 7.000 | 7 → 7 | Stable / appropriate |
| B / Broker / handles | 179.000 | 180.515 | 181.000 | 181.000 | 181.000 | 181.000 | 181 → 179 | Stable / appropriate |
| B / Broker / threads | 8.000 | 8.764 | 9.000 | 9.000 | 9.000 | 9.000 | 9 → 8 | Stable / appropriate |

## Thread ready delay and ready time

Set B measures the delay from becoming runnable to being scheduled. Lower is
better. Waiting for packets, timers, or synchronization before becoming runnable
is separate. Only completed episodes with ready timestamp ≥1 second and
switch-in <300 seconds are included (299-second window). Boundary-crossing
episodes are excluded.

| Service | Episodes | Mean µs | P50 µs | P95 µs | P99 µs | Max µs | Better |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Engine | 3496 | 25.230 | 24.400 | 47.300 | 83.100 | 305.000 | Lower delay; episode count is coverage |
| Broker | 2077 | 22.312 | 17.600 | 52.100 | 153.000 | 272.200 | Lower delay; episode count is coverage |

The included episodes have these cumulative totals and threshold counts:

| Service | Total ready ms | Mean concurrent ready threads | >1 ms | >10 ms | >100 ms | Better |
| --- | --- | --- | --- | --- | --- | --- |
| Engine | 88.203 | 0.000295 | 0 | 0 | 0 | Lower, for equal work/window |
| Broker | 46.343 | 0.000155 | 0 | 0 | 0 | Lower, for equal work/window |

Total ready time sums the included episodes across threads and can overlap
across threads. Dividing it by 299 seconds estimates average concurrent ready
threads for this included population; it is not the complete runnable occupancy
integral. Thresholds are diagnostic cutoffs, not BFD deadlines. Per-thread
percentiles and one-second cumulative totals are supplied in the data set.

## Assessment and limits

Processing overhead is low for this workload. Combined mean CPU is 0.03880%
of guest capacity in set A and 0.05202% in set B. Context-switch averages stay
near 12/s for the engine and 7/s for the broker. Set B includes one broker
bucket with 66 switch-ins; its maximum one-second CPU remains only 0.03273%.
The trace does not establish the cause of that isolated dispatch burst.

Private commit changes by at most 36,864 bytes between the first and last
samples of either service in either set. Working sets rise by 69,632–167,936
bytes per set; handles and threads stay within narrow ranges. This supports a
small, bounded footprint over the measured windows, without proving long-term
stability.

No included ready delay exceeds 1 ms. Engine and broker maxima are 305.0 µs
and 272.2 µs, respectively. These data show no sustained guest scheduling
backlog and no obvious processing-overhead problem in this lab. They do not
justify another optimization by themselves; use a repeatable workload and
matching capture settings to evaluate any proposed change.

Interpret these observations as a steady-state reference for one authenticated
peer. They do not establish maximum peer capacity, packet latency,
failure-detection accuracy, or performance under host contention. Five-minute
resource stability cannot rule out a slow leak. The two sets have different
stack collection overhead and are not an optimization comparison.

## Numeric data and profiles

Use the following files to inspect unrounded numbers or reproduce the aggregate
calculations. The [counter reference](performance/counters.md) maps every metric
family, statistic, health check, and metadata field to its interpretation.

| File | Contents |
| --- | --- |
| [service-metrics.csv](performance/6.0.1-2026-10-23/service-metrics.csv) | All service distributions, totals, first/last/change, and Better labels |
| [supporting-cpu.csv](performance/6.0.1-2026-10-23/supporting-cpu.csv) | CPU cross-checks and mean execution per dispatch |
| [ready-time.csv](performance/6.0.1-2026-10-23/ready-time.csv) | Service ready-delay percentiles and cumulative time |
| [thread-ready-time.csv](performance/6.0.1-2026-10-23/thread-ready-time.csv) | Per-thread ready-delay percentiles |
| [ready-episodes.csv](performance/6.0.1-2026-10-23/ready-episodes.csv) | Included individual ready episodes |
| [ready-time-timeline.csv](performance/6.0.1-2026-10-23/ready-time-timeline.csv) | Per-second and cumulative ready time |
| [capture-metadata.json](performance/6.0.1-2026-10-23/capture-metadata.json) | Build identity, executable hashes, capture scope, health, and losses |
| [A-process-samples.csv](performance/6.0.1-2026-10-23/A-process-samples.csv) | Set A raw process counters |
| [B-process-samples.csv](performance/6.0.1-2026-10-23/B-process-samples.csv) | Set B raw process counters |
| [A-timeline.csv](performance/6.0.1-2026-10-23/A-timeline.csv) | Set A per-second CPU and switch-ins |
| [B-timeline.csv](performance/6.0.1-2026-10-23/B-timeline.csv) | Set B per-second CPU and switch-ins |
| [A-bgp-health.csv](performance/6.0.1-2026-10-23/A-bgp-health.csv) | Set A periodic health checks |
| [B-bgp-health.csv](performance/6.0.1-2026-10-23/B-bgp-health.csv) | Set B periodic health checks |
| [A.wprp](performance/6.0.1-2026-10-23/A.wprp) | Set A WPR collection profile |
| [B.wprp](performance/6.0.1-2026-10-23/B.wprp) | Set B WPR collection profile |
| [A.wpaProfile](performance/6.0.1-2026-10-23/A.wpaProfile) | Set A WPA export profile |
| [B.wpaProfile](performance/6.0.1-2026-10-23/B.wpaProfile) | Set B WPA export profile |

Full machine-wide ETL files and intermediate WPA exports remain local under
`target/performance-v6.0.1-20261023`. They are not committed. Published episode
data omits other processes' names, executable paths, and call stacks. All
published performance numbers in this section describe version 6.0.1.
