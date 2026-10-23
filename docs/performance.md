# Windows service performance: event-driven BGP dispatcher

Cowabunga, service maintainers. Use this measured reference to inspect CPU,
memory, context switches, and thread-ready behavior for the BFD engine and BGP
broker. The results cover two five-minute recordings on October 23, 2026, with
the event-driven BGP request dispatcher enabled.

The engine uses the published v5.0.0 binary. The broker uses a local development
build based on v5.0.0 with the dispatcher change; its file version remains
5.0.0. These measurements describe this one-peer lab workload.

These recordings precede the secrecy changes and the combined 6.0.0 build.
They measure the dispatcher change only. See the
[6.0.0 validation record](releases/6.0.0.md#validation) for combined-build testing.

To inspect a metric, see [CPU usage](#cpu-usage),
[context switches](#context-switches-per-second), [memory](#memory-usage), or
[thread ready delay and ready time](#thread-ready-delay-and-ready-time).
The [measurement limits](#measurement-limits) and
[build identity](#data-and-build-identity) define the scope of these results.

## Test environment

The services exchange Bidirectional Forwarding Detection (BFD) and Border
Gateway Protocol (BGP) traffic between a Windows VM and an Ubuntu VM:

| Setting | Value |
| --- | --- |
| Windows guest | Windows Server 2025 Standard Evaluation, build 26100 |
| Windows VM | `BFD-WS2025`, two virtual CPUs, Hyper-V dynamic memory |
| Ubuntu peer | `BFD-Ubuntu2604`, BIRD 2.18 |
| BFD session | One classical single-hop session |
| Authentication | Meticulous keyed SHA-1, key ID 23 |
| BFD TX / RX intervals | 300 ms / 300 ms |
| Detection multiplier / negotiated detection time | 3 / 900 ms |
| BGP peer | `BirdLab`, Windows AS 64513, BIRD AS 64512 |
| Advertised routes | Windows: `198.51.100.53/32`; BIRD: `203.0.113.54/32` |
| Engine / broker process IDs | 4392 / 3944 |

In the tables, **Engine** means `BfdWinService` (`bfd-winservice.exe`), and
**Broker** means `BfdBgpBroker` (`bfd-bgp-broker.exe`).

## Capture sets

Windows Performance Recorder collects Event Tracing for Windows (ETW) data.
Windows Performance Analyzer Exporter exports scheduler, sampled CPU, memory,
and process data. Each set also has 301 process-counter samples per service,
collected at approximately one-second intervals:

| Capture | Purpose | UTC window on 2026-10-23 | Analysis duration |
| --- | --- | --- | ---: |
| A | CPU and memory | 03:44:57–03:49:57 | 300 s |
| B | CPU, memory, and thread-ready stacks | 03:52:16–03:57:16 | 300 s |

Both sets record process/thread lifecycle, context switches, ready-thread
events, sampled CPU stacks, and memory counters. Capture B also records
context-switch and readying stacks. Each recorder uses 32 MiB of kernel buffers.
Additional stack collection changes profiling overhead, so keep the two sets
separate when interpreting the values.

BFD remains Up and BGP remains connected throughout both recordings. Each set
has 11 successful Windows BGP/route checks, no BFD event records, zero lost ETW
events, and zero lost buffers. Ubuntu checks also show BFD Up, BGP Established,
and the Windows advertisement in the kernel route table. No service restart or
failure injection occurs during either recording.

## Units and percentiles

CPU percentages use the full capacity of the two-vCPU Windows guest. For
example, 100% means both vCPUs are occupied for the whole interval. Scheduled
CPU is the sum of the measured thread on-CPU intervals; its mean percentage is
scheduled milliseconds / (300 × 2 × 1,000) × 100.

P50 is the median. P95 and P99 use the nearest-rank method: sort the
observations and select rank ceil(percentile × count). CPU and context-switch
percentiles use 300 one-second buckets. Memory, handle, and thread statistics
use the 301 process samples. Ready-delay percentiles use individual completed
thread dispatches.

One MiB is 1,048,576 bytes. One ms is 1,000 µs. Tables round values for
readability; the companion CSV files retain the numeric values used to calculate
the tables, including memory in bytes.

## CPU usage

Scheduled CPU totals and mean utilization cover the first 300 seconds of each
trace:

| Capture / service | Scheduled CPU (ms) | Mean CPU (% of VM) |
| --- | ---: | ---: |
| A / Engine | 227.9221 | 0.03799 |
| A / Broker | 90.6106 | 0.01510 |
| B / Engine | 311.9190 | 0.05199 |
| B / Broker | 121.8151 | 0.02030 |

One-second CPU utilization has the following distribution. Every value is a
percentage of total guest CPU capacity:

| Capture / service | P50 (%) | P95 (%) | P99 (%) | Maximum (%) |
| --- | ---: | ---: | ---: | ---: |
| A / Engine | 0.03717 | 0.04646 | 0.05072 | 0.05861 |
| A / Broker | 0.01495 | 0.02107 | 0.02562 | 0.04122 |
| B / Engine | 0.05165 | 0.06200 | 0.06795 | 0.07366 |
| B / Broker | 0.02030 | 0.02529 | 0.03301 | 0.03759 |

Combined mean service CPU is 0.05309% in capture A and 0.07229% in capture B.
The process CPU counters and sampled CPU observations provide supporting
measurements:

| Capture / service | Process CPU counter (ms) | Sampled CPU observations |
| --- | ---: | ---: |
| A / Engine | 171.875 | 34 |
| A / Broker | 62.500 | 52 |
| B / Engine | 265.625 | 83 |
| B / Broker | 109.375 | 127 |

Counter quantization and sparse samples affect these short CPU bursts. Use
scheduler intervals as the primary CPU measurement for this capture; the
supporting values use different measurement methods.

## Context switches per second

A context-switch count records a dispatch into a thread belonging to the
process. The total covers 300 seconds; percentiles describe the per-second
counts:

| Capture / service | Total | Mean/s | Minimum/s | P50/s | P95/s | P99/s | Maximum/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A / Engine | 4501 | 15.003 | 10 | 15 | 19 | 20 | 20 |
| A / Broker | 2074 | 6.913 | 0 | 7 | 9 | 10 | 28 |
| B / Engine | 4542 | 15.140 | 9 | 15 | 19 | 20 | 24 |
| B / Broker | 2036 | 6.787 | 0 | 7 | 8 | 9 | 14 |

## Memory usage

Private bytes measure committed private virtual memory. Working set measures
resident physical pages, including shared pages. Both tables use MiB and the
process-counter samples.

### Capture A

The sampled memory distribution is:

| Service / metric | Minimum | Mean | P50 | P95 | P99 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Engine / private | 1.391 | 1.459 | 1.430 | 1.508 | 1.508 | 1.508 |
| Engine / working set | 7.391 | 7.531 | 7.508 | 7.648 | 7.648 | 7.648 |
| Broker / private | 2.461 | 2.634 | 2.586 | 2.910 | 2.977 | 2.977 |
| Broker / working set | 12.504 | 12.612 | 12.578 | 12.730 | 12.746 | 12.758 |

### Capture B

The sampled memory distribution is:

| Service / metric | Minimum | Mean | P50 | P95 | P99 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Engine / private | 1.430 | 1.472 | 1.453 | 1.523 | 1.523 | 1.523 |
| Engine / working set | 7.590 | 7.660 | 7.664 | 7.703 | 7.703 | 7.703 |
| Broker / private | 2.426 | 2.486 | 2.469 | 2.539 | 2.539 | 2.539 |
| Broker / working set | 12.605 | 12.646 | 12.648 | 12.672 | 12.688 | 12.688 |

The first and last samples show the observed memory change within each
five-minute window. These values use raw bytes:

| Capture / service / metric | First (bytes) | Last (bytes) | Change (bytes) |
| --- | ---: | ---: | ---: |
| A / Engine / private | 1,540,096 | 1,581,056 | 40,960 |
| A / Engine / working set | 7,749,632 | 8,019,968 | 270,336 |
| A / Broker / private | 3,121,152 | 2,711,552 | -409,600 |
| A / Broker / working set | 13,279,232 | 13,295,616 | 16,384 |
| B / Engine / private | 1,499,136 | 1,568,768 | 69,632 |
| B / Engine / working set | 7,958,528 | 8,077,312 | 118,784 |
| B / Broker / private | 2,588,672 | 2,584,576 | -4,096 |
| B / Broker / working set | 13,217,792 | 13,262,848 | 45,056 |

## Handles and threads

Sampled resource counts have the following distribution. Means can be fractional
because they average observations over time:

| Capture / service / resource | Minimum | Mean | P50 | P95 | P99 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A / Engine / handles | 122 | 123.04 | 122 | 127 | 130 | 130 |
| A / Engine / threads | 6 | 7.72 | 7 | 9 | 9 | 9 |
| A / Broker / handles | 221 | 226.14 | 223 | 242 | 242 | 242 |
| A / Broker / threads | 9 | 11.37 | 10 | 16 | 18 | 18 |
| B / Engine / handles | 122 | 122.12 | 122 | 124 | 124 | 124 |
| B / Engine / threads | 7 | 7.69 | 7 | 9 | 9 | 9 |
| B / Broker / handles | 213 | 214.69 | 215 | 217 | 217 | 217 |
| B / Broker / threads | 8 | 9.57 | 9 | 11 | 11 | 11 |

## Thread ready delay and ready time

Capture B supplies the thread-ready measurements. Ready delay is the time from
becoming runnable to being scheduled. Cumulative ready time sums those durations
across threads. WPA `Ready Time (s)` is the trace-relative timestamp at which a
thread becomes runnable. Blocked waits for timers, I/O, or synchronization are
measured separately.

The analysis includes completed episodes whose ready and switch-in timestamps
both fall in the interval from 1 to less than 300 seconds. This gives a
299-second window and excludes 19 boundary dispatches from the 6,580 exported
dispatches. Every duration is checked against switch-in timestamp minus ready
timestamp.

Per-service ready-delay percentiles and accumulated ready time are:

| Metric | Engine | Broker |
| --- | ---: | ---: |
| Completed dispatches | 4,533 | 2,028 |
| Mean ready delay (µs) | 33.22 | 33.13 |
| P50 ready delay (µs) | 28.40 | 26.50 |
| P95 ready delay (µs) | 65.60 | 89.50 |
| P99 ready delay (µs) | 127.40 | 230.60 |
| Maximum ready delay (µs) | 1587.10 | 480.70 |
| Cumulative ready time (ms) | 150.57 | 67.19 |
| Delays over 1 ms | 1 | 0 |
| Delays over 10 ms | 0 | 0 |
| Delays over 100 ms | 0 | 0 |

### Per-thread ready time

The following threads account for the five largest accumulated ready times in
each service. Thread IDs identify this recording only. Unnamed threads retain
their numeric ID. The companion CSV includes all 20 threads with completed
observations:

| Service | Thread ID | Thread name | Dispatches | Ready total (ms) | P99 (µs) | Maximum (µs) |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Engine | 1672 | Unnamed | 3853 | 124.570 | 97.6 | 369.8 |
| Engine | 1460 | Unnamed | 338 | 13.168 | 374.1 | 414.6 |
| Engine | 5932 | Unnamed | 306 | 11.681 | 179.2 | 1587.1 |
| Engine | 5244 | Unnamed | 22 | 0.676 | 143.8 | 143.8 |
| Engine | 4812 | Unnamed | 3 | 0.153 | 118.9 | 118.9 |
| Broker | 316 | bfd-status-monitor | 698 | 29.172 | 197.4 | 422.5 |
| Broker | 4052 | Unnamed | 323 | 19.202 | 380.6 | 480.7 |
| Broker | 4560 | bfd-status-rpc | 602 | 11.860 | 56.0 | 273.9 |
| Broker | 6132 | Unnamed | 239 | 3.932 | 71.1 | 92.0 |
| Broker | 1052 | Unnamed | 120 | 2.079 | 58.9 | 85.5 |

## Measurement limits

These results describe steady-state operation with one peer, under the recorded
authentication and timing settings. They do not establish capacity limits,
performance with many peers, worst-case latency, long-term leak freedom, or
failure-detection latency.

The guest shares a Hyper-V host with other workloads. Guest-visible memory at
capture start is 1,977.44 MiB for A and 1,737.44 MiB for B. Dynamic memory,
process age, and earlier native provider operations can affect memory and
scheduling measurements. No synthetic load is introduced during these
recordings.

Ready delay measures the guest scheduler. It does not independently measure
Hyper-V host vCPU ready time. Cumulative ready time is accumulated thread time;
it is not CPU usage or a delay applied to each DNS query, BFD packet, or BGP
operation. Threads with no dispatch in the window have no completed ready-delay
observation.

## Data and build identity

The companion files preserve the measured numeric values and capture identity:

- [Service metrics](performance/2026-10-23/service-metrics.csv): CPU, context-switch, memory, handle, and thread distributions.
- [Service ready time](performance/2026-10-23/ready-time.csv): dispatch counts, ready-delay percentiles, accumulated time, and delay thresholds.
- [Per-thread ready time](performance/2026-10-23/thread-ready-time.csv): all measured threads and their ready-delay statistics.
- [Capture metadata](performance/2026-10-23/capture-metadata.json): exact UTC capture windows, analysis windows, build provenance, source hashes, and binary hashes.

`service-metrics.csv` includes totals for additive CPU-time and context-switch
observations. Empty total fields mark metrics such as percentages and memory
sizes, whose observations are not additive. CSV memory values use bytes;
presentation tables convert them to MiB.

For exact artifact identification, use these SHA-256 hashes:

| Artifact | SHA-256 |
| --- | --- |
| Published v5.0.0 engine | `460F9ADBABC1E6C9773CC5E0CE1819B9B538303D3D0D2474247039DDD7A906A6` |
| Event-dispatcher development broker | `3CEFE8F707FBCAAABCFCEBC82C38F04C80F514E0179ACACF8FDD135D46712088` |

The source base is commit `1c191fa3486caf8717e213943d7c7fe190107c53` with the
dispatcher and test changes recorded in the metadata. Other pending repository
changes are outside this measured build. The ETL recordings and detailed WPA
exports remain local capture artifacts; they are not included in these compact
data files.

For the measurements with telemetry wake coalescing enabled, see
[coalesced telemetry performance](performance-telemetry-coalescing.md).

For operational interpretation, see [service monitoring](monitoring.md). For the
runtime boundaries, see [service communication](service-communication.md).
