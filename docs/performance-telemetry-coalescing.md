# Windows service performance: coalesced telemetry

Cowabunga, service maintainers. Use this measured reference to inspect CPU,
memory, context switches, and thread-ready behavior for the BFD engine and BGP
broker. The results cover two five-minute recordings on October 23, 2026, with
telemetry wake coalescing and the event-driven BGP dispatcher enabled.

The engine and broker use local development builds based on v5.0.0. The engine
includes telemetry wake coalescing; the broker includes the event-driven
dispatcher. Both file versions remain 5.0.0. These measurements describe this
one-peer lab workload.

These recordings precede the secrecy changes and the combined 6.0.0 build.
Their numbers measure the two scheduling changes, without attributing a
performance effect to secret storage. See the
[6.0.0 validation record](releases/6.0.0.md#validation) for combined-build testing.

To inspect a metric, see [CPU usage](#cpu-usage),
[context switches](#context-switches-per-second), [memory](#memory-usage), or
[thread ready delay and ready time](#thread-ready-delay-and-ready-time).
The [measurement limits](#measurement-limits) and
[build identity](#data-and-build-identity) define the scope of these results.

## Scheduling behavior

Routine sent, received, rejected, and withheld counters remain eligible for
publication after the 100-millisecond minimum spacing. They publish when the
packet engine already wakes for work, or at its one-second refresh target,
instead of scheduling their own 100-millisecond wake.

State transitions, detection timeouts, peer identity or advertised timing
changes, new communication failures, Poll changes, and configuration reloads
retain prompt publication eligibility. Repeated errors with the same code are
coalesced. A successful coherent snapshot clears the pending priority flag.
Protocol transmit and detection deadlines, settings retries, and BGP control
continue to determine their own work deadlines. See the
[status publication contract](rpc-session-status-design.md#snapshot-coherence-and-packet-isolation)
for the authoritative cadence and ownership rules.

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
| Engine / broker process IDs | 5192 / 3944 |

In the tables, **Engine** means `BfdWinService` (`bfd-winservice.exe`), and
**Broker** means `BfdBgpBroker` (`bfd-bgp-broker.exe`).

## Capture sets

Windows Performance Recorder collects Event Tracing for Windows (ETW) data.
Windows Performance Analyzer Exporter exports scheduler, sampled CPU, memory,
and process data. Each set also has 301 process-counter samples per service,
collected at approximately one-second intervals:

| Capture | Purpose | UTC window on 2026-10-23 | Analysis duration |
| --- | --- | --- | ---: |
| A | CPU and memory | 04:23:37–04:28:37 | 300 s |
| B | CPU, memory, and thread-ready stacks | 04:29:20–04:34:21 | 300 s |

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
| A / Engine | 148.6482 | 0.02477 |
| A / Broker | 84.9501 | 0.01416 |
| B / Engine | 188.7950 | 0.03147 |
| B / Broker | 113.3843 | 0.01890 |

One-second CPU utilization has the following distribution. Every value is a
percentage of total guest CPU capacity:

| Capture / service | P50 (%) | P95 (%) | P99 (%) | Maximum (%) |
| --- | ---: | ---: | ---: | ---: |
| A / Engine | 0.02493 | 0.03012 | 0.03370 | 0.03693 |
| A / Broker | 0.01407 | 0.01946 | 0.02194 | 0.03301 |
| B / Engine | 0.03126 | 0.03735 | 0.04287 | 0.05117 |
| B / Broker | 0.01913 | 0.02491 | 0.02778 | 0.03515 |

Combined mean service CPU is 0.03893% in capture A and 0.05036% in capture B.
The process CPU counters and sampled CPU observations provide supporting
measurements:

| Capture / service | Process CPU counter (ms) | Sampled CPU observations |
| --- | ---: | ---: |
| A / Engine | 218.750 | 23 |
| A / Broker | 109.375 | 32 |
| B / Engine | 187.500 | 36 |
| B / Broker | 93.750 | 105 |

Counter quantization and sparse samples affect these short CPU bursts. Use
scheduler intervals as the primary CPU measurement for this capture; the
supporting values use different measurement methods.

## Context switches per second

A context-switch count records a dispatch into a thread belonging to the
process. The total covers 300 seconds; percentiles describe the per-second
counts:

| Capture / service | Total | Mean/s | Minimum/s | P50/s | P95/s | P99/s | Maximum/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A / Engine | 3497 | 11.657 | 7 | 12 | 14 | 16 | 19 |
| A / Broker | 2020 | 6.733 | 1 | 7 | 8 | 9 | 30 |
| B / Engine | 3550 | 11.833 | 8 | 12 | 15 | 16 | 21 |
| B / Broker | 2008 | 6.693 | 1 | 6 | 8 | 9 | 10 |

## Memory usage

Private bytes measure committed private virtual memory. Working set measures
resident physical pages, including shared pages. Both tables use MiB and the
process-counter samples.

### Capture A

The sampled memory distribution is:

| Service / metric | Minimum | Mean | P50 | P95 | P99 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Engine / private | 1.391 | 1.438 | 1.410 | 1.500 | 1.500 | 1.500 |
| Engine / working set | 7.184 | 7.368 | 7.348 | 7.492 | 7.492 | 7.492 |
| Broker / private | 2.559 | 2.655 | 2.605 | 2.852 | 2.852 | 2.852 |
| Broker / working set | 12.797 | 12.855 | 12.820 | 12.980 | 12.980 | 12.980 |

### Capture B

The sampled memory distribution is:

| Service / metric | Minimum | Mean | P50 | P95 | P99 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Engine / private | 1.418 | 1.445 | 1.430 | 1.508 | 1.508 | 1.508 |
| Engine / working set | 7.461 | 7.519 | 7.508 | 7.559 | 7.559 | 7.559 |
| Broker / private | 2.516 | 2.538 | 2.555 | 2.555 | 2.555 | 2.559 |
| Broker / working set | 12.777 | 12.805 | 12.816 | 12.816 | 12.816 | 12.816 |

The first and last samples show the observed memory change within each
five-minute window. These values use raw bytes:

| Capture / service / metric | First (bytes) | Last (bytes) | Change (bytes) |
| --- | ---: | ---: | ---: |
| A / Engine / private | 1,458,176 | 1,572,864 | 114,688 |
| A / Engine / working set | 7,532,544 | 7,856,128 | 323,584 |
| A / Broker / private | 2,985,984 | 2,727,936 | -258,048 |
| A / Broker / working set | 13,611,008 | 13,443,072 | -167,936 |
| B / Engine / private | 1,499,136 | 1,486,848 | -12,288 |
| B / Engine / working set | 7,823,360 | 7,892,992 | 69,632 |
| B / Broker / private | 2,682,880 | 2,678,784 | -4,096 |
| B / Broker / working set | 13,422,592 | 13,438,976 | 16,384 |

## Handles and threads

Sampled resource counts have the following distribution. Means can be fractional
because they average observations over time:

| Capture / service / resource | Minimum | Mean | P50 | P95 | P99 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A / Engine / handles | 121 | 122.37 | 123 | 124 | 124 | 124 |
| A / Engine / threads | 7 | 7.66 | 7 | 9 | 9 | 9 |
| A / Broker / handles | 242 | 248.90 | 246 | 262 | 262 | 262 |
| A / Broker / threads | 9 | 10.99 | 10 | 15 | 15 | 15 |
| B / Engine / handles | 121 | 122.51 | 123 | 123 | 123 | 123 |
| B / Engine / threads | 7 | 7.47 | 7 | 9 | 9 | 9 |
| B / Broker / handles | 236 | 237.14 | 238 | 238 | 238 | 240 |
| B / Broker / threads | 8 | 8.57 | 9 | 9 | 9 | 9 |

## Thread ready delay and ready time

Capture B supplies the thread-ready measurements. Ready delay is the time from
becoming runnable to being scheduled. Cumulative ready time sums those durations
across threads. WPA `Ready Time (s)` is the trace-relative timestamp at which a
thread becomes runnable. Blocked waits for timers, I/O, or synchronization are
measured separately.

The analysis includes completed episodes whose ready and switch-in timestamps
both fall in the interval from 1 to less than 300 seconds. This gives a
299-second window and excludes 23 boundary dispatches from the 5,560 exported
dispatches. Every duration is checked against switch-in timestamp minus ready
timestamp.

Per-service ready-delay percentiles and accumulated ready time are:

| Metric | Engine | Broker |
| --- | ---: | ---: |
| Completed dispatches | 3,538 | 1,999 |
| Mean ready delay (µs) | 29.58 | 23.67 |
| P50 ready delay (µs) | 24.00 | 21.60 |
| P95 ready delay (µs) | 78.60 | 53.90 |
| P99 ready delay (µs) | 159.70 | 153.10 |
| Maximum ready delay (µs) | 459.90 | 301.00 |
| Cumulative ready time (ms) | 104.65 | 47.32 |
| Delays over 1 ms | 0 | 0 |
| Delays over 10 ms | 0 | 0 |
| Delays over 100 ms | 0 | 0 |

### Per-thread ready time

The following threads account for the five largest accumulated ready times in
each service. Thread IDs identify this recording only. Unnamed threads retain
their numeric ID. The companion CSV includes all 15 threads with completed
observations:

| Service | Thread ID | Thread name | Dispatches | Ready total (ms) | P99 (µs) | Maximum (µs) |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Engine | 2348 | Unnamed | 2780 | 67.396 | 78.7 | 459.9 |
| Engine | 1668 | Unnamed | 379 | 26.531 | 239.5 | 267.0 |
| Engine | 2256 | Unnamed | 251 | 7.268 | 148.1 | 364.6 |
| Engine | 3104 | Unnamed | 119 | 3.092 | 58.9 | 187.8 |
| Engine | 4360 | Unnamed | 4 | 0.197 | 141.5 | 141.5 |
| Broker | 316 | bfd-status-monitor | 707 | 22.108 | 168.8 | 301.0 |
| Broker | 4560 | bfd-status-rpc | 599 | 12.333 | 74.6 | 93.9 |
| Broker | 4052 | Unnamed | 301 | 7.315 | 101.9 | 276.1 |
| Broker | 1296 | Unnamed | 239 | 3.542 | 57.3 | 67.7 |
| Broker | 5984 | Unnamed | 102 | 1.574 | 50.7 | 55.0 |

## Measurement limits

These results describe steady-state operation with one peer, under the recorded
authentication and timing settings. They do not establish capacity limits,
performance with many peers, worst-case latency, long-term leak freedom, or
failure-detection latency.

The guest shares a Hyper-V host with other workloads. Guest-visible memory at
capture start is 1,917.44 MiB for A and 2,033.44 MiB for B. Dynamic memory,
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

- [Service metrics](performance/2026-10-23-telemetry-coalesced/service-metrics.csv): CPU, context-switch, memory, handle, and thread distributions.
- [Service ready time](performance/2026-10-23-telemetry-coalesced/ready-time.csv): dispatch counts, ready-delay percentiles, accumulated time, and delay thresholds.
- [Per-thread ready time](performance/2026-10-23-telemetry-coalesced/thread-ready-time.csv): all measured threads and their ready-delay statistics.
- [Capture metadata](performance/2026-10-23-telemetry-coalesced/capture-metadata.json): exact UTC capture windows, analysis windows, build provenance, source hashes, and binary hashes.

`service-metrics.csv` includes totals for additive CPU-time and context-switch
observations. Empty total fields mark metrics such as percentages and memory
sizes, whose observations are not additive. CSV memory values use bytes;
presentation tables convert them to MiB.

For exact artifact identification, use these SHA-256 hashes:

| Artifact | SHA-256 |
| --- | --- |
| Telemetry-coalescing development engine | `8820E6A779512C97284399A8F408428C0F23A652EF20C20972359B04DB502C85` |
| Event-dispatcher development broker | `3CEFE8F707FBCAAABCFCEBC82C38F04C80F514E0179ACACF8FDD135D46712088` |

The source base is commit `1c191fa3486caf8717e213943d7c7fe190107c53` with the
dispatcher, telemetry, and test changes recorded in the metadata. Other pending
repository changes are outside this measured build. The ETL recordings and
detailed WPA exports remain local capture artifacts; they are not included in
these compact data files.

For operational interpretation, see [service monitoring](monitoring.md). For the
runtime boundaries, see [service communication](service-communication.md).
