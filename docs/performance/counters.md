# Interpret the performance counters

Use this reference with the [Windows service measurements](../performance.md).
**Lower** means less overhead for the **same successful workload**, with the
same BFD timers, authentication, hardware, and capture settings. Reducing work
by dropping packets, missing deadlines, or disconnecting a peer is not an
improvement.

Microsoft's sources below define the counters and scheduling behavior. The
“Better” guidance is an interpretation for this service workload, not a
Microsoft performance threshold. Sources were checked on October 23, 2026.

## CPU and scheduling

The report uses scheduler intervals as its primary CPU measurement. The
[Microsoft CPU analysis reference](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis)
distinguishes running, ready, and waiting time and explains how WPA derives
CPU usage and context-switch counts.

| Data point | Meaning | Better |
| --- | --- | --- |
| Scheduled CPU, total or per second (`scheduled_cpu`, `CpuMilliseconds`) | Sum of thread execution intervals on the guest CPUs, in milliseconds. | Lower for the same completed work. |
| VM CPU percentage (`cpu_vm`, `CpuPercentVm`) | Scheduled time divided by elapsed time and guest logical processor count. | Lower for the same work; 100% uses every guest CPU. |
| One-core CPU percentage | Scheduled time divided by elapsed time, without dividing by processor count. | Lower for the same work; can exceed 100% across threads. |
| Process CPU total (`CpuSeconds`) | Accumulated user plus kernel execution time since process start. Compare the last-minus-first capture delta. | Lower delta for equal work and duration; the lifetime total alone is not comparable. |
| User CPU (`UserCpuSeconds`) | Accumulated execution outside the operating system core. | Lower capture delta for equal work. |
| Kernel CPU (`KernelCpuSeconds`) | Accumulated execution inside the operating system core on behalf of the process. | Lower capture delta for equal work; moving work between user and kernel mode is not itself a win. |
| Sampled CPU weight | Estimated CPU time from periodic observations of running threads. | Lower estimated time for equal work; sparse observations make this a supporting measure. |
| Sampled CPU observations | Number of sampled running-thread observations. | No independent direction; this is evidence coverage, not a throughput score. |
| Context switches, total or per second (`context_switches`, `ContextSwitches`) | Dispatches into the service's threads, counted once per switch-in. | Generally lower for equal work, provided responsiveness remains adequate. Zero is not a target for an active service. |
| Mean execution time per dispatch | Scheduled CPU divided by switch-in count. | Context dependent: longer runs can mean useful batching or more processing per wake. Assess CPU and responsiveness together. |
| Per-thread CPU and dispatch count | Execution time and switch-ins attributed to a thread. | CPU is lower for equal work; dispatch count is diagnostic and depends on the thread's role. |

The process counters come from .NET
[TotalProcessorTime](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.totalprocessortime?view=net-10.0),
[UserProcessorTime](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.userprocessortime?view=net-10.0),
and [PrivilegedProcessorTime](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.privilegedprocessortime?view=net-10.0).
Windows performs context switches to run ready threads or when a thread waits,
as described in [Context switches](https://learn.microsoft.com/en-us/windows/win32/procthread/context-switches).
Fewer unnecessary wakeups can reduce overhead; blocking while awaiting the
next packet or timer is normal.

## Memory and process resources

| Data point | Meaning | Better |
| --- | --- | --- |
| Private bytes (`private_memory`, `PrivateBytes`) | Private committed virtual memory that cannot be shared with other processes. | Lower for equal work, with a stable footprint after warmup. Persistent growth warrants investigation. |
| WPA process commit (`wpa_commit`) | Committed memory charged to the process in WPA memory snapshots. | Lower for equal work; compare like-for-like snapshots, not physical RAM. |
| Working set (`working_set`, `WorkingSetBytes`, `wpa_working_set`) | Pageable process memory resident in physical RAM, including shared pages. | Context dependent. A smaller useful footprint helps, but trimming can lower this counter while increasing page faults. |
| Private working set (`wpa_private_working_set`) | Resident working-set pages private to the process. | Context dependent for the same reason; do not force it down by trimming. |
| Virtual bytes (`virtual_memory`, `VirtualBytes`) | Virtual memory allocated to the process. | No universal direction. Look for bounded address-space use; this is not resident RAM or private commit. |
| Handles (`handles`, `Handles`) | Open operating-system object handles. | Stable and bounded for the workload. Lower is useful only when unnecessary handles are eliminated; growth can indicate a leak. |
| Threads (`threads`, `Threads`) | Threads associated with the process, including waiting threads. | Stable and appropriate for the workload. Fewer unnecessary threads can help; too few can delay work. |

Definitions: [PrivateMemorySize64](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.privatememorysize64?view=net-10.0),
[WorkingSet64](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.workingset64?view=net-10.0),
[VirtualMemorySize64](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.virtualmemorysize64?view=net-10.0),
[HandleCount](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.handlecount?view=net-10.0),
and [Threads](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.threads?view=net-10.0).
The Windows [extended process memory counters](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex2)
define process commit charge and private working set.
Microsoft's [Working set](https://learn.microsoft.com/en-us/windows/win32/memory/working-set)
reference explains trimming and page faults; its
[Virtual address space](https://learn.microsoft.com/en-us/windows/win32/memory/virtual-address-space)
reference explains why virtual addresses differ from physical storage.

## Thread ready delay and ready time

Ready delay measures the time between a thread becoming runnable and its
next switch-in. Waiting for a timer, network input, or synchronization object
is a separate state. See Microsoft's
[CPU analysis](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis)
and [ready-time analysis example](https://techcommunity.microsoft.com/blog/askperf/understanding-lock-contention-in-windows-performance-analyzer-wpa/3507387).

| Data point | Meaning | Better |
| --- | --- | --- |
| Ready delay (`ReadyDelayMicroseconds`, mean/P50/P95/P99/maximum ready µs) | Per-dispatch time runnable but not executing. | Lower, including the tail percentiles and maximum. |
| Total ready time (`total_ready_ms`, `TotalReadyMilliseconds`) | Sum of the included completed ready episodes across the service's threads. | Lower for equal work and window length; can overlap across threads. |
| Cumulative ready time | Running sum of total ready time across the capture. | Lower at the same elapsed point and workload; it naturally increases as episodes accumulate. |
| Average concurrent ready threads | Included total ready seconds divided by the 299-second analysis window. | Lower for equal work. This completed-episode estimate omits boundary-crossing episodes. |
| Delays over 1, 10, or 100 ms | Counts, or fractions, of included episodes exceeding the threshold. | Lower at equal workload and coverage; these are diagnostic cutoffs, not service deadlines. |
| Completed dispatches (`count`, `Dispatches`) | Number of ready episodes included in the analysis. | No independent direction; interpret delay distributions with this population size. |
| Blocked wait (`BlockedWaitMicroseconds`) | Time waiting before becoming ready. Retained in the local detailed export. | Context dependent: sleeping until the next packet or timer is expected, while an unintended dependency can be harmful. |

The report includes only episodes whose ready timestamp is at least 1 second
and whose switch-in is before 300 seconds. Total ready time is a sum over
those episodes, not a full time-weighted integral of all runnable threads.

## Statistics, health, and capture metadata

| Data point | Better / interpretation |
| --- | --- |
| Minimum, mean, P50, P95, P99, maximum, first, last | Inherit the underlying metric's direction. P95/P99 are tail values, not percentages of CPU by themselves. |
| Resource change (`delta = last - first`) | Bounded, stable use is desirable after warmup. Near zero supports stability; a negative delta is not automatically better. |
| BGP/route health checks and pass fraction | Higher pass fraction is better; the target is 100%. More checks improve observation coverage, not service speed. |
| BFD Up, BGP Connected/Established, expected routes present | Healthy/present is better. These are state checks, not continuous latency measurements. |
| Unexpected restarts, BFD state changes, or error events | Lower; zero is the target during this steady-state workload. Event severity and cause still matter. |
| Lost ETW events and lost buffers | Lower; zero is required for an unqualified scheduler analysis. Loss means incomplete evidence. |
| Sample count, snapshot count, capture duration, excluded boundary dispatches | Evidence metadata, without a universal higher/lower target. More coverage can improve confidence but costs recording time and overhead. |
| CPU count, guest memory, timers, authentication, routes | Configuration, without a higher/lower ranking in this report. Keep them comparable between runs. |
| Timestamp, elapsed time, capture label, process/thread ID or name, binary version/hash, source commit, profile hash, tool version | Identity and provenance, without a performance direction. |

Microsoft defines lost events and buffers in
[EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties).
Zero loss does not remove profiler overhead or make a short lab capture a
production capacity test.
