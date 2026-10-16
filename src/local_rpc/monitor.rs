//! A single owned RPC worker is supervised inside the broker process.
use super::{query_bfd_session_status, SessionStatus, SessionStatusQueryError};
use crate::runtime::Logger;
use arc_swap::ArcSwap;
use std::{
    io,
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
        Arc, OnceLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const INTERVAL: Duration = Duration::from_secs(1);
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const REPORT_INTERVAL: Duration = Duration::from_secs(60);
const QUERY_BUDGET: Duration = Duration::from_secs(8);
const FRESHNESS: Duration = Duration::from_secs(2);
static CACHE: OnceLock<Arc<ArcSwap<BrokerStatus>>> = OnceLock::new();

/// Broker telemetry availability, independent of provider operation and BFD state.
#[derive(Clone, Debug)]
pub enum BrokerStatus {
    /// No usable result, including service startup, disconnect, or shutdown.
    Unavailable,
    /// A structurally valid observation; check `is_fresh` before using as current.
    Available {
        /// Validated status from one immutable engine publication.
        session: Arc<SessionStatus>,
        /// Broker's monotonic receipt time.
        received_at: Instant,
        /// Entire fetch duration, added as a conservative transit-age allowance.
        fetch_time: Duration,
    },
    /// A stuck native worker disabled telemetry until restart.
    Quarantined,
}

impl BrokerStatus {
    /// Conservative current snapshot age; no UTC subtraction is involved.
    pub fn snapshot_age(&self) -> Option<Duration> {
        match self {
            Self::Available {
                session,
                received_at,
                fetch_time,
            } => Some(
                session
                    .snapshot_age
                    .saturating_add(*fetch_time)
                    .saturating_add(received_at.elapsed()),
            ),
            _ => None,
        }
    }

    /// Whether a validated observation is within the two-second monitoring policy.
    pub fn is_fresh(&self) -> bool {
        self.snapshot_age().is_some_and(|age| age <= FRESHNESS)
    }
}

/// Reads the broker's cache without initiating RPC. `None` means no monitor started.
pub fn cached_bfd_session_status() -> Option<Arc<BrokerStatus>> {
    CACHE.get().map(|cache| cache.load_full())
}

pub(super) fn quarantined() -> bool {
    CACHE
        .get()
        .is_some_and(|cache| matches!(*cache.load_full(), BrokerStatus::Quarantined))
}

enum Event {
    Complete(Result<Arc<SessionStatus>, SessionStatusQueryError>, Instant),
    Stop,
}

pub(crate) struct Monitor {
    stop: SyncSender<Event>,
    supervisor: Option<JoinHandle<()>>,
}

impl Monitor {
    pub(crate) fn start(log: Logger) -> io::Result<Self> {
        let cache = Arc::new(ArcSwap::from_pointee(BrokerStatus::Unavailable));
        CACHE.set(Arc::clone(&cache)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "BFD status monitor already initialized",
            )
        })?;
        Self::with_query(log, cache, query_bfd_session_status, QUERY_BUDGET, INTERVAL)
    }

    fn with_query(
        log: Logger,
        cache: Arc<ArcSwap<BrokerStatus>>,
        mut query: impl FnMut() -> Result<SessionStatus, SessionStatusQueryError> + Send + 'static,
        budget: Duration,
        interval: Duration,
    ) -> io::Result<Self> {
        // At most one completion and one Stop can be outstanding. No query backlog.
        let (events, receiver) = mpsc::sync_channel(2);
        let (request, requests) = mpsc::sync_channel(1);
        let completed = events.clone();
        let worker = thread::Builder::new()
            .name("bfd-status-rpc".into())
            .spawn(move || {
                while requests.recv().is_ok() {
                    let started = Instant::now();
                    let result = query().map(Arc::new);
                    if completed.send(Event::Complete(result, started)).is_err() {
                        break;
                    }
                }
            })?;
        let supervisor = thread::Builder::new()
            .name("bfd-status-monitor".into())
            .spawn(move || {
                supervise(log, &cache, &receiver, &request, budget, interval);
                cache.store(Arc::new(BrokerStatus::Unavailable));
                drop(request);
                // A pending call owns all of its native state on this one worker.
                // Detaching preserves that ownership; never kill a Rust/native thread.
                // No replacement worker is started, so retained storage stays bounded.
                if worker.is_finished() {
                    let _ = worker.join();
                }
            })?;
        Ok(Self {
            stop: events,
            supervisor: Some(supervisor),
        })
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.stop.send(Event::Stop);
        if let Some(supervisor) = self.supervisor.take() {
            let _ = supervisor.join();
        }
    }
}

fn supervise(
    mut log: Logger,
    cache: &ArcSwap<BrokerStatus>,
    events: &Receiver<Event>,
    request: &SyncSender<()>,
    budget: Duration,
    interval: Duration,
) {
    let mut connected = false;
    let mut last_unavailable_report = None;
    let mut last_rejected_report = None;
    let mut last_stale_report = None;
    let mut retry = RetryBackoff::new(interval);
    loop {
        if request.try_send(()).is_err() {
            break;
        }
        let result = match events.recv_timeout(budget) {
            Ok(Event::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Event::Complete(result, started)) => (result, started.elapsed()),
            Err(RecvTimeoutError::Timeout) => {
                cache.store(Arc::new(BrokerStatus::Quarantined));
                log.broker_message(
                    "BFD status worker stalled; telemetry quarantined until broker restart",
                    true,
                );
                wait_for_stop(events);
                break;
            }
        };
        let delay = match result {
            (Ok(status), fetch_time) => {
                retry.reset();
                let value = BrokerStatus::Available {
                    session: status,
                    received_at: Instant::now(),
                    fetch_time,
                };
                let fresh = value.is_fresh();
                cache.store(Arc::new(value));
                if !connected {
                    log.broker_message("BFD local RPC mutual service identity verified", false);
                }
                connected = true;
                if !fresh && report_due(&mut last_stale_report) {
                    log.broker_message(
                        "BFD session telemetry stale; provider control unchanged",
                        false,
                    );
                }
                interval
            }
            (Err(SessionStatusQueryError::Quarantined), _) => {
                // The public query guard already knows that native storage is
                // retained. Never clear that latch or launch another call.
                cache.store(Arc::new(BrokerStatus::Quarantined));
                wait_for_stop(events);
                break;
            }
            (Err(error), _) => {
                // A completed, rejected reply is not evidence of process memory
                // corruption. Discard the complete record and prior status;
                // retry on this same worker after backoff, keeping provider work
                // independent. Fatal native exceptions are not recovered here.
                cache.store(Arc::new(BrokerStatus::Unavailable));
                connected = false;
                let rejected = error.invalid_data();
                let last_report = if rejected {
                    &mut last_rejected_report
                } else {
                    &mut last_unavailable_report
                };
                if report_due(last_report) {
                    let message = if rejected {
                        "BFD status rejected; telemetry unavailable; retrying"
                    } else {
                        "BFD session status unavailable; retrying"
                    };
                    log.broker_message(format_args!("{message}: {error}"), rejected);
                }
                retry.next_delay()
            }
        };
        // Stop wakes both normal polling and even the longest retry delay.
        match events.recv_timeout(delay) {
            Err(RecvTimeoutError::Timeout) => {}
            _ => break,
        }
    }
}

struct RetryBackoff {
    interval: Duration,
    next: Duration,
}

impl RetryBackoff {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            next: interval,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = delay.saturating_mul(2).min(MAX_RETRY_INTERVAL);
        delay
    }

    fn reset(&mut self) {
        self.next = self.interval;
    }
}

fn report_due(last: &mut Option<Instant>) -> bool {
    let now = Instant::now();
    if last.is_none_or(|last| now.duration_since(last) >= REPORT_INTERVAL) {
        *last = Some(now);
        true
    } else {
        false
    }
}

fn wait_for_stop(events: &Receiver<Event>) {
    while let Ok(event) = events.recv() {
        if matches!(event, Event::Stop) {
            break;
        }
    }
}

#[cfg(test)]
mod tests;
