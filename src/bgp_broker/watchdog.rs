//! Tracks provider calls separately from idle RPC waits.
use crate::bgp::Method;
use std::{
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

/// A provider request, including schema lookup and cleanup, must finish within
/// this wall-clock budget. MI's own timeout is only advisory.
pub(super) const PROVIDER_BUDGET: Duration = Duration::from_secs(20);

#[derive(Default)]
pub(super) struct ProviderWatch(Mutex<Option<(Method, Instant)>>);

impl ProviderWatch {
    pub(super) fn begin(&self, method: Method) -> ProviderCall<'_> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((method, Instant::now()));
        ProviderCall(self)
    }

    pub(super) fn expired(&self, now: Instant) -> Option<Method> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .filter(|(_, started)| now.saturating_duration_since(*started) >= PROVIDER_BUDGET)
            .map(|(method, _)| method)
    }
}

pub(super) struct ProviderCall<'a>(&'a ProviderWatch);

impl Drop for ProviderCall<'_> {
    fn drop(&mut self) {
        *self.0 .0.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread};

    #[test]
    fn stalled_provider_is_detected_while_idle_and_completed_requests_are_exempt() {
        let watch = ProviderWatch::default();
        assert_eq!(watch.expired(Instant::now() + PROVIDER_BUDGET * 2), None);
        let (entered, started) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        thread::scope(|scope| {
            let worker_watch = &watch;
            let worker = scope.spawn(move || {
                let _call = worker_watch.begin(Method::Start);
                entered.send(Instant::now()).unwrap();
                blocked.recv().unwrap();
            });
            let now = started.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(watch.expired(now), None);
            assert_eq!(watch.expired(now + PROVIDER_BUDGET), Some(Method::Start));
            release.send(()).unwrap();
            worker.join().unwrap();
        });
        assert_eq!(watch.expired(Instant::now() + PROVIDER_BUDGET * 2), None);
    }
}
