//! An in-process state snapshot for library users and integration tests.
//! This lightweight view stays in-process. RPC reads a separate coherent
//! multi-field snapshot rather than merging this atomic state into older data.
#![forbid(unsafe_code)]

use crate::packet::State;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

const UNAVAILABLE: u8 = u8::MAX;

/// A live snapshot of the engine's local BFD state.
/// Clones share one atomic value without locking the packet loop.
#[derive(Clone)]
pub struct StateObserver {
    value: Arc<AtomicU8>,
}

impl StateObserver {
    /// Returns the current state, or `None` after the engine exits or is dropped.
    pub fn current(&self) -> Option<State> {
        // This atomic is the entire snapshot, with no dependent memory to publish.
        match self.value.load(Ordering::Relaxed) {
            0 => Some(State::AdminDown),
            1 => Some(State::Down),
            2 => Some(State::Init),
            3 => Some(State::Up),
            _ => None,
        }
    }
}

pub(crate) struct StatePublisher(StateObserver);

impl StatePublisher {
    pub(crate) fn new(state: State) -> Self {
        Self(StateObserver {
            value: Arc::new(AtomicU8::new(state as u8)),
        })
    }

    pub(crate) fn observer(&self) -> StateObserver {
        self.0.clone()
    }

    pub(crate) fn publish(&self, state: State) {
        self.0.value.store(state as u8, Ordering::Relaxed);
    }

    pub(crate) fn close(&self) {
        self.0.value.store(UNAVAILABLE, Ordering::Relaxed);
    }
}

impl Drop for StatePublisher {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observers_follow_transitions_and_become_unavailable_after_drop() {
        let publisher = StatePublisher::new(State::Down);
        let observer = publisher.observer();
        assert_eq!(observer.current(), Some(State::Down));
        for state in [State::Init, State::Up, State::Down, State::AdminDown] {
            publisher.publish(state);
            assert_eq!(observer.current(), Some(state));
        }
        drop(publisher);
        assert_eq!(observer.current(), None);
    }
}
