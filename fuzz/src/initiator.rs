//! Stateful S-BFD exchanges with an independent outstanding-probe model.
use super::{auth, options, Snapshot, FRAME_LEN, MAX_STEPS, REFLECTOR_DISC, TYPES};
use bfd_winservice::{
    config::{SessionType, Timing},
    packet::{AuthConfig, AuthType, ControlPacket, State},
    seamless::Reflector,
    session::Session,
};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

struct Probe {
    request: Vec<u8>,
    sequence: Option<u32>,
    sent_at: Instant,
    consumed: bool,
}

struct Oracle {
    session: Session,
    reflector: Reflector,
    auth: AuthConfig,
    probes: VecDeque<Probe>,
    previous_sequence: Option<u32>,
}

impl Oracle {
    fn new(selector: u8) -> Self {
        let kind = TYPES[usize::from(selector & 3)];
        let mut config = options(kind, u32::from(selector));
        config.mode = bfd_winservice::config::Mode::SingleHop;
        config.session_type = SessionType::SbfdInitiator;
        config.remote_discriminator = Some(REFLECTOR_DISC);
        let mut reflector = config.clone();
        reflector.local = config.peer;
        reflector.session_type = SessionType::SbfdReflector;
        reflector.discriminator = Some(REFLECTOR_DISC);
        reflector.remote_discriminator = None;
        Self {
            session: Session::from_config(
                config.into_validated().expect("valid initiator fixture"),
            ),
            reflector: Reflector::from_config(
                &reflector.into_validated().expect("valid reflector fixture"),
            )
            .expect("reflector role"),
            auth: auth(kind, u32::from(selector)),
            probes: VecDeque::new(),
            previous_sequence: None,
        }
    }

    fn transmit(&mut self, now: Instant) -> Vec<u8> {
        // The public packet API commits generation as a transmission. The native
        // runtime's separate prepare/commit failure path has crate unit tests.
        let request = self.session.packet_at(false, now);
        let sequence = self
            .auth
            .verify(&request, None)
            .expect("valid generated probe");
        if let (Some(previous), Some(current)) = (self.previous_sequence, sequence) {
            assert_eq!(current, previous.wrapping_add(1));
        }
        self.previous_sequence = sequence;
        if self.probes.len() == MAX_STEPS {
            self.probes.pop_front();
        }
        self.probes.push_back(Probe {
            request: request.clone(),
            sequence,
            sent_at: now,
            consumed: false,
        });
        request
    }

    fn receive(&mut self, wire: &[u8], now: Instant) -> bool {
        let before = Snapshot::of(&self.session);
        let sequence = self.auth.verify(wire, None).ok().flatten();
        let outstanding = sequence.and_then(|sequence| {
            self.probes.iter().position(|probe| {
                probe.sequence == Some(sequence)
                    && !probe.consumed
                    && now.saturating_duration_since(probe.sent_at) < self.session.detection_time()
            })
        });
        if self.session.receive(wire, now).is_err() {
            assert_eq!(Snapshot::of(&self.session), before);
            return false;
        }
        let reply = ControlPacket::decode(wire).expect("accepted response header");
        assert!(!reply.demand);
        assert_eq!(reply.my_discriminator, REFLECTOR_DISC);
        assert_eq!(reply.your_discriminator, self.session.local_discriminator());
        assert!(matches!(reply.state, State::Up | State::AdminDown));
        assert!(self.auth.verify(wire, None).is_ok());
        if matches!(
            self.auth.kind(),
            AuthType::KeyedSha1 | AuthType::MeticulousSha1
        ) {
            self.probes[outstanding.expect("accepted keyed reply requires an outstanding probe")]
                .consumed = true;
        }
        assert!(self.session.communicating());
        assert_eq!(
            self.session.state(),
            if reply.state == State::Up {
                State::Up
            } else {
                State::Down
            }
        );
        if reply.state == State::AdminDown {
            assert!(self.session.jittered_interval() >= Duration::from_secs(1));
        }
        true
    }

    fn exchange(&mut self, now: Instant) {
        let request = self.transmit(now);
        let reply = self
            .reflector
            .respond(&request)
            .expect("valid generated request");
        assert!(self.receive(&reply, now));
    }
}

pub(super) fn check(data: &[u8]) {
    let Some((&selector, frames)) = data.split_first() else {
        return;
    };
    let mut oracle = Oracle::new(selector);
    let mut now = Instant::now();
    for frame in frames.chunks(FRAME_LEN).take(MAX_STEPS) {
        let Some((&action, rest)) = frame.split_first() else {
            continue;
        };
        let Some((&delta, payload)) = rest.split_first() else {
            continue;
        };
        now += Duration::from_millis(u64::from(delta) * 10);
        match action & 7 {
            0 => {
                oracle.receive(payload, now);
            }
            1 => oracle.exchange(now),
            2 => {
                let expired = oracle
                    .session
                    .detection_deadline()
                    .is_some_and(|end| now >= end);
                oracle.session.expire(now);
                if expired {
                    oracle.probes.clear();
                }
            }
            3 => {
                let timing = Timing::new(
                    super::word(payload, 0).max(1),
                    super::word(payload, 4).max(1),
                    delta.max(1),
                )
                .expect("nonzero timing");
                let _ = oracle.session.set_timing(timing);
            }
            4 => {
                oracle.transmit(now);
            } // A transmitted probe with a lost reply.
            5 => {
                if !oracle.probes.is_empty() {
                    let index =
                        usize::from(payload.first().copied().unwrap_or(0)) % oracle.probes.len();
                    let reply = oracle
                        .reflector
                        .respond(&oracle.probes[index].request)
                        .expect("retained request");
                    oracle.receive(&reply, now); // Includes delayed and consumed replies.
                }
            }
            6 => {
                let request = oracle.transmit(now);
                let reply = oracle
                    .reflector
                    .respond(&request)
                    .expect("generated request");
                let mut packet = ControlPacket::decode(&reply).expect("generated response");
                let sequence = oracle
                    .auth
                    .verify(&reply, None)
                    .expect("generated authentication");
                if let Some(sequence) = sequence {
                    // At most 32 consecutive sequences can be outstanding.
                    let unissued = packet.encode(&oracle.auth, sequence.wrapping_add(1024));
                    let before = Snapshot::of(&oracle.session);
                    assert!(oracle.session.receive(&unissued, now).is_err());
                    assert_eq!(Snapshot::of(&oracle.session), before);
                }
                packet.your_discriminator = oracle.session.local_discriminator().wrapping_add(1);
                let invalid = packet.encode(&oracle.auth, sequence.unwrap_or(0));
                let before = Snapshot::of(&oracle.session);
                assert!(oracle.session.receive(&invalid, now).is_err());
                assert_eq!(Snapshot::of(&oracle.session), before);
                assert!(oracle.receive(&reply, now)); // Rejection cannot consume the valid probe.
            }
            7 => {
                oracle
                    .reflector
                    .set_admin_down(payload.first().copied().unwrap_or(0) & 1 != 0);
                oracle.exchange(now);
            }
            _ => unreachable!("three action bits"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_authentication_modes_cover_exchange_loss_replay_reload_and_maintenance() {
        for selector in 0..4 {
            let mut input = vec![selector];
            for (action, delta, value) in [
                (1, 0, 0),
                (5, 0, 0),
                (4, 0, 0),
                (2, 255, 0),
                (5, 0, 0),
                (3, 1, 1),
                (1, 0, 0),
                (6, 0, 0),
                (7, 0, 1),
                (7, 0, 0),
            ] {
                let mut frame = [0; FRAME_LEN];
                frame[0] = action;
                frame[1] = delta;
                frame[2] = value;
                input.extend_from_slice(&frame);
            }
            check(&input);
        }
    }
}
