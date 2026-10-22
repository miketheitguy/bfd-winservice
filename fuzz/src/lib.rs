//! Bounded, socket-free fuzzing oracles for BFD's untrusted packet boundaries.
#![deny(unsafe_code)]

mod initiator;
#[cfg(all(feature = "fuzzing", target_env = "msvc"))]
#[allow(unsafe_code)]
mod msvc_coverage;
#[cfg(any(feature = "fuzzing", test))]
mod mutators;

use bfd_winservice::{
    config::{Mode, Options, Timing},
    packet::{AuthConfig, AuthType, ControlPacket, Diagnostic, State},
    seamless::Reflector,
    session::Session,
};
use std::time::{Duration, Instant};

const TYPES: [AuthType; 5] = [
    AuthType::None,
    AuthType::SimplePassword,
    AuthType::KeyedSha1,
    AuthType::MeticulousSha1,
    AuthType::MeticulousMd5,
];
const KEY_ID: u8 = 7;
const LOCAL_DISC: u32 = 7;
const REFLECTOR_DISC: u32 = 42;
const FRAME_LEN: usize = 64;
const MAX_STEPS: usize = 32;
const MAX_PACKET_INPUT: usize = 256;

/// Checks stateful S-BFD probing, correlation, replay rejection, and live timing.
pub fn check_initiator(data: &[u8]) {
    initiator::check(data);
}

/// Registers MSVC sanitizer-coverage sections after the C++ runtime is ready.
///
/// Fuzz targets must call this before evaluating their first input. Other
/// toolchains use libFuzzer's normal startup registration.
#[cfg(feature = "fuzzing")]
pub fn initialize_fuzzer_coverage() {
    #[cfg(target_env = "msvc")]
    msvc_coverage::initialize();
}

/// Mutates a packet-target input while retaining a path through byte-level mutation.
#[cfg(feature = "fuzzing")]
pub fn mutate_packet_input(data: &mut [u8], size: usize, max_size: usize, seed: u32) -> usize {
    mutators::mutate_packet(data, size, max_size, seed, |buffer, current, limit| {
        libfuzzer_sys::fuzzer_mutate(buffer, current, limit)
    })
}

/// Mutates a session-target input while preserving useful action-frame structure.
#[cfg(feature = "fuzzing")]
pub fn mutate_session_input(data: &mut [u8], size: usize, max_size: usize, seed: u32) -> usize {
    mutators::mutate_session(data, size, max_size, seed, |buffer, current, limit| {
        libfuzzer_sys::fuzzer_mutate(buffer, current, limit)
    })
}

/// Mutates a reflector-target input and periodically emits valid signed requests.
#[cfg(feature = "fuzzing")]
pub fn mutate_reflector_input(data: &mut [u8], size: usize, max_size: usize, seed: u32) -> usize {
    mutators::mutate_reflector(data, size, max_size, seed, |buffer, current, limit| {
        libfuzzer_sys::fuzzer_mutate(buffer, current, limit)
    })
}

fn auth(kind: AuthType, public_value: u32) -> AuthConfig {
    let key = if kind == AuthType::None {
        vec![]
    } else {
        public_value.to_be_bytes().to_vec()
    };
    AuthConfig::new(kind, KEY_ID, key)
        .expect("four input-derived bytes fit every authentication mode")
}

fn options(kind: AuthType, public_value: u32) -> Options {
    let mut options = Options::new([192, 0, 2, 1].into(), [192, 0, 2, 2].into());
    options.mode = Mode::Multihop;
    options.discriminator = Some(LOCAL_DISC);
    options.auth = kind;
    options.auth_key_id = KEY_ID;
    options.auth_key_hex = (kind != AuthType::None).then(|| format!("{public_value:08x}"));
    options.min_tx_us = 100_000;
    options.min_rx_us = 100_000;
    options
}

fn peer(state: State) -> ControlPacket {
    ControlPacket {
        diagnostic: 0,
        state,
        poll: false,
        final_bit: false,
        control_plane_independent: false,
        demand: false,
        detect_mult: 3,
        my_discriminator: 99,
        your_discriminator: LOCAL_DISC,
        desired_min_tx_us: 100_000,
        required_min_rx_us: 100_000,
        required_min_echo_rx_us: 0,
    }
}

fn word(data: &[u8], offset: usize) -> u32 {
    let mut bytes = [0; 4];
    for (destination, source) in bytes.iter_mut().zip(data.iter().skip(offset)) {
        *destination = *source;
    }
    u32::from_le_bytes(bytes)
}

fn wire_word(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("accepted control packet has a complete fixed header"),
    )
}

fn assert_control_acceptance(data: &[u8]) {
    let declared = usize::from(data[3]);
    let authenticated = data[1] & 0x04 != 0;
    assert_eq!(data[0] >> 5, 1);
    assert!(declared <= data.len());
    assert!(if authenticated {
        declared >= 26
    } else {
        declared == 24
    });
    assert_ne!(data[2], 0);
    assert_eq!(data[1] & 1, 0);
    assert_ne!(data[1] & 0x30, 0x30);
    assert_ne!(wire_word(data, 4), 0);
    assert_ne!(wire_word(data, 12), 0);
    if data[1] >> 6 >= 2 {
        assert_ne!(wire_word(data, 8), 0);
    }
}

fn assert_auth_acceptance(
    data: &[u8],
    kind: AuthType,
    last_sequence: Option<u32>,
    sequence: Option<u32>,
) {
    assert_control_acceptance(data);
    let declared = usize::from(data[3]);
    match kind {
        AuthType::None => {
            assert_eq!(declared, 24);
            assert_eq!(data[1] & 0x04, 0);
            assert_eq!(sequence, None);
        }
        AuthType::SimplePassword => {
            assert_ne!(data[1] & 0x04, 0);
            let material = wire_word(data, 4).to_be_bytes();
            assert_eq!(declared, 27 + material.len());
            let auth_length = u8::try_from(3 + material.len())
                .expect("four input-derived bytes fit the authentication length");
            assert_eq!(
                &data[24..27],
                &[AuthType::SimplePassword as u8, auth_length, KEY_ID]
            );
            assert_eq!(&data[27..declared], &material);
            assert_eq!(sequence, None);
        }
        AuthType::MeticulousMd5 | AuthType::KeyedSha1 | AuthType::MeticulousSha1 => {
            assert_ne!(data[1] & 0x04, 0);
            let auth_length = if kind == AuthType::MeticulousMd5 {
                24
            } else {
                28
            };
            assert_eq!(declared, 24 + usize::from(auth_length));
            assert_eq!(data[24], kind as u8);
            assert_eq!(data[25], auth_length);
            assert_eq!(data[26], KEY_ID);
            let accepted = sequence.expect("keyed authentication returns its sequence");
            assert_eq!(accepted, wire_word(data, 28));
            if let Some(last) = last_sequence {
                let delta = accepted.wrapping_sub(last);
                assert!(delta <= 3 * u32::from(data[2]));
                if matches!(kind, AuthType::MeticulousMd5 | AuthType::MeticulousSha1) {
                    assert_ne!(delta, 0);
                }
            }
        }
    }
}

/// Checks arbitrary decoding, configured authentication, and canonical round trips.
pub fn check_packet(data: &[u8]) {
    let data = &data[..data.len().min(MAX_PACKET_INPUT)];
    let decoded = ControlPacket::decode(data);
    if decoded.is_ok() {
        assert_control_acceptance(data);
    }
    for kind in TYPES {
        let auth = auth(kind, word(data, 4).swap_bytes());
        for last_sequence in [None, Some(word(data, 0))] {
            if let Ok(sequence) = auth.verify(data, last_sequence) {
                assert_auth_acceptance(data, kind, last_sequence, sequence);
            }
        }
        if let Ok(packet) = &decoded {
            let encoded = packet.encode(&auth, u32::MAX);
            assert_eq!(ControlPacket::decode(&encoded).as_ref(), Ok(packet));
            let expected = matches!(
                kind,
                AuthType::MeticulousMd5 | AuthType::KeyedSha1 | AuthType::MeticulousSha1
            )
            .then_some(u32::MAX);
            assert_eq!(auth.verify(&encoded, None), Ok(expected));
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    state: State,
    diagnostic: Diagnostic,
    local_disc: u32,
    remote_disc: u32,
    remote_state: State,
    remote_diag: u8,
    polling: bool,
    communicating: bool,
    desired_tx: u32,
    tx: Duration,
    detection: Duration,
    deadline: Option<Instant>,
    can_transmit: bool,
    periodic: bool,
}

impl Snapshot {
    fn of(session: &Session) -> Self {
        Self {
            state: session.state(),
            diagnostic: session.diagnostic(),
            local_disc: session.local_discriminator(),
            remote_disc: session.remote_discriminator(),
            remote_state: session.remote_state(),
            remote_diag: session.remote_diagnostic(),
            polling: session.polling(),
            communicating: session.communicating(),
            desired_tx: session.desired_min_tx_us(),
            tx: session.transmit_interval(),
            detection: session.detection_time(),
            deadline: session.detection_deadline(),
            can_transmit: session.can_transmit(),
            periodic: session.periodic_enabled(),
        }
    }
}

fn generated_packet(data: &[u8]) -> ControlPacket {
    let mut packet = peer(match data.first().copied().unwrap_or(0) & 3 {
        0 => State::AdminDown,
        1 => State::Down,
        2 => State::Init,
        _ => State::Up,
    });
    let flags = data.get(1).copied().unwrap_or(0);
    packet.diagnostic = flags & 31;
    packet.poll = flags & 32 != 0;
    packet.final_bit = !packet.poll && flags & 64 != 0;
    packet.demand = flags & 128 != 0;
    packet.my_discriminator = word(data, 2).max(1);
    packet.detect_mult = data.get(6).copied().unwrap_or(1).max(1);
    packet.desired_min_tx_us = word(data, 7).max(1);
    packet.required_min_rx_us = word(data, 11);
    packet
}

/// Compares a session against one that never receives rejected packets.
/// The input selects authentication, then up to 32 fixed-size action frames.
/// Valid signed packets exercise state transitions without disabling authentication.
pub fn check_session(data: &[u8]) {
    let Some((&selector, frames)) = data.split_first() else {
        return;
    };
    let kind = TYPES[usize::from(selector) % TYPES.len()];
    let public_value = u32::from(selector);
    let config = options(kind, public_value)
        .into_validated()
        .expect("fixed fuzz configuration is valid");
    let auth = auth(kind, public_value);
    let mut session = Session::from_config(config.clone());
    let mut reference = Session::from_config(config);
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
                let before = Snapshot::of(&session);
                let result = session.receive(payload, now);
                if result.is_err() {
                    assert_eq!(Snapshot::of(&session), before);
                } else {
                    assert_eq!(reference.receive(payload, now), result);
                }
            }
            1 => {
                let packet = generated_packet(payload).encode(&auth, word(payload, 15));
                assert_eq!(
                    session.receive(&packet, now),
                    reference.receive(&packet, now)
                );
            }
            2 => assert_eq!(session.expire(now), reference.expire(now)),
            3 => {
                let timing = Timing::new(
                    word(payload, 0).max(1),
                    word(payload, 4).max(1),
                    delta.max(1),
                )
                .expect("bounded nonzero timing is valid");
                assert_eq!(session.set_timing(timing), reference.set_timing(timing));
            }
            4..=7 => {
                let mut packet = generated_packet(payload);
                let wire = match action & 7 {
                    4 => {
                        let mut wire = packet.encode(&auth, word(payload, 15));
                        wire[0] &= 0x1f;
                        wire
                    }
                    5 => {
                        packet.your_discriminator = LOCAL_DISC + 1;
                        packet.encode(&auth, word(payload, 15))
                    }
                    6 => {
                        packet.my_discriminator = 0;
                        packet.encode(&auth, word(payload, 15))
                    }
                    7 => {
                        let mut wire = packet.encode(&auth, word(payload, 15));
                        wire.pop();
                        wire
                    }
                    _ => unreachable!("action is in the rejection range"),
                };
                let before = Snapshot::of(&session);
                assert!(session.receive(&wire, now).is_err());
                assert_eq!(Snapshot::of(&session), before);
            }
            _ => unreachable!("three action bits have eight values"),
        }
        assert_eq!(Snapshot::of(&session), Snapshot::of(&reference));
    }
}

/// Checks stateless reflection, authentication, discriminator reversal, and replay echo.
pub fn check_reflector(data: &[u8]) {
    let data = &data[..data.len().min(MAX_PACKET_INPUT)];
    for kind in TYPES {
        let public_value = word(data, 4).swap_bytes();
        let auth = auth(kind, public_value);
        for admin_down in [false, true] {
            let mut options = options(kind, public_value);
            let mut reflector_options = Options::reflector(options.local, REFLECTOR_DISC);
            reflector_options.auth = kind;
            reflector_options.auth_key_hex = options.auth_key_hex.take();
            reflector_options.auth_key_id = KEY_ID;
            reflector_options.sbfd_admin_down = admin_down;
            let reflector = Reflector::from_config(
                &reflector_options
                    .into_validated()
                    .expect("fixed reflector configuration is valid"),
            )
            .expect("reflector role is valid");
            let before = reflector.state();
            let result = reflector.respond(data);
            assert_eq!(reflector.state(), before);
            assert_eq!(reflector.respond(data), result);
            if let Ok(response) = result {
                let request =
                    ControlPacket::decode(data).expect("accepted request has a valid header");
                assert_control_acceptance(data);
                assert_eq!(request.your_discriminator, REFLECTOR_DISC);
                assert!(request.demand);
                assert_ne!(request.state, State::Init);
                assert_eq!(request.required_min_rx_us, 0);
                assert_eq!(request.required_min_echo_rx_us, 0);
                let sequence = auth
                    .verify(data, None)
                    .expect("accepted request has valid configured authentication");
                assert_auth_acceptance(data, kind, None, sequence);
                let reply = ControlPacket::decode(&response).expect("response has a valid header");
                assert_eq!(reply.my_discriminator, request.your_discriminator);
                assert_eq!(reply.your_discriminator, request.my_discriminator);
                assert_eq!(reply.final_bit, request.poll);
                assert!(!reply.poll && !reply.demand);
                assert_eq!(
                    reply.state,
                    if admin_down {
                        State::AdminDown
                    } else {
                        State::Up
                    }
                );
                assert_eq!(auth.verify(&response, None), auth.verify(data, None));
            }
        }
    }
}

/// Generates reproducible starting cases; mutation output belongs in an ignored directory.
pub fn seed_cases() -> Vec<(&'static str, String, Vec<u8>)> {
    let mut cases = vec![];
    for (index, kind) in TYPES.into_iter().enumerate() {
        let mut initiator = vec![u8::try_from(index).expect("authentication modes fit u8")];
        for action in [1, 3, 4, 5, 6, 7, 2] {
            let mut frame = [0; FRAME_LEN];
            frame[0] = action;
            frame[1] = if action == 2 { 255 } else { 1 };
            frame[2] = 1;
            initiator.extend_from_slice(&frame);
        }
        cases.push(("initiator", format!("mode-{index}"), initiator));
        let packet = peer(State::Init);
        let auth = auth(kind, packet.my_discriminator);
        let packet = packet.encode(&auth, 100);
        cases.push(("packet", format!("mode-{index}"), packet.clone()));
        cases.push((
            "packet",
            format!("short-{index}"),
            packet[..25.min(packet.len())].to_vec(),
        ));
        let mut stream = vec![u8::try_from(index).expect("authentication modes fit u8")];
        for step in 0..3u32 {
            let mut frame = [0; FRAME_LEN];
            frame[0] = 1;
            frame[2] = if step == 0 { 2 } else { 3 };
            frame[4..8].copy_from_slice(&99u32.to_le_bytes());
            frame[8] = 3;
            frame[9..13].copy_from_slice(&100_000u32.to_le_bytes());
            frame[13..17].copy_from_slice(&100_000u32.to_le_bytes());
            frame[17..21].copy_from_slice(&(100 + step).to_le_bytes());
            stream.extend(frame);
            let mut bad = [0; FRAME_LEN];
            bad[2..2 + packet.len()].copy_from_slice(&packet);
            bad[2] ^= 0xff;
            stream.extend(bad);
        }
        for action in 4..=7 {
            let mut rejected = [0; FRAME_LEN];
            rejected[0] = action;
            rejected[2] = 2;
            rejected[4..8].copy_from_slice(&99u32.to_le_bytes());
            rejected[8] = 3;
            rejected[9..13].copy_from_slice(&100_000u32.to_le_bytes());
            rejected[13..17].copy_from_slice(&100_000u32.to_le_bytes());
            rejected[17..21].copy_from_slice(&100u32.to_le_bytes());
            stream.extend(rejected);
        }
        stream.extend([2, 255]);
        cases.push(("session", format!("mode-{index}"), stream));
        let mut request = peer(State::Down);
        request.your_discriminator = REFLECTOR_DISC;
        request.demand = true;
        request.poll = true;
        request.required_min_rx_us = 0;
        cases.push((
            "reflector",
            format!("mode-{index}"),
            request.encode(&auth, 100),
        ));
    }
    cases.push(("packet", "empty".into(), vec![]));
    cases.push(("reflector", "empty".into(), vec![]));
    cases
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_derived_material_drives_authenticated_sessions_up() {
        for selector in u8::MIN..=u8::MAX {
            let kind = TYPES[usize::from(selector) % TYPES.len()];
            let public_value = u32::from(selector);
            let config = options(kind, public_value)
                .into_validated()
                .expect("fixed configuration with input-derived authentication");
            let authentication = auth(kind, public_value);
            assert!(config.authentication() == &authentication);
            let mut session = Session::from_config(config);
            let packet = peer(State::Init).encode(&authentication, 100);
            session
                .receive(&packet, Instant::now())
                .expect("valid signed probe is accepted");
            assert_eq!(session.state(), State::Up);
            if kind != AuthType::None {
                assert!(auth(kind, public_value ^ 1).verify(&packet, None).is_err());
            }
        }
    }

    #[test]
    fn starting_corpus_satisfies_all_oracles() {
        for (target, _, bytes) in seed_cases() {
            match target {
                "packet" => check_packet(&bytes),
                "session" => check_session(&bytes),
                "initiator" => check_initiator(&bytes),
                "reflector" => check_reflector(&bytes),
                _ => unreachable!("fixed seed target"),
            }
        }
    }
}
