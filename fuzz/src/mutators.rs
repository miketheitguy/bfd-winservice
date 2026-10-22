//! Structure-aware mutations for the wire packet and framed session inputs.

use super::{
    auth, generated_packet, peer, ControlPacket, State, FRAME_LEN, KEY_ID, LOCAL_DISC, MAX_STEPS,
    REFLECTOR_DISC, TYPES,
};

const DEFAULT_MUTATION_MASK: u32 = 3;
const FRAME_PAYLOAD_OFFSET: usize = 2;

#[derive(Clone, Copy)]
enum PacketProfile {
    General,
    Reflector,
}

struct Rng(u64);

impl Rng {
    fn new(seed: u32) -> Self {
        Self(u64::from(seed) | 1)
    }

    fn next_u32(&mut self) -> u32 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        let bytes = value.to_le_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn byte(&mut self) -> u8 {
        self.next_u32().to_le_bytes()[0]
    }

    fn index(&mut self, length: usize) -> usize {
        debug_assert!(length != 0);
        usize::try_from(u64::from(self.next_u32()) % u64::try_from(length).unwrap_or(u64::MAX))
            .expect("random index is bounded by a usize length")
    }
}

pub(super) fn mutate_packet<M>(
    data: &mut [u8],
    size: usize,
    max_size: usize,
    seed: u32,
    default_mutator: M,
) -> usize
where
    M: FnOnce(&mut [u8], usize, usize) -> usize,
{
    mutate_wire(
        data,
        size,
        max_size,
        seed,
        PacketProfile::General,
        default_mutator,
    )
}

pub(super) fn mutate_reflector<M>(
    data: &mut [u8],
    size: usize,
    max_size: usize,
    seed: u32,
    default_mutator: M,
) -> usize
where
    M: FnOnce(&mut [u8], usize, usize) -> usize,
{
    mutate_wire(
        data,
        size,
        max_size,
        seed,
        PacketProfile::Reflector,
        default_mutator,
    )
}

fn mutate_wire<M>(
    data: &mut [u8],
    size: usize,
    max_size: usize,
    seed: u32,
    profile: PacketProfile,
    default_mutator: M,
) -> usize
where
    M: FnOnce(&mut [u8], usize, usize) -> usize,
{
    let current = size.min(data.len());
    let limit = max_size.min(data.len());
    if seed & DEFAULT_MUTATION_MASK == 0 || limit == 0 {
        return default_mutator(data, current, limit).min(limit);
    }

    let mut rng = Rng::new(seed);
    let mut packet = ControlPacket::decode(&data[..current])
        .unwrap_or_else(|_| generated_packet(&data[..current]));
    mutate_packet_fields(&mut packet, &mut rng);
    normalize_packet(&mut packet, profile, &mut rng);
    let kind = TYPES[rng.index(TYPES.len())];
    let sequence = rng.next_u32();
    let wire = packet.encode(&auth(kind, packet.my_discriminator), sequence);
    if wire.len() > limit {
        return default_mutator(data, current, limit).min(limit);
    }

    data[..wire.len()].copy_from_slice(&wire);
    let mut new_size = wire.len();
    if matches!(profile, PacketProfile::General) && new_size < limit && rng.byte() & 1 != 0 {
        let padding = rng.index((limit - new_size).min(16) + 1);
        for byte in &mut data[new_size..new_size + padding] {
            *byte = rng.byte();
        }
        new_size += padding;
    }
    new_size
}

fn mutate_packet_fields(packet: &mut ControlPacket, rng: &mut Rng) {
    match rng.index(10) {
        0 => packet.diagnostic = rng.byte() & 31,
        1 => packet.state = random_state(rng),
        2 => {
            let flags = rng.byte();
            packet.poll = flags & 1 != 0;
            packet.final_bit = !packet.poll && flags & 2 != 0;
            packet.control_plane_independent = flags & 4 != 0;
            packet.demand = flags & 8 != 0;
        }
        3 => packet.detect_mult = special_u8(rng),
        4 => packet.my_discriminator = special_u32(rng),
        5 => packet.your_discriminator = special_u32(rng),
        6 => packet.desired_min_tx_us = special_u32(rng),
        7 => packet.required_min_rx_us = special_u32(rng),
        8 => packet.required_min_echo_rx_us = special_u32(rng),
        9 => {
            packet.poll = !packet.poll;
            packet.final_bit = false;
        }
        _ => unreachable!("random index is below ten"),
    }
}

fn normalize_packet(packet: &mut ControlPacket, profile: PacketProfile, rng: &mut Rng) {
    packet.detect_mult = packet.detect_mult.max(1);
    packet.my_discriminator = packet.my_discriminator.max(1);
    packet.desired_min_tx_us = packet.desired_min_tx_us.max(1);
    if packet.poll && packet.final_bit {
        packet.final_bit = false;
    }
    if packet.your_discriminator == 0 && matches!(packet.state, State::Init | State::Up) {
        packet.your_discriminator = LOCAL_DISC;
    }

    match profile {
        PacketProfile::General => {}
        PacketProfile::Reflector => {
            packet.state = match rng.index(3) {
                0 => State::AdminDown,
                1 => State::Down,
                2 => State::Up,
                _ => unreachable!("random index is below three"),
            };
            packet.your_discriminator = REFLECTOR_DISC;
            packet.demand = true;
            packet.required_min_rx_us = 0;
            packet.required_min_echo_rx_us = 0;
        }
    }
}

pub(super) fn mutate_session<M>(
    data: &mut [u8],
    size: usize,
    max_size: usize,
    seed: u32,
    default_mutator: M,
) -> usize
where
    M: FnOnce(&mut [u8], usize, usize) -> usize,
{
    let current = size.min(data.len());
    let limit = max_size.min(data.len());
    if seed & DEFAULT_MUTATION_MASK == 0 || limit == 0 {
        return default_mutator(data, current, limit).min(limit);
    }

    let mut rng = Rng::new(seed);
    if current == 0 {
        data[0] = rng.byte();
    }
    let available = current.max(1).min(limit);
    let mut frame_count = available
        .saturating_sub(1)
        .div_euclid(FRAME_LEN)
        .min(MAX_STEPS);
    let mut new_size = 1 + frame_count * FRAME_LEN;
    if frame_count == 0 {
        if limit < 1 + FRAME_LEN {
            data[0] = rng.byte();
            return 1;
        }
        let selector = data[0];
        write_frame(&mut data[1..1 + FRAME_LEN], selector, &mut rng);
        frame_count = 1;
        new_size = 1 + FRAME_LEN;
    }

    match rng.index(8) {
        0 => data[0] = rng.byte(),
        1 => {
            if frame_count < MAX_STEPS && new_size + FRAME_LEN <= limit {
                let index = rng.index(frame_count + 1);
                let start = 1 + index * FRAME_LEN;
                data.copy_within(start..new_size, start + FRAME_LEN);
                let selector = data[0];
                write_frame(&mut data[start..start + FRAME_LEN], selector, &mut rng);
                new_size += FRAME_LEN;
            } else {
                rewrite_random_frame(data, frame_count, &mut rng);
            }
        }
        2 => {
            if frame_count > 1 {
                let index = rng.index(frame_count);
                let start = 1 + index * FRAME_LEN;
                data.copy_within(start + FRAME_LEN..new_size, start);
                new_size -= FRAME_LEN;
            } else {
                rewrite_random_frame(data, frame_count, &mut rng);
            }
        }
        3 => {
            if frame_count < MAX_STEPS && new_size + FRAME_LEN <= limit {
                let source = rng.index(frame_count);
                let destination = rng.index(frame_count + 1);
                let source_start = 1 + source * FRAME_LEN;
                let destination_start = 1 + destination * FRAME_LEN;
                let frame: [u8; FRAME_LEN] = data[source_start..source_start + FRAME_LEN]
                    .try_into()
                    .expect("frame bounds were calculated from the input length");
                data.copy_within(destination_start..new_size, destination_start + FRAME_LEN);
                data[destination_start..destination_start + FRAME_LEN].copy_from_slice(&frame);
                new_size += FRAME_LEN;
            } else {
                rewrite_random_frame(data, frame_count, &mut rng);
            }
        }
        4 => {
            let frame = random_frame_mut(data, frame_count, &mut rng);
            frame[0] = (frame[0] & !3) | (rng.byte() & 3);
        }
        5 => {
            let frame = random_frame_mut(data, frame_count, &mut rng);
            frame[1] = special_u8(&mut rng);
        }
        6 => {
            let frame = random_frame_mut(data, frame_count, &mut rng);
            let offset = FRAME_PAYLOAD_OFFSET + rng.index(FRAME_LEN - FRAME_PAYLOAD_OFFSET);
            frame[offset] ^= rng.byte() | 1;
        }
        7 => rewrite_random_frame(data, frame_count, &mut rng),
        _ => unreachable!("random index is below eight"),
    }
    new_size
}

fn random_frame_mut<'a>(data: &'a mut [u8], frame_count: usize, rng: &mut Rng) -> &'a mut [u8] {
    let start = 1 + rng.index(frame_count) * FRAME_LEN;
    &mut data[start..start + FRAME_LEN]
}

fn rewrite_random_frame(data: &mut [u8], frame_count: usize, rng: &mut Rng) {
    let selector = data[0];
    let frame = random_frame_mut(data, frame_count, rng);
    write_frame(frame, selector, rng);
}

fn write_frame(frame: &mut [u8], selector: u8, rng: &mut Rng) {
    frame.fill(0);
    frame[1] = special_u8(rng);
    match rng.index(8) {
        0 => write_raw_packet_frame(frame, selector, rng),
        1 => write_generated_packet_frame(frame, rng),
        2 => frame[0] = 2,
        3 => {
            frame[0] = 3;
            frame[2..6].copy_from_slice(&special_u32(rng).max(1).to_le_bytes());
            frame[6..10].copy_from_slice(&special_u32(rng).max(1).to_le_bytes());
            frame[1] = frame[1].max(1);
        }
        4 => {
            write_generated_packet_frame(frame, rng);
            frame[0] = 4;
        }
        5 => {
            write_generated_packet_frame(frame, rng);
            frame[0] = 5;
        }
        6 => {
            write_generated_packet_frame(frame, rng);
            frame[0] = 6;
        }
        7 => {
            write_generated_packet_frame(frame, rng);
            frame[0] = 7;
        }
        _ => unreachable!("random index is below eight"),
    }
}

fn write_raw_packet_frame(frame: &mut [u8], selector: u8, rng: &mut Rng) {
    frame[0] = 0;
    let kind = TYPES[usize::from(selector) % TYPES.len()];
    let mut packet = peer(random_state(rng));
    mutate_packet_fields(&mut packet, rng);
    normalize_packet(&mut packet, PacketProfile::General, rng);
    packet.your_discriminator = LOCAL_DISC;
    let wire = packet.encode(&auth(kind, u32::from(selector)), rng.next_u32());
    frame[FRAME_PAYLOAD_OFFSET..FRAME_PAYLOAD_OFFSET + wire.len()].copy_from_slice(&wire);
    for byte in &mut frame[FRAME_PAYLOAD_OFFSET + wire.len()..] {
        *byte = rng.byte();
    }
}

fn write_generated_packet_frame(frame: &mut [u8], rng: &mut Rng) {
    frame[0] = 1;
    let payload = &mut frame[FRAME_PAYLOAD_OFFSET..];
    payload[0] = rng.byte() & 3;
    let flags = rng.byte();
    payload[1] = flags;
    if payload[1] & 32 != 0 {
        payload[1] &= !64;
    }
    payload[2..6].copy_from_slice(&special_u32(rng).max(1).to_le_bytes());
    payload[6] = special_u8(rng).max(1);
    payload[7..11].copy_from_slice(&special_u32(rng).max(1).to_le_bytes());
    payload[11..15].copy_from_slice(&special_u32(rng).to_le_bytes());
    payload[15..19].copy_from_slice(&rng.next_u32().to_le_bytes());
}

fn random_state(rng: &mut Rng) -> State {
    match rng.index(4) {
        0 => State::AdminDown,
        1 => State::Down,
        2 => State::Init,
        3 => State::Up,
        _ => unreachable!("random index is below four"),
    }
}

fn special_u8(rng: &mut Rng) -> u8 {
    let values = [0, 1, 2, 3, 255, rng.byte()];
    values[rng.index(values.len())]
}

fn special_u32(rng: &mut Rng) -> u32 {
    let values = [
        0,
        1,
        u32::from(KEY_ID),
        LOCAL_DISC,
        REFLECTOR_DISC,
        100_000,
        u32::MAX,
        rng.next_u32(),
    ];
    values[rng.index(values.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{check_packet, check_reflector, check_session};

    fn no_fallback(_: &mut [u8], _: usize, _: usize) -> usize {
        panic!("structured mutation unexpectedly used the byte-level fallback")
    }

    #[test]
    fn packet_mutation_emits_decodable_authenticated_input() {
        let mut data = [0xa5; 256];
        let size = mutate_packet(&mut data, 17, 256, 1, no_fallback);

        let packet = ControlPacket::decode(&data[..size]).expect("structured packet decodes");
        assert!(TYPES
            .iter()
            .copied()
            .any(|kind| auth(kind, packet.my_discriminator)
                .verify(&data[..size], None)
                .is_ok()));
        check_packet(&data[..size]);
    }

    #[test]
    fn reflector_mutation_emits_acceptable_signed_request() {
        let mut data = [0x5a; 256];
        let size = mutate_reflector(&mut data, 11, 256, 2, no_fallback);
        let packet = ControlPacket::decode(&data[..size]).expect("structured request decodes");

        assert_eq!(packet.your_discriminator, REFLECTOR_DISC);
        assert!(packet.demand);
        assert_eq!(packet.required_min_rx_us, 0);
        assert_eq!(packet.required_min_echo_rx_us, 0);
        assert!(TYPES
            .iter()
            .copied()
            .any(|kind| auth(kind, packet.my_discriminator)
                .verify(&data[..size], None)
                .is_ok()));
        check_reflector(&data[..size]);
    }

    #[test]
    fn session_mutation_preserves_complete_action_frames() {
        let mut data = [0; 4096];
        let size = mutate_session(&mut data, 0, 4096, 3, no_fallback);

        assert!(size > FRAME_LEN);
        assert_eq!((size - 1) % FRAME_LEN, 0);
        assert!(size <= 1 + MAX_STEPS * FRAME_LEN);
        check_session(&data[..size]);
    }

    #[test]
    fn raw_session_frames_use_the_selector_authentication_material() {
        for selector in u8::MIN..=u8::MAX {
            let mut frame = [0; FRAME_LEN];
            let mut rng = Rng::new(u32::from(selector));
            write_raw_packet_frame(&mut frame, selector, &mut rng);

            let kind = TYPES[usize::from(selector) % TYPES.len()];
            let authentication = auth(kind, u32::from(selector));
            assert!(authentication
                .verify(&frame[FRAME_PAYLOAD_OFFSET..], None)
                .is_ok());
        }
    }

    #[test]
    fn structured_mutations_are_deterministic_for_the_same_seed() {
        let mut first = [0x3c; 512];
        let mut second = first;

        let first_size = mutate_session(&mut first, 129, 512, 7, no_fallback);
        let second_size = mutate_session(&mut second, 129, 512, 7, no_fallback);

        assert_eq!(first_size, second_size);
        assert_eq!(&first[..first_size], &second[..second_size]);
    }

    #[test]
    fn one_quarter_of_seeds_retain_default_byte_mutation() {
        let mut data = [0; 8];
        let size = mutate_packet(&mut data, 3, 8, 4, |buffer, current, limit| {
            assert_eq!((current, limit), (3, 8));
            buffer[3] = 0x5a;
            4
        });

        assert_eq!(size, 4);
        assert_eq!(data[3], 0x5a);
    }
}
