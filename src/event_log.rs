//! Manifest-based ETW events for BFD-Service/Operational.
//!
//! Event IDs, descriptors, and packed payloads follow events/BFD-Service.man.
//! The provider owns its registration; each EventWrite borrows a payload only
//! for the synchronous call. No callback, raw-pointer owner, or global handle
//! is needed. Logging failures are reported by Logger and never stop BFD.
// ETW registration and writes require the Windows FFI boundary.
#![allow(unsafe_code)]
use crate::{config::Options, packet::State, session::Session};
use std::{io, io::Write, net::SocketAddr, ptr};
use windows_sys::{
    core::GUID,
    Win32::System::Diagnostics::Etw::{
        EventEnabled, EventRegister, EventUnregister, EventWrite, EVENT_DATA_DESCRIPTOR,
        EVENT_DATA_DESCRIPTOR_0, EVENT_DESCRIPTOR, REGHANDLE,
    },
};

const PROVIDER_ID: GUID = GUID::from_u128(0x8f2a4f61_4d6c_4f2f_9c3e_2b73ab4d62e1);
// MC reserves the highest keyword bit for the first declared channel. It must
// be present along with our own keywords for Event Log to enable these events.
const OPERATIONAL_KEYWORD: u64 = 0x8000_0000_0000_0000;
const SERVICE_STARTED: EVENT_DESCRIPTOR = descriptor(1, 4, 1, 0x1);
const SERVICE_STOPPED: EVENT_DESCRIPTOR = descriptor(2, 4, 1, 0x1);
const SERVICE_FAILED: EVENT_DESCRIPTOR = descriptor(3, 2, 1, 0x1);
const SERVICE_WARNING: EVENT_DESCRIPTOR = descriptor(4, 3, 1, 0x1);
const BROKER_INFORMATION: EVENT_DESCRIPTOR = descriptor(300, 4, 4, 0x4);
const BROKER_ERROR: EVENT_DESCRIPTOR = descriptor(301, 2, 4, 0x4);
const BGP_CONTROL_FAILED: EVENT_DESCRIPTOR = descriptor(302, 2, 4, 0x4);
const BGP_CONTROL_RECOVERED: EVENT_DESCRIPTOR = descriptor(303, 4, 4, 0x4);
const PEER_COMMUNICATION_STARTED: EVENT_DESCRIPTOR = descriptor(100, 4, 2, 0x2);
const PEER_COMMUNICATION_STOPPED: EVENT_DESCRIPTOR = descriptor(101, 3, 2, 0x2);
const SESSION_UP: EVENT_DESCRIPTOR = descriptor(102, 4, 2, 0x2);
const SESSION_DOWN: EVENT_DESCRIPTOR = descriptor(103, 3, 2, 0x2);
const SESSION_STATE_CHANGED: EVENT_DESCRIPTOR = descriptor(104, 4, 2, 0x2);
const AUTHENTICATION_FAILED: EVENT_DESCRIPTOR = descriptor(105, 3, 2, 0x2);
const SESSION_ADMIN_DOWN: EVENT_DESCRIPTOR = descriptor(106, 4, 2, 0x2);
const REMOTE_ADMIN_DOWN: EVENT_DESCRIPTOR = descriptor(110, 4, 2, 0x2);
const REMOTE_DOWN: EVENT_DESCRIPTOR = descriptor(111, 3, 2, 0x2);
const REMOTE_INIT: EVENT_DESCRIPTOR = descriptor(112, 4, 2, 0x2);
const REMOTE_UP: EVENT_DESCRIPTOR = descriptor(113, 4, 2, 0x2);
const DIAGNOSTIC_DETECTION_EXPIRED: EVENT_DESCRIPTOR = descriptor(201, 3, 3, 0x4);
const DIAGNOSTIC_ECHO_FAILED: EVENT_DESCRIPTOR = descriptor(202, 2, 3, 0x4);
const DIAGNOSTIC_NEIGHBOR_DOWN: EVENT_DESCRIPTOR = descriptor(203, 3, 3, 0x4);
const DIAGNOSTIC_FORWARDING_RESET: EVENT_DESCRIPTOR = descriptor(204, 2, 3, 0x4);
const DIAGNOSTIC_PATH_DOWN: EVENT_DESCRIPTOR = descriptor(205, 2, 3, 0x4);
const DIAGNOSTIC_CONCATENATED_PATH_DOWN: EVENT_DESCRIPTOR = descriptor(206, 2, 3, 0x4);
const DIAGNOSTIC_ADMIN_DOWN: EVENT_DESCRIPTOR = descriptor(207, 3, 3, 0x4);
const DIAGNOSTIC_REVERSE_CONCATENATED_PATH_DOWN: EVENT_DESCRIPTOR = descriptor(208, 2, 3, 0x4);

const fn descriptor(id: u16, level: u8, task: u16, keyword: u64) -> EVENT_DESCRIPTOR {
    EVENT_DESCRIPTOR {
        Id: id,
        Version: 0,
        Channel: 16,
        Level: level,
        Opcode: 0,
        Task: task,
        Keyword: OPERATIONAL_KEYWORD | keyword,
    }
}

#[derive(Clone, Copy)]
pub(crate) enum SessionEvent {
    CommunicationStarted,
    CommunicationStopped,
    StateChanged,
    PeerStateChanged,
}

impl SessionEvent {
    fn descriptor(&self, state: State) -> &'static EVENT_DESCRIPTOR {
        match self {
            Self::CommunicationStarted => &PEER_COMMUNICATION_STARTED,
            Self::CommunicationStopped => &PEER_COMMUNICATION_STOPPED,
            Self::StateChanged => match state {
                State::Up => &SESSION_UP,
                State::Down => &SESSION_DOWN,
                State::Init => &SESSION_STATE_CHANGED,
                State::AdminDown => &SESSION_ADMIN_DOWN,
            },
            Self::PeerStateChanged => match state {
                State::AdminDown => &REMOTE_ADMIN_DOWN,
                State::Down => &REMOTE_DOWN,
                State::Init => &REMOTE_INIT,
                State::Up => &REMOTE_UP,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Origin {
    Local = 0,
    Remote = 1,
}

fn diagnostic_descriptor(code: u8) -> Option<&'static EVENT_DESCRIPTOR> {
    match code {
        1 => Some(&DIAGNOSTIC_DETECTION_EXPIRED),
        2 => Some(&DIAGNOSTIC_ECHO_FAILED),
        3 => Some(&DIAGNOSTIC_NEIGHBOR_DOWN),
        4 => Some(&DIAGNOSTIC_FORWARDING_RESET),
        5 => Some(&DIAGNOSTIC_PATH_DOWN),
        6 => Some(&DIAGNOSTIC_CONCATENATED_PATH_DOWN),
        7 => Some(&DIAGNOSTIC_ADMIN_DOWN),
        8 => Some(&DIAGNOSTIC_REVERSE_CONCATENATED_PATH_DOWN),
        _ => None,
    }
}

fn diagnostic_name(code: u8) -> &'static str {
    match code {
        0 => "None",
        1 => "DetectionExpired",
        2 => "EchoFailed",
        3 => "NeighborDown",
        4 => "ForwardingPlaneReset",
        5 => "PathDown",
        6 => "ConcatenatedPathDown",
        7 => "AdminDown",
        8 => "ReverseConcatenatedPathDown",
        _ => "Reserved",
    }
}

fn level_name(event: &EVENT_DESCRIPTOR) -> &'static str {
    match event.Level {
        2 => "Error",
        3 => "Warning",
        _ => "Information",
    }
}

pub(crate) struct Provider {
    handle: REGHANDLE,
}

pub(crate) struct Record {
    event: &'static EVENT_DESCRIPTOR,
    payload: Vec<u8>,
    pub(crate) text: Option<String>,
}

impl Record {
    pub(crate) fn bgp_control_message(
        peer: &str,
        method: &str,
        detail: &str,
        recovered: bool,
    ) -> Self {
        let mut payload = Vec::new();
        // Each field is bounded to 8192 UTF-16 units, keeping all three under 64 KiB.
        append_unicode(&mut payload, peer);
        append_unicode(&mut payload, method);
        append_unicode(&mut payload, detail);
        Self {
            event: if recovered {
                &BGP_CONTROL_RECOVERED
            } else {
                &BGP_CONTROL_FAILED
            },
            payload,
            // The logger attaches one bounded text record for the optional file.
            text: None,
        }
    }

    pub(crate) fn broker_message(message: &str, failure: bool) -> Self {
        let event = if failure {
            &BROKER_ERROR
        } else {
            &BROKER_INFORMATION
        };
        let mut payload = Vec::new();
        append_unicode(&mut payload, message);
        Self {
            event,
            payload,
            text: Some(format!(
                "event_id={} level={} {message}",
                event.Id,
                level_name(event)
            )),
        }
    }
    #[cfg(test)]
    pub(crate) fn identity(&self) -> (u16, u8) {
        (self.event.Id, self.event.Level)
    }
    pub(crate) fn service_started() -> Self {
        Self {
            event: &SERVICE_STARTED,
            payload: vec![0],
            text: None,
        }
    }
    pub(crate) fn service_stopped(exit_code: u32) -> Self {
        let mut payload = vec![0];
        payload.extend_from_slice(&exit_code.to_le_bytes());
        Self {
            event: &SERVICE_STOPPED,
            payload,
            text: None,
        }
    }
    pub(crate) fn service_failed(error: &str) -> Self {
        let mut payload = vec![0];
        append_unicode(&mut payload, error);
        Self {
            event: &SERVICE_FAILED,
            payload,
            text: None,
        }
    }
    pub(crate) fn service_warning(warning: &str) -> Self {
        let mut payload = vec![0];
        append_unicode(&mut payload, warning);
        Self {
            event: &SERVICE_WARNING,
            payload,
            text: Some(format!(
                "event_id={} level={} {warning}",
                SERVICE_WARNING.Id,
                level_name(&SERVICE_WARNING)
            )),
        }
    }
    pub(crate) fn session_event(
        event: SessionEvent,
        options: &Options,
        session: &Session,
        previous: State,
        remote_discriminator: u32,
    ) -> io::Result<Self> {
        let remote = matches!(event, SessionEvent::PeerStateChanged);
        let state = if remote {
            session.remote_state()
        } else {
            session.state()
        };
        let diagnostic = if remote {
            session.remote_diagnostic()
        } else {
            session.diagnostic() as u8
        };
        let descriptor = event.descriptor(state);
        let action = match event {
            SessionEvent::CommunicationStarted => "communication=started ",
            SessionEvent::CommunicationStopped => "communication=stopped ",
            _ => "",
        };
        let state_label = if remote { "peer_state" } else { "state" };
        let diagnostic_label = if remote {
            "peer_diagnostic"
        } else {
            "diagnostic"
        };
        Ok(Self {
            event: descriptor,
            payload: session_payload(options, session, previous, remote_discriminator, state, diagnostic)?,
            text: Some(format!(
                "event_id={} level={} scope={:?} local={} peer={} {action}{state_label}={state:?} {diagnostic_label}={} previous_state={previous:?} diagnostic_code={diagnostic} local_discriminator={} remote_discriminator={remote_discriminator} tx_us={} detection_us={}",
                descriptor.Id, level_name(descriptor),
                if remote { Origin::Remote } else { Origin::Local }, options.local, options.peer,
                diagnostic_name(diagnostic), session.local_discriminator(),
                session.transmit_interval().as_micros(), session.detection_time().as_micros(),
            )),
        })
    }

    pub(crate) fn diagnostic_event(
        options: &Options,
        session: &Session,
        origin: Origin,
        code: u8,
        previous: State,
    ) -> io::Result<Option<Self>> {
        let Some(event) = diagnostic_descriptor(code) else {
            return Ok(None);
        };
        let state = if origin == Origin::Remote {
            session.remote_state()
        } else {
            session.state()
        };
        let mut payload = session_payload(
            options,
            session,
            previous,
            session.remote_discriminator(),
            state,
            code,
        )?;
        payload.push(origin as u8);
        Ok(Some(Self {
            event,
            payload,
            text: Some(format!(
                "event_id={} level={} scope={origin:?} local={} peer={} diagnostic_code={code} diagnostic={} reported_state={state:?} previous_state={previous:?} local_discriminator={} remote_discriminator={} tx_us={} detection_us={}",
                event.Id, level_name(event), options.local, options.peer, diagnostic_name(code),
                session.local_discriminator(), session.remote_discriminator(),
                session.transmit_interval().as_micros(), session.detection_time().as_micros(),
            )),
        }))
    }
    pub(crate) fn authentication_failed(
        options: &Options,
        session: &Session,
        source: SocketAddr,
        reason: &str,
    ) -> Self {
        Self {
            event: &AUTHENTICATION_FAILED,
            payload: authentication_payload(options, session.local_discriminator(), source, reason),
            text: None,
        }
    }
}

impl Provider {
    pub(crate) fn register() -> io::Result<Self> {
        let mut handle = 0;
        // SAFETY: the GUID and writable handle are valid for the call. No
        // callback/context is registered, so ETW retains no Rust references.
        check(unsafe { EventRegister(&PROVIDER_ID, None, ptr::null(), &mut handle) })?;
        Ok(Self { handle })
    }

    fn enabled(&self, event: &EVENT_DESCRIPTOR) -> bool {
        // SAFETY: self owns a live registration and event is a valid descriptor.
        unsafe { EventEnabled(self.handle, event) }
    }

    pub(crate) fn emit(&self, record: &Record) -> io::Result<()> {
        if self.enabled(record.event) {
            self.write(record.event, &record.payload)
        } else {
            Ok(())
        }
    }

    fn write(&self, event: &EVENT_DESCRIPTOR, payload: &[u8]) -> io::Result<()> {
        let data = EVENT_DATA_DESCRIPTOR {
            Ptr: payload.as_ptr() as u64,
            Size: u32::try_from(payload.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "ETW payload too large")
            })?,
            Anonymous: EVENT_DATA_DESCRIPTOR_0 { Reserved: 0 },
        };
        // SAFETY: self owns the registration. The descriptor points to exactly
        // payload.len() initialized bytes, alive throughout this synchronous
        // call. ETW concatenates bytes without padding, matching the template.
        check(unsafe { EventWrite(self.handle, event, 1, &data) })
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: this non-Clone owner unregisters its live handle exactly once,
        // after all methods borrowing it have completed. No callbacks exist.
        if let Err(error) = check(unsafe { EventUnregister(self.handle) }) {
            let _ = writeln!(
                io::stderr().lock(),
                "Unable to unregister BFD-Service ETW provider: {error}"
            );
        }
    }
}

fn check(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        // Preserve the Windows error's bit pattern in the signed OS-error type.
        Err(io::Error::from_raw_os_error(i32::from_ne_bytes(
            status.to_ne_bytes(),
        )))
    }
}

fn append_unicode(payload: &mut Vec<u8>, text: &str) {
    // Bound free-form error text to keep the event below ETW's 64 KiB limit.
    // Encode complete characters so truncation never splits a surrogate pair.
    let mut units = 0;
    for character in text.chars() {
        let character = if character == '\0' {
            '\u{fffd}'
        } else {
            character
        };
        if units + character.len_utf16() > 8192 {
            break;
        }
        let mut encoded = [0; 2];
        for unit in character.encode_utf16(&mut encoded) {
            payload.extend_from_slice(&unit.to_le_bytes());
            units += 1;
        }
    }
    payload.extend_from_slice(&0u16.to_le_bytes());
}

fn session_payload(
    options: &Options,
    session: &Session,
    previous: State,
    remote_discriminator: u32,
    state: State,
    diagnostic: u8,
) -> io::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(256);
    append_unicode(&mut payload, &options.local.to_string());
    append_unicode(&mut payload, &options.peer.to_string());
    payload.extend_from_slice(&session.local_discriminator().to_le_bytes());
    payload.extend_from_slice(&remote_discriminator.to_le_bytes());
    payload.extend_from_slice(&[previous as u8, state as u8, diagnostic]);
    for duration in [session.transmit_interval(), session.detection_time()] {
        let micros = u64::try_from(duration.as_micros()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "BFD interval exceeds UInt64")
        })?;
        payload.extend_from_slice(&micros.to_le_bytes());
    }
    Ok(payload)
}

fn authentication_payload(
    options: &Options,
    local_discriminator: u32,
    source: SocketAddr,
    reason: &str,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(256);
    append_unicode(&mut payload, &options.local.to_string());
    append_unicode(&mut payload, &options.peer.to_string());
    append_unicode(&mut payload, &source.to_string());
    payload.extend_from_slice(&local_discriminator.to_le_bytes());
    payload.extend_from_slice(&[options.auth as u8, options.auth_key_id]);
    append_unicode(&mut payload, reason);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrative_state_has_its_own_informational_event() {
        let event = SessionEvent::StateChanged.descriptor(State::AdminDown);
        assert_eq!(event.Id, 106);
        assert_eq!(event.Level, 4);
    }

    #[test]
    fn all_state_and_diagnostic_events_use_the_requested_levels() {
        for (state, local_id, remote_id, level) in [
            (State::AdminDown, 106, 110, 4),
            (State::Down, 103, 111, 3),
            (State::Init, 104, 112, 4),
            (State::Up, 102, 113, 4),
        ] {
            for (kind, id) in [
                (SessionEvent::StateChanged, local_id),
                (SessionEvent::PeerStateChanged, remote_id),
            ] {
                let event = kind.descriptor(state);
                assert_eq!((event.Id, event.Level, event.Channel), (id, level, 16));
            }
        }
        for (code, level) in [
            (1, 3),
            (2, 2),
            (3, 3),
            (4, 2),
            (5, 2),
            (6, 2),
            (7, 3),
            (8, 2),
        ] {
            let event = diagnostic_descriptor(code).unwrap();
            assert_eq!(
                (event.Id, event.Level, event.Channel),
                (200 + u16::from(code), level, 16)
            );
        }
        for code in std::iter::once(0).chain(9..=u8::MAX) {
            assert!(diagnostic_descriptor(code).is_none());
        }
    }

    #[test]
    fn diagnostic_payload_appends_the_origin_and_keeps_peer_reason_separate() {
        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.multihop = true;
        options.discriminator = Some(7);
        let auth = options.validate().unwrap();
        let mut session = Session::new(options.clone(), auth.clone()).unwrap();
        let mut peer = crate::packet::test_packet(State::Init);
        peer.diagnostic = 8;
        session
            .receive(&peer.encode(&auth, 0), std::time::Instant::now())
            .unwrap();
        assert_eq!(session.diagnostic(), crate::packet::Diagnostic::None);
        let record = Record::diagnostic_event(&options, &session, Origin::Remote, 8, State::Down)
            .unwrap()
            .unwrap();
        let mut expected = session_payload(
            &options,
            &session,
            State::Down,
            session.remote_discriminator(),
            State::Init,
            8,
        )
        .unwrap();
        expected.push(1);
        assert_eq!(record.payload, expected);
        assert_eq!(record.identity(), (208, 2));
        assert!(record.text.unwrap().contains("scope=Remote"));
        assert!(
            Record::diagnostic_event(&options, &session, Origin::Local, 0, State::Down)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rust_descriptors_and_guid_match_the_compiled_manifest() {
        // MC determines the Event Log channel keyword and all descriptor fields.
        // Compare against its output so a manifest change cannot silently make
        // Rust events unroutable or select a different decoder/template.
        let header = include_str!(concat!(env!("OUT_DIR"), "/BFD-Service.h"));
        let compact = |text: &str| text.split_whitespace().collect::<String>();
        let header = compact(header);
        let events = [
            ("SERVICE_STARTED", SERVICE_STARTED),
            ("SERVICE_STOPPED", SERVICE_STOPPED),
            ("SERVICE_FAILED", SERVICE_FAILED),
            ("SERVICE_WARNING", SERVICE_WARNING),
            ("BROKER_INFORMATION", BROKER_INFORMATION),
            ("BROKER_ERROR", BROKER_ERROR),
            ("BGP_CONTROL_FAILED", BGP_CONTROL_FAILED),
            ("BGP_CONTROL_RECOVERED", BGP_CONTROL_RECOVERED),
            ("PEER_COMMUNICATION_STARTED", PEER_COMMUNICATION_STARTED),
            ("PEER_COMMUNICATION_STOPPED", PEER_COMMUNICATION_STOPPED),
            ("SESSION_UP", SESSION_UP),
            ("SESSION_DOWN", SESSION_DOWN),
            ("SESSION_STATE_CHANGED", SESSION_STATE_CHANGED),
            ("AUTHENTICATION_FAILED", AUTHENTICATION_FAILED),
            ("SESSION_ADMIN_DOWN", SESSION_ADMIN_DOWN),
            ("REMOTE_ADMIN_DOWN", REMOTE_ADMIN_DOWN),
            ("REMOTE_DOWN", REMOTE_DOWN),
            ("REMOTE_INIT", REMOTE_INIT),
            ("REMOTE_UP", REMOTE_UP),
            ("DIAGNOSTIC_DETECTION_EXPIRED", DIAGNOSTIC_DETECTION_EXPIRED),
            ("DIAGNOSTIC_ECHO_FAILED", DIAGNOSTIC_ECHO_FAILED),
            ("DIAGNOSTIC_NEIGHBOR_DOWN", DIAGNOSTIC_NEIGHBOR_DOWN),
            ("DIAGNOSTIC_FORWARDING_RESET", DIAGNOSTIC_FORWARDING_RESET),
            ("DIAGNOSTIC_PATH_DOWN", DIAGNOSTIC_PATH_DOWN),
            (
                "DIAGNOSTIC_CONCATENATED_PATH_DOWN",
                DIAGNOSTIC_CONCATENATED_PATH_DOWN,
            ),
            ("DIAGNOSTIC_ADMIN_DOWN", DIAGNOSTIC_ADMIN_DOWN),
            (
                "DIAGNOSTIC_REVERSE_CONCATENATED_PATH_DOWN",
                DIAGNOSTIC_REVERSE_CONCATENATED_PATH_DOWN,
            ),
        ];
        assert_eq!(
            header.matches("constEVENT_DESCRIPTOR").count(),
            events.len()
        );
        for (symbol, event) in events {
            let declaration = format!(
                "const EVENT_DESCRIPTOR {symbol} = {{{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}}};",
                event.Id, event.Version, event.Channel, event.Level, event.Opcode, event.Task, event.Keyword,
            );
            assert!(
                header.contains(&compact(&declaration)),
                "MC descriptor differs: {symbol}"
            );
        }
        let data4 = PROVIDER_ID
            .data4
            .iter()
            .map(|byte| format!("{byte:#x}"))
            .collect::<Vec<_>>()
            .join(", ");
        let declaration = format!(
            "const GUID BFD_SERVICE_PROVIDER = {{{:#x}, {:#x}, {:#x}, {{{data4}}}}};",
            PROVIDER_ID.data1, PROVIDER_ID.data2, PROVIDER_ID.data3,
        );
        assert!(
            header.contains(&compact(&declaration)),
            "MC provider GUID differs"
        );
    }

    #[test]
    fn bgp_control_payload_matches_three_unicode_fields_and_bounds_total_size() {
        for recovered in [false, true] {
            let record =
                Record::bgp_control_message("Site 🐢", "Stop", "RPC unavailable", recovered);
            let expected: Vec<_> = ["Site 🐢", "Stop", "RPC unavailable"]
                .into_iter()
                .flat_map(|field| field.encode_utf16().chain(Some(0)))
                .flat_map(u16::to_le_bytes)
                .collect();
            assert_eq!(record.payload, expected);
            assert_eq!(
                record.identity(),
                if recovered { (303, 4) } else { (302, 2) }
            );
        }
        let long = "🐢".repeat(10_000);
        let record = Record::bgp_control_message(&long, &long, &long, false);
        assert_eq!(record.payload.len(), 3 * (8192 + 1) * 2);
        assert!(record.payload.len() < 64 * 1024);
    }

    #[test]
    fn broker_diagnostic_has_utf16_payload_and_distinct_event_severity() {
        for failure in [false, true] {
            let record = Record::broker_message("Site 🦀: stopped", failure);
            let expected: Vec<_> = "Site 🦀: stopped"
                .encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            assert_eq!(record.payload, expected);
            assert_eq!(record.identity(), if failure { (301, 2) } else { (300, 4) });
        }
    }

    #[test]
    fn session_payload_matches_manifest_field_widths_without_padding() {
        let mut options = Options::new(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        );
        options.multihop = true;
        options.discriminator = Some(7);
        let auth = options.validate().unwrap();
        let mut session = Session::new(options.clone(), auth).unwrap();
        session.admin_down();
        let payload = session_payload(
            &options,
            &session,
            State::Up,
            42,
            session.state(),
            session.diagnostic() as u8,
        )
        .unwrap();
        let mut expected = Vec::new();
        for address in ["2001:db8::1", "2001:db8::2"] {
            for unit in address.encode_utf16().chain(Some(0)) {
                expected.extend_from_slice(&unit.to_le_bytes());
            }
        }
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(&42u32.to_le_bytes());
        expected.extend_from_slice(&[3, 0, 7]);
        expected.extend_from_slice(&1_000_000u64.to_le_bytes());
        expected.extend_from_slice(&1_000_000u64.to_le_bytes());
        assert_eq!(payload, expected);
    }

    #[test]
    fn error_text_replaces_nuls_and_truncates_on_character_boundaries() {
        let mut payload = Vec::new();
        append_unicode(&mut payload, "a\0\u{1f600}");
        assert_eq!(payload, [0x61, 0, 0xfd, 0xff, 0x3d, 0xd8, 0, 0xde, 0, 0]);
        payload.clear();
        append_unicode(&mut payload, &format!("{}\u{1f600}", "a".repeat(8191)));
        assert_eq!(payload.len(), 8192 * 2);
        assert_eq!(&payload[payload.len() - 4..], &[0x61, 0, 0, 0]);
    }

    #[test]
    fn authentication_payload_contains_context_and_reason_without_key_material() {
        let mut options = Options::new(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        );
        options.multihop = true;
        options.auth = crate::packet::AuthType::MeticulousSha1;
        options.auth_key_id = 9;
        options.auth_key = Some("hidden-key".into());
        let source = "[2001:db8::2]:55000".parse().unwrap();
        let payload = authentication_payload(&options, 7, source, "authentication digest mismatch");
        let mut expected = Vec::new();
        for text in ["2001:db8::1", "2001:db8::2", "[2001:db8::2]:55000"] {
            for unit in text.encode_utf16().chain(Some(0)) {
                expected.extend_from_slice(&unit.to_le_bytes());
            }
        }
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(&[5, 9]);
        for unit in "authentication digest mismatch"
            .encode_utf16()
            .chain(Some(0))
        {
            expected.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(payload, expected);
        let key: Vec<_> = "hidden-key"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(!payload.windows(key.len()).any(|bytes| bytes == key));
    }

    #[test]
    fn service_warning_payload_and_text_use_the_warning_level() {
        let record = Record::service_warning("configure AllowedPeers");
        assert_eq!(record.identity(), (4, 3));
        let mut expected = vec![0];
        append_unicode(&mut expected, "configure AllowedPeers");
        assert_eq!(record.payload, expected);
        assert_eq!(
            record.text.as_deref(),
            Some("event_id=4 level=Warning configure AllowedPeers")
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn native_provider_registration_and_lifecycle_writes_succeed() {
        let provider = Provider::register().unwrap();
        provider.emit(&Record::service_started()).unwrap();
        provider
            .emit(&Record::service_failed("synthetic ETW smoke test"))
            .unwrap();
        provider
            .emit(&Record::service_warning("synthetic ETW warning"))
            .unwrap();
        provider.emit(&Record::service_stopped(1)).unwrap();
    }
}
