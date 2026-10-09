//! Manifest-based ETW events for BFD-Service/Operational.
//!
//! Event IDs, descriptors, and packed payloads follow events/BFD-Service.man.
//! The provider owns its registration; each EventWrite borrows a payload only
//! for the synchronous call. No callback, raw-pointer owner, or global handle
//! is needed. Logging failures are reported by Logger and never stop BFD.
// ETW registration and writes require the Windows FFI boundary.
#![allow(unsafe_code)]
use crate::{config::Options, packet::State, session::Session};
use std::{io, net::SocketAddr, ptr};
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
const PEER_COMMUNICATION_STARTED: EVENT_DESCRIPTOR = descriptor(100, 4, 2, 0x2);
const PEER_COMMUNICATION_STOPPED: EVENT_DESCRIPTOR = descriptor(101, 3, 2, 0x2);
const SESSION_UP: EVENT_DESCRIPTOR = descriptor(102, 4, 2, 0x2);
const SESSION_DOWN: EVENT_DESCRIPTOR = descriptor(103, 3, 2, 0x2);
const SESSION_STATE_CHANGED: EVENT_DESCRIPTOR = descriptor(104, 4, 2, 0x2);
const AUTHENTICATION_FAILED: EVENT_DESCRIPTOR = descriptor(105, 3, 2, 0x2);

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

pub(crate) enum SessionEvent {
    CommunicationStarted,
    CommunicationStopped,
    StateChanged,
}

impl SessionEvent {
    fn descriptor(&self, state: State) -> &EVENT_DESCRIPTOR {
        match self {
            Self::CommunicationStarted => &PEER_COMMUNICATION_STARTED,
            Self::CommunicationStopped => &PEER_COMMUNICATION_STOPPED,
            Self::StateChanged => match state {
                State::Up => &SESSION_UP,
                State::Down => &SESSION_DOWN,
                State::Init | State::AdminDown => &SESSION_STATE_CHANGED,
            },
        }
    }
}

pub(crate) struct Provider {
    handle: REGHANDLE,
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

    pub(crate) fn service_started(&self, console: bool) -> io::Result<()> {
        self.write(&SERVICE_STARTED, &[u8::from(console)])
    }

    pub(crate) fn service_stopped(&self, console: bool, exit_code: u32) -> io::Result<()> {
        let mut payload = [0; 5];
        payload[0] = u8::from(console);
        payload[1..].copy_from_slice(&exit_code.to_le_bytes());
        self.write(&SERVICE_STOPPED, &payload)
    }

    pub(crate) fn service_failed(&self, console: bool, error: &str) -> io::Result<()> {
        if !self.enabled(&SERVICE_FAILED) {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(256);
        payload.push(u8::from(console));
        append_unicode(&mut payload, error);
        self.write(&SERVICE_FAILED, &payload)
    }

    pub(crate) fn session_event(
        &self,
        event: SessionEvent,
        options: &Options,
        session: &Session,
        previous: State,
        remote_discriminator: u32,
    ) -> io::Result<()> {
        let event = event.descriptor(session.state());
        if !self.enabled(event) {
            return Ok(());
        }
        let payload = session_payload(options, session, previous, remote_discriminator)?;
        self.write(event, &payload)
    }

    pub(crate) fn authentication_failed(
        &self,
        options: &Options,
        session: &Session,
        source: SocketAddr,
        reason: &'static str,
    ) -> io::Result<()> {
        if !self.enabled(&AUTHENTICATION_FAILED) {
            return Ok(());
        }
        let payload =
            authentication_payload(options, session.local_discriminator(), source, reason);
        self.write(&AUTHENTICATION_FAILED, &payload)
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
            eprintln!("Unable to unregister BFD-Service ETW provider: {error}");
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
) -> io::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(256);
    append_unicode(&mut payload, &options.local.to_string());
    append_unicode(&mut payload, &options.peer.to_string());
    payload.extend_from_slice(&session.local_discriminator().to_le_bytes());
    payload.extend_from_slice(&remote_discriminator.to_le_bytes());
    payload.extend_from_slice(&[
        previous as u8,
        session.state() as u8,
        session.diagnostic() as u8,
    ]);
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
    reason: &'static str,
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
            ("PEER_COMMUNICATION_STARTED", PEER_COMMUNICATION_STARTED),
            ("PEER_COMMUNICATION_STOPPED", PEER_COMMUNICATION_STOPPED),
            ("SESSION_UP", SESSION_UP),
            ("SESSION_DOWN", SESSION_DOWN),
            ("SESSION_STATE_CHANGED", SESSION_STATE_CHANGED),
            ("AUTHENTICATION_FAILED", AUTHENTICATION_FAILED),
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
        let payload = session_payload(&options, &session, State::Up, 42).unwrap();
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
        options.auth_key = Some("hidden-key".to_owned());
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
    #[cfg(not(miri))]
    fn native_provider_registration_and_lifecycle_writes_succeed() {
        let provider = Provider::register().unwrap();
        provider.service_started(true).unwrap();
        provider
            .service_failed(true, "synthetic ETW smoke test")
            .unwrap();
        provider.service_stopped(true, 1).unwrap();
    }
}
