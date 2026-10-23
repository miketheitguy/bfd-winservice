//! Noninteractive DPAPI decryption; registry ACLs control access to machine-scope blobs.
#![allow(unsafe_code)]

use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
};

struct Plaintext(CRYPT_INTEGER_BLOB);

impl Drop for Plaintext {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: DPAPI returns one LocalAlloc allocation containing cbData
            // initialized bytes. This owner alone accesses and frees that allocation.
            // u32 lengths fit usize on the supported Windows x64 target.
            unsafe {
                super::wipe(std::slice::from_raw_parts_mut(
                    self.0.pbData,
                    self.0.cbData as usize,
                ));
                LocalFree(self.0.pbData.cast());
            }
        }
    }
}

pub(super) fn unprotect(ciphertext: &mut [u8]) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(ciphertext.len()).map_err(io::Error::other)?,
        pbData: ciphertext.as_mut_ptr(),
    };
    let mut plaintext = Plaintext(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    });
    // SAFETY: input describes initialized, exclusively borrowed bytes that live
    // through this synchronous call. The output is initialized writable storage.
    // No description, entropy, reserved data, or UI is supplied. The output owner
    // wipes and LocalFree-releases the native allocation on every return path.
    if unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut plaintext.0,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("cannot decrypt Secrets\\AuthKeyDpapi with DPAPI: {error}"),
        ));
    }
    // All supported BFD authentication keys are 1..=20 bytes. Mode-specific
    // limits are checked by AuthConfig before sockets or RPC become available.
    if plaintext.0.pbData.is_null() || !(1..=20).contains(&plaintext.0.cbData) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Secrets\\AuthKeyDpapi must decrypt to a key of 1..=20 bytes",
        ));
    }
    // SAFETY: successful DPAPI output owns cbData initialized bytes; the length
    // was bounded above. Copy before the native owner wipes and frees its buffer.
    Ok(unsafe {
        std::slice::from_raw_parts(plaintext.0.pbData, plaintext.0.cbData as usize).to_vec()
    })
}

#[cfg(all(test, not(miri)))]
pub(super) fn protect(key: &mut [u8]) -> Vec<u8> {
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(key.len()).unwrap(),
        pbData: key.as_mut_ptr(),
    };
    let mut output = Plaintext(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    });
    assert_ne!(
        // SAFETY: initialized borrowed input and writable output live for the entire
        // call. DPAPI allocates the output; its owner wipes and frees it after copying.
        unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        },
        0,
        "CryptProtectData: {}",
        io::Error::last_os_error()
    );
    // SAFETY: successful DPAPI output supplies cbData initialized allocated bytes.
    unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec() }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;

    #[test]
    fn machine_scope_round_trip_works_with_write_restricted_token() {
        use crate::local_rpc::test_support::{restricted_token, OwnIdentity};
        const CHILD: &str = "BFD_TEST_DPAPI_MINIMUM_PRIVILEGES";
        if std::env::var_os(CHILD).is_none() {
            // Privilege removal is permanent and confined to this child fixture.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "config::dpapi::tests::machine_scope_round_trip_works_with_write_restricted_token", "--nocapture"])
                .env(CHILD, "1").status().unwrap();
            assert!(status.success(), "{status}");
            return;
        }
        crate::runtime::drop_rpc_privileges().unwrap();
        crate::runtime::verify_service_privileges().unwrap();
        let mut expected = [0x00, 0xff, 0x80, 0x41];
        let mut ciphertext = protect(&mut expected);
        let token = restricted_token(crate::bgp::ipc::SERVICE_SID, false);
        let _identity = OwnIdentity::enter(&token);
        let mut actual = unprotect(&mut ciphertext).unwrap();
        assert_eq!(actual, expected);
        super::super::wipe(&mut actual);
    }

    #[test]
    fn rejects_malformed_ciphertext_and_invalid_plaintext_lengths_without_disclosure() {
        for mut data in [vec![], vec![0; 32], b"not-a-dpapi-blob".to_vec()] {
            let error = unprotect(&mut data).err().unwrap().to_string();
            assert!(error.contains("AuthKeyDpapi"));
            assert!(!error.contains("not-a-dpapi-blob"));
        }
        for length in [0, 21, 4096] {
            let mut ciphertext = protect(&mut vec![0x61; length]);
            assert!(unprotect(&mut ciphertext).is_err());
        }
        assert_eq!(unprotect(&mut protect(&mut [0x42; 20])).unwrap().len(), 20);
    }
}
