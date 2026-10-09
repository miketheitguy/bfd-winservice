//! Check the service executable produced by Cargo, including its PE load config.
//! Layouts: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format> and
//! <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64>.
#![cfg(all(windows, not(miri)))]
#![forbid(unsafe_code)]

use std::{fs, path::PathBuf};

#[test]
fn service_executable_is_x64_with_required_windows_mitigations() {
    let executable = std::env::var_os("BFD_HARDENING_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_bfd-winservice")));
    assert_executable(&executable);
    assert_executable(&executable.with_file_name("bfd-bgp-broker.exe"));
}

fn assert_executable(executable: &std::path::Path) {
    let image = fs::read(executable).expect("Cargo must produce the service executable");
    assert_eq!(&image[..2], b"MZ");
    let pe = usize::try_from(dword(&image, 0x3c)).expect("PE offset fits usize");
    assert_eq!(&image[pe..pe + 4], b"PE\0\0");
    assert_eq!(word(&image, pe + 4), 0x8664, "machine must be x64");
    assert_ne!(word(&image, pe + 22) & 0x20, 0, "large address awareness");

    let optional = pe + 24;
    assert_eq!(word(&image, optional), 0x20b, "image must be PE32+");
    let dll_flags = word(&image, optional + 70);
    for (mask, name) in [
        (0x0020, "high-entropy ASLR"),
        (0x0040, "ASLR"),
        (0x0100, "NX/DEP"),
        (0x4000, "CFG"),
    ] {
        assert_ne!(dll_flags & mask, 0, "missing {name}");
    }

    assert!(dword(&image, optional + 108) > 10, "PE data directories");
    let directories = optional + 112;
    assert_ne!(dword(&image, directories + 5 * 8), 0, "relocation RVA");
    assert_ne!(dword(&image, directories + 5 * 8 + 4), 0, "relocation size");

    let load_rva = dword(&image, directories + 10 * 8);
    assert_ne!(load_rva, 0, "load configuration RVA");
    assert!(dword(&image, directories + 10 * 8 + 4) >= 280);
    let sections = optional + usize::from(word(&image, pe + 20));
    let section_count = usize::from(word(&image, pe + 6));
    let load = file_offset(&image, sections, section_count, load_rva);
    assert!(dword(&image, load) >= 280, "load configuration size");

    // A cookie alone does not prove Rust instrumentation; .cargo/config.toml
    // selects stack-protector=all, which also needs compiler-output verification.
    assert_ne!(qword(&image, load + 88), 0, "stack security cookie");
    assert_ne!(qword(&image, load + 112), 0, "CFG check-function pointer");
    assert_ne!(
        qword(&image, load + 120),
        0,
        "CFG dispatch-function pointer"
    );
    assert_ne!(qword(&image, load + 128), 0, "CFG function table");
    assert_ne!(qword(&image, load + 136), 0, "CFG function count");
    assert_eq!(
        dword(&image, load + 144) & 0x500,
        0x500,
        "CFG instrumentation and function-table flags"
    );

    assert_ne!(
        dword(&image, load + 144) & 0x0040_0000,
        0,
        "EH continuation table must be enabled"
    );
    let image_base = qword(&image, optional + 24);
    let eh_table = qword(&image, load + 264);
    let eh_count = usize::try_from(qword(&image, load + 272)).expect("EH count fits usize");
    // Aborting on panic can remove all Rust landing pads. Enabled metadata with
    // an empty table is valid and disallows continuation targets in this image.
    let eh_offset = if eh_count == 0 {
        0
    } else {
        assert_ne!(eh_table, 0, "nonempty EH continuation table");
        let eh_rva = u32::try_from(eh_table.checked_sub(image_base).expect("EH table VA"))
            .expect("EH table RVA fits DWORD");
        file_offset(&image, sections, section_count, eh_rva)
    };
    let mut previous = None;
    for index in 0..eh_count {
        let target = dword(&image, eh_offset + index * 4);
        assert!(
            previous.is_none_or(|previous| target > previous),
            "EH targets must be sorted and unique"
        );
        let _ = file_offset(&image, sections, section_count, target);
        previous = Some(target);
    }

    // /CETCOMPAT records its bit in an extended-DLL-characteristics debug entry,
    // rather than in the optional header's ordinary DLL characteristics.
    let debug_rva = dword(&image, directories + 6 * 8);
    assert_ne!(debug_rva, 0, "debug directory for CET compatibility");
    let debug = file_offset(&image, sections, section_count, debug_rva);
    let debug_size = usize::try_from(dword(&image, directories + 6 * 8 + 4))
        .expect("debug directory size fits usize");
    assert_eq!(debug_size % 28, 0, "complete debug directory entries");
    let cet_compatible = (0..debug_size / 28).any(|index| {
        let entry = debug + index * 28;
        if dword(&image, entry + 12) != 20 || dword(&image, entry + 16) < 4 {
            return false;
        }
        let data = usize::try_from(dword(&image, entry + 24)).expect("debug data offset");
        dword(&image, data) & 1 != 0
    });
    assert!(cet_compatible, "image must be CET shadow-stack compatible");

    let pdb_name = executable
        .file_stem()
        .expect("executable name")
        .to_string_lossy()
        .replace('-', "_")
        + ".pdb";
    let pdb = fs::read(executable.with_file_name(pdb_name))
        .expect("full debug symbols must be generated alongside the executable");
    assert_eq!(
        &pdb[..32],
        b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0",
        "PDB container"
    );
}

fn word(image: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(image[offset..offset + 2].try_into().expect("PE word"))
}

fn dword(image: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(image[offset..offset + 4].try_into().expect("PE DWORD"))
}

fn qword(image: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(image[offset..offset + 8].try_into().expect("PE QWORD"))
}

fn file_offset(image: &[u8], sections: usize, count: usize, rva: u32) -> usize {
    for index in 0..count {
        let section = sections + index * 40;
        let virtual_address = dword(image, section + 12);
        if let Some(relative) = rva.checked_sub(virtual_address) {
            if relative < dword(image, section + 16) {
                let offset = dword(image, section + 20)
                    .checked_add(relative)
                    .expect("section file offset must not overflow");
                return usize::try_from(offset).expect("section offset fits usize");
            }
        }
    }
    panic!("RVA {rva:#x} must be backed by a PE section");
}
