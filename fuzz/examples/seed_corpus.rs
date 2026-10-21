//! Populate an isolated working corpus with deterministic protocol seeds.
#![forbid(unsafe_code)]

fn main() -> std::io::Result<()> {
    let directory = std::env::args_os()
        .nth(1)
        .map(std::path::PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "provide a corpus directory",
            )
        })?;
    for (target, name, bytes) in bfd_winservice_fuzz::seed_cases() {
        let target_directory = directory.join(target);
        std::fs::create_dir_all(&target_directory)?;
        std::fs::write(target_directory.join(name), bytes)?;
    }
    Ok(())
}
