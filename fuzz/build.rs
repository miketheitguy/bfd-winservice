fn main() {
    println!("cargo:rerun-if-changed=native/msvc_coverage.c");
    #[cfg(target_env = "msvc")]
    if std::env::var_os("CARGO_FEATURE_FUZZING").is_some()
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        // Deliberately separate from LLVM-instrumented Rust code. The helper
        // only registers image sections; it never handles packet input.
        cc::Build::new()
            .compiler("cl.exe")
            .no_default_flags(true)
            .env("CL", "")
            .env("_CL_", "")
            .env("CFLAGS", "")
            .env("HOST_CFLAGS", "")
            .env("TARGET_CFLAGS", "")
            .env("CFLAGS_x86_64_pc_windows_msvc", "")
            .env("CFLAGS_x86_64-pc-windows-msvc", "")
            .flags([
                "/nologo",
                "/TC",
                "/MD",
                "/GS",
                "/guard:cf",
                "/guard:ehcont",
                "/sdl",
                "/W4",
                "/WX",
                "/analyze",
                "/analyze:external-",
                "/D_WIN32_WINNT=0x0602",
            ])
            .file("native/msvc_coverage.c")
            .compile("bfd_fuzz_coverage");
    }
}
