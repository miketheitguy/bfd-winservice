#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    bfd_winservice_fuzz::initialize_fuzzer_coverage();
    bfd_winservice_fuzz::check_packet(data);
});

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    bfd_winservice_fuzz::mutate_packet_input(data, size, max_size, seed)
});
