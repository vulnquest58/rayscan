#![no_main]

use libfuzzer_sys::fuzz_target;
use rayscan::fingerprint::TcpFingerprint;

fuzz_target!(|data: &[u8]| {
    std::hint::black_box(rayscan::syn::packet::parse_frame(data));
    let mut fingerprint = TcpFingerprint::default();
    rayscan::fingerprint::parse_tcp_options(data, &mut fingerprint);
    std::hint::black_box(fingerprint);
});
