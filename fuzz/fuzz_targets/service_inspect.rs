#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let port = u16::from_be_bytes([data[0], data[1]]);
    let payload = &data[2..];
    std::hint::black_box(rayscan::service::inspect(port, payload));
});
