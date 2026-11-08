# Fuzz targets

Coverage-guided fuzzing for the untrusted-input parsers.

```bash
cargo install cargo-fuzz --locked
rustup toolchain install nightly
cargo +nightly fuzz run service_inspect -- -max_total_time=60
cargo +nightly fuzz run udp_inspect -- -max_total_time=60
cargo +nightly fuzz run packet_parse -- -max_total_time=60
```

Targets:

- `service_inspect` – TCP banner/product detection (`rayscan::service::inspect`).
- `udp_inspect` – DNS/NTP/SNMP/SIP/NetBIOS response parsers.
- `packet_parse` – Ethernet/IPv4/TCP frame parser and TCP option parser.

Corpus dictionaries and generated artifacts are ignored by git. Crashes should
be added to the regression suite as unit tests before the next release.
