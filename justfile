test:
    cargo nextest run

check:
    bacon clippy

build:
    cargo build

release:
    cargo build --release

example-chrono:
        cargo run --example totp_chrono

example-time:
    cargo run --example totp_time
