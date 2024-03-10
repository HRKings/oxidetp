test:
    cargo nextest run

check:
    bacon clippy

build:
    cargo build

release:
    cargo build --release

example-chrono:
    cargo run -p totp-chrono

example-time:
    cargo run -p totp-time
