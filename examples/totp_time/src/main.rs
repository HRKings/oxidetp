use std::time::SystemTime;

use oxidetp::totp::Totp;

pub fn main() -> anyhow::Result<()> {
    // Initialize the TOTP with the defaults (SHA1 hash, 6-digits and 30 seconds period)
    let totp = Totp::new("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".into());

    // Calculate time since Unix Epoch
    let now = SystemTime::now();
    let time_since_epoch = now.duration_since(SystemTime::UNIX_EPOCH)?;

    // Generate the code with the seconds
    let code = totp.generate(time_since_epoch.as_secs())?;

    // Print the code
    println!(
        "Code: {}, Remaining time: {}",
        code,
        totp.remaining_seconds(time_since_epoch.as_secs())
    );

    Ok(())
}
