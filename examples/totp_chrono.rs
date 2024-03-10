use chrono::offset;
use oxidetp::totp::Totp;

pub fn main() -> anyhow::Result<()> {
    // Initialize the TOTP with the defaults (SHA1 hash, 6-digits and 30 seconds period)
    let totp = Totp::new("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".into());

    // Get seconds since Unix Epoch
    let now = offset::Local::now().timestamp();

    // Generate the code with the seconds
    let code = totp.generate(now as u64)?;

    // Print the code
    println!(
        "Code: {}, Remaining time: {}",
        code,
        totp.remaining_seconds(now as u64)
    );

    Ok(())
}
