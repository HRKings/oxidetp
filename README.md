# OxideTP (OTP)

This is a simple crate that provides methods for generating HOTP and TOTP codes, supporting window verification for TOTPs, creating an URI for QR Codes and also importing a URI.

## Code Examples

By reading the examples and tests, you can get a feel of what the library does, but here is some snippets

TOTP:

```rust
// Create a TOTP with a secret and the defaults: SHA1 hash. 6-digit code and a period of 30 seconds
let mut totp_base = TOTP::new("BASE32SECRET");

// TOTP supports the builder pattern:
totp_base
    .with_algorithm(OtpHashAlgorithm::SHA512)
    // Sets the period to 60 seconds
    .with_period(60)
    // Set the TOTP to generate 8-digit codes
    .with_digits(8);


// The generation code will return a u32 and the digits, to zero-pad use the to_string() method
let generated_otp = totp_base.generate(123)?;

// The generation code will create a u32 code, to zero-pad use the provided method
generated_otp.to_string()

// Generates the URI
let generated_uri = totp_base.to_uri("john.doe@email.com", Some("ACME Co"))?;
// the code above will generate this: "otpauth://totp/ACME%20Co:john.doe@email.com?secret=BASE32SECRET&issuer=ACME+Co&algorithm=SHA1&digits=6&period=30"

// This will take the above URI and recreate the TOTP
let parsed_totp = TOTP::from_uri(&generated_uri)
```

HOTP:

```rust
// Create a HOTP with secret and SHA1 hash
let mut hotp_base = TOTP::new("BASE32SECRET");

// HOTP supports the builder pattern:
hotp_base
    .with_algorithm(OtpHashAlgorithm::SHA512)
    // Set the TOTP to generate 8-digit codes
    .with_digits(8);

// Sets the internal counter, which is used to generate the URI
hotp_base.with_counter(123);

// Generate the code, in this example, the code will be generated from a 123 counter
let generated_otp = hotp_base.generate(123)?;

// Alternatively, you can generate the code and update the counter, it is recommended that the counter is stored in another place (like a cache and/or database) for ease of access and distribution of the counter 
let generated_otp = generate_and_update_counter.generate(123)?;

// The generation code will return a u32 and the digits, to zero-pad use the to_string() method
generated_otp.to_string()

// Generates the URI, remember to set the counter beforehand
let generated_uri = hotp_base.to_uri("john.doe@email.com", Some("ACME Co"))?;
// the code above will generate this: "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=BASE32SECRET&issuer=ACME+Co&algorithm=SHA1&digits=6&counter=30"

// This will take the above URI and recreate the TOTP
let parsed_hotp = HOTP::from_uri(&generated_uri)
```

## Observations about time

In case of TOTPs, the library does not provide a timestamp implementation, instead relying on the developer to pass the seconds since the Unix Epoch directly into the function, this was done because I didn't want to use the `chrono` or `time` crates as some people use one or another. I also recommend implementing a way to correct the time if the local one is wrong.

If the necessity arises, I will implement those time functions into the code. For now, examples are provided for both crates

## References

- <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
- <https://github.com/WesleyBatista/rust-otp>
- <https://github.com/kspearrin/Otp.NET>
