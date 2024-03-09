# OxideTP (OTP)

This is a simple crate that provides methods for generating HOTP and TOTP codes, supporting window verification for TOTPs, creating an URI for QR Codes and also importing a URI.

## Code Examples
By reading the tests, you can get a feel of what the library does, but here is some examples

TOTP:

```rust
// Create a TOTP with secret, SHA1 hash and a period of 30 seconds
let mut totp_base = TOTP::new("BASE32SECRET", OTPHashAlgorithm::SHA1, 30);

// Set the TOTP to generate 8-digit codes. By default it will generate 6, which is the widely accepted length
totp_base.with_digits(8);

// Generate the code, in this example, the code will be generated from 123 seconds since the Unix Epoch
let generated_otp = totp_base.generate(123).unwrap();

// The generation code will create a u32 code, to zero-pad use the provided method
totp_base.pad_code(generated_otp)

// Generates the URI
let generated_uri = totp_base.to_uri("john.doe@email.com", Some("ACME Co"));
// the code above will generate this: "otpauth://totp/ACME%20Co:john.doe@email.com?secret=BASE32SECRET&issuer=ACME+Co&algorithm=SHA1&digits=6&period=30"

// This will take the above URI and recreate the TOTP
let parsed_totp = TOTP::from_uri(&generated_uri)
```

HOTP:

```rust
// Create a HOTP with secret and SHA1 hash
let mut hotp_base = TOTP::new("BASE32SECRET", OTPHashAlgorithm::SHA1);

// Set the HOTP to generate 8-digit codes. By default it will generate 6, which is the widely accepted length
hotp_base.with_digits(8);

// Sets the internal counter, which is used to generate the URI
hotp_base.with_counter(123);

// Generate the code, in this example, the code will be generated from a 123 counter
let generated_otp = hotp_base.generate(123).unwrap();

// Alternatively, you can generate the code and update the counter, it is recommended that the counter is stored in another place (like a cache and/or database) for ease of access and distribution of the counter 
let generated_otp = generate_and_update_counter.generate(123).unwrap();

// The generation code will create a u32 code, to zero-pad use the provided method
hotp_base.pad_code(generated_otp)

// Generates the URI, remember to set the counter beforehand
let generated_uri = hotp_base.to_uri("john.doe@email.com", Some("ACME Co"));
// the code above will generate this: "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=BASE32SECRET&issuer=ACME+Co&algorithm=SHA1&digits=6&counter=30"

// This will take the above URI and recreate the TOTP
let parsed_hotp = HOTP::from_uri(&generated_uri)
```

## Observations about time

In case of TOTPs, the library does not provide a timestamp implementation, instead relying on the developer to pass the seconds since the Unix Epoch directly into the function, this was done because I didn't want to use the `chrono` or `time` crates as some people use one or another. I also recommend implementing a way to correct the time if the local one is wrong.

If the necessity arises, I will implement those time functions into the code.

## References

- <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
- <https://github.com/WesleyBatista/rust-otp>
- <https://github.com/kspearrin/Otp.NET>
