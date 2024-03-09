# OxideTP (OTP)

This is a simple crate that provides methods for generating HOTP and TOTP codes, supporting window verification for TOTPs, creating an URI for QR Codes and also importing a URI.

## Observations about time

In case of TOTPs, the library does not provide a timestamp implementation, instead relying on the developer to pass the seconds since the Unix Epoch directly into the function, this was done because I didn't want to use the `chrono` or `time` crates as some people use one or another. I also recommend implementing a way to correct the time if the local one is wrong.

If the necessity arises, I will implement those time functions into the code.

## References

- <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
- <https://github.com/WesleyBatista/rust-otp>
- <https://github.com/kspearrin/Otp.NET>
