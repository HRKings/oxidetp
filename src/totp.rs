use crate::{
    uri_helper::{self, otp_to_uri, OtpType, OtpUriInput},
    Otp, OtpCode, OtpError, OtpHashAlgorithm,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Totp {
    pub(crate) secret: String,
    pub(crate) algorithm: OtpHashAlgorithm,
    pub(crate) period: u64,
    pub(crate) digits: u32,
}

impl Otp for Totp {
    fn to_uri(&self, user: &str, issuer: Option<&str>) -> Result<String, OtpError> {
        otp_to_uri(OtpUriInput::Totp(self), user, issuer)
    }

    fn from_uri(uri: &str) -> Result<Self, OtpError> {
        let result = uri_helper::otp_from_uri(uri, OtpType::Totp)?;
        match result {
            uri_helper::OtpUriResult::Totp(r) => Ok(r),
            _ => panic!(),
        }
    }
}

impl Totp {
    /// Creates the config for the [Time-based One-time Password Algorithm](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
    /// (TOTP) given an RFC4648 base32 encoded secret, the period in seconds,
    /// and a skew in seconds.
    ///
    /// Obs.: This method defaults to the SHA1 hash, a 6-digit code and a period of 30 seconds
    pub fn new(secret: String) -> Self {
        Self {
            secret,
            algorithm: OtpHashAlgorithm::SHA1,
            period: 30,
            digits: 6,
        }
    }

    ///  Sets hashing algorithm
    pub fn with_algorithm(&mut self, algorithm: OtpHashAlgorithm) -> &mut Self {
        self.algorithm = algorithm;

        self
    }

    ///  Sets the period in seconds
    pub fn with_period(&mut self, period: u64) -> &mut Self {
        self.period = period;

        self
    }

    ///  Sets the number of digits to generate
    pub fn with_digits(&mut self, digits: u32) -> &mut Self {
        self.digits = digits;

        self
    }

    /// Generates a Totp from the provided seconds since the UNIX epoch
    /// truncated to the specified number of digits
    pub fn generate(&self, seconds_since_epoch: u64) -> Result<OtpCode, OtpError> {
        let calculated_time = seconds_since_epoch / self.period;

        let decoded = Self::decode_secret(self.secret.as_str())?;
        let digest = self.calc_digest(decoded.as_slice(), self.algorithm, calculated_time);

        let code = Self::encode_digest_truncated(digest.as_ref(), self.digits)?;

        Ok(OtpCode {
            code,
            digits: self.digits,
        })
    }

    /// Validates a code in the given window
    /// Returning the window that it was found or None if the code is invalid
    ///
    /// Obs.: the RFC recommends a window of 1 frame in the future and 1 in the past,
    /// but this function accepts any window you would like
    pub fn validate_window(
        &self,
        otp_to_validate: u32,
        seconds_since_epoch: u64,
        past_frames: u64,
        future_frames: u64,
    ) -> Result<Option<u64>, OtpError> {
        let mut frames = vec![seconds_since_epoch];

        for i in 1..=past_frames {
            let old_frame = seconds_since_epoch.checked_sub(i);
            if old_frame.is_none() {
                break;
            }

            frames.push(old_frame.unwrap());
        }

        for i in 1..=future_frames {
            frames.push(seconds_since_epoch + i);
        }

        for i in 0..frames.len() {
            let generated_otp = self.generate(*frames.get(i).expect("Frame not in the vector."))?;

            if generated_otp.integer() == otp_to_validate {
                return Ok(Some(frames[i]));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use rstest::{fixture, rstest};

    use crate::{totp::Totp, Otp, OtpHashAlgorithm};

    #[fixture]
    #[once]
    pub fn sha1_secret() -> String {
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string()
    }

    #[fixture]
    #[once]
    pub fn sha256_secret() -> String {
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA".to_string()
    }

    #[fixture]
    #[once]
    pub fn sha512_secret() -> String {
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA".to_string()
    }

    #[rstest]
    #[case(sha1_secret(), "sha1", 59, "94287082")]
    #[case(sha256_secret(), "sha256", 59, "46119246")]
    #[case(sha512_secret(), "sha512", 59, "90693936")]
    #[case(sha1_secret(), "sha1", 1111111109, "07081804")]
    #[case(sha256_secret(), "sha256", 1111111109, "68084774")]
    #[case(sha512_secret(), "sha512", 1111111109, "25091201")]
    #[case(sha1_secret(), "sha1", 1111111111, "14050471")]
    #[case(sha256_secret(), "sha256", 1111111111, "67062674")]
    #[case(sha512_secret(), "sha512", 1111111111, "99943326")]
    #[case(sha1_secret(), "sha1", 1234567890, "89005924")]
    #[case(sha256_secret(), "sha256", 1234567890, "91819424")]
    #[case(sha512_secret(), "sha512", 1234567890, "93441116")]
    #[case(sha1_secret(), "sha1", 2000000000, "69279037")]
    #[case(sha256_secret(), "sha256", 2000000000, "90698825")]
    #[case(sha512_secret(), "sha512", 2000000000, "38618901")]
    #[case(sha1_secret(), "sha1", 20000000000, "65353130")]
    #[case(sha256_secret(), "sha256", 20000000000, "77737706")]
    #[case(sha512_secret(), "sha512", 20000000000, "47863826")]
    #[case(sha1_secret(), "sha1", 20000000000, "353130")]
    #[case(sha256_secret(), "sha256", 20000000000, "737706")]
    #[case(sha512_secret(), "sha512", 20000000000, "863826")]
    fn totp_test(
        #[case] secret: String,
        #[case] hash: OtpHashAlgorithm,
        #[case] timestamp: u64,
        #[case] expected: &str,
    ) {
        let mut totp_base = Totp::new(secret);
        totp_base
            .with_algorithm(hash)
            .with_digits(expected.len() as u32);

        let generated_otp = totp_base.generate(timestamp).unwrap();
        assert_eq!(expected, generated_otp.to_string());
    }

    #[rstest]
    #[case("sha1", 6, 30,
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA1&digits=6&period=30")]
    #[case("sha256", 8, 30,
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA256&digits=8&period=30")]
    #[case("sha512", 6, 10,
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA512&digits=6&period=10")]
    fn to_uri_test(
        #[case] hash: OtpHashAlgorithm,
        #[case] digits: u32,
        #[case] period: u64,
        #[case] expected: &str,
    ) {
        let mut totp_base = Totp::new("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string());
        totp_base
            .with_algorithm(hash)
            .with_period(period)
            .with_digits(digits);

        let generated_uri = totp_base
            .to_uri("john.doe@email.com", Some("ACME Co"))
            .unwrap();

        assert_eq!(expected, generated_uri)
    }

    #[rstest]
    #[case("sha1", 6, 30,
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")]
    #[case("sha256", 8, 30,
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA256&digits=8&period=30")]
    #[case("sha512", 6, 10,
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA512&digits=6&period=10")]
    fn from_uri_test(
        #[case] hash: OtpHashAlgorithm,
        #[case] digits: u32,
        #[case] period: u64,
        #[case] input_uri: &str,
    ) {
        let mut expected_totp = Totp::new("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string());
        expected_totp
            .with_algorithm(hash)
            .with_period(period)
            .with_digits(digits);

        let totp_base = Totp::from_uri(input_uri).unwrap();

        assert_eq!(expected_totp, totp_base);
        assert_eq!(
            expected_totp.generate(0).unwrap(),
            totp_base.generate(0).unwrap()
        );
        assert_eq!(
            expected_totp.generate(0).unwrap(),
            totp_base.generate(0).unwrap()
        );
    }
}
