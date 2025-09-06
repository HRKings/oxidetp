use crate::{
    uri_helper::{self, otp_to_uri, OtpType, OtpUriInput},
    Otp, OtpCode, OtpError, OtpHashAlgorithm,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Hotp {
    pub(crate) secret: String,
    pub(crate) algorithm: OtpHashAlgorithm,
    // How many digits to generate
    pub(crate) digits: u32,
    // The internal counter, used to generate the URI
    pub(crate) counter: u64,
}

impl Otp for Hotp {
    fn to_uri(&self, user: &str, issuer: Option<&str>) -> Result<String, OtpError> {
        otp_to_uri(OtpUriInput::Hotp(self), user, issuer)
    }

    fn from_uri(uri: &str) -> Result<Self, OtpError> {
        let result = uri_helper::otp_from_uri(uri, OtpType::Hotp)?;
        match result {
            uri_helper::OtpUriResult::Hotp(r) => Ok(r),
            _ => panic!(),
        }
    }
}

impl Hotp {
    /// Creates the config for the [HMAC-based One-time Password Algorithm](http://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm)
    /// (HOTP) given an RFC4648 base32 encoded secret
    ///
    /// Obs.: This method defaults to the SHA1 hash and a 6-digit code
    pub fn new(secret: String) -> Self {
        Self {
            secret,
            algorithm: OtpHashAlgorithm::SHA1,
            digits: 6,
            counter: 0,
        }
    }

    ///  Sets hashing algorithm
    pub fn with_algorithm(&mut self, algorithm: OtpHashAlgorithm) -> &mut Self {
        self.algorithm = algorithm;

        self
    }

    ///  Sets the number of digits to generate
    pub fn with_digits(&mut self, digits: u32) -> &mut Self {
        self.digits = digits;

        self
    }

    ///  Sets the internal counter
    pub fn with_counter(&mut self, counter: u64) -> &mut Self {
        self.counter = counter;

        self
    }

    /// Generates a HTOPT from the provided counter
    /// truncated to the specified number of digits
    pub fn generate(&self, counter: u64) -> Result<OtpCode, OtpError> {
        let decoded = Self::decode_secret(self.secret.as_str())?;
        let digest = self.calc_digest(decoded.as_slice(), self.algorithm, counter);

        let code = Self::encode_digest_truncated(digest.as_ref(), self.digits)?;

        Ok(OtpCode {
            code,
            digits: self.digits,
        })
    }

    /// Generates a HTOPT from the provided counter
    /// truncated to the specified number of digits
    ///
    /// Also updates the internal counter
    pub fn generate_and_update_counter(&mut self, counter: u64) -> Result<OtpCode, OtpError> {
        self.with_counter(counter);
        self.generate(counter)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    use crate::{hotp::Hotp, Otp, OtpHashAlgorithm};

    #[rstest]
    #[case(0, 755224)]
    #[case(1, 287082)]
    #[case(2, 359152)]
    #[case(3, 969429)]
    #[case(4, 338314)]
    #[case(5, 254676)]
    #[case(6, 287922)]
    #[case(7, 162583)]
    #[case(8, 399871)]
    #[case(9, 520489)]
    fn hotp(#[case] counter: u64, #[case] expected: u32) {
        let hotp = Hotp::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string());

        assert_eq!(hotp.generate(counter).unwrap().integer(), expected);
    }

    #[rstest]
    #[case("sha1", 6, 30,
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA1&digits=6&counter=30")]
    #[case("sha256", 8, 30,
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA256&digits=8&counter=30")]
    #[case("sha512", 6, 10,
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA512&digits=6&counter=10")]
    fn to_uri_test(
        #[case] hash: OtpHashAlgorithm,
        #[case] digits: u32,
        #[case] counter: u64,
        #[case] expected: &str,
    ) {
        let mut hotp_base = Hotp::new("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string());
        hotp_base
            .with_algorithm(hash)
            .with_digits(digits)
            .with_counter(counter);

        let generated_uri = hotp_base
            .to_uri("john.doe@email.com", Some("ACME Co"))
            .unwrap();

        assert_eq!(expected, generated_uri)
    }

    #[rstest]
    #[case("sha1", 6, 30,
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&counter=30")]
    #[case("sha256", 8, 30,
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&counter=30")]
    #[case("sha512", 6, 10,
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA512&digits=6&counter=10")]
    fn from_uri_test(
        #[case] hash: OtpHashAlgorithm,
        #[case] digits: u32,
        #[case] counter: u64,
        #[case] input_uri: &str,
    ) {
        let mut expected_hotp = Hotp::new("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string());
        expected_hotp
            .with_algorithm(hash)
            .with_digits(digits)
            .with_counter(counter);

        let generated_hotp = Hotp::from_uri(input_uri).unwrap();

        assert_eq!(expected_hotp, generated_hotp);
        assert_eq!(
            expected_hotp.generate(expected_hotp.counter).unwrap(),
            generated_hotp.generate(generated_hotp.counter).unwrap()
        );
        assert_eq!(
            expected_hotp.generate(expected_hotp.counter).unwrap(),
            generated_hotp.generate(generated_hotp.counter).unwrap()
        );
    }
}
