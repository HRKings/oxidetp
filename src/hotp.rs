use std::{borrow::Cow, str::FromStr};

use crate::{OTPHashAlgorithm, OTP};


#[derive(Debug, Clone, PartialEq)]
pub struct HOTP {
    pub(crate) secret: String,
    algorithm: OTPHashAlgorithm,
    // How many digits to generate
    digits: u32,
    // The internal counter, used to generate the URI
    counter: u64,
}

impl OTP for HOTP {
    fn get_digits(&self) -> u32 {
        self.digits
    }

    fn to_uri(&self, user: &str, issuer: Option<&str>) -> Result<String> {
        let mut uri = url::Url::parse("otpauth://hotp/")?;

        if issuer.is_some_and(|i| !i.is_empty()) {
            uri.set_path(&format!("{}:{}", issuer.unwrap(), user));
        } else {
            uri.set_path(user);
        }

        {
            let mut query_params = uri.query_pairs_mut();

            query_params.append_pair("secret", &self.secret);

            if issuer.is_some_and(|i| !i.is_empty()) {
                query_params.append_pair("issuer", issuer.unwrap());
            }

            query_params
                .append_pair("algorithm", &self.algorithm.to_string())
                .append_pair("digits", &self.digits.to_string())
                .append_pair("counter", &self.counter.to_string());
        }

        Ok(uri.to_string())
    }

    fn from_uri(uri: &str) -> Result<Self> {
        let uri = url::Url::parse(uri)?;

        let domain = uri.domain();
        if domain.is_none() || domain.is_some_and(|d| d != "hotp") {
            return Err(anyhow!("The provided URI is not from a HOTP"));
        }

        let mut secret = "".to_string();
        let mut algorithm = OTPHashAlgorithm::default();
        let mut counter = None;
        let mut digits = 6;

        for params in uri.query_pairs() {
            match params.0 {
                Cow::Borrowed("secret") => secret = params.1.to_string(),
                Cow::Borrowed("algorithm") => {
                    algorithm = OTPHashAlgorithm::from_str(params.1.as_ref())?
                }
                Cow::Borrowed("counter") => counter = Some(u64::from_str(params.1.as_ref())?),
                Cow::Borrowed("digits") => digits = u32::from_str(params.1.as_ref())?,
                _ => (),
            }
        }

        if secret.is_empty() {
            return Err(anyhow!("Secret could not be retrieved from the URI."));
        }

        if counter.is_none() {
            return Err(anyhow!("Counter could not be retrieved from the URI."));
        }
        let counter = counter.unwrap();

        Ok(Self {
            secret,
            algorithm,
            counter,
            digits,
        })
    }
}

impl HOTP {
    /// Creates the config for the [HMAC-based One-time Password Algorithm](http://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm)
    /// (HOTP) given an RFC4648 base32 encoded secret
    ///
    /// Obs.: This method defaults to a 6-digit code.
    pub fn new(secret: String, algorithm: OTPHashAlgorithm) -> Self {
        Self {
            secret,
            algorithm,
            digits: 6,
            counter: 0,
        }
    }

    ///  Sets the number of digits to generate
    ///
    /// WARNING: A digit count different from 6 is not tested
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
    pub fn generate(&self, counter: u64) -> Result<u32, OtpError> {
        let decoded = Self::decode_secret(self.secret.as_str())?;
        let digest = self.calc_digest(decoded.as_slice(), self.algorithm, counter);

        Self::encode_digest_truncated(digest.as_ref(), self.digits)
    }

    /// Generates a HTOPT from the provided counter
    /// truncated to the specified number of digits
    ///
    /// Also updates the internal counter
    pub fn generate_and_update_counter(&mut self, counter: u64) -> Result<u32, OtpError> {
        self.with_counter(counter);
        self.generate(counter)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    use crate::{hotp::HOTP, OTPHashAlgorithm, OTP};

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
        let hotp = HOTP::new(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            OTPHashAlgorithm::SHA1,
        );

        assert_eq!(hotp.generate(counter).unwrap(), expected);
    }

    #[rstest]
    #[case("sha1", 6, 30,
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA1&digits=6&counter=30")]
    #[case("sha256", 8, 30,
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA256&digits=8&counter=30")]
    #[case("sha512", 6, 10,
        "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME+Co&algorithm=SHA512&digits=6&counter=10")]
    fn to_uri_test(
        #[case] hash: OTPHashAlgorithm,
        #[case] digits: u32,
        #[case] counter: u64,
        #[case] expected: &str,
    ) {
        let mut hotp_base = HOTP::new("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(), hash);
        hotp_base.with_digits(digits);
        hotp_base.with_counter(counter);

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
        #[case] hash: OTPHashAlgorithm,
        #[case] digits: u32,
        #[case] counter: u64,
        #[case] input_uri: &str,
    ) {
        let mut expected_hotp = HOTP::new("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(), hash);
        expected_hotp.with_digits(digits);
        expected_hotp.with_counter(counter);

        let generated_hotp = HOTP::from_uri(input_uri).unwrap();

        assert_eq!(expected_hotp, generated_hotp);
        assert_eq!(
            expected_hotp.generate(expected_hotp.counter).unwrap(),
            generated_hotp.generate(generated_hotp.counter).unwrap()
        );
        assert_eq!(
            expected_hotp.pad_code(expected_hotp.generate(expected_hotp.counter).unwrap()),
            generated_hotp.pad_code(generated_hotp.generate(generated_hotp.counter).unwrap())
        );
    }
}
