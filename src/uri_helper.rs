use std::{borrow::Cow, str::FromStr};

use crate::{hotp::Hotp, totp::Totp, OtpError, OtpHashAlgorithm};

const TOTP_TYPE: &str = "totp";
const HOTP_TYPE: &str = "hotp";

const URI_SECRET_QUERY: &str = "secret";
const URI_HASH_QUERY: &str = "algorithm";
const URI_PERIOD_QUERY: &str = "period";
const URI_COUNTER_QUERY: &str = "counter";
const URI_DIGITS_QUERY: &str = "digits";

pub enum OtpType {
    Totp,
    Hotp,
}

pub enum OtpUriResult {
    Totp(Totp),
    Hotp(Hotp),
}

pub enum OtpUriInput<'a> {
    Totp(&'a Totp),
    Hotp(&'a Hotp),
}

pub fn otp_from_uri(uri: &str, otp_type: OtpType) -> Result<OtpUriResult, OtpError> {
    let uri = url::Url::parse(uri).map_err(OtpError::UriParseError)?;

    let otp_type_str = match otp_type {
        OtpType::Totp => TOTP_TYPE,
        OtpType::Hotp => HOTP_TYPE,
    };

    let domain = uri.domain();
    if domain.is_none() || domain.is_some_and(|d| d != otp_type_str) {
        return Err(OtpError::InvalidUriType(
            domain.unwrap_or("None").into(),
            otp_type_str.into(),
        ));
    }

    let mut secret = "".to_string();
    let mut algorithm = OtpHashAlgorithm::default();
    let mut period = 30;
    let mut counter = None;
    let mut digits = 6;

    for params in uri.query_pairs() {
        match params.0 {
            Cow::Borrowed(URI_SECRET_QUERY) => secret = params.1.to_string(),
            Cow::Borrowed(URI_HASH_QUERY) => {
                algorithm = OtpHashAlgorithm::from_str(params.1.as_ref())?
            }
            Cow::Borrowed(URI_PERIOD_QUERY) => {
                period = u64::from_str(params.1.as_ref())
                    .map_err(|e| OtpError::IntegerParseError(e, URI_PERIOD_QUERY.into()))?
            }
            Cow::Borrowed(URI_DIGITS_QUERY) => {
                digits = u32::from_str(params.1.as_ref())
                    .map_err(|e| OtpError::IntegerParseError(e, URI_DIGITS_QUERY.into()))?
            }
            Cow::Borrowed(URI_COUNTER_QUERY) => {
                counter = Some(
                    u64::from_str(params.1.as_ref())
                        .map_err(|e| OtpError::IntegerParseError(e, URI_COUNTER_QUERY.into()))?,
                )
            }
            _ => (),
        }
    }

    if secret.is_empty() {
        return Err(OtpError::UriMissingSecret);
    }

    if matches!(otp_type, OtpType::Totp) {
        return Ok(OtpUriResult::Totp(Totp {
            secret,
            algorithm,
            period,
            digits,
        }));
    }

    if counter.is_none() {
        return Err(OtpError::UriMissingHotpCounter);
    }
    let counter = counter.unwrap();

    Ok(OtpUriResult::Hotp(Hotp {
        secret,
        algorithm,
        counter,
        digits,
    }))
}

pub fn otp_to_uri(
    input: OtpUriInput,
    user: &str,
    issuer: Option<&str>,
) -> Result<String, OtpError> {
    let otp_uri_type = match input {
        OtpUriInput::Totp(_) => TOTP_TYPE,
        OtpUriInput::Hotp(_) => HOTP_TYPE,
    };

    let mut uri =
        url::Url::parse(&format!("otpauth://{otp_uri_type}/")).map_err(OtpError::UriParseError)?;

    if issuer.is_some_and(|i| !i.is_empty()) {
        uri.set_path(&format!("{}:{}", issuer.unwrap(), user));
    } else {
        uri.set_path(user);
    }

    {
        let secret;
        let algorithm;
        let period;
        let counter;
        let digits;

        match input {
            OtpUriInput::Totp(inner) => {
                secret = inner.secret.as_str();
                algorithm = inner.algorithm.to_string();
                period = inner.period.to_string();
                counter = "None".to_string();
                digits = inner.digits.to_string();
            }
            OtpUriInput::Hotp(inner) => {
                secret = inner.secret.as_str();
                algorithm = inner.algorithm.to_string();
                period = "None".to_string();
                counter = inner.counter.to_string();
                digits = inner.digits.to_string();
            }
        }

        let mut query_params = uri.query_pairs_mut();

        query_params.append_pair("secret", secret);

        if issuer.is_some_and(|i| !i.is_empty()) {
            query_params.append_pair("issuer", issuer.unwrap());
        }

        query_params
            .append_pair(URI_HASH_QUERY, algorithm.as_str())
            .append_pair(URI_DIGITS_QUERY, digits.as_str());

        match input {
            OtpUriInput::Totp(_) => query_params.append_pair(URI_PERIOD_QUERY, period.as_str()),
            OtpUriInput::Hotp(_) => query_params.append_pair(URI_COUNTER_QUERY, counter.as_str()),
        };
    }

    Ok(uri.to_string())
}
