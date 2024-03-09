pub mod hotp;
pub mod totp;

use std::{fmt::Display, str::FromStr};

use anyhow::Result;
use ring::hmac;

#[derive(Debug, thiserror::Error)]
pub enum OTPError {
    #[error("Invalid digest.")]
    InvalidDigest(Vec<u8>),
    #[error("Invalid hashing algorithm, found {0}. Expected one of: SHA1, SHA256 or SHA512")]
    InvalidHashingAlgorithm(String),
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum OTPHashAlgorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl Display for OTPHashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SHA1 => write!(f, "SHA1"),
            Self::SHA256 => write!(f, "SHA256"),
            Self::SHA512 => write!(f, "SHA512"),
        }
    }
}

impl FromStr for OTPHashAlgorithm {
    type Err = OTPError;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let normalized = s.to_uppercase();

        match normalized.as_str() {
            "SHA1" => Ok(Self::SHA1),
            "SHA256" => Ok(Self::SHA256),
            "SHA512" => Ok(Self::SHA512),
            _ => Err(OTPError::InvalidHashingAlgorithm(s.to_string())),
        }
    }
}

pub trait OTP {
    /// Decodes a secret (given as an RFC4648 base32-encoded ASCII string)
    /// into a byte string
    fn decode_secret(secret: &str) -> Result<Vec<u8>, data_encoding::DecodeError> {
        data_encoding::BASE32_NOPAD.decode(secret.as_bytes())
    }

    /// Calculates the HMAC digest for the given secret.
    fn calc_digest(
        &self,
        decoded_secret: &[u8],
        algorithm: OTPHashAlgorithm,
        data: u64,
    ) -> hmac::Tag {
        let hmac_algorithm = match algorithm {
            OTPHashAlgorithm::SHA1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            OTPHashAlgorithm::SHA256 => hmac::HMAC_SHA256,
            OTPHashAlgorithm::SHA512 => hmac::HMAC_SHA512,
        };

        let key = hmac::Key::new(hmac_algorithm, decoded_secret);
        hmac::sign(&key, &data.to_be_bytes())
    }

    /// Encodes the HMAC digest into a truncated integer.
    fn encode_digest_truncated(digest: &[u8], target_digits_count: u32) -> Result<u32> {
        // While sometimes this is a hardcoded 19
        // the last byte tells us the offset for any algorithm
        let offset = match digest.last() {
            Some(x) => *x & 0xf,
            None => return Err(OTPError::InvalidDigest(Vec::from(digest)).into()),
        } as usize;

        // Gets the 4 bytes that will compose the code
        let code_bytes: [u8; 4] = match digest[offset..offset + 4].try_into() {
            Ok(x) => x,
            Err(_) => return Err(OTPError::InvalidDigest(Vec::from(digest)).into()),
        };

        let code = u32::from_be_bytes(code_bytes);
        let truncation_factor = u32::pow(10, target_digits_count);

        Ok((code & 0x7fffffff) % truncation_factor)
    }

    fn get_digits(&self) -> u32;
    fn pad_code(&self, code: u32) -> String {
        format!("{:0padding$}", code, padding = (self.get_digits() as usize))
    }

    fn to_uri(&self, user: &str, issuer: Option<&str>) -> Result<String>;
    fn from_uri(uri: &str) -> Result<Self>
    where
        Self: std::marker::Sized;
}
