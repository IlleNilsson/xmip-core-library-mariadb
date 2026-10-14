//! `mysql_native_password`, the login every `MariaDB` server speaks — the
//! name is the protocol's, older than the fork.
//!
//! The answer is `SHA1(password) XOR SHA1(nonce + SHA1(SHA1(password)))`:
//! the server holds `SHA1(SHA1(password))` and recovers `SHA1(password)`
//! from the answer to check it, and a listener on the wire gets neither.
//! One answer and no more: a server that asks for more after it is not
//! speaking this plugin.

use codec::sha1::{DIGEST_LENGTH, digest};

use crate::Result;
use crate::authentication::{Authentication, Conversation, Verification};

/// The plugin's name on the wire.
pub const NATIVE_PASSWORD: &str = "mysql_native_password";

/// The native password, both ends.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativePassword;

/// `password` scrambled with `nonce` the native way; empty for an empty
/// password, which is what the server expects of an account without one.
#[must_use]
pub fn scramble(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let first = digest(password.as_bytes());
    let second = digest(&first);
    let mut salted = Vec::with_capacity(nonce.len() + DIGEST_LENGTH);
    salted.extend_from_slice(nonce);
    salted.extend_from_slice(&second);
    let third = digest(&salted);
    first.iter().zip(third).map(|(a, b)| a ^ b).collect()
}

/// True when `response` is `password` scrambled with `nonce`.
#[must_use]
pub fn verify(password: &str, nonce: &[u8], response: &[u8]) -> bool {
    codec::constant_time::equal(&scramble(password, nonce), response)
}

impl Authentication for NativePassword {
    fn plugin(&self) -> &'static str {
        NATIVE_PASSWORD
    }

    fn first(&self, password: &str, nonce: &[u8]) -> Result<Vec<u8>> {
        Ok(scramble(password, nonce))
    }
}

impl Verification for NativePassword {
    fn plugin(&self) -> &'static str {
        NATIVE_PASSWORD
    }

    fn verify(
        &self,
        _: &mut Conversation<'_>,
        password: &str,
        nonce: &[u8],
        response: &[u8],
    ) -> Result<bool> {
        Ok(verify(password, nonce, response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::hex;

    #[test]
    fn the_native_password_is_the_documented_scramble() {
        let nonce: Vec<u8> = (1..=20).collect();
        let scrambled = scramble("secret", &nonce);
        assert_eq!(scrambled.len(), DIGEST_LENGTH);
        let mut salted = nonce.clone();
        salted.extend_from_slice(&digest(&digest(b"secret")));
        let expected: Vec<u8> = digest(b"secret")
            .iter()
            .zip(digest(&salted))
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(hex::encode(&scrambled), hex::encode(&expected));
        assert!(verify("secret", &nonce, &scrambled));
        assert!(!verify("wrong", &nonce, &scrambled));
        assert!(!verify("secret", &[0; 20], &scrambled), "another nonce");
        assert_eq!(scramble("", &nonce), [] as [u8; 0]);
        assert!(verify("", &nonce, &[]));
    }
}
