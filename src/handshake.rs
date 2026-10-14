//! The login's packets: the greeting a server opens with, the SSL request a
//! client may answer it with first, the response it then answers with, and
//! the switch a server asks for when it wants another plugin. Written and
//! read on both sides, because the far-end [`crate::Session`] speaks the
//! server's half.
//!
//! The greeting is `HandshakeV10`: a version, a connection id, twenty
//! bytes of nonce in two parts, and the capabilities and plugin the server
//! offers. The response is `HandshakeResponse41`, the shape every client
//! since 4.1 sends: the capabilities the client takes up, the user, the
//! plugin's first answer, the database and the plugin name. This crate
//! takes up four capabilities — protocol 4.1, the secure connection that
//! gives the answer a length byte, plugin authentication so both sides can
//! name the plugin, and connecting straight to the database — and
//! [`CLIENT_SSL`] where the connection is to be guarded, and no more:
//! `CLIENT_DEPRECATE_EOF` is left off so a result set is bounded by the EOF
//! packets `result.rs` reads.
//!
//! The SSL request is the response's first thirty-two bytes and nothing
//! after: the capabilities with [`CLIENT_SSL`], the packet size and the
//! character set. Both ends hand the socket to TLS once it is sent, and
//! the response follows guarded, the sequence counting on.

use codec::cursor::Cursor;
use codec::writer::ByteWriter;

use crate::native_password::NATIVE_PASSWORD;
use crate::wire::{MariaDb, MariaDbWrite};
use crate::{Result, protocol_error};

/// The version byte a greeting opens with.
pub const PROTOCOL_VERSION: u8 = 10;
/// A nonce is twenty bytes: eight in the greeting's first part, twelve in
/// its second.
pub const NONCE_LENGTH: usize = 20;

/// Connect straight to a database.
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
/// The 4.1 shapes of the response and of every result.
pub const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
/// The connection is upgraded to TLS after the SSL request.
pub const CLIENT_SSL: u32 = 0x0000_0800;
/// The answer behind a length byte rather than a NUL.
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
/// Both sides name the plugin.
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
/// The answer behind a length-encoded length; read, never sent.
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
/// What this crate takes up.
pub const CAPABILITIES: u32 =
    CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_WITH_DB;
/// utf8mb4, general collation.
const UTF8MB4: u8 = 45;
/// The most a client says it takes in one packet.
const MAX_PACKET_SIZE: u32 = 0x0100_0000;
/// The SSL request's length: the response's fixed head and nothing after.
const SSL_REQUEST_LENGTH: usize = 32;

/// What a server opens with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeV10 {
    pub server_version: String,
    pub connection_id: u32,
    pub nonce: Vec<u8>,
    pub capabilities: u32,
    pub plugin: String,
}

/// What a client answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResponse41 {
    pub capabilities: u32,
    pub user: String,
    /// The plugin's first answer, or empty where there is no password.
    pub auth_response: Vec<u8>,
    pub database: String,
    pub plugin: String,
}

/// `greeting` as a payload.
#[must_use]
pub fn encode_handshake(greeting: &HandshakeV10) -> Vec<u8> {
    let mut nonce = greeting.nonce.clone();
    nonce.resize(NONCE_LENGTH, b'x');
    let capabilities = greeting.capabilities.to_le_bytes();
    let mut out = vec![PROTOCOL_VERSION];
    out.cstring(&greeting.server_version)
        .u32_le(greeting.connection_id)
        .bytes(&nonce[..8])
        .byte(0)
        .bytes(&capabilities[..2])
        .byte(UTF8MB4)
        .u16_le(2) // SERVER_STATUS_AUTOCOMMIT
        .bytes(&capabilities[2..])
        .byte(u8::try_from(NONCE_LENGTH + 1).unwrap_or(21))
        .bytes(&[0u8; 10])
        .bytes(&nonce[8..])
        .byte(0)
        .cstring(&greeting.plugin);
    out
}

/// The greeting a payload carries.
///
/// # Errors
/// A version other than 10, or a payload that breaks off.
pub fn decode_handshake(payload: &[u8]) -> Result<HandshakeV10> {
    let mut cursor = Cursor::new(payload);
    let version = cursor.byte()?;
    if version != PROTOCOL_VERSION {
        return Err(protocol_error(format!(
            "handshake version {version} is not 10"
        )));
    }
    let server_version = cursor.cstring()?;
    let connection_id = cursor.u32_le()?;
    let mut nonce = cursor.take(8)?.to_vec();
    cursor.skip(1)?;
    let lower = cursor.u16_le()?;
    cursor.skip(3)?;
    let upper = cursor.u16_le()?;
    let capabilities = u32::from(lower) | (u32::from(upper) << 16);
    let nonce_length = usize::from(cursor.byte()?);
    cursor.skip(10)?;
    if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let second = nonce_length.saturating_sub(8).max(13);
        nonce.extend_from_slice(cursor.take(second)?);
        nonce.truncate(NONCE_LENGTH);
    }
    let plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
        cursor.cstring()?
    } else {
        NATIVE_PASSWORD.to_string()
    };
    Ok(HandshakeV10 {
        server_version,
        connection_id,
        nonce,
        capabilities,
        plugin,
    })
}

/// The SSL request: `capabilities` with [`CLIENT_SSL`], and nothing a
/// listener on the wire could use.
#[must_use]
pub fn encode_ssl_request(capabilities: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(SSL_REQUEST_LENGTH);
    out.u32_le(capabilities | CLIENT_SSL)
        .u32_le(MAX_PACKET_SIZE)
        .byte(UTF8MB4)
        .bytes(&[0u8; 23]);
    out
}

/// True when `payload` is an SSL request rather than a response.
#[must_use]
pub fn is_ssl_request(payload: &[u8]) -> bool {
    payload.len() == SSL_REQUEST_LENGTH
        && Cursor::new(payload)
            .u32_le()
            .is_ok_and(|capabilities| capabilities & CLIENT_SSL != 0)
}

/// `response` as a payload.
#[must_use]
pub fn encode_response(response: &HandshakeResponse41) -> Vec<u8> {
    let mut out = Vec::new();
    out.u32_le(response.capabilities)
        .u32_le(MAX_PACKET_SIZE)
        .byte(UTF8MB4)
        .bytes(&[0u8; 23])
        .cstring(&response.user)
        .byte(u8::try_from(response.auth_response.len()).unwrap_or(u8::MAX))
        .bytes(&response.auth_response);
    if response.capabilities & CLIENT_CONNECT_WITH_DB != 0 {
        out.cstring(&response.database);
    }
    if response.capabilities & CLIENT_PLUGIN_AUTH != 0 {
        out.cstring(&response.plugin);
    }
    out
}

/// The response a payload carries.
///
/// # Errors
/// A client without protocol 4.1, or a payload that breaks off.
pub fn decode_response(payload: &[u8]) -> Result<HandshakeResponse41> {
    let mut cursor = Cursor::new(payload);
    let capabilities = cursor.u32_le()?;
    if capabilities & CLIENT_PROTOCOL_41 == 0 {
        return Err(protocol_error("a client without protocol 4.1"));
    }
    cursor.skip(4 + 1 + 23)?;
    let user = cursor.cstring()?;
    let auth_response = if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        let length = usize::try_from(cursor.lenenc_int()?).unwrap_or(0);
        cursor.take(length)?.to_vec()
    } else if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let length = usize::from(cursor.byte()?);
        cursor.take(length)?.to_vec()
    } else {
        let text = cursor.cstring()?;
        text.into_bytes()
    };
    let database = if capabilities & CLIENT_CONNECT_WITH_DB != 0 {
        cursor.cstring()?
    } else {
        String::new()
    };
    let plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
        cursor.cstring()?
    } else {
        NATIVE_PASSWORD.to_string()
    };
    Ok(HandshakeResponse41 {
        capabilities,
        user,
        auth_response,
        database,
        plugin,
    })
}

/// A server's request to switch plugins mid-login, as a payload: `0xFE`,
/// the plugin and its nonce.
#[must_use]
pub fn encode_auth_switch(plugin: &str, nonce: &[u8]) -> Vec<u8> {
    let mut out = vec![0xfe];
    out.cstring(plugin).bytes(nonce).byte(0);
    out
}

/// A server's request to switch plugins mid-login: the plugin and its
/// nonce. The payload opens with `0xFE`.
///
/// # Errors
/// A payload that breaks off.
pub fn decode_auth_switch(payload: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut cursor = Cursor::new(payload);
    cursor.skip(1)?;
    let plugin = cursor.cstring()?;
    let mut nonce = cursor.take_rest().to_vec();
    if nonce.last() == Some(&0) {
        nonce.pop();
    }
    Ok((plugin, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_password::scramble;

    #[test]
    fn the_greeting_and_the_response_round_trip() {
        let greeting = HandshakeV10 {
            server_version: "8.4.0 (xmip)".into(),
            connection_id: 42,
            nonce: (b'a'..=b't').collect(),
            capabilities: CAPABILITIES | CLIENT_SSL,
            plugin: NATIVE_PASSWORD.into(),
        };
        let bytes = encode_handshake(&greeting);
        assert_eq!(bytes[0], PROTOCOL_VERSION);
        assert_eq!(decode_handshake(&bytes).expect("greeting"), greeting);
        assert!(decode_handshake(&[9, 0]).is_err(), "version 9");
        assert!(decode_handshake(&bytes[..12]).is_err(), "breaks off");

        let response = HandshakeResponse41 {
            capabilities: CAPABILITIES,
            user: "xmip".into(),
            auth_response: scramble("secret", &greeting.nonce),
            database: "orders".into(),
            plugin: NATIVE_PASSWORD.into(),
        };
        let bytes = encode_response(&response);
        assert_eq!(decode_response(&bytes).expect("response"), response);
        assert!(decode_response(&[0, 0, 0, 0]).is_err(), "not 4.1");
        assert!(decode_response(&bytes[..40]).is_err(), "breaks off");
        assert!(!is_ssl_request(&bytes), "a response is not an SSL request");

        let no_database = HandshakeResponse41 {
            capabilities: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION,
            database: String::new(),
            plugin: NATIVE_PASSWORD.into(),
            ..response
        };
        let bytes = encode_response(&no_database);
        assert_eq!(decode_response(&bytes).expect("older client"), no_database);
    }

    #[test]
    fn an_ssl_request_is_the_responses_head_with_ssl() {
        let request = encode_ssl_request(CAPABILITIES);
        assert_eq!(request.len(), SSL_REQUEST_LENGTH);
        assert!(is_ssl_request(&request));
        assert!(!is_ssl_request(&encode_ssl_request(0)[..31]), "too short");
        let mut plain = request.clone();
        plain[1] &= !0x08;
        assert!(!is_ssl_request(&plain), "without CLIENT_SSL");
    }

    #[test]
    fn an_auth_switch_names_its_plugin_and_nonce() {
        let payload = encode_auth_switch("caching_sha2_password", b"nonce-nonce-nonce-no");
        let (plugin, nonce) = decode_auth_switch(&payload).expect("switch");
        assert_eq!(plugin, "caching_sha2_password");
        assert_eq!(nonce, b"nonce-nonce-nonce-no");
        assert!(decode_auth_switch(&[0xfe, b'x']).is_err());
    }
}
