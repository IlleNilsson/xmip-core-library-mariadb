#![forbid(unsafe_code)]

//! The `MariaDB` client/server protocol, both halves, once.
//!
//! What every client since 4.1 speaks on port 3306: the packet framing
//! (`wire.rs`), the greeting a server opens with and the response a client
//! answers it with (`handshake.rs`), the switch to another authentication
//! plugin and the packets a plugin exchanges after it, the OK, ERR and EOF
//! replies and the text result set (`result.rs`), `COM_QUERY` and
//! `COM_QUIT`. [`Client`] is the near end: it logs in, queries and executes
//! in the text protocol, and closes; [`Session`] is the far end a test or
//! the Playground serves, not a database.
//!
//! **The login is a plugin's.** A client is handed the plugins it speaks
//! ([`Authentication`]) and a far end the one it checks ([`Verification`]);
//! the exchange around them — the first response, a switch, the packets a
//! plugin asks for after — is this library's. The native password, which
//! every `MariaDB` server speaks, is here ([`NativePassword`]), so the
//! transport, the archive target and Xmip Storage reach a `MariaDB` server
//! with nothing of their own. A server whose plugins differ carries its own
//! beside this: MySQL's `caching_sha2_password` is the MySQL transport's,
//! and whatever MySQL changes stays there.
//!
//! **TLS is the estate's** (`xmip-core-library-tls`, ADR-0033). Asked for
//! with a [`Guard`], the client sends the SSL request after the greeting
//! and the connection is upgraded in place before the login; a server that
//! offers no TLS is refused rather than spoken to in the clear. A far end
//! given a server configuration offers TLS and upgrades a client that asks.
//!
//! **A refusal is [`net::NetError`]**, as every library's is: a
//! connection's failure keeps its kind, and an error the server answered is
//! retryable where its code or SQLSTATE class says the trouble is the
//! connection, the server's load, a lock or a deadlock ([`sql_error`]).
//!
//! Who uses it: `xmip-core-transport-mariadb`, `xmip-core-transport-mysql`
//! and `xmip-core-archive-mariadb`. Until 2026-10-14 all of it sat in the
//! `MariaDB` transport, and the archive target reached it through that.

pub mod authentication;
pub mod client;
pub mod expecting;
pub mod handshake;
pub mod native_password;
pub mod result;
pub mod session;
pub mod wire;

pub use authentication::{Authentication, Conversation, Step, Verification};
pub use client::{Client, Guard, Logon, QueryResult, sql_error};
pub use expecting::Expecting;
pub use native_password::{NATIVE_PASSWORD, NativePassword};
pub use session::{Answer, Event, Insert, Session};

/// What this library answers: a value, or why not.
pub type Result<T> = core::result::Result<T, net::NetError>;

/// What a peer sent that is not the protocol: the peer's, and never
/// retried.
#[must_use]
pub fn protocol_error(message: impl Into<String>) -> net::NetError {
    net::NetError::new(message)
}

/// A connection's failure while `doing`, keeping its kind.
#[must_use]
pub fn classify(doing: &str, error: &std::io::Error) -> net::NetError {
    net::NetError::from_io(doing, error)
}

/// A TLS failure, in words: the handshake's own trouble surfaces on the
/// first read or write, with the connection's kind.
#[must_use]
pub fn guard_error(error: &tls::TlsError) -> net::NetError {
    net::NetError::new(error.message.clone())
}
