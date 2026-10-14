//! A login plugin, as each end sees it.
//!
//! The exchange is the protocol's and the answers are the plugin's. A
//! client answers the greeting's nonce with its plugin's [`first`] answer,
//! inside the response; where the server names another plugin it switches
//! to it with a fresh nonce and is answered again; and where the plugin
//! asks for more — a packet opening `0x01` — the client's plugin is shown
//! what it asked ([`Step`]) and says what goes back, if anything. A far end
//! checks the first answer with its [`Verification`], which may ask the
//! client for more through the [`Conversation`] it is handed.
//!
//! [`first`]: Authentication::first

use std::io::{Read, Write};

use crate::wire::{frame, read_packet};
use crate::{Result, classify, protocol_error};

/// Opens a packet a plugin sends after the first answer.
pub const AUTH_MORE_DATA: u8 = 0x01;

/// What the server asked a plugin for after its first answer.
#[derive(Clone, Copy, Debug)]
pub struct Step<'a> {
    /// The password the login is for.
    pub password: &'a str,
    /// The nonce the first answer was made with.
    pub nonce: &'a [u8],
    /// What the server sent, its `0x01` taken off.
    pub data: &'a [u8],
    /// Whether the connection is under TLS, where a password may be sent
    /// as it is.
    pub guarded: bool,
}

/// A login plugin, the client's end.
pub trait Authentication: Sync {
    /// The plugin's name on the wire.
    fn plugin(&self) -> &'static str;

    /// The answer to `nonce` for `password`, sent in the response or after
    /// a switch.
    ///
    /// # Errors
    /// Where the plugin cannot answer.
    fn first(&self, password: &str, nonce: &[u8]) -> Result<Vec<u8>>;

    /// What goes back for `step`, or `None` where the plugin waits for the
    /// server's verdict. A plugin with one answer refuses anything more.
    ///
    /// # Errors
    /// Where the server asked for what the plugin does not give.
    fn more(&self, step: &Step<'_>) -> Result<Option<Vec<u8>>> {
        let _ = step;
        Err(protocol_error(format!(
            "the server asks for more than {} gives",
            self.plugin()
        )))
    }
}

/// A login plugin, the far end's: whether an answer proves the password.
pub trait Verification: Sync {
    /// The plugin's name on the wire, which the greeting offers.
    fn plugin(&self) -> &'static str;

    /// Whether `response`, the client's first answer to `nonce`, proves
    /// `password`; `conversation` asks the client for more where the
    /// plugin does.
    ///
    /// # Errors
    /// Where the connection broke while asking.
    fn verify(
        &self,
        conversation: &mut Conversation<'_>,
        password: &str,
        nonce: &[u8],
        response: &[u8],
    ) -> Result<bool>;
}

/// The far end's side of a login in progress, handed to a
/// [`Verification`] that asks the client for more.
pub struct Conversation<'a> {
    pub(crate) reader: &'a mut dyn Read,
    pub(crate) writer: &'a mut dyn Write,
    pub(crate) sequence: &'a mut u8,
    pub(crate) guarded: bool,
}

impl Conversation<'_> {
    /// Whether the client logs in under TLS.
    #[must_use]
    pub const fn guarded(&self) -> bool {
        self.guarded
    }

    /// Send `data` to the client as the plugin's own packet, `0x01` first.
    ///
    /// # Errors
    /// Where the connection broke.
    pub fn more(&mut self, data: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(data.len() + 1);
        payload.push(AUTH_MORE_DATA);
        payload.extend_from_slice(data);
        self.writer
            .write_all(&frame(self.sequence, &payload))
            .and_then(|()| self.writer.flush())
            .map_err(|e| classify("writing a login packet", &e))
    }

    /// The client's next packet.
    ///
    /// # Errors
    /// Where the connection broke or the client closed.
    pub fn read(&mut self) -> Result<Vec<u8>> {
        let (seen, payload) = read_packet(&mut self.reader)?
            .ok_or_else(|| protocol_error("the client closed inside the login"))?;
        *self.sequence = seen.wrapping_add(1);
        Ok(payload)
    }
}
