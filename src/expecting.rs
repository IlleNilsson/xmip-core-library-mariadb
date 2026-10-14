//! The one login a far end admits: the user, the password, the plugin that
//! checks it, whether TLS is offered, and the plugin the greeting names.

use std::sync::Arc;

use crate::authentication::Verification;

/// The one login a far end admits, and how it is checked.
#[derive(Clone)]
pub struct Expecting<'a> {
    pub(crate) user: &'a str,
    pub(crate) password: &'a str,
    pub(crate) verification: &'a dyn Verification,
    /// TLS offered to a client that asks for it; none where `None`.
    pub(crate) guard: Option<Arc<tls::ServerConfig>>,
    /// The plugin the greeting names; the verification's where `None`.
    pub(crate) greeting: Option<&'static str>,
}

impl<'a> Expecting<'a> {
    /// `user` with `password`, checked by `verification`, in the clear.
    #[must_use]
    pub fn new(user: &'a str, password: &'a str, verification: &'a dyn Verification) -> Self {
        Self {
            user,
            password,
            verification,
            guard: None,
            greeting: None,
        }
    }

    /// TLS offered with `config`, to a client that asks for it.
    #[must_use]
    pub fn guarded(mut self, config: Arc<tls::ServerConfig>) -> Self {
        self.guard = Some(config);
        self
    }

    /// The greeting names `plugin`, and a client that answers in it is
    /// switched to the verification's — as a server greets in its default
    /// and switches an account that has another.
    #[must_use]
    pub const fn greeting_in(mut self, plugin: &'static str) -> Self {
        self.greeting = Some(plugin);
        self
    }

    /// The plugin the greeting names.
    pub(crate) fn greeting(&self) -> &'static str {
        self.greeting.unwrap_or_else(|| self.verification.plugin())
    }
}
