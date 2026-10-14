//! The server's side of one connection: what a test puts at the far end,
//! and what the Playground drives.
//!
//! Not a database. One session does the login for one client — a greeting
//! with a fresh nonce in the plugin its [`crate::Verification`] speaks, a switch
//! to that plugin where the client answered in another, TLS where the far
//! end was given a configuration and the client asks for it — and answers
//! each query from a closure or from one fixed table: any SELECT gets the
//! table's rows, an INSERT of one literal into one column is reported as
//! an [`Insert`], anything else is completed with OK. Planning, storage
//! and SQL are a database's.

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use sql::{Literal, MARIADB, Verb};

use crate::authentication::Conversation;
use crate::expecting::Expecting;
use crate::handshake::{
    CAPABILITIES, CLIENT_SSL, HandshakeV10, NONCE_LENGTH, decode_response, encode_auth_switch,
    encode_handshake, is_ssl_request,
};
use crate::result::{Reply, encode_column, encode_column_count, encode_reply, encode_row};
use crate::wire::{Command, decode_command, frame, read_packet};
use crate::{Result, classify, guard_error, protocol_error};

/// What this far end says it is.
pub const SERVER_VERSION: &str = "8.4.0-xmip";
/// `SERVER_STATUS_AUTOCOMMIT`, the one status a session reports.
const AUTOCOMMIT: u16 = 2;

/// One literal a client inserted into one column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insert {
    pub table: String,
    pub column: String,
    pub literal: Literal,
}

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client ran a SELECT; here it is.
    Selected(String),
    /// The client inserted one value; here it is.
    Inserted(Insert),
    /// The client ran something else; here it is.
    Executed(String),
}

/// How a query is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Option<String>>>,
    },
    /// OK, with this many rows affected.
    Complete(u64),
    Error {
        code: u16,
        state: String,
        message: String,
    },
}

/// What answers a query before the fixed table: `None` declines.
type Answering = Box<dyn FnMut(&str) -> Option<Answer> + Send>;

pub struct Session {
    reader: BufReader<Box<dyn Read + Send>>,
    writer: Box<dyn Write + Send>,
    peer: SocketAddr,
    guarded: bool,
    user: String,
    database: String,
    columns: Vec<String>,
    rows: Vec<Vec<Option<String>>>,
    answering: Option<Answering>,
}

impl Session {
    /// Log the client on `stream` in, admitting only what `expecting` says.
    ///
    /// # Errors
    /// Where the client did not answer the greeting with a 4.1 response,
    /// asked for TLS where none is offered, or gave another user or
    /// password — which is told to the client as error 1045 before this
    /// returns.
    pub fn accept(stream: TcpStream, expecting: &Expecting<'_>) -> Result<Self> {
        let peer = stream
            .peer_addr()
            .map_err(|e| classify("reading the peer's address", &e))?;
        let writer = stream
            .try_clone()
            .map_err(|e| classify("cloning the connection", &e))?;
        let socket = writer
            .try_clone()
            .map_err(|e| classify("cloning the connection", &e))?;
        let mut session = Self {
            reader: BufReader::new(Box::new(stream)),
            writer: Box::new(writer),
            peer,
            guarded: false,
            user: String::new(),
            database: String::new(),
            columns: Vec::new(),
            rows: Vec::new(),
            answering: None,
        };
        let offered = expecting.guard.as_ref().map_or(0, |_| CLIENT_SSL);
        let mut nonce = fresh_nonce();
        let greeting = HandshakeV10 {
            server_version: SERVER_VERSION.to_string(),
            connection_id: CONNECTIONS.fetch_add(1, Ordering::Relaxed),
            nonce: nonce.clone(),
            capabilities: CAPABILITIES | offered,
            plugin: expecting.greeting().to_string(),
        };
        let mut sequence = 0;
        session.write(&mut sequence, &encode_handshake(&greeting))?;
        let mut payload = session.login_packet(&mut sequence)?;
        if is_ssl_request(&payload) {
            let config = expecting.guard.as_ref().ok_or_else(|| {
                protocol_error("the client asks for TLS, and this far end offers none")
            })?;
            session.guard(socket, Arc::clone(config))?;
            payload = session.login_packet(&mut sequence)?;
        }
        let response = decode_response(&payload)?;
        session.user = response.user;
        session.database = response.database;
        let mut answer = response.auth_response;
        let plugin = expecting.verification.plugin();
        if response.plugin != plugin {
            nonce = fresh_nonce();
            session.write(&mut sequence, &encode_auth_switch(plugin, &nonce))?;
            answer = session.login_packet(&mut sequence)?;
        }
        let proved = {
            let mut conversation = Conversation {
                reader: &mut session.reader,
                writer: &mut *session.writer,
                sequence: &mut sequence,
                guarded: session.guarded,
            };
            expecting
                .verification
                .verify(&mut conversation, expecting.password, &nonce, &answer)?
        };
        if session.user != expecting.user || !proved {
            let message = format!(
                "Access denied for user '{}'@'{}' (using password: {})",
                session.user,
                peer.ip(),
                if answer.is_empty() { "NO" } else { "YES" }
            );
            let reply = Reply::Err {
                code: 1045,
                state: "28000".to_string(),
                message: message.clone(),
            };
            session.write(&mut sequence, &encode_reply(&reply))?;
            return Err(protocol_error(message));
        }
        session.write(&mut sequence, &encode_reply(&ok(0)))?;
        Ok(session)
    }

    /// The client's next packet inside the login.
    fn login_packet(&mut self, sequence: &mut u8) -> Result<Vec<u8>> {
        let (seen, payload) = read_packet(&mut self.reader)?
            .ok_or_else(|| protocol_error("the client closed inside the login"))?;
        *sequence = seen.wrapping_add(1);
        Ok(payload)
    }

    /// The connection handed to TLS in place, after the SSL request.
    fn guard(&mut self, socket: TcpStream, config: Arc<tls::ServerConfig>) -> Result<()> {
        let guarded = tls::server(socket, config).map_err(|e| guard_error(&e))?;
        let halves = tls::duplex::split(guarded).map_err(|e| guard_error(&e))?;
        self.reader = BufReader::new(Box::new(halves.reading));
        self.writer = Box::new(halves.writing);
        self.guarded = true;
        Ok(())
    }

    /// The user the client logged in as.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The database the client asked for.
    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Where the client connected from.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Whether the client logged in under TLS.
    #[must_use]
    pub const fn guarded(&self) -> bool {
        self.guarded
    }

    /// Answer any SELECT with these `columns` and `rows`.
    #[must_use]
    pub fn with_table(mut self, columns: &[&str], rows: &[&[Option<&str>]]) -> Self {
        self.columns = columns.iter().map(ToString::to_string).collect();
        self.rows = rows
            .iter()
            .map(|row| row.iter().map(|v| v.map(ToString::to_string)).collect())
            .collect();
        self
    }

    /// Answer queries with `answering` first; what it declines falls to the
    /// table.
    #[must_use]
    pub fn answering(
        mut self,
        answering: impl FnMut(&str) -> Option<Answer> + Send + 'static,
    ) -> Self {
        self.answering = Some(Box::new(answering));
        self
    }

    /// The next value the client inserts, or `None` when it closed.
    /// Everything else is answered on the way.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_insert(&mut self) -> Result<Option<Insert>> {
        while let Some(event) = self.next_event()? {
            if let Event::Inserted(insert) = event {
                return Ok(Some(insert));
            }
        }
        Ok(None)
    }

    /// The next query the client ran, answered, or `None` when it quit.
    ///
    /// # Errors
    /// Where the connection broke, nothing arrived before the timeout, or
    /// the client sent a command this crate does not serve.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        let Some((seen, payload)) = read_packet(&mut self.reader)? else {
            return Ok(None);
        };
        match decode_command(&payload)? {
            Command::Quit => Ok(None),
            Command::Query(sql) => {
                let (answer, event) = self.answer(&sql);
                let mut sequence = seen.wrapping_add(1);
                self.write_answer(&mut sequence, &answer)?;
                Ok(Some(event))
            }
        }
    }

    /// Serve the client until it quits; everything it did, in order.
    ///
    /// # Errors
    /// Where the connection broke or nothing arrived before the timeout.
    pub fn serve(mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        while let Some(event) = self.next_event()? {
            events.push(event);
        }
        Ok(events)
    }

    fn answer(&mut self, sql: &str) -> (Answer, Event) {
        if let Some(answer) = self.answering.as_mut().and_then(|f| f(sql)) {
            return (answer, Event::Executed(sql.to_string()));
        }
        match Verb::of_statement(sql) {
            Some(Verb::Select) => (
                Answer::Rows {
                    columns: self.columns.clone(),
                    rows: self.rows.clone(),
                },
                Event::Selected(sql.to_string()),
            ),
            Some(Verb::Insert) => match MARIADB.parse_insert_literal(sql) {
                Some((table, column, literal)) => (
                    Answer::Complete(1),
                    Event::Inserted(Insert {
                        table,
                        column,
                        literal,
                    }),
                ),
                None => (
                    Answer::Error {
                        code: 1064,
                        state: "42000".to_string(),
                        message: "only INSERT INTO t (c) VALUES (...) is served here".to_string(),
                    },
                    Event::Executed(sql.to_string()),
                ),
            },
            _ => (Answer::Complete(0), Event::Executed(sql.to_string())),
        }
    }

    fn write_answer(&mut self, sequence: &mut u8, answer: &Answer) -> Result<()> {
        match answer {
            Answer::Rows { columns, rows } => {
                let mut out = frame(sequence, &encode_column_count(columns.len()));
                for column in columns {
                    out.extend(frame(sequence, &encode_column(column)));
                }
                out.extend(frame(sequence, &encode_reply(&eof())));
                for row in rows {
                    out.extend(frame(sequence, &encode_row(row)));
                }
                out.extend(frame(sequence, &encode_reply(&eof())));
                self.write_all(&out)
            }
            Answer::Complete(affected) => self.write(sequence, &encode_reply(&ok(*affected))),
            Answer::Error {
                code,
                state,
                message,
            } => self.write(
                sequence,
                &encode_reply(&Reply::Err {
                    code: *code,
                    state: state.clone(),
                    message: message.clone(),
                }),
            ),
        }
    }

    fn write(&mut self, sequence: &mut u8, payload: &[u8]) -> Result<()> {
        self.write_all(&frame(sequence, payload))
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer
            .write_all(bytes)
            .map_err(|e| classify("writing a packet", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a packet", &e))
    }
}

/// Ids handed out, one a connection.
static CONNECTIONS: AtomicU32 = AtomicU32::new(1);

/// Twenty printable random bytes: the challenge a password is answered
/// against, each byte folded into `!`..`~` the way a server does so no NUL
/// lands in a field a NUL ends.
fn fresh_nonce() -> Vec<u8> {
    codec::random::array::<NONCE_LENGTH>()
        .iter()
        .map(|byte| b'!' + byte % 94)
        .collect()
}

const fn ok(affected_rows: u64) -> Reply {
    Reply::Ok {
        affected_rows,
        last_insert_id: 0,
        status: AUTOCOMMIT,
        warnings: 0,
    }
}

const fn eof() -> Reply {
    Reply::Eof {
        warnings: 0,
        status: AUTOCOMMIT,
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::Duration;

    use super::*;
    use crate::authentication::{Authentication, Step, Verification};
    use crate::client::{Client, Guard, Logon};
    use crate::native_password::{NATIVE_PASSWORD, NativePassword};

    const TIMEOUT: Option<Duration> = Some(Duration::from_secs(5));

    /// A plugin for the tests: the password as it is, then the password
    /// with a `!` when the far end asks once more.
    struct Twice;

    impl Authentication for Twice {
        fn plugin(&self) -> &'static str {
            "xmip_test_twice"
        }

        fn first(&self, password: &str, _: &[u8]) -> Result<Vec<u8>> {
            Ok(password.as_bytes().to_vec())
        }

        fn more(&self, step: &Step<'_>) -> Result<Option<Vec<u8>>> {
            let again = format!("{}!", step.password).into_bytes();
            Ok((step.data == b"once more").then_some(again))
        }
    }

    impl Verification for Twice {
        fn plugin(&self) -> &'static str {
            "xmip_test_twice"
        }

        fn verify(
            &self,
            conversation: &mut Conversation<'_>,
            password: &str,
            _: &[u8],
            response: &[u8],
        ) -> Result<bool> {
            if response != password.as_bytes() {
                return Ok(false);
            }
            conversation.more(b"once more")?;
            Ok(conversation.read()? == format!("{password}!").into_bytes())
        }
    }

    /// A far end serving one client on a fresh port, `serving` doing the
    /// rest; its address and what `serving` returned.
    fn far_end<T: Send + 'static>(
        serving: impl FnOnce(TcpStream) -> T + Send + 'static,
    ) -> (String, std::thread::JoinHandle<T>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(TIMEOUT).expect("timeout");
            serving(stream)
        });
        (address, handle)
    }

    fn logon<'a>(password: &'a str, plugins: &'a [&'a dyn Authentication]) -> Logon<'a> {
        Logon {
            user: "xmip",
            password,
            database: "orders",
            plugins,
            guard: None,
        }
    }

    fn native(stream: TcpStream) -> Result<Session> {
        Session::accept(stream, &Expecting::new("xmip", "secret", &NativePassword))
    }

    #[test]
    fn a_nonce_is_printable_and_fresh() {
        let first = fresh_nonce();
        assert_eq!(first.len(), NONCE_LENGTH);
        assert!(first.iter().all(|b| (b'!'..=b'~').contains(b)));
        assert_ne!(first, fresh_nonce());
    }

    #[test]
    fn a_client_logs_in_queries_inserts_and_quits() {
        let (address, far) = far_end(|stream| {
            let session = native(stream)
                .expect("login")
                .with_table(&["id", "payload"], &[&[Some("41"), None]])
                .answering(|sql| {
                    sql.starts_with("DELETE").then(|| Answer::Error {
                        code: 1213,
                        state: "40001".into(),
                        message: "Deadlock found".into(),
                    })
                });
            assert_eq!((session.user(), session.database()), ("xmip", "orders"));
            assert!(!session.guarded());
            session.serve().expect("served")
        });
        let plugins: [&dyn Authentication; 1] = [&NativePassword];
        let mut client =
            Client::connect(&address, &logon("secret", &plugins), TIMEOUT).expect("logged in");
        assert_eq!(client.server_version(), SERVER_VERSION);
        let rows = client.query("SELECT id, payload FROM inbox").expect("rows");
        assert_eq!(rows.columns, ["id", "payload"]);
        assert_eq!(rows.rows, [[Some("41".to_string()), None]]);
        let inserted = client.execute("INSERT INTO inbox (payload) VALUES (X'6869')");
        assert_eq!(inserted.expect("one row"), 1);
        let deadlock = client.execute("DELETE FROM inbox").expect_err("refused");
        assert!(
            deadlock.io.is_some(),
            "a deadlock is tried again: {deadlock:?}"
        );
        client.close().expect("quit");
        let events = far.join().expect("thread");
        assert_eq!(
            events[0],
            Event::Selected("SELECT id, payload FROM inbox".into())
        );
        assert_eq!(
            events[1],
            Event::Inserted(Insert {
                table: "inbox".into(),
                column: "payload".into(),
                literal: Literal::Bytes(b"hi".to_vec()),
            })
        );
        assert_eq!(events[2], Event::Executed("DELETE FROM inbox".into()));
    }

    #[test]
    fn a_wrong_password_is_refused_on_both_ends() {
        let (address, far) = far_end(|stream| native(stream).err());
        let plugins: [&dyn Authentication; 1] = [&NativePassword];
        let refused = Client::connect(&address, &logon("wrong", &plugins), TIMEOUT)
            .err()
            .expect("refused");
        assert!(
            refused.message.contains("1045 (28000)"),
            "{}",
            refused.message
        );
        assert!(refused.io.is_none(), "an access denied is not tried again");
        let far = far.join().expect("thread").expect("refused");
        assert!(
            far.message.contains("using password: YES"),
            "{}",
            far.message
        );
    }

    #[test]
    fn a_switch_names_the_plugin_and_a_plugin_may_ask_for_more() {
        let (address, far) = far_end(|stream| {
            let expecting = Expecting::new("xmip", "secret", &Twice).greeting_in(NATIVE_PASSWORD);
            Session::accept(stream, &expecting).map(Session::serve)
        });
        let plugins: [&dyn Authentication; 2] = [&NativePassword, &Twice];
        let client = Client::connect(&address, &logon("secret", &plugins), TIMEOUT).expect("in");
        client.close().expect("quit");
        let served = far.join().expect("thread").expect("logged in");
        assert_eq!(served.expect("served"), [] as [Event; 0]);

        let (address, far) = far_end(|stream| {
            Session::accept(stream, &Expecting::new("xmip", "secret", &Twice)).err()
        });
        let refused = Client::connect(&address, &logon("secret", &plugins[..1]), TIMEOUT)
            .err()
            .expect("not spoken");
        let said = "asks for xmip_test_twice, and this client speaks mysql_native_password";
        assert!(refused.message.contains(said), "{}", refused.message);
        assert!(far.join().expect("thread").is_some());
    }

    #[test]
    fn a_guarded_login_is_upgraded_in_place_and_a_server_without_tls_is_refused() {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        let served = tls::server_config(
            signed.cert.pem().as_bytes(),
            signed.key_pair.serialize_pem().as_bytes(),
        )
        .expect("server config");
        let served = Arc::new(served);
        let trust = tls::trusting(signed.cert.pem().as_bytes()).expect("trust");
        let guard = Guard {
            trust: Some(Arc::new(trust)),
            name: Some("localhost".into()),
        };
        let (address, far) = far_end(move |stream| {
            let expecting = Expecting::new("xmip", "secret", &NativePassword).guarded(served);
            let session = Session::accept(stream, &expecting).expect("login");
            assert!(session.guarded());
            let rows: [&[Option<&str>]; 1] = [&[Some("1")]];
            session.with_table(&["n"], &rows).serve().expect("served")
        });
        let plugins: [&dyn Authentication; 1] = [&NativePassword];
        let guarded = Logon {
            guard: Some(&guard),
            ..logon("secret", &plugins)
        };
        let mut client = Client::connect(&address, &guarded, TIMEOUT).expect("guarded");
        assert!(client.guarded());
        let rows = client.query("SELECT 1").expect("rows").rows;
        assert_eq!(rows, [[Some("1".to_string())]]);
        client.close().expect("quit");
        assert_eq!(far.join().expect("thread").len(), 1);

        let (address, far) = far_end(|stream| native(stream).err());
        let refused = Client::connect(&address, &guarded, TIMEOUT)
            .err()
            .expect("no TLS");
        assert!(
            refused.message.contains("offers no TLS"),
            "{}",
            refused.message
        );
        drop(far);
    }
}
