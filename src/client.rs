//! The client's side of one connection to a server: the login, a query
//! and its rows, a statement and its count. The text protocol only, which
//! is what `COM_QUERY` gives.

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::authentication::{AUTH_MORE_DATA, Authentication, Step};
use crate::handshake::{
    CAPABILITIES, CLIENT_PROTOCOL_41, CLIENT_SSL, HandshakeResponse41, decode_auth_switch,
    decode_handshake, encode_response, encode_ssl_request,
};
use crate::result::{
    EOF_HEADER, ERR_HEADER, Reply, decode_column, decode_column_count, decode_in_result_set,
    decode_reply, decode_row,
};
use crate::wire::{Command, encode_command, frame, read_packet};
use crate::{Result, classify, guard_error, protocol_error};

/// The port a server listens on unless its address names another.
pub const PORT: u16 = 3306;

/// `SERVER_STATUS_NO_BACKSLASH_ESCAPES`: the session's `sql_mode` holds
/// `NO_BACKSLASH_ESCAPES`, so a backslash in a literal is itself.
pub const NO_BACKSLASH_ESCAPES: u16 = 0x0200;

/// What a query came back with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryResult {
    pub columns: Vec<String>,
    /// Each row, each column as text or NULL.
    pub rows: Vec<Vec<Option<String>>>,
    /// What a statement without rows reported; zero for a result set.
    pub affected_rows: u64,
}

/// How a login is guarded: the trust store the server's certificate is
/// checked against, and the name it is checked for.
#[derive(Clone, Debug, Default)]
pub struct Guard {
    /// The trust a caller holds — a Party's own authority, a test's; the
    /// operating system's store where `None`.
    pub trust: Option<Arc<tls::ClientConfig>>,
    /// The name the certificate must carry; the address's host where `None`.
    pub name: Option<String>,
}

/// Who logs in, to what, and how.
#[derive(Clone, Copy)]
pub struct Logon<'a> {
    pub user: &'a str,
    /// Empty where the account has none.
    pub password: &'a str,
    pub database: &'a str,
    /// The plugins this client speaks: the one the greeting names where it
    /// is among them, the first otherwise, and any a switch names.
    pub plugins: &'a [&'a dyn Authentication],
    /// TLS before the login; the clear where `None`.
    pub guard: Option<&'a Guard>,
}

/// One logged-in connection, kept between statements while the server
/// keeps it open.
pub struct Client {
    reader: BufReader<Box<dyn Read + Send>>,
    writer: Box<dyn Write + Send>,
    /// The connection under both, whether guarded or not.
    socket: TcpStream,
    guarded: bool,
    server_version: String,
    connection_id: u32,
    /// The status flags the server last said: in its greeting, then in
    /// every OK packet.
    status: u16,
}

impl Client {
    /// Connect to `server` — `host:port`, the port 3306 where left out —
    /// and log in as `logon` says.
    ///
    /// # Errors
    /// Where the server could not be reached, refused the login, offers no
    /// TLS where it was asked for, or asks for a plugin `logon` does not
    /// speak.
    pub fn connect(server: &str, logon: &Logon<'_>, timeout: Option<Duration>) -> Result<Self> {
        let stream = net::connect(net::authority::with_default_port(server, PORT), timeout)?;
        let socket = clone(&stream)?;
        let mut client = Self {
            reader: BufReader::new(Box::new(clone(&stream)?)),
            writer: Box::new(stream),
            socket,
            guarded: false,
            server_version: String::new(),
            connection_id: 0,
            status: 0,
        };
        client.login(server, logon)?;
        Ok(client)
    }

    fn login(&mut self, server: &str, logon: &Logon<'_>) -> Result<()> {
        let (_, payload) = self.read("the greeting")?;
        if payload.first() == Some(&ERR_HEADER) {
            return Err(refused(decode_reply(&payload)?));
        }
        let greeting = decode_handshake(&payload)?;
        if greeting.capabilities & CLIENT_PROTOCOL_41 == 0 {
            return Err(protocol_error("a server without protocol 4.1"));
        }
        self.server_version = greeting.server_version;
        self.connection_id = greeting.connection_id;
        self.status = greeting.status;
        let mut sequence = 1;
        let mut capabilities = CAPABILITIES;
        if let Some(guard) = logon.guard {
            if greeting.capabilities & CLIENT_SSL == 0 {
                return Err(protocol_error(
                    "the server offers no TLS, and this login is to be guarded",
                ));
            }
            capabilities |= CLIENT_SSL;
            self.write(&mut sequence, &encode_ssl_request(CAPABILITIES))?;
            self.guard(server, guard)?;
        }
        let mut plugin = chosen(logon.plugins, &greeting.plugin)
            .or_else(|| logon.plugins.first().copied())
            .ok_or_else(|| protocol_error("a login with no plugin to answer in"))?;
        let mut nonce = greeting.nonce;
        let response = HandshakeResponse41 {
            capabilities,
            user: logon.user.to_string(),
            auth_response: plugin.first(logon.password, &nonce)?,
            database: logon.database.to_string(),
            plugin: plugin.plugin().to_string(),
        };
        self.write(&mut sequence, &encode_response(&response))?;
        loop {
            let (seen, payload) = self.read("the login's answer")?;
            sequence = seen.wrapping_add(1);
            match decode_reply(&payload)? {
                Reply::Ok { status, .. } => {
                    self.status = status;
                    return Ok(());
                }
                error @ Reply::Err { .. } => return Err(refused(error)),
                Reply::Data(bytes) if bytes.first() == Some(&EOF_HEADER) => {
                    let (named, fresh) = decode_auth_switch(&bytes)?;
                    plugin = chosen(logon.plugins, &named).ok_or_else(|| {
                        protocol_error(format!(
                            "the server asks for {named}, and this client speaks {}",
                            spoken(logon.plugins)
                        ))
                    })?;
                    nonce = fresh;
                    let answer = plugin.first(logon.password, &nonce)?;
                    self.write(&mut sequence, &answer)?;
                }
                Reply::Data(bytes) if bytes.first() == Some(&AUTH_MORE_DATA) => {
                    let step = Step {
                        password: logon.password,
                        nonce: &nonce,
                        data: &bytes[1..],
                        guarded: self.guarded,
                    };
                    if let Some(answer) = plugin.more(&step)? {
                        self.write(&mut sequence, &answer)?;
                    }
                }
                Reply::Eof { .. } => {
                    return Err(protocol_error(
                        "the server asks for the pre-4.1 password, which this crate does not speak",
                    ));
                }
                Reply::Data(_) => {
                    return Err(protocol_error("the server answered the login with data"));
                }
            }
        }
    }

    /// The connection handed to TLS in place, after the SSL request.
    fn guard(&mut self, server: &str, guard: &Guard) -> Result<()> {
        let name = guard
            .name
            .as_deref()
            .unwrap_or_else(|| net::authority::host_of(server));
        let socket = clone(&self.socket)?;
        let guarded = tls::client_trusting(name, socket, guard.trust.as_ref())
            .map_err(|e| guard_error(&e))?;
        let halves = tls::duplex::split(guarded).map_err(|e| guard_error(&e))?;
        self.reader = BufReader::new(Box::new(halves.reading));
        self.writer = Box::new(halves.writing);
        self.guarded = true;
        Ok(())
    }

    /// What the server said it was, `8.4.0` say.
    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// The id the server gave this connection.
    #[must_use]
    pub const fn connection_id(&self) -> u32 {
        self.connection_id
    }

    /// The SQL dialect the server reads now: [`sql::MARIADB`], or
    /// [`sql::MARIADB_NO_BACKSLASH_ESCAPES`] where the status flags it last
    /// said carry [`NO_BACKSLASH_ESCAPES`]. A literal is quoted by it, so a
    /// backslash is written as the session's `sql_mode` reads it.
    #[must_use]
    pub const fn dialect(&self) -> &'static sql::Dialect {
        if self.status & NO_BACKSLASH_ESCAPES == 0 {
            &sql::MARIADB
        } else {
            &sql::MARIADB_NO_BACKSLASH_ESCAPES
        }
    }

    /// Whether the connection is under TLS.
    #[must_use]
    pub const fn guarded(&self) -> bool {
        self.guarded
    }

    /// The connection under the protocol, for a pool to see whether the
    /// server has closed it.
    #[must_use]
    pub const fn socket(&self) -> &TcpStream {
        &self.socket
    }

    /// Run `sql` and take its rows.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn query(&mut self, sql: &str) -> Result<QueryResult> {
        let mut sequence = 0;
        self.write(
            &mut sequence,
            &encode_command(&Command::Query(sql.to_string())),
        )?;
        let (_, payload) = self.read("the query's answer")?;
        let count = match decode_reply(&payload)? {
            Reply::Ok {
                affected_rows,
                status,
                ..
            } => {
                self.status = status;
                return Ok(QueryResult {
                    affected_rows,
                    ..QueryResult::default()
                });
            }
            error @ Reply::Err { .. } => return Err(refused(error)),
            Reply::Eof { .. } => return Err(protocol_error("EOF where a result set should open")),
            Reply::Data(bytes) => decode_column_count(&bytes)?,
        };
        let mut result = QueryResult::default();
        for _ in 0..count {
            let (_, payload) = self.read("a column definition")?;
            result.columns.push(decode_column(&payload)?);
        }
        let (_, payload) = self.read("the end of the columns")?;
        match decode_in_result_set(&payload)? {
            Reply::Eof { .. } => {}
            error @ Reply::Err { .. } => return Err(refused(error)),
            _ => return Err(protocol_error("no EOF after the column definitions")),
        }
        loop {
            let (_, payload) = self.read("a row")?;
            match decode_in_result_set(&payload)? {
                Reply::Eof { .. } => return Ok(result),
                error @ Reply::Err { .. } => return Err(refused(error)),
                Reply::Data(bytes) => result.rows.push(decode_row(&bytes, count)?),
                Reply::Ok { .. } => return Err(protocol_error("OK in the middle of the rows")),
            }
        }
    }

    /// Run `sql` for its effect; the rows the server said it touched.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn execute(&mut self, sql: &str) -> Result<u64> {
        self.query(sql).map(|result| result.affected_rows)
    }

    /// Say goodbye and hang up.
    ///
    /// # Errors
    /// Where the server had already gone.
    pub fn close(mut self) -> Result<()> {
        self.write(&mut 0, &encode_command(&Command::Quit))
    }

    fn read(&mut self, waiting_for: &str) -> Result<(u8, Vec<u8>)> {
        read_packet(&mut self.reader)?
            .ok_or_else(|| protocol_error(format!("the server closed before {waiting_for}")))
    }

    fn write(&mut self, sequence: &mut u8, payload: &[u8]) -> Result<()> {
        self.writer
            .write_all(&frame(sequence, payload))
            .map_err(|e| classify("writing a packet", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a packet", &e))
    }
}

/// The plugin among `plugins` named `name`.
fn chosen<'a>(plugins: &[&'a dyn Authentication], name: &str) -> Option<&'a dyn Authentication> {
    plugins
        .iter()
        .copied()
        .find(|plugin| plugin.plugin() == name)
}

/// The plugins' names, for a refusal.
fn spoken(plugins: &[&dyn Authentication]) -> String {
    let names: Vec<_> = plugins.iter().map(|plugin| plugin.plugin()).collect();
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

fn clone(stream: &TcpStream) -> Result<TcpStream> {
    stream
        .try_clone()
        .map_err(|e| classify("cloning the connection", &e))
}

/// The error an ERR reply carries; anything else is a broken protocol.
fn refused(reply: Reply) -> net::NetError {
    match reply {
        Reply::Err {
            code,
            state,
            message,
        } => sql_error(code, &state, &message),
        other => protocol_error(format!("{other:?} where an error was expected")),
    }
}

/// An error the server answered, retryable where the code or the SQLSTATE
/// class says the trouble is the connection, the server's load, a lock or
/// a deadlock — what a later attempt might not meet. Retryable is said the
/// way every library says it, by the kind of the connection's failure: the
/// statement was interrupted.
#[must_use]
pub fn sql_error(code: u16, state: &str, message: &str) -> net::NetError {
    let text = format!("the server answered {code} ({state}): {message}");
    let transient = matches!(code, 1040 | 1053 | 1077 | 1205 | 1213 | 1317)
        || matches!(state.get(..2), Some("08" | "40"));
    net::NetError {
        message: text,
        io: transient.then_some(std::io::ErrorKind::Interrupted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{HandshakeV10, encode_handshake};
    use crate::result::encode_reply;

    const AUTOCOMMIT: u16 = 2;

    /// A far end whose greeting and login OK carry `NO_BACKSLASH_ESCAPES`,
    /// and whose OK to the one statement after clears it.
    fn far_end(listener: &std::net::TcpListener) {
        let (stream, _) = listener.accept().expect("accepted");
        let mut reader = BufReader::new(stream.try_clone().expect("cloned"));
        let mut writer = stream;
        let mut send = |sequence: u8, payload: &[u8]| {
            let framed = frame(&mut { sequence }, payload);
            writer.write_all(&framed).expect("written");
        };
        let ok = |status| {
            encode_reply(&Reply::Ok {
                affected_rows: 0,
                last_insert_id: 0,
                status,
                warnings: 0,
            })
        };
        let greeting = HandshakeV10 {
            server_version: "11.8.0".into(),
            connection_id: 1,
            nonce: vec![b'n'; 20],
            capabilities: CAPABILITIES,
            status: AUTOCOMMIT | NO_BACKSLASH_ESCAPES,
            plugin: crate::NATIVE_PASSWORD.into(),
        };
        send(0, &encode_handshake(&greeting));
        let (seen, _) = read_packet(&mut reader).expect("read").expect("login");
        send(seen.wrapping_add(1), &ok(AUTOCOMMIT | NO_BACKSLASH_ESCAPES));
        read_packet(&mut reader).expect("read").expect("statement");
        send(1, &ok(AUTOCOMMIT));
        read_packet(&mut reader).expect("read").expect("quit");
    }

    #[test]
    fn the_dialect_follows_the_status_the_greeting_and_each_ok_carry() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bound");
        let address = listener.local_addr().expect("address").to_string();
        let serving = std::thread::spawn(move || far_end(&listener));
        let plugins: [&dyn Authentication; 1] = [&crate::NativePassword];
        let logon = Logon {
            user: "xmip",
            password: "",
            database: "orders",
            plugins: &plugins,
            guard: None,
        };
        let mut client =
            Client::connect(&address, &logon, Some(Duration::from_secs(5))).expect("logged in");
        assert_eq!(
            client.dialect().quote_text("a\\'"),
            "'a\\'''",
            "NO_BACKSLASH_ESCAPES: a backslash is itself"
        );
        client.execute("SET sql_mode = ''").expect("set");
        assert_eq!(
            client.dialect().quote_text("a\\'"),
            "'a\\\\'''",
            "the default mode: a backslash escaped"
        );
        client.close().expect("quit");
        serving.join().expect("the far end");
    }

    #[test]
    fn an_error_is_judged_by_its_code_and_class() {
        let retryable = |e: net::NetError| e.io.is_some();
        assert!(retryable(sql_error(1040, "08004", "Too many connections")));
        assert!(retryable(sql_error(1213, "40001", "Deadlock found")));
        assert!(retryable(sql_error(
            1205,
            "HY000",
            "Lock wait timeout exceeded"
        )));
        assert!(retryable(sql_error(2013, "08S01", "Lost connection")));
        assert!(!retryable(sql_error(1045, "28000", "Access denied")));
        assert!(!retryable(sql_error(1146, "42S02", "Table doesn't exist")));
        assert!(!retryable(sql_error(0, "", "nothing")));
        assert!(
            refused(Reply::Eof {
                warnings: 0,
                status: 0
            })
            .message
            .contains("expected")
        );
    }
}
