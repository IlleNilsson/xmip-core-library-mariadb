# xmip-core-library-mariadb

The MariaDB client/server protocol for Xmip, one copy, both halves: what a
client and a server send, read and written; a client that logs in, queries and
executes in the text protocol; and the far end the tests and the Playground
serve. What a row means to Xmip stays with the transport and the archive target.

| Item | What it is |
| --- | --- |
| `wire` | The framing — a three-byte length, a sequence byte, a payload split at 16 MiB less one — and the protocol's own fields on codec's `Cursor` and beside its writer: the length-encoded integer and string, the NUL-ended string; `COM_QUERY` and `COM_QUIT` |
| `handshake` | The protocol-41 login: `HandshakeV10`, the SSL request, `HandshakeResponse41`, the authentication switch |
| `result` | OK, ERR and EOF, and the text result set: a column count, one definition a column, one row a row |
| `authentication` | A login plugin as each end sees it: `Authentication` (the client's first answer and any step after), `Verification` (the far end's check, which may ask for more through a `Conversation`) |
| `native_password` | `mysql_native_password`, both ends: the login every MariaDB server speaks |
| `Client` | Connects inside one deadline (`net::connect`), the port 3306 where the address names none; upgrades to TLS after the SSL request where a `Guard` asks; logs in with the plugins its `Logon` names, switching where the server asks; `query`, `execute`, `close` |
| `Session` | The far end: a greeting with a fresh nonce in its verification's plugin, a switch to it, TLS where it was given a configuration and the client asks; then any SELECT answered from one table, an INSERT of one literal reported as an `Insert`, anything else completed |

**TLS is the estate's** (`xmip-core-library-tls`, ADR-0033): a guarded login
sends the SSL request after the greeting and hands the socket to TLS in place;
a server that offers no TLS is refused rather than spoken to in the clear.

**A refusal is `net::NetError`**, as every library's is. An error the server
answered is retryable where its code or SQLSTATE class says the trouble is the
connection, the server's load, a lock or a deadlock (`sql_error`); an access
denied, a missing table, a syntax error are not.

Who uses it: `xmip-core-transport-mariadb` with the native password,
`xmip-core-transport-mysql` with MySQL's `caching_sha2_password` beside it (the
MySQL transport's own, so whatever MySQL changes stays there), and
`xmip-core-archive-mariadb`. Named for MariaDB because MariaDB is also a Xmip
Storage server, and what Storage reaches carries no other vendor's name. Until
2026-10-14 all of it sat in the MariaDB transport, and the archive target
reached it through that.

`architecture.toml` carries the maturity.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
