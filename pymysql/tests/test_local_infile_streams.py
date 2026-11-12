"""Tests for per-command LOAD DATA LOCAL INFILE stream grants.

A malicious in-memory MySQL peer (no real server, no network beyond
127.0.0.1, no real private files) drives the client through 0xfb
``LOAD LOCAL`` packets.  Probes record every ``open()``/``read()`` call so
the tests can prove that authorized stream names never reach the
filesystem and that each granted stream is consumed at most once.
"""

from __future__ import annotations

import builtins
import io
import socket
import struct
import sys
import threading
import warnings

import pytest

import pymysql
from pymysql import cursors, err
from pymysql.constants import CLIENT, COMMAND, FIELD_TYPE, SERVER_STATUS

MAX_PACKET_LEN = 2**24 - 1


# ---------------------------------------------------------------------------
# Probes: record open()/read() without ever touching real private files.
# ---------------------------------------------------------------------------


class ProbeStream:
    """In-memory binary stream that records reads and reports closes."""

    def __init__(self, data, events, label):
        self._buf = io.BytesIO(data)
        self._events = events
        self._label = label
        self.closed = False
        self.read_count = 0

    def read(self, size=-1):
        self.read_count += 1
        chunk = self._buf.read(size)
        self._events.append(("stream_read", self._label, size, len(chunk)))
        return chunk

    def close(self):
        # The library must never close streams it does not own.
        self.closed = True
        self._events.append(("stream_close", self._label))


class FailingStream:
    """Binary stream whose read() always fails mid-command."""

    def __init__(self, events, label):
        self._events = events
        self._label = label
        self.closed = False

    def read(self, size=-1):
        self._events.append(("stream_read_error", self._label))
        raise OSError("simulated stream failure")

    def close(self):
        self.closed = True
        self._events.append(("stream_close", self._label))


class InterruptingStream:
    """Binary stream whose read() raises a BaseException (not Exception)."""

    def __init__(self, events, label):
        self._events = events
        self._label = label
        self.closed = False

    def read(self, size=-1):
        self._events.append(("stream_read_keyboard_interrupt", self._label))
        raise KeyboardInterrupt

    def close(self):
        self.closed = True
        self._events.append(("stream_close", self._label))


class ProbeOpen:
    """Replacement for the ``open`` builtin.

    Only ``open()`` calls originating from ``pymysql/connections.py`` are
    recorded; the tests themselves and the tmp_path fixture keep using the
    real builtin untouched.
    """

    def __init__(self, events):
        self._events = events
        self._real_open = builtins.open
        self.calls = []

    def _from_pymysql(self):
        frame = sys._getframe()
        while frame is not None:
            if frame.f_code.co_filename.replace("\\", "/").endswith(
                "pymysql/connections.py"
            ):
                return True
            frame = frame.f_back
        return False

    def __call__(self, file, mode="r", *args, **kwargs):
        if self._from_pymysql():
            self.calls.append((file, mode))
            self._events.append(("open", file, mode))
            real = self._real_open(file, mode, *args, **kwargs)
            return _ProbeFile(real, self._events)
        return self._real_open(file, mode, *args, **kwargs)


class _ProbeFile:
    def __init__(self, real, events):
        self._real = real
        self._events = events

    def read(self, size=-1):
        chunk = self._real.read(size)
        self._events.append(("file_read", size, len(chunk)))
        return chunk

    def close(self):
        self._events.append(("file_close",))
        self._real.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------
# Scripted server-side events.
# ---------------------------------------------------------------------------


class LoadLocal:
    """Server asks the client to upload a file named by raw ``filename``.

    ``has_next`` marks the intermediate OK packet of a multi-statement
    command; another result set/0xfb request follows the upload.
    ``trailing`` replaces the terminating OK with an arbitrary raw packet,
    for desynchronization tests.
    """

    def __init__(self, filename, has_next=False, trailing=None):
        self.filename = filename
        self.has_next = has_next
        self.trailing = trailing


class Ok:
    def __init__(self, has_next=False):
        self.has_next = has_next


class ResultSet:
    def __init__(self, rows, has_next=False):
        self.rows = rows
        self.has_next = has_next


class ServerError:
    def __init__(self, code=1064, message=b"scripted error"):
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Minimal MySQL protocol peer speaking just enough of the wire protocol.
# ---------------------------------------------------------------------------


def _lenenc(value):
    assert value < 0xFB
    return bytes([value])


def _lenenc_str(value):
    return _lenenc(len(value)) + value


def _ok_payload(status, warnings=0):
    return b"\x00\x00\x00" + struct.pack("<HH", status, warnings)


def _eof_payload(status, warnings=0):
    # EOFPacketWrapper skips the leading 0xfe with "<xhh", so the remaining
    # payload is exactly the warnings and status shorts.
    return b"\xfe" + struct.pack("<hh", warnings, status)


def _error_payload(code, message):
    return b"\xff" + struct.pack("<H", code) + b"#" + b"42000" + message


def _column_definition(name):
    payload = b"".join(_lenenc_str(part) for part in (b"def", b"", b"", b"", name, b""))
    payload += b"\x0c"  # fixed-length fields follow
    payload += struct.pack("<H", 33)  # character set
    payload += struct.pack("<I", 11)  # column length
    payload += bytes([FIELD_TYPE.LONG])
    payload += struct.pack("<H", 0)  # flags
    payload += b"\x00"  # decimals
    payload += b"\x00\x00"  # filler
    return payload


class FakeMySQLPeer:
    """One-shot scripted MySQL server on an ephemeral loopback port."""

    def __init__(self, on_query):
        self._on_query = on_query
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self.host, self.port = self._sock.getsockname()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        # Everything the server observed: SQL texts and uploaded chunks.
        self.queries = []
        self.uploads = []
        self._thread.start()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                with conn:
                    self._handle(conn)
            except (OSError, ConnectionError):
                # The client legitimately hangs up after a forced close.
                continue

    def _recvn(self, conn, size):
        chunks = []
        remaining = size
        while remaining:
            chunk = conn.recv(remaining)
            if not chunk:
                raise ConnectionError("peer closed connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_packet(self, conn):
        """Return (sequence_id, payload) of one logical MySQL packet."""
        chunks = []
        seq = 0
        while True:
            header = self._recvn(conn, 4)
            length = int.from_bytes(header[:3], "little")
            seq = header[3]
            chunks.append(self._recvn(conn, length))
            if length < MAX_PACKET_LEN:
                break
        return seq, b"".join(chunks)

    def _send_packet(self, conn, payload, seq):
        conn.sendall(struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload)
        return (seq + 1) % 256

    def _handshake(self, conn):
        caps = (
            CLIENT.PROTOCOL_41
            | CLIENT.SECURE_CONNECTION
            | CLIENT.PLUGIN_AUTH
            | CLIENT.CONNECT_ATTRS
            | CLIENT.MULTI_RESULTS
        )
        salt = b"01234567" + b"abcdefghijkl"
        payload = (
            bytes([10])
            + b"8.0.0\0"
            + struct.pack("<I", 1)  # thread id
            + salt[:8]
            + b"\x00"  # filler
            + struct.pack("<H", caps & 0xFFFF)
            + bytes([33])  # charset
            + struct.pack("<H", SERVER_STATUS.SERVER_STATUS_AUTOCOMMIT)
            + struct.pack("<H", caps >> 16)
            + bytes([21])  # auth plugin data length
            + b"\x00" * 10  # reserved
            + salt[8:]
            + b"mysql_native_password\0"
        )
        self._send_packet(conn, payload, 0)
        client_seq, _ = self._read_packet(conn)  # handshake response
        self._send_packet(
            conn,
            _ok_payload(SERVER_STATUS.SERVER_STATUS_AUTOCOMMIT),
            (client_seq + 1) % 256,
        )

    def _handle(self, conn):
        self._handshake(conn)
        while True:
            try:
                _, command = self._read_packet(conn)
            except ConnectionError:
                return
            if not command:
                return
            if command[0] == COMMAND.COM_QUIT:
                return
            if command[0] != COMMAND.COM_QUERY:
                return
            sql = command[1:]
            self.queries.append(sql)
            events = self._on_query(sql)
            if events is None or sql.lstrip().upper().startswith(b"SET "):
                # Bookkeeping queries issued while connecting
                # (SET NAMES, SET AUTOCOMMIT, ...) always get a plain OK.
                events = [Ok()]
            seq = 1
            for event in events:
                if isinstance(event, LoadLocal):
                    seq = self._send_packet(conn, b"\xfb" + event.filename, seq)
                    chunks = []
                    while True:
                        data_seq, data = self._read_packet(conn)
                        if not data:
                            break
                        chunks.append(data)
                    # The server's OK follows the client's last (empty) packet.
                    seq = (data_seq + 1) % 256
                    self.uploads.append((event.filename, b"".join(chunks)))
                    if event.trailing is not None:
                        seq = self._send_packet(conn, event.trailing, seq)
                    elif event.has_next:
                        status = (
                            SERVER_STATUS.SERVER_STATUS_AUTOCOMMIT
                            | SERVER_STATUS.SERVER_MORE_RESULTS_EXISTS
                        )
                        seq = self._send_packet(conn, _ok_payload(status), seq)
                elif isinstance(event, Ok):
                    status = SERVER_STATUS.SERVER_STATUS_AUTOCOMMIT
                    if event.has_next:
                        status |= SERVER_STATUS.SERVER_MORE_RESULTS_EXISTS
                    seq = self._send_packet(conn, _ok_payload(status), seq)
                elif isinstance(event, ResultSet):
                    status = SERVER_STATUS.SERVER_STATUS_AUTOCOMMIT
                    if event.has_next:
                        status |= SERVER_STATUS.SERVER_MORE_RESULTS_EXISTS
                    seq = self._send_packet(conn, _lenenc(1), seq)
                    seq = self._send_packet(conn, _column_definition(b"id"), seq)
                    seq = self._send_packet(conn, _eof_payload(status), seq)
                    for row in event.rows:
                        seq = self._send_packet(conn, _lenenc_str(row[0]), seq)
                    seq = self._send_packet(conn, _eof_payload(status), seq)
                elif isinstance(event, ServerError):
                    seq = self._send_packet(
                        conn,
                        _error_payload(event.code, event.message),
                        seq,
                    )
                else:  # pragma: no cover - programming error in the test
                    raise TypeError(f"unknown event {event!r}")

    def stop(self):
        self._sock.close()


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
def events():
    return []


@pytest.fixture
def probe_open(monkeypatch, events):
    probe = ProbeOpen(events)
    monkeypatch.setattr(builtins, "open", probe)
    return probe


@pytest.fixture
def peer_factory():
    peers = []

    def factory(on_query):
        peer = FakeMySQLPeer(on_query)
        peers.append(peer)
        return peer

    yield factory

    for peer in peers:
        peer.stop()


@pytest.fixture
def connect_factory(peer_factory):
    conns = []

    def connect(peer, **kwargs):
        params = {
            "user": "user",
            "password": "pw",
            "host": peer.host,
            "port": peer.port,
            "ssl_disabled": True,
            "local_infile": True,
            "autocommit": True,
            "connect_timeout": 5,
            "read_timeout": 5,
            "write_timeout": 5,
        }
        params.update(kwargs)
        conn = pymysql.connect(**params)
        conns.append(conn)
        return conn

    yield connect

    for conn in conns:
        if conn.open:
            conn.close()


# Every test scenario only ever exchanges these generated bytes.
PAYLOAD_A = b"1,alpha\n2,beta\n" * 2000  # > 16KB: multiple data packets
PAYLOAD_B = b"3,gamma\n4,delta\n"
NAME_A = b"approved-a.csv"
NAME_B = b"approved-b.csv"


def make_streams(events):
    return {
        NAME_A: ProbeStream(PAYLOAD_A, events, "A"),
        NAME_B: ProbeStream(PAYLOAD_B, events, "B"),
    }


# ---------------------------------------------------------------------------
# Happy path and exact byte matching.
# ---------------------------------------------------------------------------


def test_authorized_upload_buffered(connect_factory, peer_factory, events):
    peer = peer_factory(lambda sql: [LoadLocal(NAME_A), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()
    streams = make_streams(events)

    affected = cur.execute("LOAD DATA LOCAL INFILE 'x'", local_infile_streams=streams)

    assert affected == 0
    assert peer.uploads == [(NAME_A, PAYLOAD_A)]
    assert conn._local_infile_streams is None
    # The caller still owns the stream; it must not have been closed.
    assert not streams[NAME_A].closed
    # The caller's own mapping must not be mutated by the one-shot pop.
    assert NAME_A in streams


def test_authorized_upload_sscursor(connect_factory, peer_factory, events):
    peer = peer_factory(lambda sql: [LoadLocal(NAME_A), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor(cursors.SSCursor)
    streams = make_streams(events)

    cur.execute("LOAD DATA LOCAL INFILE 'x'", local_infile_streams=streams)

    assert peer.uploads == [(NAME_A, PAYLOAD_A)]
    assert conn._local_infile_streams is None
    assert not streams[NAME_A].closed


def test_raw_filename_bytes_matched_exactly(
    connect_factory, peer_factory, events, probe_open
):
    # Bytes that are invalid UTF-8 must still match byte-for-byte.
    raw_name = b"caf\xe9-\xff.bin"
    peer = peer_factory(lambda sql: [LoadLocal(raw_name), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()
    stream = ProbeStream(PAYLOAD_B, events, "raw")

    cur.execute(
        "LOAD DATA LOCAL INFILE 'x'",
        local_infile_streams={raw_name: stream},
    )

    assert peer.uploads == [(raw_name, PAYLOAD_B)]
    assert probe_open.calls == []
    assert not stream.closed


def test_case_difference_is_rejected(connect_factory, peer_factory, events, probe_open):
    peer = peer_factory(lambda sql: [LoadLocal(b"NAME.CSV"), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()

    with pytest.raises(
        err.OperationalError,
        match="not authorized",
    ) as exc_info:
        cur.execute(
            "SELECT 1",
            local_infile_streams={b"name.csv": ProbeStream(b"x", events, "x")},
        )

    assert exc_info.value.args[0] == 2068
    assert not conn.open
    assert probe_open.calls == []


# ---------------------------------------------------------------------------
# Hostile server behavior.
# ---------------------------------------------------------------------------


def test_malicious_select_requests_unauthorized_file(
    connect_factory, peer_factory, events, probe_open
):
    # A plain SELECT is answered with a 0xfb packet for a name the caller
    # never granted.
    peer = peer_factory(lambda sql: [LoadLocal(b"secret.txt"), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()

    with pytest.raises(err.OperationalError, match="not authorized"):
        cur.execute("SELECT 1", local_infile_streams={})

    # No server-provided name may reach open(), and the connection is dead.
    assert probe_open.calls == []
    assert not conn.open
    with pytest.raises(err.InterfaceError):
        cur.execute("SELECT 2")


def test_duplicate_request_consumes_stream_once(
    connect_factory, peer_factory, events, probe_open
):
    # The second, identical 0xfb request is a new result set of the same
    # multi-statement command; the stream was already consumed, so the grant
    # can no longer satisfy it.
    peer = peer_factory(
        lambda sql: [
            LoadLocal(NAME_A, has_next=True),
            LoadLocal(NAME_A),
            Ok(),
        ]
    )
    conn = connect_factory(peer)
    cur = conn.cursor()
    streams = make_streams(events)

    with pytest.raises(err.OperationalError, match="not authorized"):
        cur.execute(
            "LOAD DATA LOCAL INFILE 'x'; SELECT 1",
            local_infile_streams=streams,
        )
        while cur.nextset():
            pass

    # The first request used the stream exactly once; the repeated one was
    # rejected without any filesystem access.
    assert peer.uploads == [(NAME_A, PAYLOAD_A)]
    assert streams[NAME_A].read_count > 0
    assert not streams[NAME_A].closed
    assert probe_open.calls == []
    assert not conn.open


def test_multiple_legal_imports_in_one_command(connect_factory, peer_factory, events):
    peer = peer_factory(
        lambda sql: [
            LoadLocal(NAME_A, has_next=True),
            LoadLocal(NAME_B),
            Ok(),
        ]
    )
    conn = connect_factory(peer)
    cur = conn.cursor()
    streams = make_streams(events)

    cur.execute(
        "LOAD DATA LOCAL INFILE 'x'; LOAD DATA LOCAL INFILE 'y'",
        local_infile_streams=streams,
    )
    assert cur.nextset() is True

    assert peer.uploads == [(NAME_A, PAYLOAD_A), (NAME_B, PAYLOAD_B)]
    assert cur.nextset() is None
    assert conn._local_infile_streams is None
    assert not streams[NAME_A].closed
    assert not streams[NAME_B].closed


def test_stream_read_error_closes_connection(
    connect_factory, peer_factory, events, probe_open
):
    peer = peer_factory(lambda sql: [LoadLocal(NAME_A), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()
    failing = FailingStream(events, "failing")

    with pytest.raises(err.OperationalError, match="Error reading"):
        cur.execute(
            "LOAD DATA LOCAL INFILE 'x'",
            local_infile_streams={NAME_A: failing},
        )

    assert not conn.open
    assert not failing.closed  # ownership stays with the caller
    assert probe_open.calls == []
    # Nothing complete was uploaded; the server saw no terminating packet.
    assert peer.uploads == []


def test_base_exception_during_read_also_closes_connection(
    connect_factory, peer_factory, events, probe_open
):
    peer = peer_factory(lambda sql: [LoadLocal(NAME_A), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()
    stream = InterruptingStream(events, "interrupted")

    with pytest.raises(KeyboardInterrupt):
        cur.execute(
            "LOAD DATA LOCAL INFILE 'x'",
            local_infile_streams={NAME_A: stream},
        )

    assert not conn.open
    assert not stream.closed
    assert probe_open.calls == []


def test_unexpected_trailing_packet_closes_connection(
    connect_factory, peer_factory, events, probe_open
):
    # After the upload's empty packet the server must answer OK; a second
    # 0xfb packet instead means the command boundary was not honored.
    peer = peer_factory(
        lambda sql: [LoadLocal(NAME_A, trailing=b"\xfb" + b"other.csv")]
    )
    conn = connect_factory(peer)
    cur = conn.cursor()
    streams = make_streams(events)

    with pytest.raises(err.OperationalError, match="Commands Out of Sync"):
        cur.execute("LOAD DATA LOCAL INFILE 'x'", local_infile_streams=streams)

    assert not conn.open
    assert probe_open.calls == []
    assert peer.uploads == [(NAME_A, PAYLOAD_A)]


def test_server_error_after_upload_leaves_protocol_intact(
    connect_factory, peer_factory, events
):
    # An ERR packet is a synchronized terminal response, so the connection
    # must remain usable for the next command.
    peer_followup = [False]

    def script(sql):
        if peer_followup[0]:
            return [Ok()]
        return [LoadLocal(NAME_A, trailing=_error_payload(1262, b"blocked"))]

    peer = peer_factory(script)
    conn = connect_factory(peer)
    cur = conn.cursor()

    with pytest.raises(err.MySQLError):
        cur.execute(
            "LOAD DATA LOCAL INFILE 'x'",
            local_infile_streams={NAME_A: ProbeStream(PAYLOAD_A, events, "A")},
        )
    assert conn.open
    assert conn._local_infile_streams is None

    # A follow-up command still gets a clean exchange.
    peer_followup[0] = True
    cur.execute("SELECT 1")
    assert peer.queries[-1] == b"SELECT 1"


# ---------------------------------------------------------------------------
# Grant lifetime across result sets, cursors and commands.
# ---------------------------------------------------------------------------


def test_grant_spans_buffered_multi_results(connect_factory, peer_factory, events):
    def script(sql):
        if sql == b"SELECT 1; LOAD DATA LOCAL INFILE 'x'":
            return [
                ResultSet([(b"1",)], has_next=True),
                LoadLocal(NAME_A),
                Ok(),
            ]
        return [Ok()]

    peer = peer_factory(script)
    conn = connect_factory(peer)
    cur = conn.cursor()
    streams = make_streams(events)

    cur.execute(
        "SELECT 1; LOAD DATA LOCAL INFILE 'x'",
        local_infile_streams=streams,
    )
    # First result set is buffered, but the command is not finished.
    assert conn._local_infile_streams is not None
    assert cur.fetchone() == (1,)
    assert cur.nextset() is True

    assert peer.uploads == [(NAME_A, PAYLOAD_A)]
    assert cur.nextset() is None
    assert conn._local_infile_streams is None


def test_grant_spans_sscursor_multi_results(connect_factory, peer_factory, events):
    def script(sql):
        return [
            ResultSet([(b"1",)], has_next=True),
            LoadLocal(NAME_A),
            Ok(),
        ]

    peer = peer_factory(script)
    conn = connect_factory(peer)
    cur = conn.cursor(cursors.SSCursor)
    streams = make_streams(events)

    cur.execute(
        "SELECT 1; LOAD DATA LOCAL INFILE 'x'",
        local_infile_streams=streams,
    )
    assert conn._local_infile_streams is not None
    assert cur.fetchone() == (1,)
    assert cur.fetchone() is None  # consume the first result set's EOF
    assert conn._local_infile_streams is not None
    assert cur.nextset() is True

    assert peer.uploads == [(NAME_A, PAYLOAD_A)]
    assert cur.nextset() is None
    assert conn._local_infile_streams is None


def test_sscursor_grant_alive_while_rows_unread_then_revoked_on_close(
    connect_factory, peer_factory, events
):
    peer = peer_factory(lambda sql: [ResultSet([(b"1",), (b"2",)])])
    conn = connect_factory(peer)
    cur = conn.cursor(cursors.SSCursor)

    cur.execute("SELECT 1", local_infile_streams=make_streams(events))
    assert conn._local_infile_streams is not None
    assert cur.fetchone() == (1,)

    cur.close()  # drains the remaining rows instead of leaving them hanging
    assert conn._local_infile_streams is None


def test_buffered_cursor_close_revokes_grant_with_pending_nextset(
    connect_factory, peer_factory, events
):
    def script(sql):
        if sql.startswith(b"SELECT"):
            return [ResultSet([(b"1",)], has_next=True), ResultSet([(b"2",)])]
        return [Ok()]

    peer = peer_factory(script)
    conn = connect_factory(peer)
    cur = conn.cursor()

    cur.execute("SELECT 1; SELECT 2", local_infile_streams=make_streams(events))
    assert conn._local_infile_streams is not None
    cur.fetchone()

    cur.close()  # never call nextset(); close must revoke the grant itself
    assert conn._local_infile_streams is None


def test_exception_revokes_grant(connect_factory, peer_factory, events):
    peer = peer_factory(lambda sql: [ServerError()])
    conn = connect_factory(peer)
    cur = conn.cursor()

    # 1064 surfaces as ProgrammingError, a subclass of MySQLError.
    with pytest.raises(err.MySQLError):
        cur.execute("SELECT 1", local_infile_streams=make_streams(events))

    assert conn._local_infile_streams is None
    assert conn.open  # an error packet keeps the protocol synchronized


def test_reconnect_revokes_grant(connect_factory, peer_factory, events):
    peer = peer_factory(lambda sql: [Ok()])
    conn = connect_factory(peer)
    conn._set_local_infile_streams(make_streams(events))
    assert conn._local_infile_streams is not None

    conn.close()
    conn.connect()

    assert conn._local_infile_streams is None


def test_new_command_reusing_old_name_is_rejected(
    connect_factory, peer_factory, events, probe_open
):
    peer = peer_factory(lambda sql: [LoadLocal(NAME_A), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()

    cur.execute(
        "LOAD DATA LOCAL INFILE 'x'",
        local_infile_streams={NAME_A: ProbeStream(PAYLOAD_A, events, "A")},
    )
    assert peer.uploads == [(NAME_A, PAYLOAD_A)]

    # The second command carries a fresh grant that does not include the
    # previously used name; the old authorization must not carry over.
    with pytest.raises(err.OperationalError, match="not authorized"):
        cur.execute(
            "LOAD DATA LOCAL INFILE 'x'",
            local_infile_streams={NAME_B: ProbeStream(PAYLOAD_B, events, "B")},
        )
    assert not conn.open
    assert probe_open.calls == []


def test_new_command_may_reauthorize_same_name(connect_factory, peer_factory, events):
    peer = peer_factory(lambda sql: [LoadLocal(NAME_A), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()

    cur.execute(
        "LOAD DATA LOCAL INFILE 'x'",
        local_infile_streams={NAME_A: ProbeStream(PAYLOAD_A, events, "A1")},
    )
    cur.execute(
        "LOAD DATA LOCAL INFILE 'x'",
        local_infile_streams={NAME_A: ProbeStream(PAYLOAD_B, events, "A2")},
    )

    assert peer.uploads == [(NAME_A, PAYLOAD_A), (NAME_A, PAYLOAD_B)]


def test_fresh_grant_installed_after_draining_old_sscursor_result(
    connect_factory, peer_factory, events
):
    # The first command leaves an unbuffered result unread; the second
    # command's grant must be installed only after that result is drained,
    # so draining it cannot revoke the new grant.
    def script(sql):
        if sql.startswith(b"SELECT"):
            return [ResultSet([(b"1",), (b"2",)])]
        return [LoadLocal(NAME_A), Ok()]

    peer = peer_factory(script)
    conn = connect_factory(peer)
    cur = conn.cursor(cursors.SSCursor)

    cur.execute("SELECT 1", local_infile_streams=make_streams(events))
    assert cur.fetchone() == (1,)
    # Do not read the remaining row before issuing the next command.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cur.execute(
            "LOAD DATA LOCAL INFILE 'x'",
            local_infile_streams={NAME_A: ProbeStream(PAYLOAD_A, events, "A")},
        )

    assert peer.uploads == [(NAME_A, PAYLOAD_A)]
    assert conn._local_infile_streams is None


# ---------------------------------------------------------------------------
# Legacy behavior and argument validation.
# ---------------------------------------------------------------------------


def test_legacy_open_path_still_works(
    connect_factory, peer_factory, events, probe_open, tmp_path
):
    data_file = tmp_path / "legacy.csv"
    data_file.write_bytes(PAYLOAD_B)
    peer = peer_factory(lambda sql: [LoadLocal(str(data_file).encode()), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()

    cur.execute("LOAD DATA LOCAL INFILE 'x'")  # no stream mapping

    assert peer.uploads == [(str(data_file).encode(), PAYLOAD_B)]
    assert probe_open.calls[0][0] == str(data_file).encode()
    assert probe_open.calls[0][1] == "rb"
    assert any(event[0] == "file_read" for event in events)


def test_legacy_disabled_switch_rejects_packet(connect_factory, peer_factory):
    peer = peer_factory(lambda sql: [LoadLocal(NAME_A), Ok()])
    conn = connect_factory(peer, local_infile=False)
    cur = conn.cursor()

    with pytest.raises(RuntimeError, match="local_infile option is false"):
        cur.execute("LOAD DATA LOCAL INFILE 'x'")


def test_streams_require_local_infile_capability(connect_factory, peer_factory, events):
    peer = peer_factory(lambda sql: [Ok()])
    conn = connect_factory(peer, local_infile=False)
    cur = conn.cursor()

    with pytest.raises(err.ProgrammingError, match="local_infile=True"):
        cur.execute("SELECT 1", local_infile_streams=make_streams(events))
    assert conn._local_infile_streams is None


def test_invalid_grant_arguments(connect_factory, peer_factory, events):
    peer = peer_factory(lambda sql: [Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()

    with pytest.raises(TypeError, match="mapping"):
        cur.execute("SELECT 1", local_infile_streams=[(NAME_A, b"x")])
    with pytest.raises(TypeError, match="raw filename bytes"):
        cur.execute(
            "SELECT 1",
            local_infile_streams={"approved-a.csv": ProbeStream(b"x", events, "x")},
        )
    with pytest.raises(TypeError, match="readable binary streams"):
        cur.execute("SELECT 1", local_infile_streams={NAME_A: b"not-a-stream"})
    assert conn._local_infile_streams is None
    assert conn.open


def test_explicit_none_grant_keeps_legacy_behavior(
    connect_factory, peer_factory, events
):
    peer = peer_factory(lambda sql: [Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()

    cur.execute("SELECT 1", local_infile_streams=None)

    assert conn._local_infile_streams is None
    assert conn.open


def test_revoke_is_safe_without_live_result(connect_factory, peer_factory, events):
    peer = peer_factory(lambda sql: [Ok()])
    conn = connect_factory(peer)
    conn._set_local_infile_streams(make_streams(events))
    conn._result = None

    conn._maybe_revoke_local_infile_streams()

    assert conn._local_infile_streams is None


def test_sscursor_ok_only_command_revokes_grant_immediately(
    connect_factory, peer_factory, events
):
    # An unbuffered OK-only command (no row result set) completes at once,
    # so the grant must not wait for row fetches.
    peer = peer_factory(lambda sql: [Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor(cursors.SSCursor)

    cur.execute("INSERT INTO t VALUES (1)", local_infile_streams=make_streams(events))

    assert conn._local_infile_streams is None
    assert cur.fetchone() is None


def test_legacy_out_of_sync_tail_preserves_old_behavior(
    connect_factory, peer_factory, probe_open, tmp_path
):
    # Legacy mode keeps the historical behavior: an unexpected packet raises
    # Commands Out of Sync without force-closing the socket.
    data_file = tmp_path / "legacy.csv"
    data_file.write_bytes(PAYLOAD_B)
    peer = peer_factory(
        lambda sql: [
            LoadLocal(
                str(data_file).encode(),
                trailing=b"\xfb" + b"another.csv",
            )
        ]
    )
    conn = connect_factory(peer)
    cur = conn.cursor()

    with pytest.raises(err.OperationalError, match="Commands Out of Sync"):
        cur.execute("LOAD DATA LOCAL INFILE 'x'")

    assert conn.open
    assert probe_open.calls[0][0] == str(data_file).encode()


def test_write_failure_during_granted_upload_closes_connection(
    connect_factory, peer_factory, events, monkeypatch
):
    peer = peer_factory(lambda sql: [LoadLocal(NAME_A), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()
    stream = ProbeStream(PAYLOAD_B, events, "write-fail")

    def broken_write_packet(payload):
        raise err.OperationalError(2006, "simulated write failure")

    monkeypatch.setattr(conn, "write_packet", broken_write_packet)

    with pytest.raises(err.OperationalError, match="simulated write failure"):
        cur.execute(
            "LOAD DATA LOCAL INFILE 'x'",
            local_infile_streams={NAME_A: stream},
        )

    assert not conn.open
    assert not stream.closed
    assert peer.uploads == []


def test_empty_mapping_rejects_every_server_name(
    connect_factory, peer_factory, probe_open
):
    peer = peer_factory(lambda sql: [LoadLocal(b"anything"), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor()

    with pytest.raises(err.OperationalError, match="not authorized"):
        cur.execute("SELECT 1", local_infile_streams={})
    assert not conn.open
    assert probe_open.calls == []


def test_rejection_also_closes_for_sscursor(
    connect_factory, peer_factory, events, probe_open
):
    peer = peer_factory(lambda sql: [LoadLocal(b"secret.txt"), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor(cursors.SSCursor)

    with pytest.raises(err.OperationalError, match="not authorized"):
        cur.execute(
            "SELECT 1",
            local_infile_streams={NAME_A: ProbeStream(b"x", events, "x")},
        )

    assert not conn.open
    assert probe_open.calls == []
    with pytest.raises(err.InterfaceError):
        cur.execute("SELECT 2")


def test_stream_read_error_with_sscursor(
    connect_factory, peer_factory, events, probe_open
):
    peer = peer_factory(lambda sql: [LoadLocal(NAME_A), Ok()])
    conn = connect_factory(peer)
    cur = conn.cursor(cursors.SSCursor)
    failing = FailingStream(events, "failing-ss")

    with pytest.raises(err.OperationalError, match="Error reading"):
        cur.execute(
            "LOAD DATA LOCAL INFILE 'x'",
            local_infile_streams={NAME_A: failing},
        )

    assert not conn.open
    assert not failing.closed
    assert probe_open.calls == []
