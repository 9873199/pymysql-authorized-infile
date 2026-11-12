"""Exercise the single-command authorization contract with real MySQL packets.

infile_api.execute maps only the final product's chosen entry point/parameter.
It must never implement name, stream, lifetime or error policy in the adapter.
"""
import importlib.util
from pathlib import Path
import sys
from unittest.mock import patch

import pymysql
import pytest

from infile_api import execute

spec = importlib.util.spec_from_file_location('infile_memory_peer', Path(__file__).with_name('infile-memory-peer.py'))
peer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = peer
spec.loader.exec_module(peer)


class ReadOnlyStream(peer.ObservedStream):
    def read(self, n=-1):
        if getattr(self, '_returned_eof', False):
            self.after_eof_calls = getattr(self, 'after_eof_calls', 0) + 1
        data = super().read(n)
        if data == b'':
            self._returned_eof = True
        return data

    def writable(self):
        return False

    def write(self, data):
        raise OSError('Read-only generated fixture')

    def writelines(self, lines):
        raise OSError('Read-only generated fixture')

    def truncate(self, size=None):
        raise OSError('Read-only generated fixture')


@pytest.fixture(autouse=True)
def no_file_open():
    # This is the initial product's exact server-filename filesystem lookup site.
    # A new lookup site, if added, also needs review and an equivalent probe.
    with patch('pymysql.connections.open', side_effect=AssertionError('Server-selected disk open is forbidden'), create=True) as opened:
        yield opened
        assert not opened.called


def test_exact_opaque_name_uploads_only_authorized_bytes():
    name = b'opaque-\xff/../data'
    stream = ReadOnlyStream(b'only-generated-bytes')
    server = peer.MemoryPeer([[('infile', name)]])
    connection = server.connection()
    cursor = connection.cursor()
    execute(cursor, 'LOAD DATA LOCAL generated', {name: stream})
    while cursor.nextset():
        pass
    assert server.uploads == [{'name': name, 'data': b'only-generated-bytes'}]
    assert stream.read_calls and not stream.closed and stream.close_calls == 0


@pytest.mark.parametrize('supplied,requested', [
    (b'folder/file', b'folder/./file'), (b'folder/file', b'folder\\file'),
    (b'FILE', b'file'), (b'\xff', b'\xef\xbf\xbd')])
def test_no_decoding_path_or_case_normalization(supplied, requested):
    stream = ReadOnlyStream(b'never-sent')
    server = peer.MemoryPeer([[('infile', requested)]])
    connection = server.connection()
    with pytest.raises(Exception):
        execute(connection.cursor(), 'SELECT innocent', {supplied: stream})
    assert not stream.read_calls and not stream.closed
    assert all(item['data'] == b'' for item in server.uploads)


def test_select_without_authorization_cannot_read_disk():
    server = peer.MemoryPeer([[('infile', b'generated-only')]])
    connection = server.connection()
    with pytest.raises(Exception):
        execute(connection.cursor(), 'SELECT innocent', {})
    assert all(item['data'] == b'' for item in server.uploads)


@pytest.mark.parametrize('cursor_class', [pymysql.cursors.Cursor, pymysql.cursors.SSCursor])
def test_authorization_survives_original_unread_result_and_multiple_sets(cursor_class):
    first = ReadOnlyStream(b'first-generated')
    second = ReadOnlyStream(b'second-generated')
    server = peer.MemoryPeer([[('select', [b'one', b'two']), ('infile', b'a'), ('infile', b'b')]])
    connection = server.connection(cursor_class)
    cursor = connection.cursor()
    execute(cursor, 'CALL generated-multiset', {b'a': first, b'b': second})
    assert not first.read_calls and not second.read_calls
    assert tuple(cursor.fetchall()) == ((b'one',), (b'two',))
    while cursor.nextset():
        cursor.fetchall()
    assert server.uploads == [{'name': b'a', 'data': b'first-generated'}, {'name': b'b', 'data': b'second-generated'}]
    assert first.close_calls == second.close_calls == 0


@pytest.mark.parametrize('same_name', [True, False])
def test_one_stream_object_cannot_be_consumed_twice(same_name):
    stream = ReadOnlyStream(b'once')
    second = b'a' if same_name else b'alias'
    server = peer.MemoryPeer([[('infile', b'a'), ('infile', second)]])
    connection = server.connection()
    cursor = connection.cursor()
    with pytest.raises(Exception):
        execute(cursor, 'CALL repeat', {b'a': stream, b'alias': stream})
        while cursor.nextset():
            pass
    nonempty = [item for item in server.uploads if item['data']]
    assert len(nonempty) == 1 and nonempty[0]['data'] == b'once'
    assert getattr(stream, 'after_eof_calls', 0) == 0
    assert stream.close_calls == 0


def test_completed_command_cannot_reuse_previous_authorization():
    stream = ReadOnlyStream(b'one-command')
    server = peer.MemoryPeer([[('infile', b'a')], [('infile', b'a')]])
    connection = server.connection()
    cursor = connection.cursor()
    execute(cursor, 'LOAD DATA one', {b'a': stream})
    while cursor.nextset():
        pass
    prior = len(stream.read_calls)
    with pytest.raises(Exception):
        execute(cursor, 'SELECT next-command', {})
    assert len(stream.read_calls) == prior and stream.close_calls == 0
    assert len([item for item in server.uploads if item['data']]) == 1


def test_read_error_does_not_close_caller_stream_or_leave_pending_protocol_reusable():
    stream = ReadOnlyStream(b'generated', fail_after_reads=0)
    server = peer.MemoryPeer([[('infile', b'a')], [('select', [b'new'])]])
    connection = server.connection()
    with pytest.raises(Exception):
        execute(connection.cursor(), 'LOAD DATA broken', {b'a': stream})
    assert not stream.closed and stream.close_calls == 0
    if not server.closed and connection._sock is not None:
        # A recovery may explicitly end the transfer and consume its ACK. Only
        # then can a fresh query prove the socket is usable and auth is revoked.
        assert server.current_upload is None and not server.input and not server.actions
        cursor = connection.cursor()
        execute(cursor, 'SELECT recovery-control', {})
        assert tuple(cursor.fetchall()) == ((b'new',),)


def test_cursor_close_removes_unused_stream_authorization():
    stream = ReadOnlyStream(b'not-authorized-after-close')
    server = peer.MemoryPeer([[('select', [b'one']), ('infile', b'a')], [('infile', b'a')]])
    connection = server.connection(pymysql.cursors.SSCursor)
    cursor = connection.cursor()
    execute(cursor, 'CALL lazy-result', {b'a': stream})
    assert not stream.read_calls
    cursor.close()
    # Closing may drain the still-authorized original result. The requirement
    # revokes authority AFTER close, not necessarily at entry into close().
    assert stream.close_calls == 0 and connection._local_infile_streams is None
    prior = len(stream.read_calls)
    with pytest.raises(Exception):
        execute(connection.cursor(), 'SELECT after-close', {})
    assert len(stream.read_calls) == prior and stream.close_calls == 0


def test_same_stream_alias_is_not_a_second_authorization_after_caller_rewind():
    stream = ReadOnlyStream(b'one-generated-stream')
    server = peer.MemoryPeer([[('infile', b'a'), ('infile', b'alias')]])
    connection = server.connection()
    cursor = connection.cursor()
    execute(cursor, 'CALL repeated-source', {b'a': stream, b'alias': stream})
    assert server.uploads == [{'name': b'a', 'data': b'one-generated-stream'}]
    # This remains the same caller-owned read-only, seekable stream object.
    # Its original grant cannot become consumable twice merely by rewinding it.
    stream.seek(0)
    reads = len(stream.read_calls)
    with pytest.raises(Exception):
        cursor.nextset()
    assert len(stream.read_calls) == reads
    assert server.uploads == [{'name': b'a', 'data': b'one-generated-stream'}]
