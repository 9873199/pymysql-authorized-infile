"""Additional command ownership checks; adapter must only call product APIs."""
import importlib.util
from pathlib import Path
import sys
from unittest.mock import patch

import pymysql
import pytest
from infile_api import execute

spec = importlib.util.spec_from_file_location(
    'infile_lifetime_peer', Path(__file__).with_name('infile-memory-peer.py'))
peer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = peer
spec.loader.exec_module(peer)


class GeneratedReadOnlyStream(peer.ObservedStream):
    def writable(self):
        return False

    def write(self, data):
        raise OSError('Read-only generated fixture')


@pytest.mark.parametrize('cursor_class', [pymysql.cursors.Cursor,
                                        pymysql.cursors.SSCursor])
def test_close_revokes_before_any_pending_import_is_drained(cursor_class):
    stream = GeneratedReadOnlyStream(b'generated-not-for-close')
    server = peer.MemoryPeer([[('select', [b'one']), ('infile', b'a')]])
    connection = server.connection(cursor_class)
    cursor = connection.cursor()
    with patch('pymysql.connections.open',
               side_effect=AssertionError('Forbidden filesystem lookup'),
               create=True) as opened:
        execute(cursor, 'CALL pending-close', {b'a': stream})
        assert not stream.read_calls
        try:
            cursor.close()
        except Exception:
            pass
        assert not stream.read_calls and stream.close_calls == 0
        assert all(item['data'] == b'' for item in server.uploads)
        assert not opened.called


@pytest.mark.parametrize('cursor_class', [pymysql.cursors.Cursor,
                                        pymysql.cursors.SSCursor])
def test_new_command_authority_cannot_leak_into_prior_unread_result(cursor_class):
    old = GeneratedReadOnlyStream(b'old-authorized-name')
    new = GeneratedReadOnlyStream(b'new-command-only')
    server = peer.MemoryPeer([
        [('select', [b'one', b'two']), ('infile', b'new')],
        [('ok', None)]])
    connection = server.connection(cursor_class)
    original = connection.cursor()
    with patch('pymysql.connections.open',
               side_effect=AssertionError('Forbidden filesystem lookup'),
               create=True) as opened:
        execute(original, 'CALL previous-command', {b'old': old})
        assert not new.read_calls
        try:
            execute(connection.cursor(), 'SELECT next-command', {b'new': new})
        except Exception:
            pass
        assert not old.read_calls and not new.read_calls
        assert old.close_calls == new.close_calls == 0
        assert all(item['data'] == b'' for item in server.uploads)
        assert not opened.called


def test_legacy_bool_entry_still_uses_its_original_generated_file_path():
    server = peer.MemoryPeer([[('infile', b'generated-legacy')]])
    connection = server.connection()
    calls = []

    def generated_open(name, mode):
        calls.append((name, mode))
        assert name == b'generated-legacy' and mode == 'rb'
        return peer.ObservedStream(b'legacy-generated-content')

    with patch('pymysql.connections.open', generated_open, create=True):
        connection.cursor().execute('LOAD DATA LOCAL legacy')
    assert calls == [(b'generated-legacy', 'rb')]
    assert server.uploads == [{'name': b'generated-legacy',
                               'data': b'legacy-generated-content'}]
