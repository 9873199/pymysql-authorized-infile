"""Real protocol ERR while reading an established unbuffered result."""
import importlib.util
from pathlib import Path
import struct
import sys
from unittest.mock import patch

import pymysql
import pytest
from infile_api import execute

spec = importlib.util.spec_from_file_location(
    'infile_exception_peer', Path(__file__).with_name('infile-memory-peer.py'))
peer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = peer
spec.loader.exec_module(peer)


class ErrorAfterMetadataPeer(peer.MemoryPeer):
    def next_action(self):
        super().next_action()
        # A result with no rows already contains metadata EOF followed by a
        # terminal EOF. Replace only the latter with a valid MySQL ERR frame.
        assert self.input[-9:-6] == b'\x05\x00\x00'
        sequence = self.input[-6]
        del self.input[-9:]
        self.sequence = sequence
        self.packet(b'\xff' + struct.pack('<H', 1105) + b'#HY000generated result failure')


@pytest.mark.parametrize('operation', ['fetchone', 'close'])
def test_established_unbuffered_error_revokes_grant(operation):
    server = ErrorAfterMetadataPeer([[('select', [])]])
    connection = server.connection(pymysql.cursors.SSCursor)
    cursor = connection.cursor()
    stream = peer.ObservedStream(b'caller-generated-data')
    with patch('pymysql.connections.open', create=True,
               side_effect=AssertionError('No filesystem lookups')) as opened:
        execute(cursor, 'SELECT generated', {b'a': stream})
        assert connection._local_infile_streams is not None
        caught = None
        try:
            getattr(cursor, operation)()
        except pymysql.err.OperationalError as error:
            caught = error.args
        observed = {
            'operation': operation, 'error': caught,
            'grant_revoked': connection._local_infile_streams is None,
            'connection_open': connection.open,
            'stream_read_calls': len(stream.read_calls),
            'stream_close_calls': stream.close_calls,
        }
        print(observed)
        try:
            assert caught == (1105, 'generated result failure')
            assert not opened.called and not stream.read_calls
            assert stream.close_calls == 0
            assert connection._local_infile_streams is None
        finally:
            connection._force_close()
