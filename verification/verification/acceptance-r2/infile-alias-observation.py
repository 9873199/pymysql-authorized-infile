"""Capture exact same-object alias behavior without adding product policy."""
import importlib.util
import json
from pathlib import Path
import sys
from infile_api import execute

spec = importlib.util.spec_from_file_location('alias_peer', Path(__file__).with_name('infile-memory-peer.py'))
peer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = peer
spec.loader.exec_module(peer)

stream = peer.ObservedStream(b'one-generated-stream')
server = peer.MemoryPeer([[('infile', b'a'), ('infile', b'alias')]])
connection = server.connection()
cursor = connection.cursor()
execute(cursor, 'CALL repeated-source', {b'a': stream, b'alias': stream})
stream.seek(0)
reads = len(stream.read_calls)
raised = None
try:
    cursor.nextset()
except Exception as error:
    raised = {'type': type(error).__name__, 'message': str(error)}
print(json.dumps({'same_object_for_both_names': True, 'read_calls_before_alias': reads,
    'read_calls_after_alias': len(stream.read_calls), 'raised': raised,
    'uploads': [{'name': item['name'].decode(), 'data': item['data'].decode()}
                for item in server.uploads], 'caller_stream_closed': stream.closed,
    'connection_open': connection.open}))
