"""A deterministic in-memory MySQL peer; no network or real file reads."""
import io
import struct
from unittest.mock import patch

import pymysql
from pymysql.constants import FIELD_TYPE


def lc(data):
    assert len(data) < 251
    return bytes([len(data)]) + data


class MemoryPeer:
    def __init__(self, commands):
        self.commands = list(commands)
        self.input = bytearray()
        self.actions = []
        self.sequence = 0
        self.closed = False
        self.queries = []
        self.uploads = []
        self.read_calls = []
        self.current_upload = None
        self.current_name = None
        self.wire_errors = []

    def settimeout(self, value):
        pass

    def close(self):
        self.closed = True

    def read(self, n):
        self.read_calls.append(n)
        data = bytes(self.input[:n])
        del self.input[:n]
        return data

    def packet(self, payload):
        self.input.extend(len(payload).to_bytes(3, 'little') + bytes([self.sequence]) + payload)
        self.sequence = (self.sequence + 1) & 255

    def next_action(self):
        kind, value = self.actions.pop(0)
        more = 8 if self.actions else 0
        if kind == 'infile':
            self.current_name = value
            self.current_upload = bytearray()
            self.packet(b'\xfb' + value)
        elif kind == 'ok':
            self.packet(b'\x00\x00\x00' + struct.pack('<HH', 2 | more, 0))
            if self.actions:
                self.next_action()
        elif kind == 'select':
            self.packet(b'\x01')
            descriptor = b''.join(lc(x) for x in (b'def', b'', b'', b'', b'value', b''))
            descriptor += b'\x0c' + struct.pack('<HIBHB', 63, 255, FIELD_TYPE.VAR_STRING, 0, 0) + b'\x00\x00'
            self.packet(descriptor)
            self.packet(b'\xfe' + struct.pack('<HH', 0, 2))
            for row in value:
                self.packet(lc(row))
            self.packet(b'\xfe' + struct.pack('<HH', 0, 2 | more))
            if self.actions:
                self.next_action()
        else:
            raise AssertionError(kind)

    def sendall(self, data):
        assert not self.closed
        while data:
            n = int.from_bytes(data[:3], 'little')
            sequence = data[3]
            payload = data[4:4+n]
            assert len(payload) == n
            data = data[4+n:]
            if sequence == 0:
                assert payload[0] == 3 and self.current_upload is None
                self.queries.append(payload[1:])
                assert self.commands, 'Unexpected new command'
                self.actions = list(self.commands.pop(0))
                self.sequence = 1
                self.next_action()
            else:
                assert self.current_upload is not None, 'Upload without server request'
                assert sequence == self.sequence, (sequence, self.sequence)
                self.sequence = (sequence + 1) & 255
                if payload:
                    self.current_upload.extend(payload)
                else:
                    self.uploads.append({'name': self.current_name, 'data': bytes(self.current_upload)})
                    self.current_upload = None
                    more = 8 if self.actions else 0
                    self.packet(b'\x00\x00\x00' + struct.pack('<HH', 2 | more, 0))
                    if self.actions:
                        self.next_action()

    def connection(self, cursorclass=pymysql.cursors.Cursor):
        conn = pymysql.Connection(defer_connect=True, local_infile=True, cursorclass=cursorclass)
        conn._sock = self
        conn._rfile = self
        conn._current_timeout = None
        conn.server_status = 2
        conn.server_version = '8.0.0-local-peer'
        return conn


class ObservedStream(io.BytesIO):
    def __init__(self, data, *, fail_after_reads=None):
        super().__init__(data)
        self.read_calls = []
        self.close_calls = 0
        self.fail_after_reads = fail_after_reads

    def read(self, n=-1):
        self.read_calls.append(n)
        if self.fail_after_reads is not None and len(self.read_calls) > self.fail_after_reads:
            raise OSError('generated stream read failure')
        return super().read(n)

    def close(self):
        self.close_calls += 1
        super().close()


if __name__ == '__main__':
    import json
    p = MemoryPeer([[('select', [b'one', b'two'])], [('infile', b'generated-only')]])
    conn = p.connection()
    c = conn.cursor()
    assert c.execute('SELECT local-generated') == 2
    assert c.fetchall() == ((b'one',), (b'two',))
    opened = []
    def generated_open(name, mode):
        opened.append((name, mode))
        assert name == b'generated-only' and mode == 'rb'
        return io.BytesIO(b'generated test bytes')
    with patch('pymysql.connections.open', generated_open, create=True):
        c.execute('LOAD DATA LOCAL generated-only')
    assert p.uploads == [{'name': b'generated-only', 'data': b'generated test bytes'}]
    conn.close()
    assert len(opened) == 1
    print(json.dumps({'positive_control': 'PASS', 'queries': len(p.queries), 'legacy_open_calls': len(opened), 'real_file_reads': 0, 'network_used': False}))
