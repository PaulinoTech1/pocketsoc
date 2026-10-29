import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
import socket
from unittest.mock import AsyncMock, patch
from atlas_rf.analysis import analyze, markdown, report, topology
from atlas_rf.cli import main, write_private
from atlas_rf.collectors import probe, split_nm, targets
from atlas_rf.model import clean, validate
from atlas_rf.store import Store


def wifi(time='2026-01-01T12:00:00Z', **fields):
    o = dict(kind='wifi', id='02:00:00:00:00:01', observed_at=time,
             source='test:sensor', name='Lab', security='WPA2', rssi=-70)
    o.update(fields)
    return o


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'data/atlas.sqlite3')
    def tearDown(self):
        self.store.close()
        self.temp.cleanup()
    def test_replay_and_chronological_history(self):
        self.assertEqual(self.store.add([wifi(), wifi()]), 1)
        self.store.add([wifi('2026-01-01T11:00:00Z')])
        rows = self.store.observations()
        self.assertLess(rows[0]['observed_at'], rows[1]['observed_at'])
        self.assertEqual(os.stat(self.store.path).st_mode & 0o777, 0o600)
    def test_import_rolls_back_after_valid_row(self):
        path = Path(self.temp.name) / 'bad.jsonl'
        path.write_text(json.dumps(wifi()) + '\n{"kind":"nope"}\n')
        with self.assertRaisesRegex(ValueError, 'line 2'):
            self.store.ingest(path)
        self.assertEqual(self.store.stats(), {})
    def test_oversize_line(self):
        path = Path(self.temp.name) / 'large.jsonl'
        path.write_text('x' * 17000)
        with self.assertRaises(ValueError):
            self.store.ingest(path)
    def test_window_and_purge(self):
        self.store.add([wifi(), wifi('2026-01-01T12:01:00Z')])
        r = report(self.store, 1)
        self.assertTrue(r['coverage']['truncated'])
        self.assertEqual(self.store.purge('2026-01-01T12:00:30.000000+00:00'), 1)
        self.assertEqual(len(self.store.observations()), 1)
    def test_report_escapes_untrusted_name(self):
        self.store.add([wifi(name='\x1b[31m[x](https://example.org)'), wifi('2026-01-01T12:01:00Z', id='02:00:00:00:00:02', name='\x1b[31m[x](https://example.org)')])
        text = markdown(report(self.store))
        self.assertNotIn('\x1b', text)
        self.assertIn('\\[x\\]', text)
    def test_new_output_only(self):
        path = Path(self.temp.name) / 'report.md'
        write_private(path, 'assessment')
        with self.assertRaises(FileExistsError):
            write_private(path, 'overwrite')
        self.assertEqual(path.read_text(), 'assessment')


class IntelligenceTests(unittest.TestCase):
    def test_out_of_order_downgrade_and_rssi(self):
        observations = [validate(wifi('2026-01-01T12:01:00Z', security='OPEN', rssi=-30)), validate(wifi())]
        rules = {f['rule'] for f in analyze(observations)}
        self.assertTrue({'wifi-security-downgrade', 'wifi-weak-security', 'rapid-rssi-change'} <= rules)
    def test_sources_are_separate_baselines(self):
        rows = [validate(wifi()), validate(wifi('2026-01-01T12:01:00Z', source='other', security='OPEN'))]
        self.assertNotIn('wifi-security-downgrade', {f['rule'] for f in analyze(rows)})
    def test_unknown_is_not_open(self):
        self.assertEqual(analyze([validate(wifi(security='UNKNOWN'))]), [])
    def test_no_invented_radio_edges(self):
        graph = topology([validate(wifi()), validate(wifi(id='02:00:00:00:00:02'))])
        self.assertEqual(len(graph['edges']), 2)
        self.assertTrue(all(e['source'] == 'source:test:sensor' for e in graph['edges']))
    def test_validation(self):
        for changes in ({'rssi': float('nan')}, {'rssi': True}, {'observed_at': '2026-01-01'}, {'id': 'invalid'}, {'unexpected': 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate(wifi(**changes))
    def test_terminal_controls(self):
        self.assertNotIn('\x1b', clean('\x1b]0;hostile\x07'))
        self.assertNotIn('\u202e', clean('text\u202e'))
    def test_nmcli_escaping(self):
        self.assertEqual(split_nm(r'02\:00\:00\:00\:00\:01:Lab\:east:WPA2'), ['02:00:00:00:00:01', 'Lab:east', 'WPA2'])
    def test_scope_limits(self):
        for scope in ('10.0.0.0/16', 'example.com', '224.0.0.1', '0.0.0.0', 'fe80::1'):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                targets([scope])
        self.assertEqual(targets(['127.0.0.1']), ['127.0.0.1'])
        self.assertEqual(len(targets(['10.0.0.0/24'])), 254)


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_local_tcp_and_bounded_workers(self):
        try:
            sock = socket.socket()
        except PermissionError:
            self.skipTest('execution sandbox denies TCP socket creation; run on target Debian')
        else:
            sock.close()
        async def accept(reader, writer):
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(accept, '127.0.0.1', 0)
        try:
            port = server.sockets[0].getsockname()[1]
            rows, summary = await probe(['127.0.0.1'], [port], concurrency=2)
            self.assertEqual(summary['attempts'], 1)
            self.assertEqual(rows[0]['port'], port)
            self.assertEqual(validate(rows[0])['ip'], '127.0.0.1')
        finally:
            server.close()
            await server.wait_closed()
    async def test_invalid_limits(self):
        for kwargs in ({'concurrency': 100}, {'timeout': 100}):
            with self.assertRaises(ValueError):
                await probe(['127.0.0.1'], [80], **kwargs)

    async def test_socket_denial_is_not_no_hosts(self):
        with patch('atlas_rf.collectors.asyncio.open_connection', new=AsyncMock(side_effect=PermissionError('denied'))):
            with self.assertRaisesRegex(ValueError, 'sockets denied'):
                await probe(['127.0.0.1'], [80])

    async def test_refused_port_is_not_recorded(self):
        with patch('atlas_rf.collectors.asyncio.open_connection', new=AsyncMock(side_effect=ConnectionRefusedError())):
            rows, summary = await probe(['127.0.0.1'], [80])
            self.assertEqual(rows, [])
            self.assertEqual(summary['attempts'], 1)

    def test_neighbor_requires_mac(self):
        with self.assertRaisesRegex(ValueError, 'requires mac'):
            validate(dict(kind='neighbor', id='192.0.2.1', ip='192.0.2.1', source='test', observed_at='2026-01-01T12:00:00Z'))


if __name__ == '__main__':
    unittest.main()
