"""Private event logs must not append to aliased files or special devices."""
import os
from pathlib import Path
import tempfile
import unittest

from atlas.core.logging import PrivateRotatingFileHandler


class PrivateLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'events.log'

    def tearDown(self):
        self.temp.cleanup()

    def test_hardlinked_log_refused_without_changing_target(self):
        target = self.root / 'evidence'
        target.write_text('sensitive evidence')
        target.chmod(0o640)
        os.link(target, self.path)
        with self.assertRaises(ValueError):
            PrivateRotatingFileHandler(self.path)
        self.assertEqual(target.read_text(), 'sensitive evidence')
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_fifo_log_refused(self):
        os.mkfifo(self.path)
        # Keep a peer open so even a regressed blocking open cannot hang this test.
        peer = os.open(self.path, os.O_RDWR | os.O_NONBLOCK)
        try:
            with self.assertRaises(ValueError):
                PrivateRotatingFileHandler(self.path)
        finally:
            os.close(peer)

    def test_shared_parent_refused(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            PrivateRotatingFileHandler(self.path)
        self.assertFalse(self.path.exists())

    def test_private_regular_log_and_rotation(self):
        import logging
        handler = PrivateRotatingFileHandler(self.path, maxBytes=32, backupCount=2)
        try:
            for _ in range(8):
                handler.emit(logging.LogRecord('test', logging.INFO, '', 0, 'safe event', (), None))
        finally:
            handler.close()
        self.assertTrue(self.path.with_suffix('.log.1').exists())
        for path in self.root.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
