"""Configuration and policy file limits apply before parsing or blocking reads."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from atlas.core.config import load_config
from atlas.core.errors import ConfigurationError
from atlas.detection.policy import load_policy


class SecurityInputTests(unittest.TestCase):
    def test_yaml_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'target.yaml'
            target.write_text('{}')
            link = Path(root) / 'link.yaml'
            link.symlink_to(target)
            for loader in (load_config, load_policy):
                with self.subTest(loader=loader.__name__), self.assertRaises(ConfigurationError):
                    loader(link)

    def test_yaml_fifo_reads_fail_without_a_writer(self):
        with tempfile.TemporaryDirectory() as root:
            fifo = Path(root) / 'input.yaml'
            os.mkfifo(fifo)
            for module, function in (('atlas.core.config', 'load_config'),
                                     ('atlas.detection.policy', 'load_policy')):
                code = (f'from {module} import {function}\n'
                        'from atlas.core.errors import ConfigurationError\n'
                        'import sys\n'
                        f'try: {function}(sys.argv[1])\n'
                        'except ConfigurationError: sys.exit(0)\n'
                        'sys.exit(1)\n')
                with self.subTest(loader=function):
                    result = subprocess.run([sys.executable, '-c', code, str(fifo)],
                                            capture_output=True, timeout=2)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
