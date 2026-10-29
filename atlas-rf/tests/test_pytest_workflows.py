"""Portable application workflows; standard unittest runs every case without pytest fixtures."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from atlas.cli import main
from atlas.storage.sqlite import Store


class ApplicationWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name)
    def tearDown(self):
        self.temporary.cleanup()
    def invoke(self,args):
        out=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(io.StringIO()):
            code=main(args)
        return code,out.getvalue()
    def test_xdg_status_does_not_create_storage(self):
        with patch.dict(os.environ,{'XDG_DATA_HOME':str(self.root/'xdg')}):
            code,out=self.invoke(['status'])
        self.assertEqual(code,0)
        self.assertEqual(json.loads(out)['database']['path'],str(self.root/'xdg/atlas-rf/atlas.sqlite3'))
        self.assertFalse((self.root/'xdg').exists())
    def test_report_refuses_overwrite(self):
        db=self.root/'atlas.sqlite3'
        store=Store(db)
        try: store.ingest(Path(__file__).resolve().parents[1]/'examples/demo.jsonl')
        finally: store.close()
        output=self.root/'assessment.json'
        args=['--db',str(db),'report','--output',str(output)]
        self.assertEqual(self.invoke(args)[0],0)
        self.assertEqual(len(json.loads(output.read_text())['findings']),5)
        before=output.read_bytes()
        self.assertEqual(self.invoke(args)[0],2)
        self.assertEqual(output.read_bytes(),before)
    def test_monitor_emits_exact_sample_count(self):
        config=self.root/'atlas.yaml';config.write_text('monitor: {interval_seconds: 0.5}\n')
        code,out=self.invoke(['--config',str(config),'monitor','--samples','2'])
        self.assertEqual(code,0)
        events=[json.loads(line) for line in out.splitlines()]
        self.assertEqual(len(events),2)
        self.assertTrue(all(e['event']=='resource.snapshot' for e in events))
        self.assertLess(len(out),8192)
