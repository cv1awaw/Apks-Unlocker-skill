"""Consent-flow tests use a fictional local declaration, never accept terms for a user."""
from pathlib import Path
import contextlib
import io
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import setup_tools

class AuthorizedUseTests(unittest.TestCase):
    def setUp(self):
        self.base=(ROOT/'.validation/policy-test-work').resolve();self.base.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='case-',dir=self.base);self.work=Path(self.temp.name).resolve();self.assertIn(self.base,self.work.parents)
        (self.work/'TERMS_OF_USE.md').write_text('Fictional local test declaration only.',encoding='utf-8')
    def tearDown(self):
        self.assertIn(self.base,self.work.resolve().parents);self.temp.cleanup()
    def headless(self):
        return patch('setup_tools.sys.stdin.isatty',return_value=False)
    def test_download_or_missing_record_is_not_consent(self):
        with self.headless(),contextlib.redirect_stdout(io.StringIO()):accepted=setup_tools.acknowledge_authorized_use(root=self.work)
        self.assertFalse(accepted);self.assertFalse((self.work/'.local').exists())
    def test_explicit_acknowledgment_is_local_and_minimal(self):
        self.assertTrue(setup_tools.acknowledge_authorized_use(True,self.work));data=json.loads((self.work/'.local/authorized-use.json').read_text())
        self.assertTrue(data['accepted']);self.assertEqual(data['terms_sha256'],setup_tools.digest(self.work/'TERMS_OF_USE.md'));self.assertEqual(set(data),{'accepted','terms_sha256','accepted_at_utc','method','scope'})
    def test_matching_acknowledgment_does_not_reprompt(self):
        setup_tools.acknowledge_authorized_use(True,self.work)
        with patch('setup_tools.sys.stdin.isatty',side_effect=AssertionError('Unexpected repeat prompt')):
            self.assertTrue(setup_tools.acknowledge_authorized_use(False,self.work))
    def test_changed_terms_need_explicit_review(self):
        setup_tools.acknowledge_authorized_use(True,self.work);(self.work/'TERMS_OF_USE.md').write_text('Changed fictional test declaration.',encoding='utf-8')
        with self.headless(),contextlib.redirect_stdout(io.StringIO()):self.assertFalse(setup_tools.acknowledge_authorized_use(False,self.work))
        self.assertTrue(setup_tools.acknowledge_authorized_use(True,self.work))
    def test_string_true_is_not_a_valid_acknowledgment(self):
        folder=self.work/'.local';folder.mkdir();record={'accepted':'true','terms_sha256':setup_tools.digest(self.work/'TERMS_OF_USE.md')};(folder/'authorized-use.json').write_text(json.dumps(record))
        with self.headless(),contextlib.redirect_stdout(io.StringIO()):self.assertFalse(setup_tools.acknowledge_authorized_use(False,self.work))
    def test_installer_stops_before_provisioning_without_acknowledgment(self):
        with patch('setup_tools.sys.argv',['setup_tools.py','--download-tools']),patch('setup_tools.acknowledge_authorized_use',return_value=False),patch('setup_tools.run',side_effect=AssertionError('Provisioning must not run')),patch('setup_tools.download',side_effect=AssertionError('Download must not run')):
            self.assertEqual(setup_tools.main(),2)

if __name__=='__main__':unittest.main()
