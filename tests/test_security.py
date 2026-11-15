import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import secure_state as vault
import query_locations as query
import local_anisette_probe as probe
from cryptography.exceptions import InvalidTag

class EncryptedStateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.old_state,self.old_key=vault.STATE,vault._key
        vault.STATE=Path(self.temp.name)
        vault._key=os.urandom(32)
    def tearDown(self):
        vault.STATE,vault._key=self.old_state,self.old_key
        self.temp.cleanup()
    def test_roundtrip_private_and_no_plaintext(self):
        p=vault.STATE/'session.json';vault.write_bytes(p,b'synthetic-sensitive-value')
        self.assertEqual(vault.read_bytes(p),b'synthetic-sensitive-value')
        self.assertFalse(p.exists())
        self.assertNotIn(b'synthetic-sensitive-value',vault.sealed_path(p).read_bytes())
        self.assertEqual(vault.sealed_path(p).stat().st_mode & 0o777,0o600)
    def test_tamper_rejected(self):
        p=vault.STATE/'session.json';vault.write_bytes(p,b'test')
        file=vault.sealed_path(p);d=file.read_bytes();file.write_bytes(d[:-1]+bytes([d[-1]^1]))
        with self.assertRaises(InvalidTag):vault.read_bytes(p)
    def test_wrong_path_rejected(self):
        a=vault.STATE/'first';b=vault.STATE/'second';vault.write_bytes(a,b'test')
        vault.sealed_path(b).write_bytes(vault.sealed_path(a).read_bytes())
        with self.assertRaises(InvalidTag):vault.read_bytes(b)
    def test_traversal_rejected(self):
        for p in [vault.STATE/'../outside',Path('/tmp/outside')]:
            with self.assertRaises(ValueError):vault.sealed_path(p)
    def test_symlink_ancestor_rejected(self):
        (vault.STATE/'linked').symlink_to(vault.STATE,target_is_directory=True)
        with self.assertRaises(ValueError):vault.write_bytes(vault.STATE/'linked/value',b'test')
    def test_keychain_failure_has_no_plaintext_fallback(self):
        vault._key=None
        with patch.object(vault,'key',side_effect=RuntimeError('unavailable')):
            with self.assertRaises(RuntimeError):vault.write_bytes(vault.STATE/'value',b'test')
        self.assertFalse((vault.STATE/'value').exists())

class ProtocolTests(unittest.TestCase):
    def test_delegate_zero_not_missing(self):
        self.assertEqual(query.mobileme_status({'delegates':{'com.apple.mobileme':{'status':0}}}),0)
    def test_delegate_error_not_masked(self):
        self.assertEqual(query.mobileme_status({'status':0,'delegates':{'com.apple.mobileme':{'status':1}}}),1)
        self.assertIsNone(query.mobileme_status({}))
    def test_no_implicit_binary_download(self):
        for source in [None,'https://invalid.example/library.zip']:
            with self.assertRaises(ValueError):probe.local_only_libs(source)
    def test_http_and_redirect_destinations_fail_before_network(self):
        import asyncio
        for url in ['http://gsa.apple.com/x','https://apple.com.invalid.example/x','https://user:pass@gsa.apple.com/x']:
            with self.assertRaises(ValueError):asyncio.run(query.apple_request(None,'GET',url))

class EntryPointTests(unittest.TestCase):
    def test_help_is_safe_under_isolated_python(self):
        tools=Path(__file__).resolve().parents[1]/'tools'
        for name in ['initialize.py','query_locations.py']:
            with tempfile.TemporaryDirectory() as temp:
                result=subprocess.run([sys.executable,'-I',str(tools/name),'--help'],env={**os.environ,'FINDMY_TOOLS_HOME':temp+'/state'},capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertFalse((Path(temp)/'state').exists())

if __name__=='__main__':unittest.main()
