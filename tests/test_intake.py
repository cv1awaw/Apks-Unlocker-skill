"""Local synthetic APK fixtures; no network, devices, credentials or private app data."""
from pathlib import Path
import importlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from apk_common import APKArchive,APKError,parse_manifest,sha256_file
from inspect_apk import inspect,signature

MANIFEST=b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" xmlns:x="urn:test" package="dev.example.lab" android:versionCode="7" x:versionCode="999" android:versionName="1.2"><uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><application><activity android:name=".MainActivity" android:exported="false"/></application></manifest>'''

class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.base=(ROOT/'.validation/test-work').resolve();self.base.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='case-',dir=self.base);self.work=Path(self.temp.name).resolve()
        self.assertIn(self.base,self.work.parents)
    def tearDown(self):
        self.assertIn(self.base,self.work.resolve().parents);self.temp.cleanup()
    def apk(self,name='sample.apk',manifest=MANIFEST,extra=None):
        path=self.work/name
        with zipfile.ZipFile(path,'w') as z:
            z.writestr('AndroidManifest.xml',manifest)
            for key,value in (extra or {}).items():z.writestr(key,value)
        return path
    def cli(self,script,*args):
        return subprocess.run([sys.executable,str(ROOT/'scripts'/script),*map(str,args)],capture_output=True,text=True,encoding='utf-8',timeout=30)
    def test_manifest_namespace_sdk_and_exported(self):
        r=parse_manifest(MANIFEST);self.assertEqual(r['package'],'dev.example.lab');self.assertEqual(r['version_code'],'7');self.assertEqual(r['min_sdk'],'24');self.assertEqual(r['components'][0]['exported_explicit'],'false')
    def test_intake_preserves_original(self):
        apk=self.apk();before=apk.read_bytes();r=inspect(apk);self.assertEqual(r['sha256'],sha256_file(apk));self.assertEqual(apk.read_bytes(),before);self.assertEqual(r['signature']['status'],'not_requested')
    def test_dex_header_is_metadata_not_source(self):
        dex=bytearray(112);dex[:8]=b'dex\n035\x00';struct.pack_into('<I',dex,32,112);struct.pack_into('<I',dex,40,0x12345678);struct.pack_into('<I',dex,96,12)
        r=inspect(self.apk(extra={'classes.dex':dex}));self.assertTrue(r['dex'][0]['recognized_header']);self.assertEqual(r['dex'][0]['class_count'],12);self.assertIn('source recovery',r['not_performed'])
    def test_duplicate_zip_rejected(self):
        apk=self.apk()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(apk,'a') as z:z.writestr('AndroidManifest.xml',MANIFEST)
        with self.assertRaises(APKError):inspect(apk)
    def test_zip_slip_rejected(self):
        with self.assertRaises(APKError):inspect(self.apk(extra={'../escape.txt':b'bad'}))
        self.assertFalse((self.work.parent/'escape.txt').exists())
    def test_dtd_entities_rejected(self):
        with self.assertRaises(APKError):parse_manifest(b'<!DOCTYPE manifest [<!ENTITY x "boom">]><manifest package="&x;"/>')
    def test_malformed_xml_is_reported(self):
        r=inspect(self.apk(manifest=b'<manifest'))
        self.assertIsNone(r['manifest']);self.assertTrue(r['warnings'])
    def test_budget_precedes_digest_read(self):
        apk=self.apk()
        with patch('apk_common.MAX_APK',1),patch('inspect_apk.sha256_file',side_effect=AssertionError('Hash should not run')):
            with self.assertRaises(APKError):inspect(apk)
    def test_source_change_is_detected(self):
        with patch('inspect_apk.sha256_file',side_effect=['a'*64,'b'*64]):
            with self.assertRaisesRegex(APKError,'changed'):inspect(self.apk())
    def test_case_cannot_be_reused_for_other_apk(self):
        one=self.apk();out=self.work/'out';self.assertEqual(self.cli('inspect_apk.py',one,'--out',out).returncode,0)
        old=(out/'inventory.json').read_bytes();two=self.apk('other.apk',MANIFEST.replace(b'1.2',b'1.3'));r=self.cli('inspect_apk.py',two,'--out',out)
        self.assertEqual(r.returncode,2);self.assertEqual((out/'inventory.json').read_bytes(),old)
    def test_output_cannot_overwrite_input(self):
        apk=self.apk('summary.md');before=apk.read_bytes();r=self.cli('inspect_apk.py',apk,'--out',self.work)
        self.assertEqual(r.returncode,2);self.assertEqual(apk.read_bytes(),before)
    def test_unowned_summary_is_preserved(self):
        apk=self.apk();out=self.work/'out';out.mkdir();(out/'summary.md').write_text('user note');r=self.cli('inspect_apk.py',apk,'--out',out)
        self.assertEqual(r.returncode,2);self.assertEqual((out/'summary.md').read_text(),'user note')
    def test_fixed_flutter_extraction_only(self):
        payload=b'\x7fELF'+bytes(60);apk=self.apk(extra={'lib/arm64-v8a/libapp.so':payload,'lib/arm64-v8a/libflutter.so':payload+b'engine','assets/unrelated.txt':b'leave untouched'})
        out=self.work/'libs';r=self.cli('extract_flutter.py',apk,'--abi','arm64-v8a','--out',out)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual({p.name for p in (out/'arm64-v8a').iterdir()},{'libapp.so','libflutter.so','extraction.json'});self.assertEqual((out/'arm64-v8a/libapp.so').read_bytes(),payload)
    def test_extraction_does_not_overwrite_different_library(self):
        payload=b'\x7fELF'+bytes(60);apk=self.apk(extra={'lib/arm64-v8a/libapp.so':payload,'lib/arm64-v8a/libflutter.so':payload});out=self.work/'libs';folder=out/'arm64-v8a';folder.mkdir(parents=True);(folder/'libapp.so').write_bytes(b'original')
        self.assertNotEqual(self.cli('extract_flutter.py',apk,'--abi','arm64-v8a','--out',out).returncode,0);self.assertEqual((folder/'libapp.so').read_bytes(),b'original');self.assertFalse((folder/'libflutter.so').exists())
    def test_missing_pair_causes_no_partial_library_write(self):
        apk=self.apk(extra={'lib/arm64-v8a/libapp.so':b'\x7fELF'+bytes(60)});out=self.work/'libs'
        self.assertNotEqual(self.cli('extract_flutter.py',apk,'--abi','arm64-v8a','--out',out).returncode,0);self.assertFalse((out/'arm64-v8a/libapp.so').exists())
    def test_signature_schemes_keep_minor_versions_distinct(self):
        java=self.work/'java';java.write_bytes(b'trusted-tool-placeholder');build=self.work/'sdk';(build/'lib').mkdir(parents=True);(build/'lib/apksigner.jar').write_bytes(b'jar-placeholder')
        output='Verified using v3 scheme: true\nVerified using v3.1 scheme: false\nSigner #1 certificate SHA-256 digest: '+'a'*64
        with patch('inspect_apk.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=output,stderr='')):
            r=signature(self.apk(),{'java_executable':str(java),'build_tools':str(build)})
        self.assertTrue(r['schemes']['v3']);self.assertFalse(r['schemes']['v3.1']);self.assertEqual(r['status'],'verified')

if __name__=='__main__':unittest.main()
