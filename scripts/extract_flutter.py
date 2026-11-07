#!/usr/bin/env python3
"""Copy only the selected Flutter library pair; never execute it or extract all entries."""
from pathlib import Path
import argparse
import hashlib
import json
from apk_common import APKArchive, APKError, MAX_LIBRARY, sha256_file

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('apk',type=Path);p.add_argument('--abi',choices=['arm64-v8a','armeabi-v7a','x86_64','x86'],required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    target=a.out.resolve()/a.abi
    if target.is_symlink():raise APKError("ABI output symlink refused")
    target.mkdir(parents=True,exist_ok=True)
    manifest=target/"extraction.json"
    if manifest.is_symlink() or manifest.resolve()==a.apk.resolve():raise APKError("Unsafe extraction report destination")
    record={'apk_sha256':None,'abi':a.abi,'libraries':[]}
    with APKArchive(a.apk) as z:
        record['apk_sha256']=sha256_file(a.apk)
        if manifest.exists() and json.loads(manifest.read_text(encoding='utf-8')).get('apk_sha256')!=record['apk_sha256']:raise APKError('Extraction case belongs to a different input')
        payloads=[]
        for name in ('libapp.so','libflutter.so'):
            entry='lib/'+a.abi+'/'+name;data=z.read(entry,MAX_LIBRARY);dest=target/name;digest=hashlib.sha256(data).hexdigest()
            if not data.startswith(b'\x7fELF'):raise APKError('Selected library is not ELF: '+entry)
            if dest.resolve()==a.apk.resolve():raise APKError('Output would overwrite input APK')
            if dest.is_symlink() or (dest.exists() and sha256_file(dest)!=digest):raise APKError('Refusing to replace a different library: '+str(dest))
            payloads.append((dest,data));record['libraries'].append({'entry':entry,'bytes':len(data),'sha256':digest})
        if sha256_file(a.apk)!=record['apk_sha256']:raise APKError('APK changed during extraction')
        for dest,data in payloads:dest.write_bytes(data)
    manifest=target/'extraction.json'
    if manifest.is_symlink():raise APKError('Output symlink refused')
    manifest.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8');print(manifest)

if __name__=='__main__':main()
