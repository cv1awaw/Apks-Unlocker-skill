#!/usr/bin/env python3
"""Provision private Python/JAR tools; reuse SDK/JDK/Blutter without changing them."""
from pathlib import Path,PurePosixPath
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
APKTOOL_URL='https://github.com/iBotPeaches/Apktool/releases/download/v2.12.1/apktool_2.12.1.jar'
APKTOOL_SHA='66cf4524a4a45a7f56567d08b2c9b6ec237bcdd78cee69fd4a59c8a0243aeafa'
JADX_URL='https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip'
JADX_ARCHIVE_SHA='545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974'
JADX_JAR_SHA='fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b'

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def run(args):subprocess.run([str(x) for x in args],check=True)

def download(url,dest,expected):
    if dest.is_symlink():raise ValueError('Tool destination symlink refused')
    if dest.exists():
        if digest(dest)==expected:return
        raise ValueError('Existing file has a different digest; refusing to overwrite: '+str(dest))
    temp=dest.with_suffix(dest.suffix+'.download')
    if temp.exists():raise ValueError('A prior partial download exists; inspect it before retrying: '+str(temp))
    total=0
    with urllib.request.urlopen(url,timeout=45) as source,temp.open('xb') as out:
        while True:
            block=source.read(1024*1024)
            if not block:break
            total+=len(block)
            if total>160*1024*1024:raise ValueError('Vendor download exceeds budget')
            out.write(block)
    if digest(temp)!=expected:raise ValueError('Vendor digest mismatch; partial file retained for review')
    temp.rename(dest)

def extract_vendor(archive,target):
    if target.is_symlink():raise ValueError('Tool directory symlink refused')
    target.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        infos=z.infolist()
        if sum(i.file_size for i in infos)>300*1024*1024:raise ValueError('Vendor archive exceeds extraction budget')
        planned=[]
        for info in infos:
            name=info.filename;parts=PurePosixPath(name).parts
            if name.startswith(('/','\\')) or '\\' in name or ':' in name or '..' in parts:raise ValueError('Unsafe vendor archive path')
            dest=target.joinpath(*parts)
            if dest.is_symlink() or (dest.resolve()!=target.resolve() and target.resolve() not in dest.resolve().parents):raise ValueError('Vendor extraction escape')
            if not info.is_dir() and dest.exists():
                with z.open(info) as source:expected=hashlib.sha256(source.read()).hexdigest()
                if digest(dest)!=expected:raise ValueError('Existing tool file differs; refusing to overwrite: '+name)
            planned.append((info,dest))
        for info,dest in planned:
            if info.is_dir():dest.mkdir(parents=True,exist_ok=True)
            elif not dest.exists():
                dest.parent.mkdir(parents=True,exist_ok=True)
                with z.open(info) as source,dest.open('xb') as out:shutil.copyfileobj(source,out)

def version_key(p):return tuple(int(x) for x in re.findall(r'\d+',p.name))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download-tools',action='store_true',help='Fetch the two pinned official vendor artifacts')
    parser.add_argument('--skip-python-install',action='store_true',help='Only configure/check tools; use an already provisioned environment')
    parser.add_argument('--sdk',type=Path)
    args=parser.parse_args()
    venv=ROOT/'.venv';python=venv/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
    if venv.is_symlink():raise ValueError('Python environment symlink refused')
    if not python.exists():run([sys.executable,'-m','venv',venv])
    if not args.skip_python_install:run([python,'-m','pip','install','--disable-pip-version-check','-r',ROOT/'requirements.txt'])
    tools=ROOT/'tools'
    if tools.is_symlink():raise ValueError('Tool directory symlink refused')
    tools.mkdir(exist_ok=True)
    apktool=tools/'apktool.jar';jadx=tools/'jadx/lib/jadx-1.5.6-all.jar'
    if args.download_tools:
        download(APKTOOL_URL,apktool,APKTOOL_SHA)
        if not jadx.exists() or digest(jadx)!=JADX_JAR_SHA:
            archive=tools/'jadx-1.5.6.zip';download(JADX_URL,archive,JADX_ARCHIVE_SHA);extract_vendor(archive,tools/'jadx')
        if digest(jadx)!=JADX_JAR_SHA:raise ValueError('Extracted JADX digest mismatch')
    if args.sdk:sdk=args.sdk.resolve()
    elif os.environ.get('ANDROID_HOME'):sdk=Path(os.environ['ANDROID_HOME'])
    elif os.environ.get('ANDROID_SDK_ROOT'):sdk=Path(os.environ['ANDROID_SDK_ROOT'])
    else:sdk=Path.home()/('AppData/Local/Android/Sdk' if os.name=='nt' else 'Library/Android/sdk' if sys.platform=='darwin' else 'Android/Sdk')
    build=sorted((sdk/'build-tools').glob('*'),key=version_key) if (sdk/'build-tools').is_dir() else []
    build=[p for p in build if (p/'lib/apksigner.jar').is_file()]
    platforms=sorted((sdk/'platforms').glob('*/android.jar'),key=lambda p:version_key(p.parent)) if (sdk/'platforms').is_dir() else []
    wsl=shutil.which('wsl') if os.name=='nt' else None
    blutter=False
    if wsl:
        try:blutter=subprocess.run([wsl,'-d','Ubuntu','--','test','-f','/root/blutter/blutter.py'],capture_output=True,timeout=20).returncode==0
        except (OSError,subprocess.TimeoutExpired):pass
    cached=[]
    if blutter:
        for version in ['3.13.2']:
            if subprocess.run([wsl,'-d','Ubuntu','--','test','-x','/root/blutter/bin/blutter_dartvm'+version+'_android_arm64'],capture_output=True,timeout=20).returncode==0:cached.append(version)
    config={'version':'1.0.0','java_executable':shutil.which('java'),'sdk_root':str(sdk) if sdk.is_dir() else None,'build_tools':str(build[-1]) if build else None,'android_jar':str(platforms[-1]) if platforms else None,'apktool_jar':str(apktool) if apktool.exists() else None,'jadx_jar':str(jadx) if jadx.exists() else None,'wsl_executable':wsl,'wsl_distribution':'Ubuntu' if blutter else None,'blutter_root':'/root/blutter' if blutter else None,'blutter_cached_dart_versions':cached,'tool_sources':{'apktool':{'url':APKTOOL_URL,'sha256':APKTOOL_SHA},'jadx':{'url':JADX_URL,'archive_sha256':JADX_ARCHIVE_SHA,'jar_sha256':JADX_JAR_SHA}}}
    dest=tools/'toolchain.json'
    if dest.is_symlink():raise ValueError('Configuration symlink refused')
    dest.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
    print('Ready. No global PATH, SDK, signing key, account or Codex settings were modified.')
    print('Check readiness with:',python,ROOT/'scripts/check_tools.py','--probe')

if __name__=='__main__':main()
