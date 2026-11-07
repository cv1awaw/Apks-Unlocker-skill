#!/usr/bin/env python3
"""Check configured dependencies only; never install, crawl projects or execute APKs."""
from pathlib import Path
import argparse
import importlib.metadata
import json
import subprocess
import sys

SKILL=Path(__file__).resolve().parents[1]

def probe(args,timeout=25):
    try:
        p=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
        return {'ok':p.returncode==0,'exit_code':p.returncode,'output':(p.stdout+'\n'+p.stderr).strip()[:1600]}
    except (OSError,subprocess.TimeoutExpired) as e:return {'ok':False,'error':type(e).__name__}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--probe',action='store_true');p.add_argument('--out',type=Path);a=p.parse_args();config=SKILL/'tools/toolchain.json';cfg=json.loads(config.read_text(encoding='utf-8')) if config.exists() else {}
    r={'python':sys.executable,'packages':{},'paths':{},'probes':{},'no_apk_or_network_operations':True}
    for name in ('pyelftools','PyYAML'):
        try:r['packages'][name]=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:r['packages'][name]='missing'
    for key in ('java_executable','android_jar','apktool_jar','jadx_jar','wsl_executable'):r['paths'][key]={'path':cfg.get(key),'exists':bool(cfg.get(key)) and Path(cfg[key]).is_file()}
    bt=Path(cfg['build_tools']) if cfg.get('build_tools') else None
    for name in ('aapt.exe','aapt2.exe','lib/apksigner.jar','lib/d8.jar'):r['paths'][name]={'path':str(bt/name) if bt else None,'exists':bool(bt) and (bt/name).is_file()}
    if a.probe:
        java=cfg.get('java_executable')
        if java:
            r['probes']['java']=probe([java,'-version'])
            if cfg.get('apktool_jar'):r['probes']['apktool']=probe([java,'-jar',cfg['apktool_jar'],'--version'])
            if cfg.get('jadx_jar'):r['probes']['jadx']=probe([java,'-cp',str(Path(cfg['jadx_jar']).parent/'*'),'jadx.cli.JadxCLI','--version'])
            if bt:r['probes']['apksigner']=probe([java,'-jar',str(bt/'lib/apksigner.jar'),'version'])
        if cfg.get('wsl_executable') and cfg.get('blutter_root') and cfg.get('wsl_distribution'):
            r['probes']['blutter_script']=probe([cfg['wsl_executable'],'-d',cfg['wsl_distribution'],'--','test','-f',cfg['blutter_root']+'/blutter.py'])
            r['probes']['blutter_cache']={v:probe([cfg['wsl_executable'],'-d',cfg['wsl_distribution'],'--','test','-x',cfg['blutter_root']+'/bin/blutter_dartvm'+v+'_android_arm64']) for v in cfg.get('blutter_cached_dart_versions',[])}
    text=json.dumps(r,ensure_ascii=False,indent=2)+'\n'
    if a.out:
        if a.out.is_symlink():raise ValueError('Output symlink refused')
        if a.out.exists() and json.loads(a.out.read_text(encoding='utf-8')).get('no_apk_or_network_operations') is not True:raise ValueError('Refusing to overwrite an unrelated file')
        a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(text,encoding='utf-8')
    print(text)

if __name__=='__main__':main()
