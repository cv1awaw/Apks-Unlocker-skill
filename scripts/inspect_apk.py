#!/usr/bin/env python3
"""Offline APK evidence intake. No app/backend execution and no generic patching."""
from pathlib import Path
from collections import Counter
import argparse
import io
import json
import re
import struct
import subprocess
import sys
import zipfile
from apk_common import APKArchive, APKError, MAX_MANIFEST, MAX_LIBRARY, parse_manifest, sha256_file

SKILL=Path(__file__).resolve().parents[1]

def snapshot_candidate(data):
    result={'snapshot_hash_candidate':None,'snapshot_symbol':None,'coverage':'symbol/header metadata only; no source or semantic recovery'}
    try:
        from elftools.elf.elffile import ELFFile
        elf=ELFFile(io.BytesIO(data));symbols=elf.get_section_by_name('.dynsym')
        if symbols is None:return result
        for name in ('_kDartSnapshotData','_kDartVmSnapshotData'):
            found=symbols.get_symbol_by_name(name)
            if not found:continue
            sym=found[0];address=int(sym['st_value']);offset=None
            for seg in elf.iter_segments():
                if seg['p_type']=='PT_LOAD' and int(seg['p_vaddr'])<=address and address+52<=int(seg['p_vaddr'])+int(seg['p_filesz']):offset=int(seg['p_offset'])+address-int(seg['p_vaddr']);break
            result['snapshot_symbol']=name
            if offset is not None and offset+52<=len(data):
                raw=data[offset+20:offset+52]
                if re.fullmatch(rb'[0-9a-fA-F]{32}',raw):result['snapshot_hash_candidate']=raw.decode('ascii')
            break
    except ImportError:result['limit']='pyelftools unavailable'
    except Exception as e:result['limit']=type(e).__name__+': '+str(e)[:180]
    return result

def signature(apk,config):
    result={'status':'unavailable','certificate_sha256':[]}
    java=config.get('java_executable');bt=config.get('build_tools');jar=Path(bt)/'lib/apksigner.jar' if bt else None
    if not java or jar is None or not Path(java).is_file() or not jar.is_file():return result
    try:
        p=subprocess.run([java,'-jar',str(jar),'verify','--verbose','--print-certs',str(apk)],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
        body=p.stdout+'\n'+p.stderr
        result['status']='verified' if p.returncode==0 else 'invalid_or_verifier_rejected'
        result['certificate_sha256']=re.findall(r'certificate SHA-256 digest:\s*([0-9a-fA-F]{64})',body)
        result['schemes']={m[0]:m[1]=='true' for m in re.findall(r'Verified using (v\d+(?:\.\d+)?)[^\n]*:\s*(true|false)',body)}
        if p.returncode:result['diagnostic']='Verifier rejected this package; inspect local verifier output in a focused follow-up.'
    except (OSError,subprocess.TimeoutExpired) as e:result['diagnostic']=type(e).__name__
    return result

def inspect(apk,verify=False,config=None):
    apk=Path(apk).resolve();report={'input':str(apk),'bytes':apk.stat().st_size,'sha256':None,'analysis_mode':'offline static metadata','manifest':None,'dex':[],'native_libraries':[],'framework_markers':{},'warnings':[],'not_performed':['app execution','network/backend requests','credential discovery','code modifications','source recovery','visual/runtime verification']}
    with APKArchive(apk) as z:
        report['sha256']=sha256_file(apk)
        infos=z.infos();names={i.filename for i in infos};report['entries']=len(infos)
        try:report['manifest']=parse_manifest(z.read('AndroidManifest.xml',MAX_MANIFEST))
        except (KeyError,APKError,ValueError,struct.error,UnicodeError) as e:report['warnings'].append('Manifest: '+type(e).__name__+': '+str(e)[:180])
        for info in infos:
            name=info.filename
            if re.fullmatch(r'classes\d*\.dex',name):
                row={'entry':name,'bytes':info.file_size,'recognized_header':False}
                try:
                    with z.z.open(info) as f:header=f.read(112)
                    if len(header)>=112 and re.fullmatch(rb'dex\n[0-9]{3}\x00',header[:8]):
                        if struct.unpack_from('<I',header,40)[0]!=0x12345678:raise APKError('Unsupported DEX endianness')
                        row.update(recognized_header=True,version=header[4:7].decode('ascii'),declared_bytes=struct.unpack_from('<I',header,32)[0],string_count=struct.unpack_from('<I',header,56)[0],method_count=struct.unpack_from('<I',header,88)[0],class_count=struct.unpack_from('<I',header,96)[0])
                except Exception as e:row['limit']=type(e).__name__
                report['dex'].append(row)
            if re.fullmatch(r'lib/[^/]+/[^/]+\.so',name):
                abi=name.split('/')[1];row={'entry':name,'abi':abi,'bytes':info.file_size}
                if name.endswith(('/libapp.so','/libflutter.so')):
                    try:row['sha256']=z.hash(name)
                    except Exception as e:row['limit']=type(e).__name__+': '+str(e)[:180]
                report['native_libraries'].append(row)
        aot=[i for i in report['native_libraries'] if i['entry'].endswith('/libapp.so')]
        markers={'flutter_assets':any(n.startswith('assets/flutter_assets/') for n in names),'dart_aot_abis':sorted({i['abi'] for i in aot}),'react_native_bundle':'assets/index.android.bundle' in names,'hermes_library':any(n.endswith('/libhermes.so') for n in names),'unity_il2cpp':any(n.endswith('/libil2cpp.so') for n in names)}
        report['framework_markers']=markers
        report['classification']='Flutter AOT markers'+(' + Android DEX entries' if report['dex'] else '') if aot else 'React Native markers' if markers['react_native_bundle'] or markers['hermes_library'] else 'Unity/IL2CPP markers' if markers['unity_il2cpp'] else 'Android DEX entry markers; source language unproven' if report['dex'] else 'Native/split/unknown'
        report['abis']=sorted({i['abi'] for i in report['native_libraries']})
        assets=[i for i in infos if i.filename.startswith('assets/') and not i.is_dir()]
        report['asset_inventory']={'files':len(assets),'extensions':dict(Counter(Path(i.filename).suffix.lower() or '[none]' for i in assets))}
        preferred=next((i for i in aot if i['abi']=='arm64-v8a'),None)
        if preferred:
            abi=preferred['abi'];detail={'abi':abi,'library':preferred['entry']}
            try:detail.update(snapshot_candidate(z.read(preferred['entry'],MAX_LIBRARY)))
            except Exception as e:detail['limit']=type(e).__name__+': '+str(e)[:180]
            engine='lib/'+abi+'/libflutter.so';detail['dart_engine_version_candidate']=None
            if engine in names:
                try:
                    data=z.read(engine,MAX_LIBRARY);m=re.search(rb'Dart VM version:\s*([0-9]+\.[0-9]+\.[0-9]+[^\x00\r\n]{0,100})',data)
                    if m:detail['dart_engine_version_candidate']=m.group(1).decode('ascii',errors='replace')
                except Exception as e:detail['engine_limit']=type(e).__name__
            report['flutter_snapshot']=detail
        elif aot:report['warnings'].append('No arm64-v8a AOT library; installed Blutter route not assumed compatible')
    report['signature']=signature(apk,config or {}) if verify else {'status':'not_requested'}
    if sha256_file(apk)!=report['sha256']:raise APKError('APK changed during inspection')
    return report

def safe_text(value):return str(value).replace('\r','\\r').replace('\n','\\n').replace('|','\\|').replace('`','\\`')[:500]

def markdown(r):
    m=r.get('manifest') or {};f=r.get('flutter_snapshot') or {}
    lines=['# APK static intake','', '| Field | Observed result |','| --- | --- |']
    for key,value in [('APK SHA-256',r['sha256']),('Package',m.get('package')),('Version',str(m.get('version_name'))+' / '+str(m.get('version_code'))),('SDK min / target',str(m.get('min_sdk'))+' / '+str(m.get('target_sdk'))),('Classification',r['classification']),('ABIs',', '.join(r['abis']) or 'none observed'),('Signature',r['signature']['status']),('DEX files',len(r['dex'])),('Native libraries',len(r['native_libraries'])),('Permissions',len(m.get('permissions',[]))),('Snapshot hash candidate',f.get('snapshot_hash_candidate')),('Dart engine version candidate',f.get('dart_engine_version_candidate'))]:lines.append('| '+key+' | '+safe_text(value)+' |')
    lines+=['','## Coverage','Offline container/manifest/header/symbol metadata only. No app execution, backend access, source recovery or feature modification.','', 'Snapshot and version values are candidates; decompilation/runtime support is not established.','', '## Limits']
    lines += ['- '+safe_text(x) for x in r['warnings']] or ['- No intake warnings. This is not a completeness guarantee.']
    lines+=['','## Next question','شنو الميزات المصرّح بتطويرها أو الأخطاء اللي تريد نشتغل عليها؟','']
    return '\n'.join(lines)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('apk',type=Path);p.add_argument('--out',type=Path,required=True);p.add_argument('--verify-signature',action='store_true');p.add_argument('--config',type=Path,default=SKILL/'tools/toolchain.json');args=p.parse_args()
    cfg=json.loads(args.config.read_text(encoding='utf-8')) if args.config.exists() else {}
    try:
        r=inspect(args.apk,args.verify_signature,cfg);out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
        for name in ('inventory.json','summary.md'):
            if (out/name).is_symlink():raise APKError('Output symlink refused')
            if (out/name).resolve()==args.apk.resolve():raise APKError('Output would overwrite the input APK')
        previous=out/'inventory.json'
        if not previous.exists() and (out/'summary.md').exists():raise APKError('Refusing to replace an unrelated summary')
        if previous.exists() and json.loads(previous.read_text(encoding='utf-8')).get('sha256')!=r['sha256']:raise APKError('Output case belongs to a different APK')
        previous.write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');(out/'summary.md').write_text(markdown(r),encoding='utf-8')
        print(json.dumps({'report':str(previous),'summary':str(out/'summary.md'),'classification':r['classification'],'package':(r['manifest'] or {}).get('package'),'signature':r['signature']['status'],'warnings':r['warnings']},ensure_ascii=False,indent=2))
    except (APKError,OSError,ValueError,zipfile.BadZipFile) as e:print('Intake stopped: '+type(e).__name__+': '+str(e),file=sys.stderr);return 2
    return 0

if __name__=='__main__':raise SystemExit(main())
