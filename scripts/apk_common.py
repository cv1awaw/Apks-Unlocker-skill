"""Bounded, read-only container and manifest primitives. Never execute APK contents."""
from collections import Counter
from pathlib import Path, PurePosixPath
import hashlib
import struct
import zipfile
import xml.etree.ElementTree as ET

MAX_APK=1024*1024*1024
MAX_MANIFEST=4*1024*1024
MAX_LIBRARY=128*1024*1024
ANDROID='http://schemas.android.com/apk/res/android'

class APKError(ValueError):pass

def sha256_file(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

class APKArchive:
    def __init__(self,path):
        self.path=Path(path).resolve();self.z=None
    def __enter__(self):
        size=self.path.stat().st_size
        if size>MAX_APK:raise APKError('APK exceeds the 1 GiB intake budget')
        with self.path.open('rb') as f:
            f.seek(max(0,size-65557));tail=f.read()
        at=tail.rfind(b'PK\x05\x06')
        if at<0 or at+22>len(tail):raise APKError('ZIP end record missing')
        values=struct.unpack_from('<4s4H2LH',tail,at)
        if at+22+values[7]!=len(tail):raise APKError('Ambiguous ZIP end record')
        if values[1] or values[2] or values[3]!=values[4]:raise APKError('Multi-disk ZIP unsupported')
        if values[4]==65535 or values[5]==0xffffffff:raise APKError('ZIP64 requires a separately budgeted inspection')
        if values[5]>32*1024*1024 or values[6]+values[5]>size:raise APKError('Central directory budget/bounds invalid')
        self.z=zipfile.ZipFile(self.path)
        try:
            infos=self.z.infolist()
            if len(infos)!=values[4]:raise APKError('ZIP entry-count mismatch')
            duplicates=[n for n,c in Counter(i.filename for i in infos).items() if c>1]
            if duplicates:raise APKError('Duplicate ZIP entries; package interpretation is ambiguous')
            for i in infos:
                n=i.filename
                if n.startswith(('/','\\')) or '\\' in n or ':' in n or '..' in PurePosixPath(n).parts:
                    raise APKError('Unsafe ZIP entry path; no entries were extracted')
            return self
        except Exception:
            self.z.close();raise
    def __exit__(self,*args):
        if self.z:self.z.close()
    def infos(self):return self.z.infolist()
    def read(self,name,limit):
        info=self.z.getinfo(name)
        if info.flag_bits&1:raise APKError('Encrypted entry unsupported: '+name)
        if info.file_size>limit:raise APKError('Entry exceeds read budget: '+name)
        if info.file_size>1024*1024 and info.file_size/max(1,info.compress_size)>1000:raise APKError('Entry expansion ratio exceeds budget')
        with self.z.open(info) as f:data=f.read(limit+1)
        if len(data)>limit or len(data)!=info.file_size:raise APKError('Entry length/budget mismatch')
        return data
    def hash(self,name,limit=MAX_LIBRARY):
        info=self.z.getinfo(name)
        if info.file_size>limit:raise APKError('Library exceeds hash budget: '+name)
        if info.flag_bits&1:raise APKError('Encrypted library unsupported')
        h=hashlib.sha256();total=0
        with self.z.open(info) as f:
            for block in iter(lambda:f.read(1024*1024),b''):
                total+=len(block)
                if total>limit:raise APKError('Expanded library exceeds budget')
                h.update(block)
        if total!=info.file_size:raise APKError('Library length mismatch')
        return h.hexdigest()

def _length(data,pos,wide):
    width=2 if wide else 1
    if pos+width>len(data):raise APKError('String length out of bounds')
    value=int.from_bytes(data[pos:pos+width],'little');pos+=width;mask=0x8000 if wide else 0x80
    if value&mask:
        if pos+width>len(data):raise APKError('Extended string length out of bounds')
        value=((value&~mask)<<(15 if wide else 8))|int.from_bytes(data[pos:pos+width],'little');pos+=width
    return value,pos

def _strings(chunk):
    if len(chunk)<28:raise APKError('Short string pool')
    _,header,size,count,styles,flags,start,styles_start=struct.unpack_from('<HHIIIIII',chunk)
    if count>100000 or header+4*(count+styles)>len(chunk) or start>len(chunk):raise APKError('Invalid string pool bounds')
    out=[];utf8=bool(flags&0x100)
    for i in range(count):
        offset=struct.unpack_from('<I',chunk,header+4*i)[0];pos=start+offset
        chars,pos=_length(chunk,pos,not utf8)
        if utf8:chars,pos=_length(chunk,pos,False)
        n=chars*(1 if utf8 else 2)
        if pos+n>len(chunk):raise APKError('String payload out of bounds')
        out.append(chunk[pos:pos+n].decode('utf-8' if utf8 else 'utf-16le',errors='strict'))
    return out

def manifest_events(data):
    if len(data)>MAX_MANIFEST:raise APKError('Manifest read budget exceeded')
    if data.lstrip().startswith(b'<'):
        if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():raise APKError('DTD/entity declarations are not supported')
        try:root=ET.fromstring(data)
        except ET.ParseError as e:raise APKError("Malformed plain XML manifest") from e
        for n in root.iter():yield n.tag.rsplit('}',1)[-1],{(k.rsplit('}',1)[-1] if k.startswith('{'+ANDROID+'}') else k):v for k,v in n.attrib.items()}
        return
    if len(data)<8 or struct.unpack_from('<H',data)[0]!=3:raise APKError('Unsupported manifest encoding')
    total=struct.unpack_from('<I',data,4)[0]
    if total!=len(data):raise APKError('Binary XML length mismatch')
    strings=None;pos=8
    while pos<total:
        if pos+8>total:raise APKError('Truncated XML chunk')
        kind,header,size=struct.unpack_from('<HHI',data,pos)
        if size<header or header<8 or size==0 or pos+size>total:raise APKError('Invalid XML chunk bounds')
        chunk=data[pos:pos+size]
        if kind==1:strings=_strings(chunk)
        elif kind==0x102:
            if strings is None or size<36:raise APKError('Element without string pool/header')
            tag=struct.unpack_from('<I',chunk,20)[0]
            start,width,count=struct.unpack_from('<HHH',chunk,24)
            if width<20 or 16+start+width*count>size:raise APKError('Attribute bounds invalid')
            attrs={}
            for i in range(count):
                at=16+start+i*width;name=struct.unpack_from('<I',chunk,at+4)[0];raw=struct.unpack_from('<I',chunk,at+8)[0];typ=chunk[at+15];value=struct.unpack_from('<I',chunk,at+16)[0]
                if name>=len(strings):raise APKError('Invalid attribute-name index')
                if typ==3:
                    if value>=len(strings):raise APKError('Invalid attribute string index')
                    v=strings[value]
                elif typ==0x12:v=bool(value)
                elif typ in (0x10,0x11):v=value
                elif raw!=0xffffffff:
                    if raw>=len(strings):raise APKError('Invalid raw attribute index')
                    v=strings[raw]
                else:v='@0x%08x'%value
                namespace=struct.unpack_from('<I',chunk,at)[0]
                if namespace!=0xffffffff and namespace>=len(strings):raise APKError('Invalid namespace index')
                key=strings[name] if namespace==0xffffffff or strings[namespace]==ANDROID else '{'+strings[namespace]+'}'+strings[name]
                attrs[key]=v
            if tag>=len(strings):raise APKError('Invalid element index')
            yield strings[tag],attrs
        pos+=size

def parse_manifest(data):
    result={'package':None,'version_code':None,'version_name':None,'min_sdk':None,'target_sdk':None,'split':None,'permissions':[],'components':[]}
    for tag,a in manifest_events(data):
        if tag=='manifest':
            for dst,src in [('package','package'),('version_code','versionCode'),('version_name','versionName'),('split','split')]:result[dst]=a.get(src)
        elif tag=='uses-sdk':result.update(min_sdk=a.get('minSdkVersion'),target_sdk=a.get('targetSdkVersion'))
        elif tag.startswith('uses-permission') and a.get('name'):result['permissions'].append(a['name'])
        elif tag in ('activity','activity-alias','service','receiver','provider'):
            result['components'].append({'kind':tag,'name':a.get('name'),'exported_explicit':a.get('exported'),'permission':a.get('permission')})
    return result
