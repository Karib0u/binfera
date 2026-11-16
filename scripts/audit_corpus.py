#!/usr/bin/env python3
"""Read-only corpus inventory. Never loads or executes sample code.

Archive payloads are streamed to a bounded prefix and discarded. Classification
is structural header evidence, not a promise that a complete file is valid.
"""
import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import threading
import zipfile

LIMIT = 65536
ELF_MACHINE = {2:'SPARC',3:'x86',4:'m68k',8:'MIPS',20:'PowerPC',21:'PowerPC64',22:'s390',40:'ARM32',42:'SuperH',43:'SPARC64',62:'x64',83:'AVR',92:'OpenRISC',93:'ARC',94:'Xtensa',113:'Nios2',183:'AArch64',189:'MicroBlaze',191:'TILE-Gx',195:'ARCv2',243:'RISC-V',247:'BPF',258:'LoongArch'}
PE_MACHINE = {0x14c:'x86',0x8664:'x64',0xaa64:'AArch64',0x1c0:'ARM32',0x1c2:'ARM-Thumb',0x1c4:'ARM-Thumb2',0x200:'IA64',0xa641:'ARM64EC',0xa64e:'ARM64X'}
MACH_CPU = {7:'x86',0x1000007:'x64',12:'ARM32',0x100000c:'AArch64',18:'PowerPC',0x1000012:'PowerPC64'}

def classify(b):
    out = {'format':'unclassified'}
    def u(offset, fmt): return struct.unpack_from(fmt,b,offset)[0]
    try:
        if b[:4] == b'\x7fELF':
            endian = '<' if b[5] == 1 else '>'
            bits = {1:32,2:64}.get(b[4],0)
            machine = u(18,endian+'H')
            out.update(format='ELF',architecture=ELF_MACHINE.get(machine,f'ELF-machine-{machine}'),bits=bits,endian='little' if endian=='<' else 'big',osabi=b[7],elf_type=u(16,endian+'H'),flags=u(36 if bits==32 else 48,endian+'I'))
        elif b[:2] == b'MZ':
            out['format']='MZ-unvalidated'
            pe=u(0x3c,'<I')
            if b[pe:pe+4]==b'PE\0\0':
                magic=u(pe+24,'<H'); dd=pe+24+(112 if magic==0x20b else 96)
                count_offset=pe+24+(108 if magic==0x20b else 92)
                count=u(count_offset,'<I'); optional_size=u(pe+20,'<H')
                clr=(count>14 and dd+120<=pe+24+optional_size and u(dd+112,'<I')!=0 and u(dd+116,'<I')!=0)
                out.update(format='PE-CLR' if clr else 'PE-native',architecture=PE_MACHINE.get(u(pe+4,'<H'),f'PE-machine-{u(pe+4,"<H")}'),bits=64 if magic==0x20b else 32,endian='little',subsystem=u(pe+24+68,'<H'))
            elif b[pe:pe+2] in [b'NE',b'LE',b'LX']:
                out['format']=b[pe:pe+2].decode()
        elif b[:4] in [b'\xce\xfa\xed\xfe',b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xce',b'\xfe\xed\xfa\xcf']:
            endian='<' if b[0] in (0xce,0xcf) else '>'
            cpu=u(4,endian+'I');sub=u(8,endian+'I')&0xffffff
            out.update(format='Mach-O',architecture='arm64e' if cpu==0x100000c and sub==2 else MACH_CPU.get(cpu,str(cpu)),bits=64 if b[:4] in [b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf'] else 32,endian='little' if endian=='<' else 'big')
        elif b[:4] in [b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf'] and 0<u(4,'>I')<=64:
            count=u(4,'>I');stride=32 if b[3]==0xbf else 20
            if b[3]==0xbe and 45<=u(6,'>H')<=100 and u(8,'>I') not in MACH_CPU:
                out['format']='Java-class'
            else:
                cpus=[u(8+i*stride,'>I') for i in range(count)]
                out.update(format='Mach-O-fat64' if stride==32 else 'Mach-O-fat',architecture=','.join(MACH_CPU.get(c,str(c)) for c in cpus))
        elif b[:4]==b'\xca\xfe\xba\xbe': out['format']='Java-class'
        elif b.startswith(b'dex\n'): out['format']='DEX'
        elif b.startswith(b'\x00asm'): out['format']='WebAssembly'
        elif b[:2] in [b'\x01\xdf',b'\x01\xf7']: out.update(format='XCOFF',architecture='PowerPC' if b[1]==0xdf else 'PowerPC64',endian='big')
        elif b.startswith(b'7z\xbc\xaf\x27\x1c'): out['format']='7z'
        elif b.startswith(b'PK\x03\x04') or b.startswith(b'PK\x05\x06'): out['format']='ZIP'
        elif b.startswith(b'Rar!'): out['format']='RAR'
        elif b.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'): out['format']='OLE-CFB'
        elif b.startswith(b'%PDF'): out['format']='PDF'
        elif b.startswith(b'{\\rtf'): out['format']='RTF'
        elif b.startswith(b'L\0\0\0\x01\x14\x02\0'): out['format']='LNK'
        elif b.startswith(b'\x1f\x8b'): out['format']='gzip'
    except (struct.error,IndexError): out['header_truncated']=True
    return out

def paths(root, vx=False):
    for d,ds,fs in os.walk(root,followlinks=False):
        ds[:]=sorted(x for x in ds if not x.startswith('.') and x not in ['analysis','yara'] and not x.endswith('_images') and not (Path(d)/x).is_symlink())
        for name in sorted(fs):
            p=Path(d)/name; rel=p.relative_to(root)
            if name.startswith('.') or p.is_symlink(): continue
            if vx and 'Samples' not in rel.parts:continue
            if not vx and (len(rel.parts)<2 or p.suffix.lower() in ['.json','.yar']):continue
            yield p

def prefix_archive(p):
    proc=subprocess.Popen(['7zz','x','-so','-pinfected','-bd','-y','--',str(p)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    timed_out=threading.Event()
    def kill():
        timed_out.set()
        try:proc.kill()
        except ProcessLookupError:pass
    timer=threading.Timer(15,kill);timer.start()
    try:
        b=proc.stdout.read(LIMIT)
        bounded=len(b)==LIMIT
        if bounded and proc.poll() is None:proc.kill()
        rc=proc.wait(timeout=5)
        return b,{'archive_status':'timeout' if timed_out.is_set() else 'prefix-limit' if bounded else 'complete-stream' if rc==0 else 'read-error','archive_returncode':rc}
    finally:
        timer.cancel()
        if proc.poll() is None:proc.kill();proc.wait()
        proc.stdout.close()

def inspect(item):
    source,root,p,prior=item
    row={'source':source,'path':str(p.relative_to(root)),'bytes':p.stat().st_size}
    try:
        with p.open('rb') as f:b=f.read(LIMIT)
        outer=classify(b);row['outer_format']=outer['format']
        if prior:
            row['prior_label']=prior.get('inner_magika_label') or prior.get('magika_label')
            row['prior_size_matches']=row['bytes']==int(prior['size_bytes'])
        if source=='vx' and outer['format']=='7z':
            b,status=prefix_archive(p);row.update(status)
        row.update(classify(b));row['prefix_bytes']=len(b);row['prefix_sha256']=hashlib.sha256(b).hexdigest()
        if row['format']=='ZIP' and source=='malpedia':
            try:
                with zipfile.ZipFile(p) as z:
                    names=z.namelist()
                    if 'AndroidManifest.xml' in names: row['format']='APK'
                    elif any(n.endswith('.class') for n in names):row['format']='JAR'
                    row['zip_members']=len(names)
            except (zipfile.BadZipFile,OSError):pass
        if row['format']=='unclassified' or row['format'] in ['ZIP','OLE-CFB','MZ-unvalidated']:
            r=subprocess.run(['file','-b','-'],input=b,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
            row['file_description']=r.stdout.decode(errors='replace').strip()
        if source=='malpedia':row['family']=p.relative_to(root).parts[0]
    except Exception as e:row['error']=str(e)
    return row

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--malpedia',type=Path,required=True);ap.add_argument('--vx',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--jobs',type=int,default=8);args=ap.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    import csv
    prior_path=args.vx/'analysis/sample_manifest.csv'
    with prior_path.open() as f:prior={r['path']:r for r in csv.DictReader(f)}
    totals={};old=set(prior);new=[];seen=set();families=[]
    for source,root in [('malpedia',args.malpedia),('vx',args.vx)]:
        files=list(paths(root,source=='vx'));print(source,len(files),flush=True)
        rows=[]
        with (args.output/f'{source}-inventory.jsonl').open('w') as out, concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            items=((source,root,p,prior.get(str(p.relative_to(root))) if source=='vx' else None) for p in files)
            for i,row in enumerate(pool.map(inspect,items),1):
                out.write(json.dumps(row,ensure_ascii=True)+'\n');rows.append(row)
                if source=='vx':
                    seen.add(row['path'])
                    if row['path'] not in old:new.append(row['path'])
                if i%2000==0:out.flush();print(source,i,flush=True)
        totals[source]={'files':len(rows),'bytes':sum(r['bytes'] for r in rows),'formats':dict(collections.Counter(r.get('format','error') for r in rows)),'architectures':dict(collections.Counter(f"{r['format']}/{r.get('architecture','unknown')}/{r.get('endian','unknown')}" for r in rows if 'architecture' in r)),'archive_status':dict(collections.Counter(r['archive_status'] for r in rows if 'archive_status' in r)),'errors':sum('error' in r for r in rows)}
    totals['vx_prior_manifest']={'rows':len(old),'current_new_paths':len(new),'prior_paths_missing':len(old-seen),'new_paths':new,'missing_paths':sorted(old-seen),'sha256':hashlib.sha256(prior_path.read_bytes()).hexdigest()}
    for p in sorted(args.malpedia.glob('*/*.json')):
        try:
            data=json.loads(p.read_text());families.append({'family':p.parent.name,'description':data.get('description',''),'notes':data.get('notes',[])})
        except (ValueError,OSError):continue
    totals['malpedia_family_prefixes']=dict(collections.Counter(r['family'].split('.')[0] for r in families))
    (args.output/'summary.json').write_text(json.dumps(totals,indent=2,ensure_ascii=True)+'\n')
    print(json.dumps({k:v for k,v in totals.items() if k!='vx_prior_manifest'},indent=2),flush=True)

if __name__=='__main__':main()
