#!/usr/bin/env python3
"""Supplement the structural audit with probabilistic labels for new evidence.

Run with a Python environment containing Magika 0.5.0. Samples remain data.
"""
import argparse
import csv
import json
from pathlib import Path
from magika import Magika
from audit_corpus import LIMIT, paths, prefix_archive, classify

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--malpedia',type=Path,required=True)
    ap.add_argument('--vx',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();model=Magika()
    with (args.vx/'analysis/sample_manifest.csv').open() as f:old={r['path'] for r in csv.DictReader(f)}
    rows=[]
    for source,root in [('malpedia',args.malpedia),('vx',args.vx)]:
        for p in paths(root,source=='vx'):
            rel=str(p.relative_to(root))
            if source=='vx' and rel in old:continue
            with p.open('rb') as f:b=f.read(LIMIT)
            fmt=classify(b)['format']
            if source=='malpedia' and fmt not in ['unclassified','ZIP','OLE-CFB','MZ-unvalidated']:continue
            status={}
            if source=='vx' and fmt=='7z':b,status=prefix_archive(p)
            result=model.identify_bytes(b).output
            rows.append({'source':source,'path':rel,'prefix_bytes':len(b),'label':result.ct_label,'score':result.score,**status})
            if len(rows)%500==0:print(len(rows),flush=True)
    (args.output/'supplementary-labels.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=True)+'\n' for r in rows))
    print('labels',len(rows),flush=True)

if __name__=='__main__':main()
