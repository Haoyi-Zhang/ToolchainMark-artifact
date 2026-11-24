"""Fresh ToolchainMark arm; isolated from the independent direct observer."""
from __future__ import annotations
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
import time
from target_adapter import CommandRecorder,target_class


def main():
    p=argparse.ArgumentParser();p.add_argument('--artifact',type=Path,required=True)
    p.add_argument('--cohort',required=True);p.add_argument('--carrier',required=True)
    p.add_argument('--host',type=Path,required=True);p.add_argument('--workspace',type=Path,required=True)
    args=p.parse_args();args.workspace.mkdir(parents=True,exist_ok=True)
    Target=target_class(args.artifact)
    from toolchainmark.admission import evaluate
    from toolchainmark.integrity import carrier_snapshot
    from toolchainmark.transform_admission import assess_removal_postcondition
    class Observed(Target):
        def __init__(self,*args):
            super().__init__(*args);self.source_snapshot=None;self.followup_snapshot=None;self.current=False
            self.capture_ns=[]
        def remove_carrier(self,result,directory):
            t=time.perf_counter_ns();self.source_snapshot=carrier_snapshot(self.carrier,result.binary,'key-alpha')
            self.capture_ns.append(time.perf_counter_ns()-t)
            path=super().remove_carrier(result,directory)
            t=time.perf_counter_ns();self.followup_snapshot=carrier_snapshot(self.carrier,path,'key-alpha')
            self.capture_ns.append(time.perf_counter_ns()-t)
            self.current=path.read_bytes()==self.followup_snapshot.artifact_bytes
            return path
    target=Observed(args.carrier,args.cohort)
    started=time.perf_counter_ns()
    with CommandRecorder(args.workspace/'commands.jsonl') as recorder:
        recorder.phase='reference-evaluation'
        extraction=evaluate('MR09',target,args.host,args.workspace/'case')
        transform=assess_removal_postcondition(args.carrier,target.source_snapshot,target.followup_snapshot,
            b'Morph-01',removal_requested=True,transformation_completed=target.completed,
            postcondition_snapshot_current=target.current)
    snapshots={};destination=args.workspace/'observations';destination.mkdir()
    import hashlib
    for role,raw in [('source',target.original_bytes),('postcondition',target.followup_bytes),('after-extraction',target.after_bytes)]:
        if raw is None:continue
        path=destination/(role+'.bin');path.write_bytes(raw)
        snapshots[role]={'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    result={'transform_verdict':transform.verdict,'extraction_verdict':extraction.verdict,
       'transform_reason':transform.reason,'extraction_reason':extraction.reason,
       'transform_record':asdict(transform),'extraction_record':asdict(extraction),
       'snapshots':snapshots,'tr01_capture_ns':target.capture_ns,
       'arm_elapsed_ns':time.perf_counter_ns()-started,'tested_followup_calls':target.followup_calls}
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
