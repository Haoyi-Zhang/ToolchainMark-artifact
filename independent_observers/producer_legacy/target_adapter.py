"""Black-box command protocol around the existing controlled target operations.

This file is a target adapter, not either observer or oracle. Cohort identities
remain here. The direct oracle receives only operation responses and file paths.
"""
from __future__ import annotations
import argparse
import base64
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys
import time


class CommandRecorder:
    def __init__(self,path):self.path=Path(path);self.original=subprocess.run;self.phase='target'
    def __enter__(self):
        def run(command,*args,**kwargs):
            started=time.perf_counter_ns()
            try:
                result=self.original(command,*args,**kwargs)
                row={'phase':self.phase,'argv':list(command),'returncode':result.returncode,
                     'stdout':self.content(result.stdout),'stderr':self.content(result.stderr)}
            except BaseException as error:
                row={'phase':self.phase,'argv':list(command),'exception':type(error).__name__,'message':str(error)}
                row['elapsed_ns']=time.perf_counter_ns()-started;self.append(row);raise
            row['elapsed_ns']=time.perf_counter_ns()-started;self.append(row);return result
        subprocess.run=run;return self
    def __exit__(self,*_):subprocess.run=self.original
    def append(self,row):
        with self.path.open('a') as handle:handle.write(json.dumps(row,sort_keys=True)+'\n')
    @staticmethod
    def content(value):
        if isinstance(value,bytes):return {'encoding':'base64','value':base64.b64encode(value).decode('ascii')}
        return {'encoding':'text','value':value}


def target_class(artifact):
    sys.path.insert(0,str(Path(artifact)/'src'))
    from toolchainmark.pipeline import Pipeline
    class ControlledTarget(Pipeline):
        def __init__(self,carrier,cohort):
            super().__init__(carrier,{'clean-removal':'CLEAN','skipped-removal':'M15',
              'accepted-after-removal':'M09','restored-during-extraction':'CLEAN'}[cohort])
            self.cohort=cohort;self.original_bytes=None;self.followup_path=None
            self.followup_bytes=None;self.after_bytes=None;self.completed=False;self.followup_calls=0
        def remove_carrier(self,result,directory):
            self.original_bytes=result.binary.read_bytes()
            target=super().remove_carrier(result,directory)
            self.followup_path=target;self.followup_bytes=target.read_bytes();self.completed=True
            return target
        def extract(self,binary,key):
            if binary==self.followup_path:
                self.followup_calls+=1
                if self.cohort=='restored-during-extraction':binary.write_bytes(self.original_bytes)
            try:return super().extract(binary,key)
            finally:
                if binary==self.followup_path:self.after_bytes=binary.read_bytes()
    return ControlledTarget


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--artifact',type=Path,required=True)
    parser.add_argument('--cohort',required=True);parser.add_argument('--carrier',required=True)
    parser.add_argument('--workspace',type=Path,required=True);args=parser.parse_args()
    args.workspace.mkdir(parents=True,exist_ok=True)
    Target=target_class(args.artifact)
    from toolchainmark.model import BuildRequest,ExtractionError
    pipeline=Target(args.carrier,args.cohort);built=None
    with CommandRecorder(args.workspace/'commands.jsonl') as recorder:
        for line in sys.stdin:
            request=json.loads(line);op=request['op'];recorder.phase=op
            started=time.perf_counter_ns()
            try:
                if op=='build':
                    built=pipeline.build(BuildRequest(host=Path(request['host']),payload=bytes.fromhex(request['payload']),
                        key=request['key'],compiler=request['compiler'],optimization=request['optimization'],
                        work_dir=args.workspace/'source',guard_upstream=True))
                    response={'status':'ok','artifact':str(built.binary),'generated_source':str(built.source),
                              'requested':[built.requested_compiler,built.requested_optimization],
                              'actual':[built.actual_compiler,built.actual_optimization]}
                elif op=='remove':
                    path=pipeline.remove_carrier(built,args.workspace/'followup')
                    response={'status':'ok','artifact':str(path)}
                elif op=='extract':
                    try:
                        payload=pipeline.extract(Path(request['artifact']),request['key'])
                        observation={'kind':'payload','value':payload.hex()}
                    except ExtractionError as error:observation={'kind':'rejection','value':error.kind}
                    response={'status':'ok','observation':observation}
                elif op=='stop':break
                else:raise ValueError('unknown target operation')
            except Exception as error:
                response={'status':'unavailable','exception':type(error).__name__,'message':str(error)}
            response['target_ns']=time.perf_counter_ns()-started
            print(json.dumps(response,sort_keys=True),flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
