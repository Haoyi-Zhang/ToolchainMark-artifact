"""Ordinary assertions with independently acquired live byte observations.

No ToolchainMark modules, admission facts, cohort labels, or expected verdicts
are consumed. The target command and its private behavior remain opaque here.
"""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import time
from independent_observer import LiveObserver,identity

DOMAIN_REJECTIONS=frozenset({'absent','wrong-key','checksum','malformed',
                              'version','path','sidecar'})


def domain_observation(response):
    """Unavailable/unknown protocol outcomes are not typed domain rejections."""
    if response.get('status')=='unavailable':return None
    if response.get('status')!='ok':raise ValueError('unknown target response status')
    observation=response.get('observation')
    if not isinstance(observation,dict):raise ValueError('missing typed domain observation')
    kind=observation.get('kind');value=observation.get('value')
    if not isinstance(value,str):raise ValueError('domain observation is not a string value')
    if kind=='payload':
        if bytes.fromhex(value).hex()!=value:raise ValueError('payload is not canonical hexadecimal')
    elif kind=='rejection':
        if value not in DOMAIN_REJECTIONS:raise ValueError('non-domain rejection type')
    else:raise ValueError('unknown domain observation kind')
    return observation


class Endpoint:
    def __init__(self,command,directory):
        self.command=command;self.directory=Path(directory);self.events=[]
    def __enter__(self):
        self.err=(self.directory/'target-stderr.txt').open('w')
        self.process=subprocess.Popen(self.command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                      stderr=self.err,text=True,bufsize=1)
        return self
    def call(self,**request):
        started=time.perf_counter_ns();self.process.stdin.write(json.dumps(request)+'\n');self.process.stdin.flush()
        raw=self.process.stdout.readline()
        if not raw:raise RuntimeError('target protocol closed without a response')
        response=json.loads(raw)
        self.events.append({'request':request,'raw_response':raw,'response':response,
                            'roundtrip_ns':time.perf_counter_ns()-started})
        return response
    def __exit__(self,*_):
        try:self.process.stdin.write('{"op":"stop"}\n');self.process.stdin.flush()
        except (BrokenPipeError,ValueError):pass
        self.process.stdin.close();self.process.wait(timeout=30);self.err.close()
        (self.directory/'protocol.jsonl').write_text(''.join(json.dumps(x,sort_keys=True)+'\n' for x in self.events))


def judge(command,directory,host,carrier,payload,key):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    observer=LiveObserver(directory/'observations',carrier,key)
    expected={'kind':'payload','value':payload.hex()}
    result={'transform_verdict':'INADMISSIBLE','extraction_verdict':'INADMISSIBLE',
            'transform_reason':'source-unestablished','extraction_reason':'source-unestablished'}
    started=time.perf_counter_ns()
    with Endpoint(command,directory) as endpoint:
        try:
            built=endpoint.call(op='build',host=str(host),payload=payload.hex(),key=key,compiler='gcc',optimization='O2')
            if built['status']!='ok':return finish(result,observer,started)
            source,physical_source=observer.capture(built['artifact'],'source',parse=True)
            source_out=endpoint.call(op='extract',artifact=built['artifact'],key=key)
            if physical_source!=expected or domain_observation(source_out)!=expected:
                return finish(result,observer,started)
            transformed=endpoint.call(op='remove')
            if transformed['status']!='ok':
                result.update(transform_reason='transformation-unavailable',extraction_reason='transformation-unavailable')
                return finish(result,observer,started)
            target=transformed['artifact'];captured,physical=observer.capture(target,'postcondition',parse=True)
            current,_=observer.capture(target,'postcondition-current')
            if current!=captured:
                result.update(transform_reason='postcondition-observation-changed',extraction_reason='postcondition-observation-changed')
                return finish(result,observer,started)
            permitted={'absent','wrong-key','checksum','malformed','version'} if carrier=='string' else {'absent'}
            removed=physical['kind']=='rejection' and physical['value'] in permitted
            result.update(transform_verdict='SATISFIED' if removed else 'INCONSISTENT',
                          transform_reason='carrier-removed' if removed else 'carrier-remains',
                          extraction_reason='removal-unestablished')
            if not removed:return finish(result,observer,started)
            before,_=observer.capture(target,'before-extraction')
            if before!=captured:
                result['extraction_reason']='target-changed-before-extraction';return finish(result,observer,started)
            observed=endpoint.call(op='extract',artifact=target,key=key)
            after,_=observer.capture(target,'after-extraction')
            if after!=captured:
                result['extraction_reason']='target-changed-during-extraction';return finish(result,observer,started)
            outcome=domain_observation(observed)
            if outcome is None:
                result['extraction_reason']='extraction-unavailable';return finish(result,observer,started)
            correct=outcome==physical
            result.update(extraction_verdict='SATISFIED' if correct else 'INCONSISTENT',
                          extraction_reason='expected-rejection' if correct else 'unexpected-domain-outcome')
        except (OSError,ValueError,RuntimeError,KeyError,TypeError) as error:
            result['observation_error']={'type':type(error).__name__,'message':str(error)}
            result['extraction_reason']='observation-unavailable'
        return finish(result,observer,started)


def finish(result,observer,started):
    result['observer_events']=observer.events
    result['observer_cost']={'captures':len(observer.events),'parsed_views':sum(x['parse'] for x in observer.events),
      'captured_bytes':sum(x['identity']['bytes'] for x in observer.events),
      'read_ns':sum(x['read_ns'] for x in observer.events),'parse_ns':sum(x['parse_ns'] for x in observer.events),
      'elf_utility_calls':0}
    result['arm_elapsed_ns']=time.perf_counter_ns()-started
    return result
