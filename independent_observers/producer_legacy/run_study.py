"""Paired fresh runs of ordinary assertions and the contract-aware executor.

The plan and all producer source hashes are frozen before formal execution.
Pilot output is separate. There is no access to prior verdict tables, cohort
expected pairs, or the other arm's observations during either classification.
"""
from __future__ import annotations
import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time
from direct_oracle import judge

HERE=Path(__file__).resolve().parent
COHORTS=('clean-removal','skipped-removal','accepted-after-removal','restored-during-extraction')
CARRIERS=('string','symbol','section')
PRODUCER_FILES=('independent_observer.py','target_adapter.py','direct_oracle.py','reference_arm.py','run_study.py')


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,data):Path(path).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
def category(row):
    pair=(row['transform_verdict'],row['extraction_verdict'])
    if pair==('SATISFIED','SATISFIED'):return 'both-clauses-satisfied'
    if pair==('INCONSISTENT','INADMISSIBLE'):return 'transformation-postcondition-violated'
    if pair==('SATISFIED','INCONSISTENT'):return 'extraction-clause-violated'
    if pair==('SATISFIED','INADMISSIBLE') and row['extraction_reason'] in (
        'target-changed-during-extraction','followup_unchanged_during_extraction'):
        return 'observed-target-changed'
    return 'other-inadmissible-observation'


def source_manifest(artifact):
    files=[]
    for name in PRODUCER_FILES:
        path=HERE/name;files.append({'root':'prototype','path':path.name,'sha256':digest(path)})
    for folder in ('src','hosts','specs'):
        for path in sorted((artifact/folder).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc':
                files.append({'root':'artifact','path':path.relative_to(artifact).as_posix(),'sha256':digest(path)})
    return files


def execute(task):
    artifact,output,pass_name,host,carrier,cohort,reverse=task
    artifact=Path(artifact);case=Path(output)/pass_name/Path(host).stem/carrier/cohort
    direct=case/'direct';reference=case/'reference'
    direct.mkdir(parents=True);reference.mkdir(parents=True)
    target=[sys.executable,'-B',str(HERE/'target_adapter.py'),'--artifact',str(artifact),
      '--cohort',cohort,'--carrier',carrier,'--workspace',str(direct/'target')]
    ref=[sys.executable,'-B',str(HERE/'reference_arm.py'),'--artifact',str(artifact),
      '--cohort',cohort,'--carrier',carrier,'--workspace',str(reference),'--host',str(artifact/'hosts'/host)]
    write(case/'invocation.json',{'direct_target_command':target,'reference_arm_command':ref})
    values={};elapsed={}
    for arm in (('reference','direct') if reverse else ('direct','reference')):
        started=time.perf_counter_ns()
        if arm=='direct':value=judge(target,direct,artifact/'hosts'/host,carrier,b'Morph-01','key-alpha')
        else:
            result=subprocess.run(ref,capture_output=True,text=True,timeout=120)
            (reference/'arm-stdout.txt').write_text(result.stdout);(reference/'arm-stderr.txt').write_text(result.stderr)
            if result.returncode:raise RuntimeError('reference arm failed: '+result.stderr)
            value=json.loads(result.stdout)
        elapsed[arm]=time.perf_counter_ns()-started;values[arm]=value
        write(case/(arm+'.json'),value)
    a=values['direct'];b=values['reference']
    identical={}
    for role in ('source','postcondition','after-extraction'):
        ap=direct/'observations'/(role+'.bin');bp=reference/'observations'/(role+'.bin')
        identical[role]=((not ap.exists() and not bp.exists()) or
                         (ap.exists() and bp.exists() and ap.read_bytes()==bp.read_bytes()))
    commands={}
    for arm,path in [('direct',direct/'target/commands.jsonl'),('reference',reference/'commands.jsonl')]:
        rows=[json.loads(x) for x in path.read_text().splitlines()]
        commands[arm]=dict(Counter(Path(r['argv'][0]).name for r in rows))
    row={'host':host,'carrier':carrier,'cohort':cohort,'arm_order':['reference','direct'] if reverse else ['direct','reference'],
         'direct_pair':[a['transform_verdict'],a['extraction_verdict']],
         'reference_pair':[b['transform_verdict'],b['extraction_verdict']],
         'direct_diagnosis':category(a),'reference_diagnosis':category(b),
         'paired_byte_identity':identical,'direct_observer_cost':a['observer_cost'],
         'commands_by_executable':commands,'coordinator_elapsed_ns':elapsed,
         'direct_record':str((case/'direct.json').relative_to(Path(output))),
         'reference_record':str((case/'reference.json').relative_to(Path(output)))}
    write(case/'comparison.json',row);return row


def summarize(rows):
    groups={}
    for cohort in COHORTS:
        group=[r for r in rows if r['cohort']==cohort]
        groups[cohort]={'cases':len(group),'direct_pairs':dict(Counter('/'.join(r['direct_pair']) for r in group)),
          'reference_pairs':dict(Counter('/'.join(r['reference_pair']) for r in group)),
          'pair_disagreements':sum(r['direct_pair']!=r['reference_pair'] for r in group),
          'diagnostic_disagreements':sum(r['direct_diagnosis']!=r['reference_diagnosis'] for r in group),
          'byte_identity_mismatches':sum(not all(r['paired_byte_identity'].values()) for r in group)}
    return {'cases':len(rows),'cohorts':groups,
      'direct_observer_captures':sum(r['direct_observer_cost']['captures'] for r in rows),
      'direct_observer_parsed_views':sum(r['direct_observer_cost']['parsed_views'] for r in rows),
      'direct_observer_bytes':sum(r['direct_observer_cost']['captured_bytes'] for r in rows),
      'median_coordinator_seconds':{arm:statistics.median(r['coordinator_elapsed_ns'][arm] for r in rows)/1e9
                                   for arm in ('direct','reference')},
      'command_counts':{arm:dict(sum((Counter(r['commands_by_executable'][arm]) for r in rows),Counter()))
                        for arm in ('direct','reference')}}


def main():
    p=argparse.ArgumentParser();p.add_argument('--artifact',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--pilot',action='store_true')
    p.add_argument('--workers',type=int,default=4);args=p.parse_args();artifact=args.artifact.resolve();output=args.out.resolve()
    if output.exists():p.error('output already exists')
    output.mkdir(parents=True)
    hosts=[p.name for p in sorted((artifact/'hosts').glob('H*.c'))]
    if args.pilot:hosts=hosts[:1]
    plan={'protocol':'independent-live-direct-oracle-v1','phase':'pilot' if args.pilot else 'formal',
      'frozen_utc':datetime.now(timezone.utc).isoformat(),'hosts':hosts,'carriers':list(CARRIERS),
      'cohorts':list(COHORTS),'passes':['first'] if args.pilot else ['first','second'],
      'payload_hex':b'Morph-01'.hex(),'key':'key-alpha','compiler':'gcc','optimization':'O2',
      'cases_per_pass':len(hosts)*len(CARRIERS)*len(COHORTS),
      'arm_order':'alternating by case index; reversed in second pass',
      'primary_metrics':['paired stage-verdict agreement','diagnostic agreement','paired artifact-byte identities'],
      'secondary_metrics':['observer capture/parse counts','external command counts','descriptive elapsed time'],
      'scope':'Fresh independent acquisition and ordinary assertions on existing constructed target behaviors. '
        'Both arms receive equal declared source, carrier and endpoint obligations. Neither consumes the other arm facts. '
        'Agreement does not establish comparative detection superiority, independently maintained product validity, '
        'general parser correctness, or atomic snapshot semantics.'}
    write(output/'plan.json',plan);frozen=source_manifest(artifact);write(output/'source-inputs.json',frozen)
    for entry in frozen:
        source=(HERE if entry['root']=='prototype' else artifact)/entry['path']
        saved=output/'source-snapshot'/entry['root']/entry['path'];saved.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,saved)
    env={'python':sys.version,'platform':platform.platform(),'artifact_root_at_execution':str(artifact),'prototype_root_at_execution':str(HERE)}
    env['tools']={name:subprocess.run([name,'--version'],text=True,capture_output=True,check=True).stdout.splitlines()[0]
                  for name in ('gcc','clang','objcopy','nm','strip','readelf')}
    write(output/'environment.json',env)
    write(output/'invocation.json',{'argv':sys.argv,'working_directory':str(Path.cwd()),'workers':args.workers})
    all_rows={}
    for pass_index,pass_name in enumerate(plan['passes']):
        cases=[(h,c,k) for h in hosts for c in CARRIERS for k in COHORTS]
        tasks=[(str(artifact),str(output),pass_name,h,c,k,bool((i+pass_index)%2)) for i,(h,c,k) in enumerate(cases)]
        rows=[]
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            for i,row in enumerate(pool.map(execute,tasks),1):
                rows.append(row)
                if i%36==0 or i==len(tasks):print(pass_name,i,'/',len(tasks),flush=True)
        all_rows[pass_name]=rows;write(output/(pass_name+'.json'),rows)
    repeated=[]
    if 'second' in all_rows:
        fields=('host','carrier','cohort','direct_pair','reference_pair','direct_diagnosis','reference_diagnosis','paired_byte_identity','commands_by_executable')
        repeated=[{'case':i,'field':field} for i,(a,b) in enumerate(zip(all_rows['first'],all_rows['second']))
                  for field in fields if a[field]!=b[field]]
    stable=source_manifest(artifact)==frozen
    summaries={name:summarize(rows) for name,rows in all_rows.items()}
    valid=stable and not repeated and all(not g['pair_disagreements'] and not g['diagnostic_disagreements']
         and not g['byte_identity_mismatches'] for summary in summaries.values() for g in summary['cohorts'].values())
    report={'verdict':'PASS' if valid else 'FAIL','source_inputs_unchanged':stable,'passes':summaries,
       'rerun_non_timing_differences':repeated,'scope':plan['scope'],'finished_utc':datetime.now(timezone.utc).isoformat()}
    write(output/'summary.json',report);print(json.dumps(report,indent=2),flush=True)
    return int(not valid)


if __name__=='__main__':raise SystemExit(main())
