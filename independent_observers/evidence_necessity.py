"""Finite ambiguity witnesses for the explicitly declared fact vocabulary.

This enumerates an abstract observation domain, not native test executions.
Minimality is relative to these five named predicates; different sufficient
statistics, direct byte observations, or stronger contracts can change it.
"""
from itertools import product,combinations
import json

FACTS=('source_valid','operation_and_observation_completed','carrier_removed',
       'endpoint_coherent','expected_rejection')


def contract_verdict(bits):
    source,completed,removed,coherent,rejected=bits
    transform=('SATISFIED' if removed else 'INCONSISTENT') if source and completed else 'INADMISSIBLE'
    extraction=('SATISFIED' if rejected else 'INCONSISTENT') if source and completed and removed and coherent else 'INADMISSIBLE'
    return transform,extraction


def ordinary_assertions(bits):
    source,completed,removed,coherent,rejected=bits
    if not source or not completed:return 'INADMISSIBLE','INADMISSIBLE'
    if not removed:return 'INCONSISTENT','INADMISSIBLE'
    if not coherent:return 'SATISFIED','INADMISSIBLE'
    if rejected:return 'SATISFIED','SATISFIED'
    return 'SATISFIED','INCONSISTENT'


def main():
    traces=list(product((False,True),repeat=len(FACTS)))
    witnesses={}
    for omitted,name in enumerate(FACTS):
        remaining=tuple(i for i in range(len(FACTS)) if i!=omitted)
        for a in traces:
            b=tuple(not value if i==omitted else value for i,value in enumerate(a))
            if contract_verdict(a)!=contract_verdict(b):
                witnesses[name]={'shared_projection':{FACTS[i]:a[i] for i in remaining},
                                 'left':dict(zip(FACTS,a)),'left_pair':contract_verdict(a),
                                 'right':dict(zip(FACTS,b)),'right_pair':contract_verdict(b)}
                break
    sufficient=[]
    for count in range(len(FACTS)+1):
        for indices in combinations(range(len(FACTS)),count):
            mapping={};valid=True
            for trace in traces:
                key=tuple(trace[i] for i in indices);value=contract_verdict(trace)
                if key in mapping and mapping[key]!=value:valid=False;break
                mapping[key]=value
            if valid:sufficient.append([FACTS[i] for i in indices])
    result={'abstract_valuations':len(traces),'ordinary_assertion_disagreements':
            sum(contract_verdict(t)!=ordinary_assertions(t) for t in traces),
            'omission_witnesses':witnesses,'sufficient_named_fact_subsets':sufficient,
            'scope':'Finite mathematical witness generation, not empirical/native execution. '
              'The five facts are a chosen semantic vocabulary, not a universal lower bound on raw fields, '
              'bits, observer calls, or alternative sufficient statistics.'}
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
