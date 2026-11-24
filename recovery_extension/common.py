"""SR01 plan identities and source boundaries."""
import json
from pathlib import Path

from postfreeze_challenge.common import checkout_inputs, require, safe_path, sha

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PLAN_SHA256 = '07bfe64612cb84ed24f7af6bea7619b5e288db9f12a40e808bc0b7a098f46f4c'
FREEZE_SHA256 = 'f124f73297ccf4f89cb4863dd7032cd9a4b679ccba413693abade846136eca3a'
PRODUCERS = ('__init__.py', 'common.py', 'model.py', 'run.py', 'derive.py')


def load_plan(folder=HERE):
    raw = (folder / 'plan.json').read_bytes()
    require(sha(raw) == PLAN_SHA256, 'SR01 registered plan identity differs')
    plan = json.loads(raw)
    frozen = (folder / 'frozen-inputs.json').read_bytes()
    require(sha(frozen) == FREEZE_SHA256 == plan['source_freeze_sha256'], 'SR01 initial input freeze differs')
    return plan, json.loads(frozen)


def verify_prior(root=ROOT, folder=HERE):
    plan, frozen = load_plan(folder)
    require(len(frozen['files']) == len({item['path'] for item in frozen['files']}) == 49,
            'SR01 prior source domain differs')
    for item in frozen['files']:
        path = safe_path(root, item['path'])
        require(path.stat().st_size == item['bytes'] and sha(path.read_bytes()) == item['sha256'],
                'Prior scientific input changed: ' + item['path'])
    return plan, frozen


# The SR01 byte parser now lives at the identical-content producer_current path.
CHECKOUT_RENAMES = {'independent_observers/producer/independent_observer.py':
                    'independent_observers/producer_current/independent_observer.py'}


def checkout_entries(prior, root=ROOT):
    """Current-checkout inputs of a fresh SR01 campaign (see postfreeze_challenge.common.checkout_inputs)."""
    frozen = {'files': [{**item, 'path': CHECKOUT_RENAMES.get(item['path'], item['path'])} for item in prior['files']]}
    return checkout_inputs(frozen, root, extra=['recovery_extension/' + name for name in PRODUCERS])
