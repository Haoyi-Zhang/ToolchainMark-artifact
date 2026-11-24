"""Declared source cases and controlled changes, fixed before layer evaluation."""
from copy import deepcopy

BASES = {
    'host': ('reference', 'pass-1/string/CLEAN/MR02'),
    'removal': ('reference', 'pass-1/string/CLEAN/MR09'),
    'parallel': ('reference', 'pass-1/string/CLEAN/MR12'),
    'changed-identity': ('identity', 'pass-1/string/replace-on-B/MR13'),
    'llvm-inconsistent': ('llwm', 'pass-1/upstream/atoi/payload-1/O0'),
    'llvm-satisfied': ('llwm', 'pass-1/literal-output-repair/atoi/payload-1/O0'),
}

# One declared association is altered per negative record. Some associations
# contain two fields (parallel order or an equality-preserving paired output).
CHANGES = [
    ('input-digest', 'host', 'The recorded input digest differs from the unchanged input object.'),
    ('action-context', 'host', 'One action names a context other than its externally selected case.'),
    ('action-order', 'host', 'The two host action records are exchanged, violating declared action order.'),
    ('parallel-order', 'parallel', 'Sibling events form a serial interval instead of the declared parallel ordering.'),
    ('guard-result', 'host', 'An attempted host action records a false guard although the declaration has no guard.'),
    ('resolved-argument', 'host', 'The first resolved host input differs from its declared input reference.'),
    ('consumed-reference', 'host', 'The host-input dependency is omitted from the consumed-reference list.'),
    ('stored-verdict', 'host', 'The stored stage label contradicts replay of its unchanged observations.'),
    ('paired-host-values', 'host', 'Both typed host outputs change together, preserving equality while contradicting retained stdout.'),
    ('process-target-before', 'llvm-satisfied', 'The process pre-call target is a different retained executable version from the action pre-call endpoint.'),
    ('process-target-after', 'llvm-satisfied', 'The process post-call target is a different retained executable version from the action post-call endpoint.'),
    ('strip-flag', 'llvm-satisfied', 'The raw command requests full stripping rather than the declared debug stripping.'),
    ('strip-return', 'llvm-satisfied', 'An available strip action contains a nonzero process return code.'),
    ('strip-input', 'llvm-satisfied', 'The raw strip command names the unmarked input rather than the declared marked input.'),
    ('strip-output', 'llvm-satisfied', 'The raw strip destination differs from the returned captured output.'),
    ('strip-command-missing', 'llvm-satisfied', 'The strip action has input/output captures but lacks its native command record.'),
    ('decoder-call-key', 'removal', 'The retained extraction call key differs from its declared and returned key.'),
    ('decoder-call-session', 'removal', 'The retained extraction call session differs from the declared live decoder session.'),
]


def patches_for(name, original):
    receipt, patches = deepcopy(original), []
    def access(path):
        node = receipt
        for token in path:
            node = node[token]
        return node
    def change(path, value):
        before = deepcopy(access(path))
        access(path[:-1])[path[-1]] = deepcopy(value)
        patches.append({'op': 'replace', 'path': path, 'before': before, 'after': deepcopy(value)})
    def remove(path):
        before = deepcopy(access(path)); del access(path[:-1])[path[-1]]
        patches.append({'op': 'remove', 'path': path, 'before': before})
    def action(identity):
        return ['actions', next(i for i, row in enumerate(receipt['actions']) if row['id'] == identity)]
    def event(identity, kind='process'):
        path = action(identity) + ['evidence']
        return path + [next(i for i, row in enumerate(access(path)) if row['kind'] == kind)]
    if name == 'input-digest':
        change(['inputs_sha256'], '0' * 64)
    elif name == 'action-context':
        path = action('base-host') + ['context_id']; change(path, access(path) + ':other')
    elif name == 'action-order':
        left, right = action('base-host'), action('marked-host')
        old_left, old_right = deepcopy(access(left)), deepcopy(access(right))
        change(left, old_right); change(right, old_left)
    elif name == 'parallel-order':
        left, right = action('first') + ['end_event'], action('second') + ['start_event']
        values = sorted((access(left), access(right)))
        change(left, values[0]); change(right, values[1])
    elif name == 'guard-result':
        change(action('base-host') + ['guard'], {'state': 'FALSE', 'value': False, 'reason': None, 'dependencies': []})
    elif name == 'resolved-argument':
        change(action('base-host') + ['arguments', 'inputs', 0], 2)
    elif name == 'consumed-reference':
        path = action('base-host') + ['consumed_references']
        change(path, [value for value in access(path) if value != 'input:host_inputs'])
    elif name == 'stored-verdict':
        change(['obligations', 0, 'verdict'], 'INCONSISTENT')
    elif name == 'paired-host-values':
        for identity in ('base-host', 'marked-host'):
            change(action(identity) + ['value', 'outputs', 0], 'coordinated-unrecorded-output')
    elif name in ('process-target-before', 'process-target-after'):
        endpoint = 'files_before' if name.endswith('before') else 'files_after'
        path = event('unmarked-key') + [endpoint]
        target = access(action('unmarked-key') + ['arguments', 'binary'])
        index = next(i for i, row in enumerate(access(path)) if row['path'] == target)
        alternate = deepcopy(access(action('marked-key') + ['value', 'before']))
        alternate['path'] = target
        change(path + [index], alternate)
    elif name.startswith('strip-'):
        path = event('strip')
        if name == 'strip-flag': change(path + ['argv', 1], '--strip-all')
        elif name == 'strip-return': change(path + ['returncode'], 7)
        elif name == 'strip-input':
            argv = access(path + ['argv'])
            change(path + ['argv', len(argv) - 1], access(action('build') + ['value', 'unmarked']))
        elif name == 'strip-output':
            change(path + ['argv', 3], access(path + ['argv', 3]) + '.other')
        elif name == 'strip-command-missing': remove(path)
        else: raise ValueError('unrecognized strip change')
    elif name == 'decoder-call-key':
        change(event('followup-value', 'python-return') + ['key'], 'key-beta')
    elif name == 'decoder-call-session':
        path = event('followup-value', 'python-return') + ['session_id']; change(path, access(path) + ':other')
    else:
        raise ValueError('unrecognized controlled change')
    if not patches or receipt == original:
        raise ValueError('controlled change did not change the original record')
    return patches
