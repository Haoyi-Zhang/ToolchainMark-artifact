#!/usr/bin/env python3
from __future__ import annotations

import argparse
from bisect import bisect_right
import csv
import hashlib
import io
import json
import re
import unicodedata
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / 'paper'
ARTIFACT = ROOT / 'artifact'
TEX = PAPER / 'main.tex'
BIB = PAPER / 'references.bib'
RECORDS = PAPER / 'evidence' / 'reference_records.json'
RECEIPTS = ARTIFACT / 'evidence' / 'reference_review_current.json'
COMPANION_RECEIPTS = ARTIFACT / 'evidence' / 'reference_review_companion.json'
LEDGER = ARTIFACT / 'citation_support.csv'
SHAPE = PAPER / 'citation_shape_audit.json'
VERIFY = PAPER / 'reference_verification_audit.json'
LINE_AUDIT = PAPER / 'reference_line_by_line_audit.csv'
CITATION = re.compile(
    r'\\[cC]ite(?:yearpar|author|year|alt|alp|num|t|p)?\*?'
    r'(?:\s*\[[^\]]*\]){0,2}\s*\{([^{}]+)\}')


def parsed_citations(text: str):
    """Parse citations without silently dropping malformed or unknown commands.

    Citation style configuration is not a citation occurrence. Other commands
    beginning with cite/Cite must be handled explicitly by this reader rather
    than disappearing from the claim ledger.
    """
    matches = list(CITATION.finditer(text))
    starts = {match.start() for match in matches}
    unknown = []
    for token in re.finditer(r'\\[cC]ite[A-Za-z@]*\*?', text):
        if token.group() in ('\\citestyle', '\\Citestyle'):
            continue
        if token.start() not in starts:
            unknown.append(token.group())
    if unknown:
        raise ValueError('Unparsed citation command(s): ' + ', '.join(unknown))
    return matches


def citation_sentence_span(text: str, match) -> tuple[int, int, int, int]:
    """Locate a citation's sentence and its containing logical paragraph.

    A physical TeX newline is whitespace, not a claim boundary. Blank lines
    delimit paragraphs. Common scholarly abbreviations and punctuation inside
    citation locators do not end the supporting sentence. The paragraph is
    retained as review context because one citation may introduce several
    connected sentences; this routine does not decide semantic entailment.
    """
    separators = list(re.finditer(r'\n[ \t]*\n', text))
    preceding = [s for s in separators if s.end() <= match.start()]
    following = [s for s in separators if s.start() >= match.end()]
    pstart = preceding[-1].end() if preceding else 0
    pend = following[0].start() if following else len(text)
    paragraph = text[pstart:pend]
    occupied = [(m.start(), m.end()) for m in CITATION.finditer(paragraph)]
    boundaries = []
    for end in re.finditer(r'[.!?](?=\s|$)', paragraph):
        pos = end.start()
        if any(start <= pos < stop for start, stop in occupied):
            continue
        prefix = paragraph[max(0, pos - 15):pos + 1]
        if re.search(r'\b(?:al|e\.g|i\.e|cf|Fig|Figs|Sec|Secs|Eq|Eqs|Dr|Prof|Mr|Ms|vs)\.$',
                     prefix, re.I):
            continue
        boundaries.append(pstart + end.end())
    left = max([pstart] + [pos for pos in boundaries if pos <= match.start()])
    right = min([pend] + [pos for pos in boundaries if pos >= match.end()])
    return left, right, pstart, pend


def extract_citation_contexts(source_lines: list[tuple[str, int, str]]) -> list[dict]:
    """Keep complete sentence/paragraph context and original command locations."""
    offsets = []
    locations = []
    chunks = []
    cursor = 0
    section = subsection = ''
    for source_file, lineno, line in source_lines:
        heading = re.match(r'\s*\\section\{([^}]+)\}', line)
        if heading:
            section, subsection = heading.group(1), ''
        heading = re.match(r'\s*\\subsection\{([^}]+)\}', line)
        if heading:
            subsection = heading.group(1)
        offsets.append(cursor)
        locations.append((source_file, lineno, section, subsection))
        chunks.append(line + '\n')
        cursor += len(line) + 1
    text = ''.join(chunks)
    result = []
    for match in parsed_citations(text):
        source_file, lineno, section, subsection = locations[bisect_right(offsets, match.start()) - 1]
        left, right, pstart, pend = citation_sentence_span(text, match)
        sentence = text[left:right]
        group = [key.strip() for other in CITATION.finditer(sentence)
                 for key in other.group(1).split(',')]
        for key in match.group(1).split(','):
            result.append({'key': key.strip(), 'file': source_file, 'line': lineno,
                           'section': section, 'subsection': subsection,
                           'sentence': strip_tex(sentence),
                           'paragraph': strip_tex(text[pstart:pend]),
                           'sentence_citation_keys': group})
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def uncomment_tex_line(line: str) -> str:
    """Remove a TeX comment while preserving an escaped percent literal."""
    for i, char in enumerate(line):
        if char != '%':
            continue
        backslashes = 0
        j = i - 1
        while j >= 0 and line[j] == '\\':
            backslashes += 1
            j -= 1
        if backslashes % 2 == 0:
            return line[:i]
    return line


def tex_source_lines(path: Path) -> list[tuple[str, int, str]]:
    """Expand literal local TeX inputs while retaining their source locations.

    This is a citation-source reader, not a TeX interpreter. It follows literal
    ``input``/``include`` commands for .tex files, ignores comments, and leaves
    non-TeX inputs (for example a font definition) to TeX. Missing local text
    inputs and cycles are errors, so moving prose into an input cannot silently
    remove it from the citation audit. Paths remain within the paper directory.
    """
    path = Path(path).resolve()
    root = path.parent
    pattern = re.compile(r'\\(?:input|include)\s*\{([^{}]+)\}')

    def visit(current: Path, stack: tuple[Path, ...]):
        if current in stack:
            raise ValueError('Cyclic TeX input: ' + str(current.relative_to(root)))
        if not current.is_relative_to(root):
            raise ValueError('TeX input escapes the paper directory')
        relative = current.relative_to(root).as_posix()
        for lineno, raw in enumerate(current.read_text(encoding='utf-8').splitlines(), 1):
            line = uncomment_tex_line(raw)
            start = 0
            for match in pattern.finditer(line):
                name = match.group(1).strip()
                target = Path(name)
                if target.suffix and target.suffix != '.tex':
                    continue
                if target.is_absolute() or '\\' in name:
                    raise ValueError('Expected a literal relative TeX input: ' + name)
                if not target.suffix:
                    target = target.with_suffix('.tex')
                candidates = [(root / target).resolve(), (current.parent / target).resolve()]
                if any(not candidate.is_relative_to(root) for candidate in candidates):
                    raise ValueError('TeX input escapes the paper directory: ' + name)
                resolved = next((candidate for candidate in candidates if candidate.is_file()), None)
                if resolved is None:
                    raise ValueError('Missing local TeX input: ' + name)
                yield (relative, lineno, line[start:match.start()])
                yield from visit(resolved, stack + (current,))
                start = match.end()
            yield (relative, lineno, line[start:])

    return list(visit(path, ()))


def read_tex_sources(path: Path) -> str:
    """Return citation-visible manuscript text, including local .tex inputs."""
    return '\n'.join(line for _, _, line in tex_source_lines(path))


def load_receipts():
    """Use companion evidence only for the bibliography bytes it binds."""
    if COMPANION_RECEIPTS.is_file():
        companion = json.loads(COMPANION_RECEIPTS.read_text(encoding='utf-8'))
        if not isinstance(companion, dict) or not isinstance(companion.get('receipts'), list):
            raise ValueError('Malformed companion reference receipt')
        identity = companion.get('bibliography_sha256')
        if not isinstance(identity, str) or not re.fullmatch(r'[0-9a-f]{64}', identity):
            raise ValueError('Missing or invalid companion bibliography binding')
        if identity == sha256(BIB):
            if companion.get('schema_version') == 'current-scoped-reference-review-v3':
                for paths_field, digest_field in [('metadata_review', 'metadata_evidence_sha256'),
                                                   ('claim_support_review', 'claim_support_evidence_sha256')]:
                    paths = companion.get(paths_field)
                    if not isinstance(paths, list) or not paths:
                        raise ValueError('Scoped companion requires local evidence documents')
                    digests = set()
                    for relative in paths:
                        if not isinstance(relative, str) or Path(relative).is_absolute():
                            raise ValueError('Invalid scoped evidence path')
                        path = (ROOT / relative).resolve()
                        if not path.is_relative_to(ROOT):
                            raise ValueError('Scoped evidence path escapes package')
                        digests.add(sha256(path))
                    if any(row.get(digest_field) not in digests for row in companion['receipts']):
                        raise ValueError('Scoped reference evidence document changed')
                for row in companion['receipts']:
                    claims = row.get('supported_claims')
                    if (not isinstance(claims, list) or not claims or
                            any(not isinstance(claim, str) or not claim.strip() for claim in claims) or
                            not isinstance(row.get('claim_boundary'), str) or not row['claim_boundary'].strip()):
                        raise ValueError('Scoped receipt requires explicit supported claims and boundary')
            return COMPANION_RECEIPTS, companion['receipts']
    return RECEIPTS, json.loads(RECEIPTS.read_text(encoding='utf-8'))


def strip_tex(text: str) -> str:
    text = ' '.join(uncomment_tex_line(line) for line in text.splitlines())
    text = CITATION.sub('', text)
    text = re.sub(r'\\(?:textsc|emph|textit|textbf|texttt|mathrm|mathsf)\{([^{}]*)\}', r'\1', text)
    text = re.sub(r'\\(?:mr|suite)\{([^{}]*)\}', r'\1', text)
    text = re.sub(r'\\[A-Za-z@]+\*?(?:\[[^\]]*\])?', '', text)
    text = text.replace('~', ' ')
    text = text.replace('``', '"').replace("''", '"')
    text = text.replace('--', '-')
    text = re.sub(r'[{}$]', '', text)
    text = re.sub(r'\\([%&_#])', r'\1', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def parse_bib(text: str) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    for match in re.finditer(r'@(\w+)\{([^,]+),\s*(.*?)\n\}', text, re.S):
        entry_type, key, body = match.group(1).lower(), match.group(2).strip(), match.group(3)
        if key in entries:
            raise ValueError('Duplicate BibTeX key: ' + key)
        fields: dict[str, str] = {'entry_type': entry_type}
        for fm in re.finditer(r'^\s*(\w+)\s*=\s*\{(.*?)\}\s*,?\s*$', body, re.M | re.S):
            field = fm.group(1).lower()
            if field in fields:
                raise ValueError('Duplicate BibTeX field for ' + key + ': ' + field)
            fields[field] = fm.group(2).strip()
        entries[key] = fields
    return entries


def normalize_people(value: str) -> str:
    value = strip_tex(value).lower()
    value = value.replace(' and ', ' ')
    return ''.join(c for c in unicodedata.normalize('NFKD', value).casefold() if c.isalnum())


def scholarly_identifier(record: dict) -> str:
    """Identify a work, not its claim support; reject absent/ambiguous identities."""
    doi = record.get('doi', '')
    repository = record.get('primary_repository', '')
    document = record.get('primary_document_url', '')
    document_digest = record.get('document_sha256', '')
    repository_commit = record.get('repository_snapshot_commit', '')
    repository_digest = record.get('repository_snapshot_sha256', '')
    documentation = record.get('primary_documentation_url', '')
    documentation_source = record.get('documentation_source_url', '')
    documentation_digest = record.get('documentation_source_sha256', '')
    if any(not isinstance(value, str) for value in
           (doi, repository, document, document_digest, repository_commit, repository_digest,
            documentation, documentation_source, documentation_digest)):
        raise ValueError('Identifiers must be strings')
    doi, repository, document = doi.strip(), repository.strip().rstrip('/'), document.strip()
    documentation = documentation.strip()
    if sum(bool(value) for value in (doi, repository, document, documentation)) != 1:
        raise ValueError('Require exactly one DOI, repository, document, or source-bound documentation identity')
    if document_digest and not document:
        raise ValueError('A document digest requires a primary document URL')
    if (repository_commit or repository_digest) and not repository:
        raise ValueError('Repository version bindings require a repository identity')
    if (documentation_source or documentation_digest) and not documentation:
        raise ValueError('Documentation source bindings require a documentation identity')
    def document_url(value):
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment
                or not parsed.path.strip('/') or re.search(r'\s', value)):
            raise ValueError('Expected an HTTPS document URL without credentials, whitespace, or a fragment')
        return parsed
    if doi:
        if not re.fullmatch(r'10\.[0-9]{4,9}/[^\s]+', doi):
            raise ValueError('Expected a bare DOI of the form 10.<registrant>/<suffix>')
        return 'doi:' + doi.casefold()
    if document:
        document_url(document)
        if not re.fullmatch(r'[0-9a-f]{64}', document_digest):
            raise ValueError('A primary document requires a lowercase SHA256 digest')
        # Paths and queries can be case-sensitive. The bytes, not a mutable
        # repository root or an invented DOI, identify this document edition.
        return 'document:' + document + '#sha256=' + document_digest
    if documentation:
        document_url(documentation)
        document_url(documentation_source)
        if not re.fullmatch(r'https://raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/[^\s?#]+', documentation_source):
            raise ValueError('Documentation source must identify a fixed GitHub commit and file')
        if not re.fullmatch(r'[0-9a-f]{64}', documentation_digest):
            raise ValueError('Documentation source requires a lowercase SHA256 digest')
        # The source digest does not assert byte equality with rendered HTML.
        # Keep both locations visible rather than assigning an unseen page a hash.
        return ('documentation:' + documentation + '#source=' + documentation_source
                + '#sha256=' + documentation_digest)
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Expected a primary GitHub repository root URL')
    if repository_commit or repository_digest:
        if not re.fullmatch(r'[0-9a-f]{40}', repository_commit) or not re.fullmatch(r'[0-9a-f]{64}', repository_digest):
            raise ValueError('A repository snapshot requires a full commit and archive SHA256')
        return ('repository:' + repository.removeprefix('https://').casefold() + '@' + repository_commit
                + '#sha256=' + repository_digest)
    return 'repository:' + repository.removeprefix('https://').casefold()


def bibliography_source_url(fields: dict) -> str:
    """Read a literal source target; a displayed link label is not an identity.

    Non-DOI works may put their source in the usual url field or in a labeled
    href in note/howpublished. Only literal targets and ordinary escaped URL
    punctuation are accepted; macros and conflicting targets fail closed.
    """
    targets = []
    direct = fields.get('url', '').strip()
    if direct:
        targets.append(direct)
    href = re.compile(r'\\href\s*\{([^{}]*)\}\s*\{')
    for name in ('note', 'howpublished'):
        text = fields.get(name, '')
        matches = list(href.finditer(text))
        if len(matches) != len(re.findall(r'\\href\b', text)):
            raise ValueError('Malformed or nonliteral bibliography source link')
        for match in matches:
            target = re.sub(r'\\([%&#_])', r'\1', match.group(1)).strip()
            if not target or '\\' in target or re.search(r'\s', target):
                raise ValueError('Expected a literal bibliography source target')
            targets.append(target)
    if not targets:
        return ''
    if any(target != targets[0] for target in targets[1:]):
        raise ValueError('Conflicting bibliography source targets')
    return targets[0]


def record_matches_bib(record: dict, fields: dict) -> bool:
    """Local metadata correspondence only, never a body-support verdict."""
    def norm(value):
        return re.sub(r'[^a-z0-9]', '', strip_tex(str(value)).lower())
    try:
        identity = scholarly_identifier(record)
        if norm(fields.get('title', '')) != norm(record['title']):
            return False
        if identity.startswith('doi:'):
            return (fields.get('doi', '').casefold() == record['doi'].casefold()
                    and normalize_people(fields.get('author', '')) == normalize_people(record['authors'])
                    and str(fields.get('year', '')) == str(record.get('year', '')))
        if identity.startswith('document:'):
            return (not fields.get('doi') and
                    bibliography_source_url(fields) == record['primary_document_url'].strip()
                    and normalize_people(fields.get('author', '')) == normalize_people(record['authors'])
                    and str(fields.get('year', '')) == str(record.get('year', '')))
        if identity.startswith('documentation:'):
            return (not fields.get('doi') and bibliography_source_url(fields) == record['primary_documentation_url'].strip()
                    and normalize_people(fields.get('author', '')) == normalize_people(record['authors'])
                    and str(fields.get('year', '')) == str(record.get('year', '')))
        repository_url = record['primary_repository'].rstrip('/')
        if record.get('repository_snapshot_commit'):
            repository_url += '/tree/' + record['repository_snapshot_commit']
        return (not fields.get('doi') and
                bibliography_source_url(fields).rstrip('/').casefold() == repository_url.casefold()
                and normalize_people(fields.get('author', '')) == normalize_people(record['authors'])
                and str(fields.get('year', '')) == str(record.get('year', '')))
    except (KeyError, TypeError, ValueError):
        return False


def validate_reference_inputs(records: list, receipts: list) -> None:
    """Shared consumer schema; declarations are not independent support proof."""
    if not isinstance(records, list) or not records or not isinstance(receipts, list) or not receipts:
        raise ValueError('Require nonempty reference and receipt lists')
    def required_text(row, names, kind):
        if not isinstance(row, dict):
            raise ValueError(kind + ' must be an object')
        for name in names:
            value = row.get(name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(kind + ' requires nonempty text: ' + name)
    for row in records:
        required_text(row, ('citation_key', 'title', 'authors'), 'Reference')
        if type(row.get('number')) is not int or row['number'] <= 0:
            raise ValueError('Reference number must be a positive integer')
        identity = scholarly_identifier(row)
        year = row.get('year', '')
        if type(year) not in (int, str):
            raise ValueError('Reference year must be text or an integer, not a Boolean')
        if identity.startswith(('doi:', 'document:', 'documentation:')) and not re.fullmatch(r'[1-9][0-9]{3}', str(year)):
            raise ValueError('DOI or document reference year must be a four-digit year')
    for row in receipts:
        required_text(row, ('citation_key', 'locator', 'source_class', 'verification_scope'), 'Receipt')
        if type(row.get('record_located_this_revision')) is not bool:
            raise ValueError('Receipt location declaration must be a Boolean')
        for name in ('full_text_reviewed', 'inherited_record_located'):
            if name in row and type(row[name]) is not bool:
                raise ValueError('Receipt ' + name + ' must be a Boolean')
        if 'body_reading_locations' in row and not isinstance(row['body_reading_locations'], list):
            raise ValueError('Receipt body_reading_locations must be a list of scoped records')
        scholarly_identifier(row)


def structural_audit(tex: str, bib: dict, records: list, receipts: list) -> dict:
    if any(type(row.get('record_located_this_revision')) is not bool for row in receipts):
        raise ValueError('Receipt location declaration must be a Boolean')
    matches = parsed_citations(tex)
    commands = [match.group(1) for match in matches]
    sentence_spans = {citation_sentence_span(tex, match)[:2] for match in matches}
    multiple = [tex[left:right] for left, right in sorted(sentence_spans)
                if len(CITATION.findall(tex[left:right])) > 1]
    keys=[k.strip() for c in commands for k in c.split(',')]
    rk={r['citation_key'] for r in records}; bk=set(bib)
    doi=[r['doi'].casefold() for r in records if r.get('doi')]
    identifiers=[]; identifier_errors=[]; receipt_identifier_mismatches=[]
    for record in records:
        try: identifiers.append(scholarly_identifier(record))
        except ValueError as error: identifier_errors.append({'key':record.get('citation_key'), 'error':str(error)})
    byrecord={r['citation_key']:r for r in records}
    for receipt in receipts:
        key=receipt['citation_key']
        try:
            if key not in byrecord or scholarly_identifier(receipt)!=scholarly_identifier(byrecord[key]):
                receipt_identifier_mismatches.append(key)
        except ValueError: receipt_identifier_mismatches.append(key)
    return {'record_count':len(records),'citation_commands':len(commands),'unique_citation_keys':len(set(keys)),
      'multi_key_commands':sum(',' in c for c in commands),
      'adjacent_citation_piles':len(re.findall(CITATION.pattern + r'\s*' + CITATION.pattern, tex)),
      'uncited_bibliography_keys':sorted(bk-set(keys)),'missing_bibliography_keys':sorted(set(keys)-bk),
      'metadata_record_keys_match':rk==bk,'doi_records_unique':len(doi)==len(set(doi)),
      'record_keys_unique':len(records)==len(rk),
      'receipt_keys_match':{r['citation_key'] for r in receipts}==rk,
      'identifier_errors':identifier_errors,
      'receipt_identifier_mismatches':receipt_identifier_mismatches,
      'scholarly_identifiers_unique':not identifier_errors and len(identifiers)==len(set(identifiers)),
      'doi_record_count':len(doi),'primary_repository_record_count':sum(bool(r.get('primary_repository')) for r in records),
      'primary_document_record_count':sum(bool(r.get('primary_document_url')) for r in records),
      'source_bound_documentation_record_count':sum(bool(r.get('primary_documentation_url')) for r in records),
      'fixed_repository_snapshot_count':sum(bool(r.get('repository_snapshot_commit')) for r in records),
      'receipt_keys_unique':len(receipts)==len({r['citation_key'] for r in receipts}),
      'fresh_record_checks':sum(bool(r['record_located_this_revision']) for r in receipts),
      'sentences_with_multiple_citation_commands':len(multiple),
      'multiple_citation_sentence_examples':multiple[:4],
      'citation_grouping_policy':'Multiple sources for a claim or comparison are permitted. Group sizes and adjacent citations are review diagnostics, not TOSEM acceptance rules. Every parsed key retains its own source-support record.',
      'numeric_citation_ranges':sum(bool(re.search(r'\d\s*[-–]\s*\d', command)) for command in commands),
      'full_text_review_claimed':False}

def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description='Audit current citation identities and scoped support records.')
    parser.add_argument('--check', action='store_true',
                        help='Compare generated audits with current sources without writing any file.')
    args = parser.parse_args(argv)
    missing = [path.relative_to(ROOT).as_posix() for path in (TEX, BIB, RECORDS) if not path.is_file()]
    if missing:
        # The citation audit needs the manuscript sources in a sibling paper/
        # directory; they are not part of the standalone artifact repository.
        print(json.dumps({'verdict': 'SKIPPED', 'reason': 'manuscript sources not present',
                          'missing_inputs': missing}, indent=2))
        return
    source_lines=tex_source_lines(TEX)
    tex='\n'.join(line for _,_,line in source_lines); bib=parse_bib(BIB.read_text(encoding='utf-8')); records=json.loads(RECORDS.read_text(encoding='utf-8'))
    # Reference numbers follow the actual compiled bibliography, not source
    # insertion order or a previous release's fixed 33-record numbering.
    bbl = PAPER / 'main.bbl'
    numbered_records = None
    if bbl.is_file():
        order = re.findall(r'\\bibitem\[.*?\]%?\s*\{([^{}]+)\}', bbl.read_text(encoding='utf-8'), re.S)
        if len(order) != len(set(order)) or set(order) != set(bib):
            raise ValueError('Compiled bibliography is stale or has a different key set; rebuild main.bbl first')
        bykey = {row['citation_key']: row for row in records}
        if set(bykey) != set(order):
            raise ValueError('Reference metadata key set differs from compiled bibliography')
        records = [{**bykey[key], 'number': number} for number, key in enumerate(order, 1)]
        numbered_records = (json.dumps(records, indent=2, ensure_ascii=False)+'\n').encode('utf-8')
    receipt_path,receipts=load_receipts()
    validate_reference_inputs(records, receipts)
    byreceipt={r['citation_key']:r for r in receipts}; shape=structural_audit(tex,bib,records,receipts)
    if not (shape['record_keys_unique'] and shape['receipt_keys_unique'] and shape['receipt_keys_match']):
        raise ValueError('Current records and receipts require unique matching keys')
    if shape['identifier_errors'] or shape['receipt_identifier_mismatches']:
        raise ValueError('Invalid or mismatched scholarly identifiers')
    citations = extract_citation_contexts(source_lines)
    audit=[];ledger=[];local_mismatches=[]
    for rec in records:
        key=rec['citation_key']; b=bib.get(key,{}); rr=byreceipt[key]; cs=[c for c in citations if c['key']==key]
        match=record_matches_bib(rec,b)
        if not match:local_mismatches.append(key)
        location='; '.join(f"{c['file']}:{c['line']} ({c['section']} / {c['subsection']})" for c in cs)
        context=' || '.join(c['sentence'] for c in cs)
        paragraphs=' || '.join(dict.fromkeys(c['paragraph'] for c in cs))
        groups=' || '.join(', '.join(c['sentence_citation_keys']) for c in cs)
        status='RECORD_LOCATED_SCOPE_LIMITED' if rr['record_located_this_revision'] else 'INHERITED_NOT_FRESHLY_VERIFIED'
        body_status='SCOPED_PRIMARY_BODY_READING_RECORDED_NOT_AUTOMATICALLY_CERTIFIED' if rr.get('body_reading_locations') else 'CLAIM_CONTEXT_RETAINED_NOT_AUTOMATICALLY_PROVEN'
        audit.append({'reference_number':rec['number'],'citation_key':key,'title':rec['title'],'authors':rec['authors'],'year':rec.get('year',''),'doi':rec.get('doi',''),'scholarly_identifier':scholarly_identifier(rec),'source_locator':rr['locator'],'source_class':rr['source_class'],'local_record_consistency':'PASS' if match else 'FAIL','external_review_status':status,'verification_scope':rr['verification_scope'],'manuscript_location':location,'local_claims':context,'support_status':body_status,'full_text_reviewed':False})
        evidence={'reference':rec,'receipt':rr,'contexts':cs}
        ledger.append({'citation_key':key,'manuscript_location':location,'scholarly_identifier':scholarly_identifier(rec),
                       'source_locator':rr['locator'],'manuscript_claims':context,
                       'surrounding_paragraphs':paragraphs,'citation_groups':groups,
                       'scoped_source_support':' || '.join(rr.get('supported_claims', [])),
                       'support_boundary':rr.get('claim_boundary', ''),
                       'source_reading_scope':rr['verification_scope'],
                       'evidence_sha256':hashlib.sha256(json.dumps(evidence,sort_keys=True,ensure_ascii=False).encode()).hexdigest(),
                       'verification_status':status})
    if local_mismatches:
        raise ValueError('Local bibliographic metadata differs: ' + repr(local_mismatches))
    ledger_path=PAPER/'reference_support.csv' if receipt_path==COMPANION_RECEIPTS else LEDGER
    outputs = {}
    if numbered_records is not None:
        outputs[RECORDS] = numbered_records
    for path,rows in [(LINE_AUDIT,audit),(ledger_path,ledger)]:
        stream = io.StringIO(newline='')
        writer = csv.DictWriter(stream, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
        outputs[path] = stream.getvalue().encode('utf-8')
    shape['local_record_mismatches']=local_mismatches
    shape['structural_verdict']='PASS' if not(local_mismatches or shape['receipt_identifier_mismatches'] or shape['uncited_bibliography_keys'] or shape['missing_bibliography_keys']) and shape['metadata_record_keys_match'] and shape['record_keys_unique'] and shape['receipt_keys_unique'] and shape['receipt_keys_match'] and shape['scholarly_identifiers_unique'] else 'FAIL'
    outputs[SHAPE] = (json.dumps(shape,indent=2)+'\n').encode('utf-8')
    report={'schema_version':'current-evidence-separated','record_count':len(records),'unique_scholarly_identifiers':len({scholarly_identifier(r) for r in records}),'doi_record_count':shape['doi_record_count'],'primary_repository_record_count':shape['primary_repository_record_count'],'primary_document_record_count':shape['primary_document_record_count'],'source_bound_documentation_record_count':shape['source_bound_documentation_record_count'],'fixed_repository_snapshot_count':shape['fixed_repository_snapshot_count'],'current_receipts':receipt_path.relative_to(ROOT).as_posix(),'fresh_documented_record_checks':shape['fresh_record_checks'],'inherited_records_not_freshly_reverified':[r['citation_key'] for r in receipts if not r['record_located_this_revision']],'scoped_primary_body_reading_records':[r['citation_key'] for r in receipts if r.get('body_reading_locations')],'source_class_counts':dict(Counter(r['source_class'] for r in receipts)),'structural_verdict':shape['structural_verdict'],'semantic_verdict':'PARTIAL_EXTERNAL_REVIEW_NOT_FULL_TEXT_CERTIFICATION','verification_scope':'Structural bibliography/citation checks are automated. DOIs, repository snapshots, URL-plus-SHA256 documents and source-bound documentation establish identity only; a declared digest is not an automatic acquisition or reading certificate. A documentation-source digest is not a digest of an unseen rendered page. Scoped primary-body reading declarations are retained in current receipts, not independently certified by this script. Inherited receipts are not freshly reverified here. A citation occurrence, matching local record, or hash is not proof of claim support; no universal full-text certification is inferred.','imported_audits':'artifact/results/protocol-history/imported-audits','verdict':'PASS_STRUCTURAL_WITH_DISCLOSED_REVIEW_LIMITS' if shape['structural_verdict']=='PASS' else 'FAIL_STRUCTURAL'}
    outputs[VERIFY] = (json.dumps(report,indent=2)+'\n').encode('utf-8')
    if args.check:
        stale = [path.relative_to(ROOT).as_posix() for path, content in outputs.items()
                 if not path.is_file() or path.read_bytes() != content]
        passed = shape['structural_verdict'] == 'PASS' and not stale
        print(json.dumps({**report, 'mode': 'check', 'stale_generated_audits': stale,
                          'verdict': 'PASS' if passed else 'FAIL'}, indent=2))
        if not passed:
            raise SystemExit(1)
    else:
        for path, content in outputs.items():
            path.write_bytes(content)
        print(json.dumps({**report, 'mode': 'generate'}, indent=2))
    if shape['structural_verdict']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
