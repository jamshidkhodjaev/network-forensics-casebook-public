"""Public-edition standard-library checks and inert transforms. No private imports."""
import csv
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TIMELINE = ['event_id','timestamp_utc','packet_number','source_role','destination_role','protocol','description','evidence_ids','classification','handling']
REGISTER = ['evidence_id','supporting_packet_numbers','observed_fact','interpretation','classification','confidence','limitations','related_event_ids','handling']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def utc(value):
    require(bool(re.fullmatch(r'-?\d+(?:\.\d{1,9})?', value)), 'Invalid epoch')
    seconds, nanos = divmod(int(Decimal(value) * 1000000000), 1000000000)
    return (datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%S')+f'.{nanos:09d}Z'


def redact_host(value):
    if value.endswith('dl.dropboxusercontent.com'):
        return '[unique-subdomain-withheld].dl.dropboxusercontent[.]com'
    return value.replace('.', '[.]')


def decode(value):
    """Inert odd-position selection and reversal; never evaluates code."""
    return value[1::2][::-1]


def read_csv(path, columns):
    with path.open(encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        require(reader.fieldnames == columns, 'CSV schema mismatch')
        rows = list(reader)
    require(all(None not in row and all(v is not None for v in row.values()) for row in rows), 'Malformed CSV')
    return rows


def validate_rows(timeline, register):
    ids = {r['event_id'] for r in timeline}
    require(len(ids) == len(timeline), 'Duplicate event ID')
    evidence = {r['evidence_id']:r for r in register}
    require(len(evidence) == len(register), 'Duplicate evidence ID')
    require(timeline == sorted(timeline,key=lambda r:(r['timestamp_utc'],int(r['packet_number']))), 'Nonchronological timeline')
    by_id={r['event_id']:r for r in timeline}
    for row in timeline:
        require(row['event_id'] == 'TL-'+row['packet_number'].zfill(5), 'Packet/event mismatch')
        require(bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z',row['timestamp_utc'])), 'Non-UTC timestamp')
        require(row['classification']=='observed', 'Packet classification mismatch')
        require(row['handling']=='redacted derivative; not synthetic', 'Missing redaction label')
        for eid in row['evidence_ids'].split(';'):
            require(eid in evidence, 'Unknown evidence ID')
            require(row['event_id'] in evidence[eid]['related_event_ids'].split(';'), 'Nonreciprocal reference')
    for row in register:
        require(row['classification'] in {'observed','static code analysis','inference','unknown'}, 'Invalid register classification')
        require(row['handling']=='redacted derivative; not synthetic', 'Missing redaction label')
        nums=row['supporting_packet_numbers'].split(';')
        related=row['related_event_ids'].split(';')
        require(related == ['TL-'+n.zfill(5) for n in nums] and set(related)<=ids, 'Unsupported register packet')
        for event in related:
            require(row['evidence_id'] in by_id[event]['evidence_ids'].split(';'), 'Nonreciprocal reference')


def validate_report(text, timeline, register):
    require(set(re.findall(r'EV-\d{3}',text)) <= {r['evidence_id'] for r in register}, 'Unsupported report evidence')
    require(set(re.findall(r'\bP(\d+)\b',text)) <= {r['packet_number'] for r in timeline}, 'Unsupported report packet')
    require('endpoint compromise remain unconfirmed' in text, 'Missing calibrated conclusion')
    require(not re.search(r'(?:infection|payload execution) (?:was|is) confirmed',text,re.I), 'Unsupported outcome')


def public_files(root):
    return sorted(p for p in root.rglob('*') if p.is_file() and not any(part in {'.git','__pycache__','.venv'} for part in p.relative_to(root).parts))


def safety(root):
    for path in public_files(root):
        require(path.suffix.lower() not in {'.pcap','.pcapng','.zip','.js','.html','.exe','.dll','.bin'}, 'Prohibited payload file')
        require(not path.name.startswith('tcp_stream'), 'Prohibited stream export')
        text=path.read_text(encoding='utf-8')
        require(not re.search(r'/(?:Users|home)/|BEGIN [A-Z ]*PRIVATE KEY|(?:PHPSESSID|key|token)=[A-Za-z0-9%+/]{8,}',text), 'Sensitive token or private path')
        require(not re.search(r'\b172\.16\.2\.\d+\b|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',text,re.I), 'Unredacted asset address')
        require(not re.search(r'https?://(?:track\.|lw2e\.|www\.dropbox)',text), 'Clickable suspicious target')


def validate(root=ROOT):
    timeline=read_csv(root/'evidence/timeline.csv',TIMELINE)
    register=read_csv(root/'evidence/evidence.csv',REGISTER)
    validate_rows(timeline,register)
    validate_report((root/'report.md').read_text(),timeline,register)
    metadata=json.loads((root/'data/provenance.json').read_text())
    require(len(timeline)==metadata['public_event_count'] and len(register)==metadata['evidence_count'], 'Count mismatch')
    require(set(json.loads((root/'data/packet-checks.json').read_text()))=={r['packet_number'] for r in timeline}, 'Packet spec mismatch')
    hashes=json.loads((root/'data/checksums.json').read_text())
    actual_names={str(p.relative_to(root)) for p in public_files(root)}
    require(set(hashes)==actual_names-{'data/checksums.json'}, 'Unexpected or missing public file')
    require(set((root/'docs/prospective-files.txt').read_text().splitlines())==actual_names, 'Prospective file list mismatch')
    for name,expected in hashes.items():
        require(digest(root/name)==expected,'Artifact hash mismatch: '+name)
    for name in ['README.md','report.md']:
        for target in re.findall(r'\]\(([^)]+)\)',(root/name).read_text()):
            if not target.startswith('https://'):
                require((root/target.split('#')[0]).is_file(),'Broken document link')
    fixture=json.loads((root/'tests/fixtures/synthetic.json').read_text())
    require(fixture['handling'].startswith('SYNTHETIC TEST FIXTURE'), 'Unlabeled synthetic fixture')
    safety(root)
    return {'timeline_events':len(timeline),'evidence_records':len(register),'validation':'offline only; no capture or endpoint outcome verification'}
