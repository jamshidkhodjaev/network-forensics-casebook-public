"""Public artifact tests plus explicitly synthetic negative/mutation cases."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import casebook as c
import reproduce


class PublicTests(unittest.TestCase):
    def setUp(self):
        self.timeline=c.read_csv(ROOT/'evidence/timeline.csv',c.TIMELINE)
        self.register=c.read_csv(ROOT/'evidence/evidence.csv',c.REGISTER)

    def test_offline_validation(self):
        self.assertEqual(c.validate()['timeline_events'],35)

    def test_report_unknown_evidence(self):
        with self.assertRaisesRegex(ValueError,'Unsupported report evidence'):
            c.validate_report((ROOT/'report.md').read_text()+' EV-999',self.timeline,self.register)

    def test_report_unknown_packet(self):
        with self.assertRaisesRegex(ValueError,'Unsupported report packet'):
            c.validate_report((ROOT/'report.md').read_text()+' P999999',self.timeline,self.register)

    def test_schema_rejects_wrong_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'synthetic.csv';p.write_text('synthetic,wrong\na,b\n')
            with self.assertRaisesRegex(ValueError,'schema'):
                c.read_csv(p,c.TIMELINE)

    def test_chronology(self):
        with self.assertRaisesRegex(ValueError,'Nonchronological'):
            c.validate_rows(list(reversed(self.timeline)),self.register)

    def test_duplicate_ids(self):
        self.timeline[1]['event_id']=self.timeline[0]['event_id']
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            c.validate_rows(self.timeline,self.register)

    def test_redaction_label_required(self):
        self.timeline[0]['handling']=''
        with self.assertRaisesRegex(ValueError,'redaction label'):
            c.validate_rows(self.timeline,self.register)

    def test_synthetic_fixture_and_transforms(self):
        fixture=json.loads((ROOT/'tests/fixtures/synthetic.json').read_text())
        self.assertIn('SYNTHETIC',fixture['handling'])
        self.assertEqual(c.utc(fixture['epoch']),fixture['utc'])
        self.assertEqual(c.decode(fixture['encoded']),fixture['decoded'])
        with self.assertRaises(ValueError):c.utc('NaN')

    def test_prohibited_payload_file(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'synthetic.js').write_text('SYNTHETIC inert fixture')
            with self.assertRaisesRegex(ValueError,'Prohibited'):
                c.safety(Path(directory))

    def test_sensitive_token_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'synthetic.txt').write_text('SYNTHETIC '+ 'token'+'='+'a'*12)
            with self.assertRaisesRegex(ValueError,'Sensitive'):
                c.safety(Path(directory))

    def test_no_private_or_raw_dependency(self):
        self.assertNotIn('connections.csv',[p.name for p in c.public_files(ROOT)])
        self.assertNotIn('corroboration.json',[p.name for p in c.public_files(ROOT)])
        self.assertEqual(c.validate()['evidence_records'],9)

    def test_missing_pcap_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError,'Missing local evidence'):
                reproduce.verify(Path(directory)/'absent.pcap','not-installed')

    def test_deterministic_offline_output(self):
        cmd=[sys.executable,'-B','-O',str(ROOT/'scripts/validate.py')]
        a=subprocess.run(cmd,capture_output=True,text=True)
        b=subprocess.run(cmd,capture_output=True,text=True)
        self.assertEqual(a.returncode,0,a.stderr)
        self.assertEqual(b.returncode,0,b.stderr)
        self.assertEqual(a.stdout,b.stdout)


if __name__=='__main__':unittest.main()
