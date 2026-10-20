import copy
import importlib.util
import json
from pathlib import Path
import unittest
import yaml
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('discovery', Path(__file__).with_name('discover.py'))
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy=json.loads((ROOT/'.github/automation/policy.json').read_text())
        self.known=module.auto_update.read(ROOT/'upstream/releases.json')
        self.row=copy.deepcopy(max(self.known, key=lambda x: module.auto_update.version_key(x['version'])))
    def test_baseline_is_never_replayed(self):
        result=module.classify(self.row,self.policy,self.known)
        self.assertFalse(result['new_release']);self.assertFalse(result['build']);self.assertFalse(result['publish'])
    def test_changed_official_digest_fails_closed(self):
        self.row['official_md5']='0'*32
        with self.assertRaises(ValueError):module.classify(self.row,self.policy,self.known)
    def test_new_release_still_obeys_rights_gate(self):
        self.row.update(version='3.0.0.1',official_date='2026-10-21')
        result=module.classify(self.row,self.policy,self.known)
        self.assertTrue(result['new_release']);self.assertFalse(result['build']);self.assertFalse(result['publish'])
    def test_historical_missing_release_not_backfilled(self):
        self.row.update(version='3.0.0.1',official_date='2026-10-19')
        with self.assertRaises(ValueError):module.classify(self.row,self.policy,self.known)
    def test_all_heavy_workflows_manual_only(self):
        for name in ('auto-update.yml','releases.yml','manual-promote.yml'):
            data=yaml.load((ROOT/'.github/workflows'/name).read_text(),Loader=yaml.BaseLoader)
            self.assertEqual(set(data['on']),{'workflow_dispatch'},name)
            self.assertNotIn('finalize',(ROOT/'.github/workflows'/name).read_text())
    def test_daily_check_does_not_download_or_publish_binaries(self):
        data=yaml.load((ROOT/'.github/workflows/source-sync.yml').read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(set(data['on']),{'schedule','workflow_dispatch'})
        self.assertEqual(data['permissions'],{'contents':'read'})
        self.assertFalse(self.policy['automatic_build']);self.assertFalse(self.policy['automatic_publish'])
    def test_existing_private_guard_retained(self):
        for name in ('auto_update.py','publish.py'):
            source=(ROOT/'tools'/name).read_text()
            self.assertIn("['private']",source)

if __name__=='__main__':unittest.main()
