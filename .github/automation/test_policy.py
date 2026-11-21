import copy
import importlib.util
import json
from email.message import Message
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch
import yaml
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('discovery', Path(__file__).with_name('discover.py'))
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy=json.loads((ROOT/'.github/automation/policy.json').read_text())
        self.known=module.auto_update.read(ROOT/'upstream/releases.json')
        self.row=copy.deepcopy(max(self.known, key=lambda x: module.auto_update.version_key(x['version'])))
    def test_metadata_fetch_does_not_follow_archive_redirect(self):
        with self.assertRaisesRegex(ValueError, 'redirected'):
            module.NoRedirect().redirect_request(None, None, 302, '', None, self.row['download_url'])

    def test_metadata_fetch_rejects_non_html_before_read(self):
        for url, content_type in (
            (module.auto_update.PAGE, 'application/zip'),
            (self.row['download_url'], 'text/html'),
            (module.auto_update.PAGE, None),
        ):
            with self.subTest(url=url, content_type=content_type):
                response = MagicMock()
                response.geturl.return_value = url
                response.headers = Message()
                if content_type is not None:
                    response.headers['Content-Type'] = content_type
                with patch.object(module.urllib.request, 'build_opener') as opener:
                    opener.return_value.open.return_value.__enter__.return_value = response
                    with self.assertRaisesRegex(ValueError, 'HTML metadata'):
                        module.fetch_metadata_html()
                    response.read.assert_not_called()

    def test_metadata_fetch_accepts_only_bounded_html(self):
        with patch.object(module.urllib.request, 'build_opener') as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.geturl.return_value = module.auto_update.PAGE
            response.headers = Message()
            response.headers['Content-Type'] = 'text/html; charset=utf-8'
            response.read.return_value = b'<table></table>'
            self.assertEqual(module.fetch_metadata_html(), '<table></table>')
            opener.return_value.open.assert_called_once_with(module.auto_update.PAGE, timeout=60)
            response.read.assert_called_once_with(module.MAX_HTML_BYTES + 1)
            response.read.return_value = b'x' * (module.MAX_HTML_BYTES + 1)
            with self.assertRaisesRegex(ValueError, 'size limit'):
                module.fetch_metadata_html()

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
    def test_candidate_and_promotion_workflows_manual_only(self):
        for name in ('auto-update.yml','releases.yml','manual-promote.yml'):
            data=yaml.load((ROOT/'.github/workflows'/name).read_text(),Loader=yaml.BaseLoader)
            self.assertEqual(set(data['on']),{'workflow_dispatch'},name)
            self.assertNotIn('finalize',(ROOT/'.github/workflows'/name).read_text())
    def test_daily_check_does_not_download_or_publish_binaries(self):
        data=yaml.load((ROOT/'.github/workflows/source-sync.yml').read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(set(data['on']),{'schedule','workflow_dispatch'})
        self.assertEqual(data['permissions'],{'contents':'read'})
        self.assertFalse(self.policy['automatic_build']);self.assertFalse(self.policy['automatic_publish'])
    def test_public_candidate_workflows_allow_only_metadata_or_source_steps(self):
        # Exact allow-list: no artifact paths (including broad directories),
        # binary builders, downstream smoke jobs, custom env or write permissions.
        for name, job_name, command in (
            ('auto-update.yml', 'check', 'python .github/automation/discover.py'),
            ('releases.yml', 'validate', 'python -m unittest discover -s tests -p test_auto_update.py -v'),
            ('source-sync.yml', 'discover', 'python .github/automation/discover.py'),
        ):
            with self.subTest(workflow=name):
                data=yaml.load((ROOT/'.github/workflows'/name).read_text(),Loader=yaml.BaseLoader)
                self.assertEqual(set(data)-{'concurrency'}, {'name','on','permissions','jobs'})
                self.assertEqual(data['permissions'], {'contents':'read'})
                self.assertEqual(set(data['jobs']), {job_name})
                job=data['jobs'][job_name]
                self.assertEqual(set(job), {'runs-on','timeout-minutes','steps'})
                checkout={'persist-credentials':'false'}
                if name=='source-sync.yml':
                    checkout['ref']='main'
                self.assertEqual(job['steps'], [
                    {'uses':'actions/checkout@v4','with':checkout},
                    {'uses':'actions/setup-python@v5','with':{'python-version':'3.12'}},
                    {'run':command},
                ])
    def test_existing_private_guard_retained(self):
        for name in ('auto_update.py','publish.py'):
            source=(ROOT/'tools'/name).read_text()
            self.assertIn("['private']",source)

if __name__=='__main__':unittest.main()
