#!/usr/bin/env python3
"""Read official metadata only. Never download executables, build or publish."""
import importlib.util
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import auto_update

def classify(row, policy, known):
    previous = next((entry for entry in known if entry['version'] == row['version']), None)
    if previous:
        for key in ('architecture', 'official_date', 'official_md5', 'official_sha1', 'download_url'):
            if row[key] != previous[key]:
                raise ValueError('Known official release identity changed: ' + key)
    is_new = row['version'] not in policy['baseline_versions']
    if is_new and (row['official_date'] <= policy['bootstrap_at'][:10] or auto_update.version_key(row['version']) <= max(map(auto_update.version_key, policy['baseline_versions']))):
        raise ValueError('Historical/older release is not automatically backfilled')
    return {'official_release': row, 'new_release': is_new, 'build': False, 'publish': False,
            'blocked_reason': policy['rights_block']}

if __name__ == '__main__':
    policy = json.loads((ROOT / '.github/automation/policy.json').read_text())
    known = auto_update.read(ROOT / 'upstream/releases.json')
    row = auto_update.parse_latest(auto_update.fetch_official(auto_update.PAGE, 2*1024*1024).decode('iso-8859-1'))
    result = classify(row, policy, known)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    import os
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as out:
            out.write('Official metadata checked, no binaries downloaded or published.\n\n' + json.dumps(result, ensure_ascii=False, indent=2))
