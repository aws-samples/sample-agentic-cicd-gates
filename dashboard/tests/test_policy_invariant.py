"""The deployed bundle, not Python source literals, defines the dashboard panel."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from deterministic.checks import check_panel_config_mirror


class PolicyInvariantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / 'dashboard/app'
        self.app.mkdir(parents=True)
        self.handler = self.app / 'handler.py'
        self.handler.write_text('# Loads a JSON policy; no model or reviewer name literals.\n')
        self.policy = {
            'version': 1,
            'defaults': {'confidence_threshold': 80},
            'agents': [{'name': 'New reviewer', 'model': 'new.model', 'thinking': 'high',
                        'rules': ['NEW-'], 'file_patterns': ['**/*.py']}],
            'rules': [{'id': 'NEW-1', 'blocking': True, 'severity': 'high'}],
        }
        self.write_policy()
        self.bundle()

    def write_policy(self):
        (self.root / '.reviewer.yaml').write_text(yaml.safe_dump(self.policy))

    def bundle(self):
        raw = (self.root / '.reviewer.yaml').read_bytes()
        self.data = {'sha256': hashlib.sha256(raw).hexdigest(),
                     'source': '.reviewer.yaml', 'agents': self.policy['agents'],
                     'rules': self.policy['rules']}
        self.write_bundle()

    def write_bundle(self):
        (self.app / 'panel_policy.json').write_text(json.dumps(self.data))

    def test_derived_handler_needs_no_hardcoded_names_or_models(self):
        self.assertEqual(check_panel_config_mirror(self.root), [])

    def test_renamed_reviewer_and_model_pass_after_regeneration(self):
        self.policy['agents'][0].update(name='Renamed reviewer', model='another.model')
        self.write_policy()
        self.bundle()
        self.assertEqual(check_panel_config_mirror(self.root), [])

    def test_stale_bundled_model_and_added_agent_fail(self):
        self.policy['agents'][0]['model'] = 'updated.model'
        self.policy['agents'].append({'name': 'Second reviewer', 'rules': ['NEW-']})
        self.write_policy()
        findings = check_panel_config_mirror(self.root)
        self.assertTrue(any('agents differ' in f for f in findings))
        self.assertTrue(any('digest is stale' in f for f in findings))

    def test_forged_digest_cannot_hide_wrong_blocking_flag(self):
        self.data = json.loads((self.app / 'panel_policy.json').read_text())
        self.data['rules'][0]['blocking'] = False
        self.write_bundle()  # Original, correct source hash; tampered contents.
        self.assertTrue(any('rules differ' in f for f in check_panel_config_mirror(self.root)))

    def test_scope_and_thinking_drift_are_checked(self):
        for field, value in [('thinking', 'low'), ('file_patterns', ['**/*.js']), ('rules', ['OTHER-'])]:
            with self.subTest(field=field):
                self.bundle()
                self.data = json.loads((self.app / 'panel_policy.json').read_text())
                self.data['agents'][0][field] = value
                self.write_bundle()
                self.assertTrue(any('agents differ' in f for f in check_panel_config_mirror(self.root)))

    def test_removed_rule_fails_even_when_names_and_models_match(self):
        self.data['rules'] = []
        self.write_bundle()
        self.assertTrue(any('rules differ' in f for f in check_panel_config_mirror(self.root)))

    def test_policy_default_changes_require_new_source_digest(self):
        self.policy['defaults']['confidence_threshold'] = 90
        self.write_policy()
        self.assertTrue(any('digest is stale' in f for f in check_panel_config_mirror(self.root)))

    def test_missing_and_malformed_bundle_fail_closed(self):
        bundle = self.app / 'panel_policy.json'
        bundle.unlink()
        self.assertTrue(check_panel_config_mirror(self.root))
        bundle.write_text('{broken')
        self.assertTrue(check_panel_config_mirror(self.root))
        bundle.write_text('[]')
        self.assertTrue(check_panel_config_mirror(self.root))

    def test_missing_or_malformed_source_fails_closed(self):
        source = self.root / '.reviewer.yaml'
        source.unlink()
        self.assertTrue(check_panel_config_mirror(self.root))
        source.write_text('agents: [broken')
        self.assertTrue(check_panel_config_mirror(self.root))

    def test_repository_without_dashboard_is_not_subject_to_this_invariant(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(check_panel_config_mirror(Path(directory)), [])


if __name__ == '__main__':
    unittest.main()
