"""Offline dashboard regressions: all AWS and GitHub reads are mocked."""
import io
import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
with patch('boto3.client'):
    import handler as h
from evidence import pages, IncompleteEvidence, report_state, matches_execution, panel_from_policy

NOW = datetime(2026, 8, 18, tzinfo=timezone.utc)
SHA = 'a' * 40
OTHER = 'b' * 40


def published_review(review_id, head, verdict="PASS", run=50, attempt=1,
                     submitted="2026-08-18T00:01:00Z"):
    persona = "Security Review Agent"
    seat = hashlib.sha256(persona.encode()).hexdigest()[:16]
    return {"id": review_id, "commit_id": head, "state": "COMMENTED",
            "user": {"id": 41898282, "login": "github-actions[bot]", "type": "Bot"},
            "body": (f"<!-- agentic-review:v2 repo=test/r pr=7 reviewer={seat} head={head} "
                     f"run={run} attempt={attempt} part=1 -->\n"
                     f"## 🛡️ {persona}: **{verdict}**\n\n"
                     f"[Workflow run](https://github.com/test/r/actions/runs/{run}/attempts/{attempt})\n\n"
                     "| 0 | 0 | 0 | `test-model` | high |\n"),
            "submitted_at": submitted, "html_url": f"https://github.com/test/r/pull/7#pullrequestreview-{review_id}"}


def report(**kw):
    return {'verdict': 'PASS', 'agents': [{'name': n, 'verdict': 'PASS'} for n in h.PERSONAS],
            'findings': [], 'stats': {'blocking': 0, 'total': 0}, **kw}


def pipeline(action='Review', ext='agentic-gates-tier1-review:old-build', status='Succeeded'):
    return {'execution_id': 'selected-run', 'stages': [{'name': 'AutomatedGates', 'actions': [
        {'name': action, 'status': status, 'external_id': ext, 'started': str(NOW), 'when': str(NOW)}]}]}


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        h._last_errors.clear(); h._cache.clear(); h._gh_errors.clear()
        self.cp = patch.object(h, '_cp', Mock()).start()
        self.logs = patch.object(h, '_logs', Mock()).start()
        self.logs.filter_log_events.return_value = {'events': []}
        self.s3 = patch.object(h, '_s3', Mock()).start()
        self.addCleanup(patch.stopall)

    def test_pagination_follows_empty_pages_and_finds_old_gate_reason(self):
        self.logs.filter_log_events.side_effect = [
            {'events': [], 'nextToken': 'two'},
            {'events': [{'message': 'THREAT-MODEL GATE: FAIL'}, {'message': '  - update required'}]}]
        self.assertEqual(h._build_log_excerpt('agentic-gates-tier1-threatmodel:old'),
                         ['THREAT-MODEL GATE: FAIL', '  - update required'])
        args = self.logs.filter_log_events.call_args_list
        self.assertNotIn('startTime', args[0].kwargs)
        self.assertEqual(args[1].kwargs['nextToken'], 'two')

    def test_cloudformation_external_url_is_not_a_codebuild_log(self):
        external = 'stack/detail?stackId=arn:aws:cloudformation:us-west-2:123456789012:stack/demo/id'
        self.assertEqual(h._build_log_excerpt(external), [])
        self.assertEqual(h._build_log_excerpt('https://console.aws.amazon.com/' + external), [])
        self.logs.filter_log_events.assert_not_called()
        self.assertNotIn('logs', h._last_errors)

    def test_pagination_rejects_incomplete_and_repeated_tokens(self):
        for response in ({'events': [], 'nextToken': 'again'},):
            with self.assertRaises(IncompleteEvidence): pages(Mock(return_value=response), 'events')
        with self.assertRaises(IncompleteEvidence):
            pages(Mock(return_value={'events': [], 'nextToken': 'x'}), 'events', max_pages=1)

    def test_old_revision_lookup_paginates_no_unrelated_fallback(self):
        self.cp.list_pipeline_executions.side_effect = [
            {'pipelineExecutionSummaries': [{'pipelineExecutionId': 'new', 'sourceRevisions': [{'revisionId': OTHER}]}], 'nextToken': 'next'},
            {'pipelineExecutionSummaries': [{'pipelineExecutionId': 'old', 'sourceRevisions': [{'revisionId': SHA}]}]}]
        self.assertEqual(h._exec_for('p', SHA), 'old')
        self.cp.list_pipeline_executions.side_effect = None
        self.cp.list_pipeline_executions.return_value = {'pipelineExecutionSummaries': []}
        self.assertIsNone(h._exec_for('p', SHA))

    def test_live_action_fallback_cannot_cross_execution(self):
        self.cp.get_pipeline_state.return_value = {'stageStates': [{'stageName': 'AutomatedGates', 'actionStates': [
            {'actionName': 'Review', 'latestExecution': {'actionExecutionId': 'new-attempt',
               'externalExecutionId': 'agentic-gates-tier1-review:new-build'}}]}]}
        self.cp.list_action_executions.return_value = {'actionExecutionDetails': [
            {'stageName': 'AutomatedGates', 'actionName': 'Review', 'actionExecutionId': 'old-attempt', 'status': 'InProgress'}]}
        view, build, _ = h._pipeline_view('p', 'selected-run', [], [])
        self.assertIsNone(build)
        self.assertIsNone(view['stages'][0]['actions'][0]['external_id'])
        self.cp.list_action_executions.return_value['actionExecutionDetails'][0]['actionExecutionId'] = 'new-attempt'
        _, build, _ = h._pipeline_view('p', 'selected-run', [], [])
        self.assertEqual(build, 'new-build')

    def test_no_execution_does_not_use_live_stage(self):
        self.cp.get_pipeline_state.return_value = {'stageStates': [{'stageName': 'Deploy', 'actionStates': [
            {'actionName': 'Deploy', 'latestExecution': {'status': 'Succeeded'}}]}]}
        view, _, _ = h._pipeline_view('p', None, [], [])
        self.assertEqual(view['stages'][0]['status'], 'NotStarted')

    def test_action_read_error_is_unavailable_not_notstarted(self):
        self.cp.get_pipeline_state.return_value = {'stageStates': [{'stageName': 'AutomatedGates', 'actionStates': [{'actionName': 'Review'}]}]}
        self.cp.list_action_executions.side_effect = RuntimeError('denied')
        view, _, _ = h._pipeline_view('p', 'run', [], [])
        self.assertEqual(view['stages'][0]['status'], 'Unavailable')

    def test_rules_derive_blocking_from_owned_metadata(self):
        meta = panel_from_policy(h.PANEL_POLICY)
        self.assertFalse(next(m['blocking'] for m in meta if m['name'] == 'Code Quality Review Agent'))
        config = {'agents': [{'name': 'custom', 'rules': ['NEW-']}], 'rules': [{'id': 'NEW-1', 'blocking': True}]}
        self.assertTrue(panel_from_policy(config)[0]['blocking'])
        config['rules'][0]['blocking'] = False
        self.assertFalse(panel_from_policy(config)[0]['blocking'])

    def test_empty_reviewer_scope_owns_all_rules_like_the_runtime(self):
        config = {'agents': [{'name': 'all-rules reviewer', 'rules': []}],
                  'rules': [{'id': 'NEW-1', 'blocking': True}]}
        meta = panel_from_policy(config)[0]
        self.assertTrue(meta['blocking'])
        self.assertEqual(meta['rules'], 'all rules')

    def test_invalid_bundle_never_invents_advisory_labels(self):
        for config in ({}, {'agents': [], 'rules': []},
                       {'agents': [{'name': 'test', 'rules': []}], 'rules': [{'id': 'NEW-1'}]}):
            with self.assertRaises(ValueError):
                panel_from_policy(config)

    def test_missing_panel_metadata_cannot_validate_a_clean_review(self):
        self.s3.get_object.return_value = {'Body': io.BytesIO(json.dumps(report()).encode())}
        with patch.object(h, '_reports_bucket', return_value='bucket'), patch.object(h, 'PERSONAS', []):
            _, state = h._execution_findings('tier1', pipeline(), SHA)
        self.assertEqual(state['state'], 'unavailable')
        self.assertIn('metadata unavailable', state['reason'])

    def test_report_states_never_conflate_missing_error_and_pass(self):
        self.assertEqual(report_state(report())['state'], 'passed')
        self.assertEqual(report_state(report(verdict='FAIL'))['state'], 'blocked')
        self.assertEqual(report_state(report(verdict='BLOCKED_ERROR'))['state'], 'blocked_error')
        self.assertEqual(report_state(report(error='timeout'))['state'], 'unavailable')
        self.assertEqual(report_state(report(agents=[]))['state'], 'unavailable')
        self.assertEqual(report_state(report(expires_at='2020-01-01T00:00:00Z'))['state'], 'expired')

    def test_revision_is_not_execution_provenance(self):
        self.assertFalse(matches_execution({'revision': SHA}, 'selected-run'))
        self.assertFalse(matches_execution({'execution_id': 'other'}, 'selected-run'))
        self.assertTrue(matches_execution({'execution_id': 'selected-run'}, 'selected-run'))

    def test_legacy_s3_report_cannot_pass_a_retry(self):
        from botocore.exceptions import ClientError
        missing = ClientError({'Error': {'Code': 'NoSuchKey'}}, 'GetObject')
        self.s3.get_object.side_effect = [missing, {'Body': io.BytesIO(json.dumps(report()).encode())}]
        with patch.object(h, '_reports_bucket', return_value='bucket'):
            doc, state = h._execution_findings('tier1', pipeline(), SHA)
        self.assertIsNone(doc); self.assertEqual(state['state'], 'unavailable')

    def test_bound_s3_report_and_expiry(self):
        for expected, extra in [('passed', {}), ('expired', {'expires_at': '2020-01-01T00:00:00Z'})]:
            self.s3.get_object.return_value = {'Body': io.BytesIO(json.dumps(report(**extra)).encode())}
            with patch.object(h, '_reports_bucket', return_value='bucket'):
                _, state = h._execution_findings('tier1', pipeline(), SHA)
            self.assertEqual(state['state'], expected)

    def test_403_does_not_mean_expired_and_404_means_missing(self):
        from botocore.exceptions import ClientError
        for code, expected in [('AccessDenied', 'unavailable'), ('NoSuchKey', 'missing')]:
            self.s3.get_object.side_effect = ClientError({'Error': {'Code': code}}, 'GetObject')
            with patch.object(h, '_reports_bucket', return_value='bucket'):
                doc, state = h._execution_findings('tier1', pipeline(), SHA)
            self.assertIsNone(doc); self.assertEqual(state['state'], expected)

    def test_tier3_reads_exact_old_stream_across_pages(self):
        self.logs.filter_log_events.side_effect = [{'events': [], 'nextToken': 'two'},
            {'events': [{'message': json.dumps(report()), 'timestamp': 1000}]}]
        _, state = h._execution_findings('tier3', pipeline('KiroReview', 'agentic-gates-tier3-kiro:old'), SHA)
        self.assertEqual(state['state'], 'passed')
        self.assertEqual(self.logs.filter_log_events.call_args.kwargs['logStreamNames'], ['old'])

    def test_tier2_does_not_take_unbound_latest_lambda_report(self):
        self.logs.filter_log_events.return_value = {'events': [{'message': json.dumps(report()), 'timestamp': 1000}]}
        doc, state = h._execution_findings('tier2', pipeline(ext='lambda-request'), SHA)
        self.assertIsNone(doc); self.assertEqual(state['state'], 'unavailable')

    def test_tier2_takes_the_lambda_report_that_names_this_run(self):
        """The gate logs review_input.pipeline_execution_id; only a match binds."""
        for run, expected in (('selected-run', 'passed'), ('other-run', 'unavailable')):
            self.logs.filter_log_events.return_value = {'events': [{'message': json.dumps(
                report(review_input={'job_id': 'job', 'pipeline_execution_id': run})),
                'timestamp': 1000}]}
            _, state = h._execution_findings('tier2', pipeline(ext='agentic-gates-tier2-gate'), SHA)
            self.assertEqual(state['state'], expected, run)

    def test_requested_missing_revision_is_not_latest(self):
        with patch.object(h, '_commits', return_value=[{'sha': OTHER, 'execution_id': 'other'}]), \
             patch.object(h, '_pipeline_view', return_value=({'stages': []}, None, None)), \
             patch.object(h, '_exec_for', return_value=None), \
             patch.object(h, '_pr_surface', return_value={'open': []}):
            snap = h.build_snapshot(commit_sha=SHA)
        self.assertIsNone(snap['commit']); self.assertIsNone(snap['execution'])
        self.assertIsNotNone(snap['selection_error'])

    def test_pr_review_and_findings_filter_to_head_and_latest_run(self):
        pr = {'number': 7, 'title': 'test', 'head': {'sha': SHA}, 'html_url': 'https://github.com/test/r/pull/7',
              'state': 'open', 'updated_at': str(NOW)}
        reviews = [published_review(n, sha) for n, sha in [(1, OTHER), (2, SHA)]]
        def reads(path, *args, **kw):
            if '/pulls?' in path: return [pr]
            if '/actions/runs?' in path: return {'workflow_runs': [
                {'id': 50, 'head_sha': SHA, 'event': 'pull_request', 'name': 'Agentic review',
                 'status': 'completed', 'run_attempt': 1}]}
            if '/jobs?' in path: return {'jobs': []}
            if '/reviews?' in path: return reviews
            if '/comments?' in path: return []
            raise AssertionError(path)
        with patch.object(h, '_gh', side_effect=reads): result = h._pr_surface([], 7, 'test/r')
        self.assertEqual([r['id'] for r in result['detail']['reviews']], [2])

    def test_another_branchs_newer_run_on_the_same_commit_is_not_this_prs(self):
        """PR #29's run #45 and closed PR #31's run #47 share one head commit.

        #47 lists no pull request once #31 closes; it must not displace #45,
        whether #45 still lists its pull request or not.
        """
        pr = {'number': 7, 'title': 'test', 'head': {'sha': SHA, 'ref': 'formatting'},
              'html_url': 'https://github.com/test/r/pull/7', 'state': 'open', 'updated_at': str(NOW)}
        other = {'id': 47, 'run_number': 47, 'workflow_id': 5, 'head_sha': SHA, 'head_branch': 'cycle',
                 'event': 'pull_request', 'name': 'Agentic review', 'status': 'completed',
                 'run_attempt': 1, 'pull_requests': []}
        for own_prs in ([{'number': 7}], []):
            own = {**other, 'id': 45, 'run_number': 45, 'head_branch': 'formatting',
                   'pull_requests': own_prs}
            jobs_read = []
            def reads(path, *args, **kw):
                if '/pulls?' in path: return [pr]
                if '/actions/runs?' in path: return {'workflow_runs': [other, own]}
                if '/jobs?' in path: jobs_read.append(path); return {'jobs': []}
                if '/reviews?' in path: return [published_review(2, SHA, run=45)]
                if '/comments?' in path: return []
                raise AssertionError(path)
            h._cache.clear()
            with patch.object(h, '_gh', side_effect=reads): result = h._pr_surface([], 7, 'test/r')
            self.assertEqual([r['id'] for r in result['detail']['reviews']], [2], own_prs)
            self.assertEqual([p.split('/jobs')[0] for p in jobs_read], ['/repos/test/r/actions/runs/45'])

    def test_github_failure_is_explicit(self):
        with patch.object(h, '_gh', return_value=None): result = h._pr_surface([], 7, 'test/r')
        self.assertEqual(result['evidence']['state'], 'unavailable')
        self.assertIsNone(result['detail'])


class MoreEvidenceTests(unittest.TestCase):
    setUp = EvidenceTests.setUp
    # Additional adversarial cases discovered during the UI/integration review.
    def test_pretty_report_split_across_pages_is_recoverable(self):
        from botocore.exceptions import ClientError
        self.s3.get_object.side_effect = ClientError({'Error': {'Code': 'NoSuchKey'}}, 'GetObject')
        lines = json.dumps(report(), indent=2).splitlines()
        self.logs.filter_log_events.side_effect = [
            {'events': [{'message': line} for line in lines[:3]], 'nextToken': 'two'},
            {'events': [{'message': line} for line in lines[3:]]}]
        with patch.object(h, '_reports_bucket', return_value='bucket'):
            doc, state = h._execution_findings('tier1', pipeline(), SHA)
        self.assertEqual(state['state'], 'passed')
        self.assertEqual(doc['verdict'], 'PASS')
        self.assertEqual(self.logs.filter_log_events.call_args.kwargs['logStreamNames'], ['old-build'])

    def test_queued_same_head_rerun_hides_old_pass(self):
        pr = {'number': 7, 'title': 'test', 'head': {'sha': SHA}, 'html_url': 'https://github.com/test/r/pull/7',
              'state': 'open', 'updated_at': str(NOW)}
        old = published_review(1, SHA)
        run = {'id': 50, 'workflow_id': 5, 'head_sha': SHA, 'event': 'pull_request',
               'name': 'Agentic review gate', 'status': 'queued', 'created_at': '2026-08-18T00:02:00Z'}
        def reads(path, *args, **kw):
            if '/pulls?' in path: return [pr]
            if '/actions/runs?' in path: return {'workflow_runs': [run]}
            if '/jobs?' in path: return {'jobs': []}
            if '/reviews?' in path: return [old]
            if '/comments?' in path: return []
            raise AssertionError(path)
        with patch.object(h, '_gh', side_effect=reads): result = h._pr_surface([], 7, 'test/r')
        self.assertEqual(result['detail']['reviews'], [])
        self.assertTrue(result['detail']['review_running'])

    def test_explicit_revision_mismatch_rejected(self):
        self.s3.get_object.return_value = {'Body': io.BytesIO(json.dumps(report(revision=OTHER)).encode())}
        with patch.object(h, '_reports_bucket', return_value='bucket'):
            doc, state = h._execution_findings('tier1', pipeline(), SHA)
        self.assertIsNone(doc); self.assertEqual(state['state'], 'unavailable')

    def test_bundle_matches_actual_rule_source(self):
        import hashlib
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(h.PANEL_POLICY['sha256'], hashlib.sha256((root / '.reviewer.yaml').read_bytes()).hexdigest())

    def test_build_bound_legacy_report_preserves_review_input_metadata(self):
        from botocore.exceptions import ClientError
        missing = ClientError({'Error': {'Code': 'NoSuchKey'}}, 'GetObject')
        doc = report(build_id='agentic-gates-tier1-review:old-build',
                     review_input={'pipeline_execution_id': 'selected-run',
                                  'head_revision': SHA, 'policy_sha256': 'test-policy'})
        self.s3.get_object.side_effect = [missing, {'Body': io.BytesIO(json.dumps(doc).encode())}]
        with patch.object(h, '_reports_bucket', return_value='bucket'):
            got, state = h._execution_findings('tier1', pipeline(), SHA)
        self.assertEqual(state['state'], 'passed')
        self.assertEqual(state['policy_sha256'], 'test-policy')
        self.assertIsNotNone(got)
        self.logs.filter_log_events.assert_not_called()

    def test_conflicting_provenance_cannot_be_ignored(self):
        doc = report(execution_id='selected-run', review_input={'pipeline_execution_id': 'other'})
        self.assertFalse(matches_execution(doc, 'selected-run'))


if __name__ == '__main__': unittest.main()
