import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bindSelection, bindExecution, changeSelection, currentReviews, readableMessage, resolveReview, reviewLabel, revisionUrl, selectedReviewAttempt, evidenceLabel, blockingLabel, initialSelection, selectionUrl, prResult, dateTime, unlistedRevisionLabel } from '../web/src/state.ts';

test('revision links use selected repo and refuse missing/malformed identities', () => {
  const snap = { selected_repo: 'road', repo: { road: 'example-org/sample-agentic-cicd-gates' } };
  assert.equal(revisionUrl(snap, 'abcdef1234'), 'https://github.com/example-org/sample-agentic-cicd-gates/commit/abcdef1234');
  assert.equal(revisionUrl(snap, undefined), undefined);
  assert.equal(revisionUrl({ selected_repo: 'x', repo: {} }, 'abcdef12'), undefined);
  assert.equal(revisionUrl(snap, '../../evil'), undefined);
});
test('all evidence states remain distinct from PASS', () => {
  const labels = ['passed', 'blocked', 'blocked_error', 'missing', 'expired', 'unavailable', 'not_reviewed', 'reviewing'].map(state => evidenceLabel({ state, reason: '' }));
  assert.equal(new Set(labels).size, labels.length);
  assert.equal(evidenceLabel(), 'Review unavailable');
});
test('unknown policy is not advisory', () => {
  assert.equal(blockingLabel(null), 'Rule policy unavailable');
  assert.equal(blockingLabel(false), 'Advisory rules');
  assert.equal(blockingLabel(true), 'Can block by rule');
});
test('deep links preserve presenter key and independent PR/revision choices', () => {
  const s = initialSelection('?present=1&repo=road&commit=abcdef12&pr=7&closed=1');
  assert.equal(s.present, true); assert.equal(s.pr, 7); assert.equal(s.commit, 'abcdef12');
  const url = selectionUrl('?present=1&k=test&pr=7', { repo: 'artifact', commit: undefined, pr: undefined });
  assert.equal(url, '?present=1&k=test&repo=artifact');
});
test('root uses the recorded overview and closed PR history; explicit full view survives reload', () => {
  assert.equal(initialSelection('').present, true);
  assert.equal(initialSelection('').closed, true);
  const full = selectionUrl('?present=1&pr=17&closed=1', { present: false, closed: false });
  assert.equal(initialSelection(full).present, false);
  assert.equal(initialSelection(full).closed, false);
  assert.equal(initialSelection(full).pr, 17);
  assert.equal(initialSelection(selectionUrl(full, { present: true })).present, true);
});
test('PR PASS requires all configured reviewers; unavailability wins', () => {
  const snap: any = { panel_meta: [{name: 'Security'}, {name: 'Quality'}], pr: { detail: { pr: {}, reviews: [{persona: 'Security', verdict: 'PASS'}] } } };
  assert.equal(prResult(snap), 'Review evidence missing');
  snap.pr.detail.reviews.push({persona: 'Quality', verdict: 'PASS'});
  assert.equal(prResult(snap), 'Review reports PASS');
  snap.pr.evidence = {state: 'unavailable'};
  assert.equal(prResult(snap), 'Review unavailable');
});
test('execution dates include year and timezone; invalid dates are not fresh', () => {
  assert.match(dateTime('2026-08-18T00:00:00Z'), /2026/);
  assert.equal(dateTime('bad'), 'Unavailable');
});
test('only a confirmed history miss can label a requested revision not found', () => {
  assert.equal(unlistedRevisionLabel({selection_state: 'not_found'}), 'not found in retained history');
  for (const snap of [undefined, null, {}, {selection_state: 'unavailable' as const}, {selection_state: 'selected' as const}]) {
    assert.equal(unlistedRevisionLabel(snap), 'execution history unavailable');
  }
});
test('review and execution links survive reload without dropping server or display parameters', () => {
  const url = selectionUrl('?k=token&focus=pr&stage=1&server=keep', {
    review: 5390249552, execution: 'run/encoded?value', pr: 17, repo: 'artifact',
  });
  const s = initialSelection(url);
  assert.equal(s.review, 5390249552);
  assert.equal(s.execution, 'run/encoded?value');
  assert.equal(s.pr, 17);
  assert.equal(new URLSearchParams(url).get('k'), 'token');
  assert.equal(new URLSearchParams(url).get('stage'), '1');
  for (const invalid of ['0', '-1', '2.5', 'NaN', '9007199254740992'])
    assert.equal(initialSelection(`?review=${invalid}`).review, undefined);
});
test('switches clear only selections that belong to the previous scope', () => {
  const s = initialSelection('?repo=artifact&pr=17&review=5390249552&execution=run1');
  assert.equal(changeSelection(s, {commit: 'abc1234'}).execution, undefined);
  assert.equal(changeSelection({...s, commit: 'abc1234'}, {execution: 'run2'}).commit, undefined);
  assert.equal(changeSelection(s, {execution: 'run2'}).review, s.review);
  assert.equal(changeSelection(s, {pr: 18}).review, undefined);
  assert.equal(changeSelection(s, {pr: 17}).review, s.review);
  const repo = changeSelection(s, {repo: 'road'});
  for (const key of ['commit', 'execution', 'pr', 'review'] as const) assert.equal(repo[key], undefined);
});
test('historical failures and same-head reruns never overwrite current cards', () => {
  const fail = { id: 1, persona: 'Security', verdict: 'FAIL', commit_id: 'abc', state: 'DISMISSED', is_current: false, run_attempt: 1 };
  const pass = { ...fail, id: 2, verdict: 'PASS', state: 'COMMENTED', is_current: true, run_attempt: 2 };
  const snap: any = { panel_meta: [{name: 'Security'}], pr: { detail: {
    pr: {head: 'abc'}, reviews: [fail, pass], history: [pass, fail] } } };
  assert.equal(prResult(snap), 'Review reports PASS');
  assert.deepEqual(currentReviews(snap.pr.detail).map(r => r.id), [2]);
  assert.equal(snap.pr.detail.history.length, 2);
  snap.pr.detail.reviews = [fail];
  assert.equal(prResult(snap), 'Review evidence missing');
  snap.pr.detail.reviews = [{ ...pass, error: 'LOCAL TEST FIXTURE: report parts missing' }];
  assert.equal(prResult(snap), 'Reports a review error');
});
test('message decoding retains the full tail and keeps HTML as text', () => {
  const message = 'LOCAL TEST FIXTURE: '.repeat(80) + '\\`&lt;img onerror=alert\\(1\\)&gt;\\` FINAL_TAIL';
  const value = readableMessage(message);
  assert.ok(value.endsWith('`<img onerror=alert(1)>` FINAL_TAIL'));
  assert.ok(value.length > 430);
});
test('publication evidence failures stay distinct from model errors or a clean PASS', () => {
  const review: any = { persona: 'Security', verdict: 'PASS', state: 'COMMENTED', error: 'Missing publication part',
    evidence: {state: 'unavailable', reason: 'Missing publication part'} };
  const snap: any = { panel_meta: [{name: 'Security'}], pr: { detail: {pr: {head: 'abc'}, reviews: [review]} } };
  assert.equal(reviewLabel(review), 'Review unavailable');
  assert.equal(prResult(snap), 'Review unavailable');
  review.evidence.state = 'missing';
  assert.equal(reviewLabel(review), 'Evidence missing');
  assert.equal(prResult(snap), 'Review evidence missing');
  review.evidence.state = 'available';
  review.verdict = 'BLOCKED_ERROR';
  assert.equal(reviewLabel(review), 'Review error');
  assert.equal(prResult(snap), 'Reports a review error');
});
test('an old server ignoring execution cannot display another run as the requested one', () => {
  const snap: any = { execution: 'new', commit: {sha: 'abc'}, findings: {tier1: {verdict: 'PASS'}},
    execution_status: 'Succeeded', pipelines: {p: {name: 'p', stages: [{status: 'Succeeded'}]}},
    pr: { detail: { pr: {number: 17} } }, failures: [{reason: 'other run'}], approval: {} };
  const safe = bindExecution(snap, 'old');
  assert.equal(safe.execution, null);
  assert.equal(safe.findings.tier1, null);
  assert.equal(safe.commit, null);
  assert.equal(safe.pipelines.p.stages.length, 0);
  assert.equal(safe.approval, null);
  assert.deepEqual(safe.failures, []);
  assert.equal(safe.pr, snap.pr);
  assert.match(safe.selection_error!, /different execution/);
  assert.equal(bindExecution(snap, 'new'), snap);
  assert.equal(bindExecution(snap, 'new', 'abc'), snap);
  assert.equal(bindExecution(snap, 'new', 'wrong-sha').execution, null);
});
test('continuation review IDs remain aliases after the primary part appears', () => {
  const orphan: any = {id: 22, review_ids: [22]};
  const complete: any = {id: 11, review_ids: [11, 22]};
  assert.equal(resolveReview([orphan], 22), orphan);
  assert.equal(resolveReview([complete], 22), complete);
  assert.equal(resolveReview([complete], 11), complete);
  assert.equal(resolveReview([complete], 33), undefined);
  assert.equal(resolveReview([complete, orphan], 22), orphan);
  assert.equal(resolveReview([complete, {...complete, id: 33}], 22), undefined);
});
test('review build links roundtrip and reset on pipeline scope changes, independently of PR', () => {
  const s = initialSelection(selectionUrl('?repo=artifact&pr=17&execution=run1&review=22', {review_build: 'project:build/with+encoding'}));
  assert.equal(s.review_build, 'project:build/with+encoding');
  for (const change of [{execution: 'run2'}, {commit: 'abc'}, {repo: 'road'}])
    assert.equal(changeSelection(s, change).review_build, undefined);
  assert.equal(changeSelection(s, {pr: 18}).review_build, s.review_build);
  assert.equal(changeSelection(s, {review: 33}).review_build, s.review_build);
});
test('attempt reports require build membership and consistent execution, revision and evidence', () => {
  const report: any = {verdict: 'FAIL', agents: [], findings: []};
  const snap: any = {execution: 'run', commit: {sha: 'abc'}, pipelines: {}, review_attempts: [{build_id: 'build'}],
    review_attempt: {build_id: 'build', report, evidence: {state: 'blocked', reason: 'fixture', execution_id: 'run', revision: 'abc', build_id: 'build'}}};
  assert.equal(selectedReviewAttempt(snap, 'build').report, report);
  assert.equal(selectedReviewAttempt(snap, 'other').report, null);
  assert.equal(selectedReviewAttempt({...snap, review_attempts: undefined}, 'build').report, null);
  assert.equal(selectedReviewAttempt({...snap, review_attempt: undefined}, 'build').report, null);
  for (const mismatch of [{execution_id: 'other'}, {revision: 'other'}, {build_id: 'other'}]) {
    const bad = {...snap, review_attempt: {...snap.review_attempt, evidence: {...snap.review_attempt.evidence, ...mismatch}}};
    assert.equal(selectedReviewAttempt(bad, 'build').report, null);
    assert.match(selectedReviewAttempt(bad, 'build').evidence!.reason, /does not match/);
  }
  for (const state of ['expired', 'missing', 'unavailable']) {
    const unavailable = {...snap, review_attempt: {...snap.review_attempt, report: {verdict: 'PASS'},
      evidence: {...snap.review_attempt.evidence, state}}};
    assert.equal(selectedReviewAttempt(unavailable, 'build').report, null);
    assert.equal(selectedReviewAttempt(unavailable, 'build').evidence!.state, state);
  }
  assert.equal(bindExecution(snap, 'wrong').review_attempt, undefined);
});


test('all scoped evidence is cleared when a server returns another repository', () => {
  const snap: any = {selected_repo:'artifact', commit:{sha:'aaa'}, execution:'run-a',
    pipelines:{p:{name:'p',stages:[{name:'Deploy'}],console:'https://example.test'}},
    findings:{tier1:{verdict:'PASS'},tier2:null,tier3:null},health:{state:'completed'},
    feed:[{text:'foreign event'}],pr:{open:[],detail:{pr:{number:17}}},commits:[{sha:'aaa'}],
    repo:{artifact:'owner/artifact',road:'owner/road'},site:'https://app.example.com'};
  const bound=bindSelection(snap,{repo:'road'});
  assert.equal(bound.selection_state,'unavailable');
  for(const field of ['health','review_attempt','panel_progress']) assert.ok(!bound[field]);
  assert.deepEqual(bound.feed,[]);assert.deepEqual(bound.pipelines,{});
  assert.equal(bound.pr.detail,null);assert.equal(bound.findings.tier1,null);
  assert.equal(bound.site,'');
});
test('revision-only and PR selections are bound even without an execution parameter', () => {
 const snap:any={selected_repo:'artifact',commit:{sha:'aaa'},execution:'run-a',
  pipelines:{},pr:{open:[],detail:{pr:{number:17}}},feed:[{text:'old event'}]};
 assert.equal(bindSelection(snap,{commit:'bbb'}).selection_state,'unavailable');
 assert.equal(bindSelection(snap,{pr:18}).pr.detail,null);
 assert.equal(bindSelection(snap,{repo:'artifact',commit:'aaa',execution:'run-a',pr:17}),snap);
});
