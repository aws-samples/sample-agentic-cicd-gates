async page => {
  // LOCAL TEST FIXTURES / CAPTURED RESPONSE REPLAY — NOT LIVE EVIDENCE.
  // Security body below is copied verbatim from PR17's captured GitHub response.
  const capturedSecurity = {
  "id": 5390249552,
  "body": "<!-- agentic-review:v2 repo=example-org/sample-agentic-cicd-artifact pr=17 reviewer=0cf9b9ba2bed46c3 head=3fb747691aeb3a7c9d2616ab515459d556a1f34c run=36989897144 attempt=1 part=1 -->\n## 🛡️ Security Review Agent: **FAIL**\n\nBot-generated review of `3fb747691aeb3a7c9d2616ab515459d556a1f34c`; rules/tooling base `eaedd818a897b0d44e2e3ec8efe7fc83734c0996`.\n\n[Workflow run](https://github.com/example-org/sample-agentic-cicd-artifact/actions/runs/36989897144/attempts/1) · 2026-10-02T09:28:37.477094+00:00\n\n| blocking | total | suppressed below threshold | model | configured thinking |\n|---|---|---|---|---|\n| 1 | 1 | 0 | `us.anthropic.claude-opus-5` | extra-high |\n\nPolicy is repeatable; model findings can be wrong or incomplete. PASS means no retained blocking findings, not human approval. Checks report results; merge enforcement depends on repository settings.\n\n### Finding\n\n**SEC-003** — high, blocking, confidence 89\n\nsrc/handler.py:37\n\nUnescaped query-string value reaches an HTML response sink. \\`ded = \\(event.get\\(\"queryStringParameters\"\\) or \\{\\}\\).get\\(\"dedication\"\\)\\` takes attacker-controlled input straight from the request URL and splices it into the page markup via \\`page.replace\\(DEDICATION\\_DEFAULT, ded\\)\\`, which is then returned with statusCode 200 as the HTML body. A request like \\`?dedication=&lt;img src=x onerror=alert\\(document.cookie\\)&gt;\\` \\(or a \\`&lt;/script&gt;\\` breakout, or \\`javascript:\\` in an attribute context\\) yields reflected/DOM XSS. Note the adjacent line escapes the far-less-trusted-looking \\`AWS\\_LAMBDA\\_FUNCTION\\_VERSION\\` with \\`escape\\(\\)\\`, so the omission here is inconsistent as well as unsafe. Apply \\`html.escape\\(ded, quote=True\\)\\` \\(already imported\\) or validate against a strict allowlist before substitution.\n\nSuggested code (review before applying):\n\n```\n    ded = (event.get(\"queryStringParameters\") or {}).get(\"dedication\")\n    page = page.replace(DEDICATION_DEFAULT, escape(ded, quote=True)) if ded else page\n```\n\n",
  "commit_id": "3fb747691aeb3a7c9d2616ab515459d556a1f34c",
  "submitted_at": "2026-10-02T09:28:57Z",
  "html_url": "https://github.com/example-org/sample-agentic-cicd-artifact/pull/17#pullrequestreview-5390249552"
};
  const repo = 'example-org/sample-agentic-cicd-artifact';
  const names = ['Security Review Agent', 'Code Quality Review Agent', 'Architecture Review Agent', 'Accessibility Review Agent'];
  const oldSha = capturedSecurity.commit_id, sha = 'dc91421' + 'a'.repeat(33);
  const oldId = capturedSecurity.id, pipeline = 'fixture-pipeline';
  const tail = 'or validate against a strict allowlist before substitution.';
  const rationale = capturedSecurity.body.split('src/handler.py:37\n\n')[1].split('\n\nSuggested code')[0];
  const failure = {
    id: oldId, persona: names[0], verdict: 'FAIL', state: 'DISMISSED', submitted: capturedSecurity.submitted_at,
    url: capturedSecurity.html_url, commit_id: oldSha, run_id: '36989897144', run_attempt: 1,
    review_ids: [oldId], report_body: capturedSecurity.body, is_current: false, history_reason: 'Earlier PR head',
    blocking: 1, total: 1, suppressed: 0, model: 'captured-model', thinking: 'captured-thinking',
    findings: [{persona: names[0], rule_id: 'SEC-003', severity: 'high', blocking: true, confidence: '89',
      path: 'src/handler.py', line: 37, message: rationale, url: capturedSecurity.html_url}],
  };
  const sameShaRun = { ...failure, id: oldId + 1, commit_id: sha, state: 'COMMENTED', run_id: 'fixture-rerun',
    review_ids: [oldId + 1], history_reason: 'Not the latest verified review workflow attempt', run_attempt: 1 };
  const current = names.map((persona, i) => ({
    ...failure, persona, id: 5390667600 + i, commit_id: sha, run_id: 'fixture-rerun', run_attempt: 2,
    review_ids: [5390667600 + i],
    state: 'COMMENTED', verdict: 'PASS', is_current: true, history_reason: undefined,
    blocking: 0, total: 0, findings: [], report_body: 'LOCAL TEST FIXTURE: final PASS report.',
  }));
  let history = [...current, sameShaRun, failure];
  let prHead = sha;
  let reviews = current;
  const finding = { ...failure.findings[0], agent: names[0], confidence: 89 };
  const longError = 'LOCAL TEST FIXTURE: model request failed. '.repeat(30) + 'ERROR_FINAL_TAIL';
  let exactExecution = true, noHistory = false, noSource = false;
  let attemptsState = 'available', attemptResponse = 'valid', currentBuild = 'fixture-review:pass';
  let pipelineCurrentVerdict;
  const failBuild = 'fixture-review:fail', passBuild = 'fixture-review:pass', errorBuild = 'fixture-review:error';
  const calls = [], errors = [];
  const queryOf = address => {
    const entries = Object.fromEntries((address.split('?')[1] || '').split('&').filter(Boolean)
      .map(pair => pair.split('=').map(decodeURIComponent)));
    return {get: key => entries[key] ?? null, has: key => Object.hasOwn(entries, key)};
  };
  page.on('pageerror', error => errors.push(String(error)));
  const snapshots = (url = '') => {
    const q = queryOf(url);
    const run = exactExecution ? q.get('execution') || 'fixture-pass' : 'fixture-pass';
    const failed = run === 'fixture-fail' || pipelineCurrentVerdict === 'FAIL', errored = run === 'fixture-error';
    const report = { verdict: errored ? 'BLOCKED_ERROR' : failed ? 'FAIL' : 'PASS',
      agents: [{name: names[0], model: 'TEST', thinking: 'TEST', verdict: errored ? 'BLOCKED_ERROR' : failed ? 'FAIL' : 'PASS',
        blocking: failed ? 1 : 0, ...(errored ? {error: longError} : {})}],
      stats: {blocking: failed ? 1 : 0, total: failed ? 1 : 0}, findings: failed ? [finding] : [] };
    const requestedBuild = q.get('review_build');
    const buildFails = requestedBuild === failBuild, buildErrors = requestedBuild === errorBuild;
    const attemptReport = {...report, verdict: buildErrors ? 'BLOCKED_ERROR' : buildFails ? 'FAIL' : 'PASS',
      findings: buildFails ? [finding] : [],
      agents: [{name: names[0], model: 'TEST', thinking: 'TEST', blocking: buildFails ? 1 : 0,
        verdict: buildErrors ? 'BLOCKED_ERROR' : buildFails ? 'FAIL' : 'PASS', ...(buildErrors ? {error: longError} : {})}]};
    const attempts = [passBuild, failBuild, errorBuild].map((build_id, i) => ({
      build_id, action_execution_id: `action-${i}`, status: i ? 'Failed' : 'Succeeded',
      started: `2026-10-03T19:0${2 - i}:00Z`, ended: `2026-10-03T19:0${3 - i}:00Z`,
      url: `https://example.org/build/${build_id}`, is_current: build_id === currentBuild,
    }));
    const pr = {number: Number(q.get('pr') || 17), title: 'LOCAL TEST FIXTURE / CAPTURED REPLAY — NOT LIVE',
      head: prHead, url: `https://github.com/${repo}/pull/17`, updated: '2026-10-03T19:00:00Z',
      checks: [{name: 'review', status: 'completed', conclusion: 'success', url: `https://github.com/${repo}/pull/17/checks`}]};
    return {
      generated_at: '2026-10-03T19:00:00Z', selected_repo: q.get('repo') || 'artifact',
      site: 'https://example.org', repo: { artifact: repo, road: 'test/road' },
      repos: [{key: 'artifact', repo, label: 'Artifact', tiers: true}, {key: 'road', repo: 'test/road', label: 'Road', tiers: true}],
      selected_execution: q.get('execution'), execution: run, execution_status: failed || errored ? 'Failed' : 'Succeeded',
      execution_started: '2026-10-03T19:00:00Z', commit: {sha, message: 'LOCAL TEST FIXTURE — NOT LIVE'},
      commits: [{sha, message: 'LOCAL TEST FIXTURE', execution_id: 'fixture-pass', status: 'Succeeded'}],
      executions: ['fixture-pass', 'fixture-fail', 'fixture-error'].map((execution_id, i) =>
        ({sha, message: 'LOCAL TEST FIXTURE', execution_id, status: i ? 'Failed' : 'Succeeded', started: `2026-10-0${3 - i}T19:00:00Z`})),
      selected_review_build: requestedBuild,
      ...(attemptsState === 'unavailable' ? {} : {
        review_attempts: ['empty', 'lookup-error'].includes(attemptsState) ? [] : attempts,
        review_attempts_evidence: {state: attemptsState === 'lookup-error' ? 'unavailable' : 'available',
          reason: attemptsState === 'lookup-error' ? 'LOCAL TEST FIXTURE: action history ThrottlingException' : 'LOCAL TEST FIXTURE: action history read'},
      }),
      review_attempt: !requestedBuild || attemptResponse === 'unsupported' ? null : {
        build_id: attemptResponse === 'wrong-build' ? passBuild : requestedBuild,
        report: attemptResponse === 'expired' ? null : attemptReport,
        evidence: {state: attemptResponse === 'expired' ? 'expired' : buildErrors ? 'blocked_error' : buildFails ? 'blocked' : 'passed',
          reason: attemptResponse === 'expired' ? 'LOCAL TEST FIXTURE: retained build report expired' : 'LOCAL TEST FIXTURE: immutable build archive',
          execution_id: attemptResponse === 'wrong-execution' ? 'WRONG' : run, revision: sha},
      },
      tiers: {tier1: pipeline}, pipelines: {[pipeline]: {name: pipeline, console: 'https://example.org/pipeline', stages: []}},
      findings: {tier1: report, tier2: null, tier3: null}, panel_progress: null,
      review_evidence: {tier1: {state: errored ? 'blocked_error' : failed ? 'blocked' : 'passed',
        reason: 'LOCAL TEST FIXTURE', execution_id: run, revision: sha}},
      panel_meta: names.map(name => ({name, model: 'TEST', thinking: 'TEST', rules: 'TEST', persona: 'TEST', blocking: true})),
      failures: failed ? [{pipeline, stage: 'Review', action: 'Agent', gate_headline: 'FAIL',
        gate_reason: [rationale], reason: 'LOCAL TEST FIXTURE action wrapper',
        log: ['LOCAL TEST FIXTURE full diagnostic log', 'LOG_FINAL_TAIL']}] : [],
      feed: [],
      pr: {open: [pr, {...pr, number: 18}], evidence: {state: 'available', reason: 'LOCAL TEST FIXTURE'},
        detail: {pr, reviews: noSource ? reviews.map(r => ({...r, report_body: undefined, findings: undefined})) : reviews,
          findings: reviews.flatMap(r => r.findings || []),
          ...(noHistory ? {} : {history})}},
    };
  };
  // LOCAL TEST sign-in: a fixture /auth-config and a stored fixture token.
  await page.route('**/auth-config', route => route.fulfill({contentType: 'application/json', body: JSON.stringify({
    region: 'us-west-2', domain: 'https://auth.example.com', client_id: 'local-test-client',
    redirect_uri: 'http://127.0.0.1:5178/'})}));
  await page.addInitScript(() => sessionStorage.setItem('dashboard.auth.token',
    JSON.stringify({access_token: 'LOCAL-TEST-TOKEN', expires_at: Date.now() + 3600e3})));
  await page.route('**/api/snapshot?*', async route => {
    calls.push(route.request().url());
    if (route.request().headers().authorization !== 'Bearer LOCAL-TEST-TOKEN') errors.push('snapshot request without bearer token');
    await route.fulfill({contentType: 'application/json', body: JSON.stringify(snapshots(route.request().url()))});
  });
  let assertions = 0;
  const check = (ok, message) => { assertions++; if (!ok) throw new Error(message); };
  const url = (params = '') => `http://127.0.0.1:5178/?repo=artifact&pr=17&${params}`;
  const ready = () => page.locator('.review-history > summary').waitFor({state: 'attached'});
  // The board polls; wait for the next snapshot request, which serves the
  // fixture state as it is now.
  const push = async () => {
    const seen = calls.length;
    for (let waited = 0; calls.length <= seen; waited += 100) {
      if (waited > 12000) throw new Error('no snapshot poll within 12 s');
      await page.waitForTimeout(100);
    }
    await page.waitForTimeout(300);
  };
  const watermark = () => page.evaluate(() => {
    document.getElementById('history-fixture-label')?.remove();
    const el = document.createElement('div'); el.id = 'history-fixture-label';
    el.textContent = 'LOCAL TEST FIXTURE / CAPTURED RESPONSE REPLAY · NOT LIVE EVIDENCE';
    Object.assign(el.style, {position: 'fixed', top: 0, right: 0, background: '#facc15', color: '#111',
      padding: '4px 8px', font: 'bold 14px system-ui', zIndex: 99999});
    document.body.append(el);
  });
  const screenshot = async name => { await watermark(); await page.screenshot({path: name, fullPage: false}); };
  const selected = page.getByRole('region', {name: 'Selected review report', exact: true});
  const choose = async id => {
    const historySummary = page.locator('.review-history > summary');
    if (await page.locator('.review-history').getAttribute('open') === null) await historySummary.click();
    await page.getByRole('combobox', {name: 'Review report', exact: true}).selectOption(String(id));
    await selected.waitFor();
  };
  await page.setViewportSize({width: 1920, height: 1080});
  // Start on FAIL, then simulate a later head PASS without changing PR/review selection.
  prHead = oldSha; reviews = [{...failure, is_current: true, state: 'COMMENTED'}];
  history = [reviews[0]];
  await page.goto(url(`focus=pr&review=${oldId}`)); await ready();
  check(await page.getByRole('heading', {name: 'Reports blocking findings', exact: true}).isVisible(), 'initial failure not displayed');
  await page.locator('.current-report-disclosure > summary').focus(); await page.keyboard.press('Enter');
  check((await page.locator('.current-report-disclosure .finding-message').innerText()).endsWith(tail), 'current rationale truncated');
  await page.locator('.current-report-disclosure > summary').click();
  prHead = sha; reviews = current; history = [...current, sameShaRun, failure];
  await push();
  await page.getByRole('heading', {name: 'Review reports PASS', exact: true}).waitFor();
  check(await selected.getByRole('heading', {name: `${names[0]} · FAIL`, exact: true}).isVisible(), 'later PASS lost selected FAIL');
  check(await page.getByRole('combobox', {name: 'Review report', exact: true}).inputValue() === String(oldId), 'refresh reset review choice');
  check(await selected.getByText('Historical report · Earlier PR head', {exact: true}).isVisible(), 'historical attribution missing');
  check(await selected.getByText(/Dismissal actor, time and reason were not returned/).isVisible(), 'missing dismissal attribution concealed');
  check((await selected.locator('.finding-message').innerText()).endsWith(tail), 'long rationale tail truncated');
  check((await selected.locator('.finding-message').innerText()).length > 700, 'captured SEC-003 rationale lost');
  check((await selected.locator('.finding-path').innerText()).includes('src/handler.py:37'), 'rule location missing');
  check(await selected.getByRole('link', {name: 'Source review', exact: false}).getAttribute('href') === capturedSecurity.html_url, 'source permalink changed');
  check(await selected.getByRole('link', {name: 'Workflow run', exact: false}).getAttribute('href') === `https://github.com/${repo}/actions/runs/36989897144/attempts/1`, 'workflow attempt link incorrect');
  await selected.locator('.finding-message').scrollIntoViewIfNeeded();
  await screenshot('history-presenter-rationale.png');
  await selected.locator('.source-report > summary').focus(); await page.keyboard.press('Enter');
  check(await selected.locator('pre').innerText() === capturedSecurity.body, 'raw published report altered');
  check((await selected.locator('pre').innerText()).includes('escape(ded, quote=True)'), 'suggested-code tail omitted');
  await selected.locator('pre').scrollIntoViewIfNeeded();
  await screenshot('history-source-report.png');
  check(queryOf(await page.url()).get('review') === String(oldId), 'review not deep linked');
  await page.reload(); await ready();
  check(await selected.getByRole('heading', {name: `${names[0]} · FAIL`, exact: true}).isVisible(), 'reload lost selected FAIL');
  check(await page.locator('.reviewer-grid').first().getByText('PASS', {exact: true}).count() === 4, 'historical FAIL altered current cards');
  const continuationId = 12345;
  history = [{...failure, id: continuationId, review_ids: [continuationId], evidence: {state: 'missing', reason: 'Primary part unavailable'}}];
  await page.goto(url(`focus=pr&review=${continuationId}`)); await ready();
  history = [{...failure, review_ids: [oldId, continuationId]}, ...current, sameShaRun];
  await push();
  check(await selected.getByRole('heading', {name: `${names[0]} · FAIL`, exact: true}).isVisible(), 'primary publication arrival lost selected continuation');
  check(await page.getByRole('combobox', {name: 'Review report', exact: true}).inputValue() === String(oldId), 'continuation alias did not resolve group');
  check(queryOf(await page.url()).get('review') === String(continuationId), 'alias deep link unexpectedly rewritten');
  history = [...current, sameShaRun, failure];
  await choose(sameShaRun.id);
  check((await selected.innerText()).includes('fixture-rerun / 1'), 'same SHA old attempt unavailable');
  await choose(current[0].id);
  check((await selected.innerText()).includes('fixture-rerun / 2'), 'same SHA new attempt unavailable');
  check(await selected.getByText('Current head report', {exact: true}).isVisible(), 'current history report mislabeled');
  // Invalid or unavailable IDs must remain selected and explicit.
  await page.goto(url('focus=pr&review=999')); await ready();
  check(await page.getByRole('status').innerText().then(t => t.includes('Selected review 999 unavailable')), 'unknown review substituted');
  noHistory = true;
  await page.reload(); await ready();
  check(await page.getByText('Review history unavailable from this server. Current reviews are not a complete history.', {exact: true}).isVisible(), 'old server appeared to have complete history');
  noHistory = false; history = [];
  await page.reload(); await ready();
  check(await page.getByText('No retained review reports returned for this PR.', {exact: true}).isVisible(), 'empty vs unavailable history conflated');
  // Errors with zero findings must still have complete details.
  const errorReview = {...failure, id: 700, commit_id: sha, verdict: 'BLOCKED_ERROR', error: longError,
    review_ids: [700], state: 'COMMENTED', is_current: true, findings: [], total: 0, blocking: 0, report_body: 'LOCAL TEST FIXTURE: error without findings.'};
  history = [errorReview, failure, ...current]; reviews = [errorReview, ...current.slice(1)];
  await page.goto(url('focus=pr&review=700')); await ready();
  check(await page.getByRole('heading', {name: 'Reports a review error', exact: true}).isVisible(), 'error review inferred PASS');
  check((await selected.locator('.report-error').innerText()).endsWith('ERROR_FINAL_TAIL'), 'zero-finding error detail truncated');
  check(await selected.getByText('No findings returned for this report. The verdict and any review error remain separate.', {exact: true}).count() === 1, 'zero-finding error unclear');
  const incomplete = {...errorReview, verdict: 'UNAVAILABLE',
    error: 'LOCAL TEST FIXTURE: missing continuation part', evidence: {state: 'unavailable', reason: 'Missing publication parts'}};
  history = [incomplete, failure, ...current]; reviews = [incomplete, ...current.slice(1)];
  await page.reload(); await ready();
  check(await page.getByRole('heading', {name: 'Review unavailable', exact: true}).isVisible(), 'publication gap labeled a model failure');
  check(await selected.getByText('Publication evidence: Review unavailable · Missing publication parts', {exact: true}).isVisible(), 'publication gap reason missing');
  check((await selected.locator('.report-error').innerText()).startsWith('Report detail:'), 'publication diagnostic mislabeled as model error');
  // HTML and Markdown are displayed as inert text, including raw source.
  history = [{...failure, report_body: '<img src=x onerror="window.__injected=true"><script>window.__injected=true</script>',
    findings: [{...failure.findings[0], message: '&lt;img src=x onerror=alert(1)&gt; <svg onload=alert(1)> TEXT_TAIL'}]}];
  reviews = current;
  await page.goto(url(`focus=pr&review=${oldId}`)); await ready();
  await selected.locator('.source-report > summary').click();
  check(await selected.locator('img, script, svg').count() === 0, 'report rendered untrusted markup');
  check(!await page.evaluate(() => window.__injected), 'untrusted report executed');
  check((await selected.locator('.finding-message').innerText()).includes('<img'), 'encoded prose was not readable text');
  history = [{...failure, url: 'javascript:alert(1)',
    report_body: failure.report_body.replace('/runs/36989897144/attempts/1', '/runs/999/attempts/9')}];
  await page.reload(); await ready();
  check(await selected.getByRole('link', {name: 'Source review', exact: false}).count() === 0, 'unsafe source link allowed');
  check(await selected.getByRole('link', {name: 'Workflow run', exact: false}).count() === 0, 'workflow URL conflicts with exact run identity');
  // Current details remain honest with the old response contract.
  noSource = true; noHistory = true;
  await page.goto(url('focus=pr')); await ready();
  await page.locator('.current-report-disclosure > summary').click();
  await page.locator('.current-report-disclosure .source-report > summary').first().click();
  check(await page.getByText('Published report text unavailable from this server. Inspect the source review for additional detail.', {exact: true}).first().isVisible(), 'missing source text hidden');
  noSource = false; noHistory = false; history = [...current, sameShaRun, failure];
  // Both controls retain independent identity, and the poll sends exactly the current selection.
  await page.goto(url(`execution=fixture-fail&review=${oldId}`)); await ready();
  check(calls.at(-1).includes('execution=fixture-fail'), 'snapshot missing exact execution');
  check(!calls.at(-1).includes('review='), 'UI-only review ID leaked into backend query');
  const pollQuery = Object.fromEntries(new URL(calls.at(-1)).searchParams);
  check(pollQuery.execution === 'fixture-fail' && !('commit' in pollQuery), 'poll sent stale execution/commit');
  check(pollQuery.pr === '17' && !('review' in pollQuery) && !('history' in pollQuery), 'poll sent stale PR/review/history');
  check(!('review_build' in pollQuery) && !('k' in pollQuery), 'poll sent a stale build attempt or a key');
  const execSelect = page.getByRole('combobox', {name: 'Pipeline execution', exact: true});
  check(await execSelect.locator('option').count() === 4, 'same-SHA executions deduplicated');
  const execLabels = await execSelect.locator('option').allTextContents();
  check(execLabels[2].includes('2026') && execLabels[2].includes('Failed') && execLabels[2].includes(sha.slice(0, 8)) && execLabels[2].includes('fixture-fail'), 'execution option lacks time/status/SHA/ID');
  await page.locator('.pipeline-report-disclosure > summary').click();
  const pipelineDetails = page.getByRole('region', {name: 'Complete pipeline review details', exact: true});
  check((await pipelineDetails.locator('.finding-message').first().innerText()).endsWith(tail), 'pipeline full finding missing');
  check((await pipelineDetails.innerText()).includes('LOG_FINAL_TAIL'), 'full failure diagnostic log missing');
  await execSelect.selectOption('fixture-error'); await ready();
  await page.locator('.pipeline-report-disclosure > summary').click();
  check((await pipelineDetails.locator('.report-error').innerText()).endsWith('ERROR_FINAL_TAIL'), 'pipeline zero-finding error missing');
  await pipelineDetails.locator('.report-error').scrollIntoViewIfNeeded();
  await screenshot('history-pipeline-error.png');
  await page.getByRole('combobox', {name: 'Deployment revision', exact: true}).selectOption(sha); await ready();
  check(!queryOf(await page.url()).has('execution'), 'revision selection did not clear execution pin');
  await execSelect.selectOption('fixture-fail'); await ready();
  check(!queryOf(await page.url()).has('commit'), 'execution selection did not clear revision pin');
  check(queryOf(await page.url()).get('review') === String(oldId), 'execution selection cleared independent review');
  // A backend that ignores execution selection is explicitly unavailable.
  exactExecution = false;
  await page.reload(); await ready();
  check((await page.getByRole('alert').innerText()).includes('different execution'), 'ignored execution pin not detected');
  check(await page.getByRole('heading', {name: 'Review unavailable', exact: true}).count() === 1, 'wrong run became PASS');
  exactExecution = true;
  // Full dashboard has the same full retained reports and execution control.
  await page.goto(url(`present=0&execution=fixture-error&review=${oldId}`)); await ready();
  check(await selected.getByRole('heading', {name: `${names[0]} · FAIL`, exact: true}).isVisible(), 'full dashboard missing retained FAIL');
  await selected.locator('.finding-message').scrollIntoViewIfNeeded();
  check((await selected.locator('.finding-message').innerText()).endsWith(tail), 'full dashboard rationale truncated');
  await screenshot('history-full-dashboard.png');
  check(await page.getByRole('combobox', {name: 'Pipeline execution', exact: true}).inputValue() === 'fixture-error', 'full execution selector lost exact run');
  await page.locator('.pipeline-report-disclosure > summary').first().click();
  check((await page.locator('.pipeline-report-disclosure .report-error').first().innerText()).endsWith('ERROR_FINAL_TAIL'), 'full dashboard pipeline error truncated');
  // Stage: disclosure keyboard use, full rationale/source, merge caveat, Exit/Escape.
  await page.goto(url(`focus=pr&stage=1&review=${oldId}`)); await ready();
  const caveat = page.locator('.presenter-card > .semantics').first();
  check(await caveat.isVisible(), 'stage hid merge caveat');
  check((await caveat.innerText()).includes('Merge protection is not verified'), 'stage changed merge caveat');
  await selected.focus(); await page.keyboard.press('End');
  await selected.locator('.finding-message').scrollIntoViewIfNeeded();
  const style = await selected.locator('.finding-message').evaluate(el => {
    const css = getComputedStyle(el);
    return { clamp: css.webkitLineClamp, overflow: css.overflow, height: el.clientHeight, scrollHeight: el.scrollHeight };
  });
  check(style.clamp === 'none' && style.overflow === 'visible' && style.height >= style.scrollHeight, 'Stage still hides long finding text');
  check((await selected.locator('.finding-message').innerText()).endsWith(tail), 'Stage truncated message tail');
  await screenshot('history-stage-rationale.png');
  await selected.locator('.source-report > summary').focus(); await page.keyboard.press('Enter');
  check(await selected.locator('pre').isVisible(), 'Stage source disclosure is not keyboard accessible');
  await selected.locator('pre').scrollIntoViewIfNeeded();
  check(await selected.locator('pre').innerText() === capturedSecurity.body, 'Stage raw source incomplete');
  check(await page.locator('.stage-exit').isVisible(), 'Stage exit hidden by detail panel');
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Stage horizontal overflow');
  await page.keyboard.press('Escape'); await ready();
  check(await page.locator('.presenter-stage').count() === 0, 'Escape did not exit Stage');
  check(queryOf(await page.url()).get('review') === String(oldId), 'Escape lost review deep link');
  await page.getByRole('link', {name: 'Stage view', exact: true}).click(); await ready();
  await page.locator('.stage-exit').click(); await ready();
  check(await page.locator('.presenter-stage').count() === 0, 'Exit did not leave Stage');
  await page.setViewportSize({width: 1000, height: 900});
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'narrow history overflow');
  await page.setViewportSize({width: 600, height: 900});
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'mobile history overflow');
  await page.setViewportSize({width: 1920, height: 1080});
  // Switching PR/repository clears scoped selections in-app and in the URL.
  await page.getByRole('combobox', {name: 'Pull request', exact: true}).selectOption('18'); await ready();
  check(!queryOf(await page.url()).has('review'), 'PR switch kept stale report');
  await choose(oldId);
  await page.getByRole('combobox', {name: 'Repository', exact: true}).selectOption('road'); await ready();
  const q = queryOf(await page.url());
  check(!q.has('review') && !q.has('pr') && !q.has('execution') && !q.has('commit'), 'repo switch kept stale scoped selections');
  // Same CodePipeline execution, immutable build attempts: later PASS must not replace selected FAIL.
  currentBuild = failBuild; pipelineCurrentVerdict = 'FAIL';
  await page.goto(url(`focus=release&execution=fixture-pass&review_build=${encodeURIComponent(failBuild)}`)); await ready();
  const buildReport = page.getByRole('region', {name: 'Selected review attempt · complete report', exact: true});
  const attemptSelector = page.getByRole('combobox', {name: 'Review attempt', exact: true});
  check(await page.getByRole('heading', {name: 'Blocked', exact: true}).isVisible(), 'initial same-execution FAIL missing');
  check(await attemptSelector.inputValue() === failBuild, 'attempt deep link not selected');
  check((await buildReport.locator('.finding-message').innerText()).endsWith(tail), 'immutable attempt finding truncated');
  currentBuild = passBuild; pipelineCurrentVerdict = 'PASS';
  await push();
  await page.getByRole('heading', {name: 'Passed', exact: true}).waitFor();
  check(await page.getByText('Historical review attempt', {exact: true}).isVisible(), 'retried build not marked historical');
  check(await buildReport.getByRole('heading', {name: `${names[0]} · FAIL`, exact: true}).isVisible(), 'same-execution PASS overwrote retained FAIL');
  check(await attemptSelector.inputValue() === failBuild, 'same-execution retry reset attempt choice');
  check((await page.locator('.selected-build').innerText()).includes('action-1'), 'action execution identity missing');
  check(await page.getByRole('link', {name: 'Source build attempt', exact: false}).getAttribute('href') === `https://example.org/build/${failBuild}`, 'attempt source URL fabricated');
  check(calls.at(-1).includes(`review_build=${encodeURIComponent(failBuild)}`), 'snapshot omitted/failed to encode build selection');
  await push();
  check(new URL(calls.at(-1)).searchParams.get('review_build') === failBuild, 'poll lost build selection');
  await buildReport.locator('.finding-message').scrollIntoViewIfNeeded();
  await screenshot('history-pipeline-retry.png');
  await page.reload(); await ready();
  check(await buildReport.getByRole('heading', {name: `${names[0]} · FAIL`, exact: true}).isVisible(), 'attempt reload lost FAIL');
  await attemptSelector.selectOption(errorBuild); await ready();
  check((await buildReport.locator('.report-error').innerText()).endsWith('ERROR_FINAL_TAIL'), 'attempt zero-finding error truncated');
  check(await page.getByRole('heading', {name: 'Passed', exact: true}).isVisible(), 'historical error changed current verdict');
  // Clearing/selecting from latest pins the parent execution in generated deep links.
  await page.goto(url('focus=release')); await ready();
  await page.locator('.pipeline-review-attempts > summary').focus(); await page.keyboard.press('Enter');
  await attemptSelector.selectOption(failBuild); await ready();
  check(queryOf(await page.url()).get('execution') === 'fixture-pass', 'choosing attempt did not pin parent execution');
  check(queryOf(await page.url()).get('review_build') === failBuild, 'chosen attempt not deep linked');
  for (const mode of ['wrong-build', 'wrong-execution', 'unsupported', 'expired']) {
    attemptResponse = mode; await page.reload(); await ready();
    check(await buildReport.getByRole('heading', {name: `${names[0]} · FAIL`, exact: true}).count() === 0, `${mode} attempt displayed unrelated report`);
    check((await buildReport.innerText()).includes(mode === 'expired' ? 'Evidence expired' : mode === 'unsupported'
      ? 'current report has not been substituted' : 'does not match'), `${mode} attempt explanation missing`);
    check(await page.getByRole('heading', {name: 'Passed', exact: true}).isVisible(), `${mode} attempt changed current verdict`);
  }
  attemptResponse = 'valid'; attemptsState = 'unavailable';
  await page.reload(); await ready();
  check(await page.getByText('Review attempt history unavailable from this server.', {exact: true}).isVisible(), 'old server attempt history inferred complete');
  check(await buildReport.getByRole('heading', {name: `${names[0]} · FAIL`, exact: true}).count() === 0, 'unverified build membership rendered report');
  attemptsState = 'empty';
  await page.reload(); await ready();
  check(await page.getByText('No retained review attempts returned for this execution.', {exact: true}).isVisible(), 'empty attempt list conflated with unavailable');
  attemptsState = 'lookup-error';
  await page.reload(); await ready();
  check((await page.locator('.pipeline-review-attempts').innerText()).includes('ThrottlingException'), 'attempt history retrieval error hidden');
  check(await page.getByText('No retained review attempts returned for this execution.', {exact: true}).count() === 0, 'failed attempt lookup labeled exhaustive empty history');
  attemptsState = 'available';
  await page.goto(url('focus=release&execution=fixture-pass&review_build=unknown-build')); await ready();
  check((await buildReport.innerText()).includes('not in the returned attempts'), 'unknown attempt silently replaced');
  check(await buildReport.getByText('Reported verdict: PASS', {exact: true}).count() === 0, 'unknown attempt adopted current PASS');
  // Same shared attempt renderer and full errors in the full dashboard.
  await page.goto(url(`present=0&execution=fixture-pass&review_build=${encodeURIComponent(errorBuild)}`)); await ready();
  check((await buildReport.locator('.report-error').innerText()).endsWith('ERROR_FINAL_TAIL'), 'full dashboard lost build error');
  await page.getByRole('link', {name: 'Presenter view', exact: true}).click(); await ready();
  await page.getByRole('combobox', {name: 'Deployment revision', exact: true}).selectOption(sha); await ready();
  check(!queryOf(await page.url()).has('review_build'), 'commit change kept stale attempt');
  await page.locator('.pipeline-review-attempts > summary').click();
  await attemptSelector.selectOption(failBuild); await ready();
  await page.getByRole('combobox', {name: 'Pipeline execution', exact: true}).selectOption('fixture-fail'); await ready();
  check(!queryOf(await page.url()).has('review_build'), 'execution change kept stale attempt');
  await page.locator('.pipeline-review-attempts > summary').click();
  await attemptSelector.selectOption(failBuild); await ready();
  await page.getByRole('combobox', {name: 'Repository', exact: true}).selectOption('road'); await ready();
  check(!queryOf(await page.url()).has('review_build'), 'repo change kept stale attempt');
  check(errors.length === 0, errors.join('\n'));
  return {result: 'PASS', assertions, consoleErrors: errors, fixture: 'NOT LIVE — local fixtures and captured response replay'};
}
