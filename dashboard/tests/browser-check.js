async page => {
  // LOCAL TEST FIXTURES ONLY, never GitHub/AWS results.
  const names = ['Security Review Agent', 'Code Quality Review Agent', 'Architecture Review Agent', 'Accessibility Review Agent'];
  const sha = 'a'.repeat(40), prSha = 'b'.repeat(40), pipeline = 'agentic-gates-tier1';
  const errors = [], calls = [];
  page.on('pageerror', error => errors.push(String(error)));
  let fixtureState = 'unavailable';
  let failSnapshots = false;
  let health;
  let snapshotOverride = {};
  let checkNames = ['review'];
  let findingMessage = 'LOCAL TEST FIXTURE: visitor-supplied text reaches an HTML sink. Render it as text or escape before insertion.';
  const snapshot = () => ({
    generated_at: '2026-10-02T19:00:00Z', health, selected_repo: 'artifact',
    site: 'https://app.example.com', repo: {artifact: 'example-org/sample-agentic-cicd-artifact'},
    repos: [{key: 'artifact', repo: 'example-org/sample-agentic-cicd-artifact', label: 'Artifact — THE FALL OF TROY', tiers: true, deploy_service: 'AWS CodeDeploy'}],
    commit: {sha, message: 'LOCAL TEST FIXTURE'}, selected_commit: sha,
    commits: [{sha, message: 'LOCAL TEST FIXTURE', status: 'Failed', execution_id: 'fixture-run', started: '2026-08-18T19:00:00Z'}],
    execution: 'fixture-run', execution_started: '2026-08-18T19:00:00Z', execution_status: 'Failed',
    tiers: {tier1: pipeline, tier2: 'agentic-gates-tier2', tier3: 'agentic-gates-tier3'},
    pipelines: {[pipeline]: {name: pipeline, console: 'https://console.aws.amazon.com/', stages: [
      {name: 'Source', status: 'Succeeded', actions: [{name: 'Source', status: 'Succeeded'}]},
      {name: 'AutomatedGates', status: 'Failed', actions: [{name: 'Review', status: 'Failed'}]},
      {name: 'Approval', status: 'NotStarted', actions: []}, {name: 'Deploy', status: 'NotStarted', actions: []}]}},
    findings: {tier1: fixtureState === 'blocked' ? {verdict: 'FAIL', agents: names.map((name, i) => ({name, model: 'test-model', thinking: 'test', verdict: i === 0 ? 'FAIL' : 'PASS', blocking: i === 0 ? 1 : 0})), stats: {blocking: 1, total: 1}, findings: []} : null, tier2: null, tier3: null},
    review_evidence: {tier1: {state: fixtureState, policy_origin: 'pipeline_deployment', policy_sha256: 'e'.repeat(64), baseline_revision: 'c'.repeat(40), reason: fixtureState === 'blocked' ? 'Policy reports blocking findings (LOCAL TEST FIXTURE)' : 'Report cannot be bound to this execution (LOCAL TEST FIXTURE)'}},
    panel_meta: names.map((name, i) => ({name, blocking: i === 0 || i === 3, model: 'test-model', thinking: 'test', rules: 'TEST-', persona: 'LOCAL TEST FIXTURE'})),
    policy_metadata: {source: '.reviewer.yaml at dashboard build (not historical review policy)'},
    panel_progress: null, failures: fixtureState === 'blocked' ? [{pipeline, stage: 'AutomatedGates', action: 'Review', gate_headline: 'Review reports 1 blocking finding', gate_reason: ['LOCAL TEST FIXTURE: Security Review Agent · SEC-003 · src/fixture.py:42 — escape visitor-supplied text before rendering.']}] : [], feed: [],
    pr: {evidence: {state: 'available', reason: 'LOCAL TEST FIXTURE'}, open: [{number: 7, title: 'LOCAL TEST FIXTURE — visitor-supplied text', head: prSha, url: 'https://github.com/example-org/sample-agentic-cicd-artifact/pull/7', updated: '2026-08-18T19:02:00Z'}], detail: {
      pr: {number: 7, title: 'LOCAL TEST FIXTURE', head: prSha, url: 'https://github.com/example-org/sample-agentic-cicd-artifact/pull/7', updated: '2026-08-18T19:02:00Z', checks: checkNames.map(name => ({name, status: 'completed', conclusion: name === 'review' ? 'failure' : 'success', url: 'https://github.com/test'}))},
      reviews: names.map((persona, i) => ({persona, verdict: i === 0 ? 'FAIL' : 'PASS', state: 'COMMENTED', url: 'https://github.com/test'})),
      findings: [{persona: names[0], rule_id: 'SEC-003', blocking: true, path: 'src/fixture.py', line: 42, confidence: '99', message: findingMessage}],
    }},
    ...snapshotOverride,
  });
  // LOCAL TEST sign-in: a fixture /auth-config and a stored fixture token.
  // The API mock below asserts that every snapshot request carries it.
  await page.route('**/auth-config', route => route.fulfill({contentType: 'application/json', body: JSON.stringify({
    region: 'us-west-2', domain: 'https://auth.example.com', client_id: 'local-test-client',
    redirect_uri: 'http://127.0.0.1:5178/'})}));
  await page.addInitScript(() => sessionStorage.setItem('dashboard.auth.token',
    JSON.stringify({access_token: 'LOCAL-TEST-TOKEN', expires_at: Date.now() + 3600e3})));
  await page.route('**/api/snapshot?*', async route => {
    calls.push(route.request().url());
    if (route.request().headers().authorization !== 'Bearer LOCAL-TEST-TOKEN') errors.push('snapshot request without bearer token');
    if (failSnapshots) return route.fulfill({status: 500, contentType: 'application/json', body: '{}'});
    await route.fulfill({contentType: 'application/json', body: JSON.stringify(snapshot())});
  });
  await page.setViewportSize({width: 1920, height: 1080});
  await page.goto(`http://127.0.0.1:5178/?present=1&repo=artifact&commit=${sha}&pr=7&closed=1`);
  await page.getByRole('heading', {name: 'AI reviews. Your rules decide.'}).waitFor();
  let checkCount = 0;
  const check = (ok, why) => { checkCount++; if (!ok) throw new Error(why); };
  check(calls.some(url => url.includes(`commit=${sha}`) && url.includes('pr=7')), 'deep-link selections not forwarded');
  check(await page.getByText('Different revision from deployment', {exact: false}).count() === 1, 'PR/deployment distinction missing');
  check(await page.getByText('Advisory rules', {exact: true}).count() === 2, 'rule policy labels incorrect');
  check(await page.getByText('Review policy: pipeline_deployment', {exact: false}).count() === 1, 'execution policy provenance missing');
  check(await page.getByText('Review unavailable', {exact: true}).count() >= 2, 'unavailable evidence hidden');
  const links = await page.locator('a').evaluateAll(a => a.map(x => x.href));
  check(!links.some(url => url.includes('undefined')), 'undefined revision link');
  check(links.includes(`https://github.com/example-org/sample-agentic-cicd-artifact/commit/${sha}`), 'revision URL incorrect');
  check(await page.locator('.release-flow').innerText().then(t => !/AgentCore|Kiro/.test(t)), 'hosting options appear as stages');
  const watermark = async () => page.evaluate(() => {
    const el = document.createElement('div'); el.id = 'fixture-label'; el.textContent = 'LOCAL TEST FIXTURE · NOT LIVE EVIDENCE';
    Object.assign(el.style, {position: 'fixed', bottom: '0', left: '0', right: '0', textAlign: 'center', background: '#facc15', color: '#111', font: 'bold 16px system-ui', zIndex: '99999'});
    document.body.appendChild(el);
  });
  await watermark();
  await page.screenshot({path: 'presenter-unavailable.png', fullPage: true});
  const geometry = await page.evaluate(() => ({width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
    height: innerHeight, scrollHeight: document.documentElement.scrollHeight,
    mainLabel: getComputedStyle(document.querySelector('.presenter h2')).fontSize}));
  check(geometry.scrollWidth <= geometry.width, 'horizontal overflow at 1920');
  check(geometry.scrollHeight <= 1080, `recording layout exceeds 1080: ${geometry.scrollHeight}`);
  fixtureState = 'blocked';
  await page.reload();
  await page.getByRole('heading', {name: 'Blocked', exact: true}).waitFor();
  await watermark(); await page.screenshot({path: 'presenter-blocked.png', fullPage: true});
  check(await page.evaluate(() => document.documentElement.scrollHeight <= 1080), 'blocked state overflows 1080');
  const healthStep = page.locator('.release-flow [data-health-state]');
  const healthDetails = page.locator('.health-evidence');
  const history = page.getByRole('region', {name: 'Selected execution health history', exact: true});
  const current = page.getByRole('region', {name: 'Current live health', exact: true});
  const reloadHealth = async () => {
    await page.reload();
    await healthDetails.waitFor();
  };
  const openHealth = async () => healthDetails.locator(':scope > summary').click();
  check(await healthStep.textContent() === 'Health evidence unavailable', 'missing health must be explicitly unavailable');
  check(await healthStep.getAttribute('data-health-state') === 'unavailable', 'missing health state is not unavailable');
  check(await healthStep.evaluate(el => getComputedStyle(el).color) !== 'rgb(166, 224, 160)', 'missing health is green');
  await openHealth();
  check(await current.getByText('Current live alias unavailable.', {exact: true}).count() === 1, 'missing alias fabricated');
  check(await history.getByText('Deployment history unavailable.', {exact: true}).count() === 1, 'missing deployment fabricated');

  // Deliberately old rollback plus a newer, healthy live alias/alarm.
  // These are LOCAL TEST FIXTURES, not recording evidence.
  health = {
    state: 'rolled_back', label: 'Rolled back after alarm', reason: 'LOCAL TEST FIXTURE: selected canary stopped on alarm.',
    execution_id: 'fixture-run', revision: sha, binding: 'Selected action → CodeDeploy deployment',
    observed_at: '2026-10-02T19:00:00Z',
    deployment: {id: 'd-FIXTURE', status: 'Stopped', url: 'https://us-west-2.console.aws.amazon.com/codedeploy/home?region=us-west-2#/deployments/d-FIXTURE',
      original_version: '68', target_version: '69', started: '2026-08-18T19:00:00Z', completed: '2026-08-18T19:12:00Z', alarm_triggered: true},
    rollback: {id: 'd-ROLLBACK', status: 'Succeeded', url: 'https://us-west-2.console.aws.amazon.com/codedeploy/home?region=us-west-2#/deployments/d-ROLLBACK', target_version: '68'},
    current: {alias: 'live', version: '70', revision: prSha, weights: {'71': 0.1}, matches_selected_revision: false},
    alarms: [{name: 'fixture-errors', state: 'OK', reason: 'LOCAL TEST FIXTURE: current errors below threshold.',
      updated: '2026-10-02T18:55:00Z', url: 'https://us-west-2.console.aws.amazon.com/cloudwatch/home?region=us-west-2#alarmsV2:alarm/fixture-errors',
      transitions: [{at: '2026-08-18T19:10:00Z', state: 'ALARM', summary: 'LOCAL TEST FIXTURE: historical error threshold breached.'},
        {at: '2026-08-18T19:20:00Z', state: 'OK', summary: 'LOCAL TEST FIXTURE: historical recovery.'}]}],
    errors: [],
  };
  await reloadHealth();
  check(await healthStep.textContent() === health.label, 'flow must use backend health label');
  check(await healthStep.getAttribute('data-health-state') === 'rolled_back', 'current OK overwrote historical rollback');
  check(await page.evaluate(() => document.documentElement.scrollHeight <= 1080), 'collapsed health overflows 1080');
  await watermark(); await page.screenshot({path: 'presenter-health-rollback.png', fullPage: true});
  await openHealth();
  await page.screenshot({path: 'presenter-health-history.png', fullPage: false});
  check(await history.getByText('Stopped', {exact: true}).count() === 1, 'historical deployment status missing');
  check(await history.getByText('Succeeded', {exact: true}).count() === 1, 'rollback result missing');
  check((await history.innerText()).includes('Version 68 → 69'), 'historical versions missing');
  check((await current.innerText()).includes('Alias live → version 70'), 'current alias mixed with rollback target');
  check((await current.innerText()).includes('v71: 10%'), 'live traffic weights missing or incorrect');
  check(await current.getByText('Live alias differs from selected revision', {exact: true}).count() === 1, 'live vs selected revision distinction missing');
  check(await current.getByText('Current alarm OK and the live alias do not prove this selected execution was healthy.', {exact: true}).count() === 1, 'historical health caveat missing');
  check(await history.getByRole('link', {name: 'CodeDeploy deployment d-FIXTURE', exact: false}).getAttribute('href') === health.deployment.url, 'deployment URL not from API');
  check(await history.getByRole('link', {name: 'CodeDeploy rollback d-ROLLBACK', exact: false}).getAttribute('href') === health.rollback.url, 'rollback URL not from API');
  check(await current.getByRole('link', {name: 'CloudWatch', exact: false}).getAttribute('href') === health.alarms[0].url, 'alarm URL not from API');
  const events = page.locator('.alarm-history');
  check(await events.getAttribute('open') === null, 'alarm history should start collapsed');
  check(!await events.getByText(health.alarms[0].transitions[0].summary, {exact: true}).isVisible(), 'event disclosure is not collapsed');
  await events.locator('summary').focus();
  await page.keyboard.press('Enter');
  check(await events.getByText(health.alarms[0].transitions[0].summary, {exact: true}).isVisible(), 'alarm events not keyboard accessible');
  check(await events.locator('time').count() === 2, 'alarm event times missing');
  check(await events.locator('[data-alarm-state="ALARM"]').count() === 1, 'historical ALARM lost to current OK');
  check(await healthStep.getAttribute('data-health-state') === 'rolled_back', 'expansion changed historical state');
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'expanded evidence horizontal overflow');
  await events.locator('li').last().scrollIntoViewIfNeeded();
  await page.screenshot({path: 'presenter-health-events.png', fullPage: false});

  // Schema states must stay distinct and labels are server supplied.
  for (const state of ['not_started', 'unavailable', 'not_applicable', 'observing', 'completed', 'rolled_back', 'failed']) {
    health = {...health, state, label: `Fixture health ${state}`};
    await reloadHealth();
    check(await healthStep.textContent() === health.label, `health label lost for ${state}`);
    check(await healthStep.getAttribute('data-health-state') === state, `health state lost for ${state}`);
    check(await healthStep.evaluate(el => getComputedStyle(el).color) === (state === 'completed' ? 'rgb(166, 224, 160)' :
      state === 'failed' || state === 'rolled_back' ? 'rgb(255, 179, 173)' :
      state === 'observing' ? 'rgb(142, 203, 255)' : 'rgb(189, 205, 221)'), `wrong health color for ${state}`);
  }
  health = {...health, state: 'unavailable', label: 'Passed', reason: 'LOCAL TEST FIXTURE: historical evidence unavailable.',
    errors: ['LOCAL TEST FIXTURE: CloudWatch history AccessDenied']};
  await reloadHealth();
  check(await healthStep.getAttribute('data-state') === null, 'health label must not inherit generic Passed styling');
  check(await healthStep.evaluate(el => getComputedStyle(el).color) !== 'rgb(166, 224, 160)', 'unavailable health is green despite current OK');
  await openHealth();
  check(await healthDetails.locator(':scope > summary b').evaluate(el => getComputedStyle(el).color) !== 'rgb(166, 224, 160)', 'unavailable disclosure is green');
  check(await page.getByRole('region', {name: 'Health evidence retrieval errors'}).getByText(health.errors[0], {exact: true}).count() === 1, 'partial retrieval errors hidden');

  const completeHealth = {...health, state: 'completed', label: 'Canary completed'};
  health = {...completeHealth, rollback: undefined, current: {...completeHealth.current, revision: sha,
    weights: {}, matches_selected_revision: true}, alarms: [{...completeHealth.alarms[0], state: 'ALARM'}]};
  await reloadHealth(); await openHealth();
  check(await healthStep.getAttribute('data-health-state') === 'completed', 'current ALARM rewrote a completed historical deployment');
  check(await current.locator('article > p > [data-alarm-state="ALARM"]').count() === 1, 'current ALARM hidden by completed historical deployment');
  check(await current.getByText('Live alias matches selected revision', {exact: true}).count() === 1, 'matching alias evidence missing');
  check(await current.getByText('No additional traffic weights reported.', {exact: true}).count() === 1, 'empty traffic weights rendered as unavailable');
  check(await history.getByText('No rollback evidence returned.', {exact: true}).count() === 1, 'current alarm fabricated a historical rollback');
  for (const mismatch of [{execution_id: 'different-execution'}, {revision: 'c'.repeat(40)}]) {
    health = {...completeHealth, ...mismatch};
    await reloadHealth();
    check(await healthStep.getAttribute('data-health-state') === 'unavailable', 'mismatched health accepted');
    await openHealth();
    check(await history.getByText('Health evidence does not match the selected repository, execution or revision.', {exact: true}).count() === 1, 'health binding mismatch not explained');
    check(await history.getByRole('link').count() === 0, 'mismatched deployment presented as selected history');
  }
  health = {state: 'unavailable', label: 'Health evidence unavailable', observed_at: 'invalid',
    current: {alias: 'live', version: '70'}, alarms: [{name: 'fixture-errors', state: 'OK'}]};
  await reloadHealth(); await openHealth();
  check((await current.innerText()).includes('Live alias revision match unavailable'), 'missing match field became false');
  check((await current.innerText()).includes('Traffic weights unavailable.'), 'missing weights became no traffic split');
  check((await current.innerText()).includes('link unavailable'), 'missing URL is fabricated');
  await page.locator('.alarm-history summary').click();
  check(await current.getByText('No alarm events returned. This does not establish a healthy historical run.', {exact: true}).isVisible(), 'missing alarm history became healthy');
  health = {state: 'completed'};
  await reloadHealth();
  check(await healthStep.getAttribute('data-health-state') === 'unavailable', 'partial health payload is green');
  health = {...completeHealth, observed_at: undefined};
  await reloadHealth();
  check(await healthStep.getAttribute('data-health-state') === 'unavailable', 'undated health payload is green');
  health = undefined;
  await reloadHealth();
  await page.getByRole('link', {name: 'Focus on PR', exact: true}).click();
  await page.getByRole('heading', {name: 'Review a pull request', exact: true}).waitFor();
  check(!await healthDetails.isVisible(), 'health panel disrupts PR focus');
  check(!await page.locator('.release-flow').isVisible(), 'release health flow disrupts PR focus');
  await page.getByRole('link', {name: 'Release overview', exact: true}).click();
  await healthDetails.waitFor();
  await page.getByRole('link', {name: 'Full dashboard', exact: true}).click();
  await page.getByRole('heading', {name: 'Agentic gates — execution evidence'}).waitFor();
  check(await page.evaluate(() => new URL(location.href).searchParams.get('present') === '0'), 'full dashboard exit failed');
  check(await page.evaluate(() => new URL(location.href).searchParams.get('pr') === '7'), 'full view lost PR selection');
  await page.setViewportSize({width: 1000, height: 900});
  await page.getByRole('link', {name: 'Presenter view', exact: true}).click();
  await page.getByRole('heading', {name: 'AI reviews. Your rules decide.'}).waitFor();
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'narrow viewport horizontal overflow');
  check(await page.evaluate(() => {
    const q = new URL(location.href).searchParams;
    return q.get('repo') === 'artifact' && q.get('pr') === '7' && q.get('commit') === 'a'.repeat(40);
  }), 'deep link lost selection parameters');
  {
    const q = new URL(calls.at(-1)).searchParams;
    check(q.get('repo') === 'artifact' && q.get('pr') === '7' && q.get('commit') === sha && !q.has('k'),
      'snapshot poll dropped selection parameters');
  }
  // Polling delivers a changed snapshot within one interval.
  fixtureState = 'expired';
  await page.getByRole('heading', {name: 'Evidence expired', exact: true}).waitFor({timeout: 12000});
  fixtureState = 'unavailable';
  await page.getByRole('combobox', {name: 'Deployment revision', exact: true}).selectOption('');
  await page.getByRole('heading', {name: 'Review unavailable', exact: true}).waitFor();
  failSnapshots = true;
  await page.getByText('Connection: Telemetry refresh unavailable; last received data may be stale', {exact: true}).waitFor({timeout: 12000});
  failSnapshots = false;
  await page.getByRole('link', {name: 'Focus on release', exact: true}).click();
  await page.getByRole('heading', {name: 'Inspect a release', exact: true}).waitFor();
  check(await page.locator('.presenter-pr-focus').count() === 0, 'release focus used PR layout');
  check(!await page.getByRole('heading', {name: 'Review where you work'}).isVisible(), 'release focus retained unrelated PR panel');
  check(await page.locator('.health-evidence > summary').isVisible(), 'release focus hid health evidence');
  await page.setViewportSize({width: 1920, height: 1080});
  findingMessage = 'LOCAL TEST FIXTURE: visitor-controlled input reaches an HTML response. '.repeat(8);
  checkNames = ['analyze', 'deterministic', 'guard', 'review', 'tests', 'threat-model'];
  await page.goto('http://127.0.0.1:5178/');
  await page.getByRole('heading', {name: 'AI reviews. Your rules decide.', exact: true}).waitFor();
  check(await page.getByRole('checkbox', {name: 'Include closed'}).isChecked(), 'root omitted retained PR history');
  await page.getByRole('link', {name: 'Focus on PR', exact: true}).click();
  await page.getByRole('link', {name: 'Stage view', exact: true}).click();
  await page.locator('.presenter-stage').waitFor();
  check(await page.locator('.stage-exit').isVisible(), 'stage view has no exit control');
  const caveat = page.locator('.presenter-card .semantics').first();
  check(await caveat.isVisible(), 'stage view hides PR reporting and merge-protection caveat');
  check((await caveat.innerText()).includes('PR checks report results. Merge protection is not verified'), 'stage caveat overclaims merge protection');
  const stageGeometry = await page.evaluate(() => {
    const box = selector => {
      const r = document.querySelector(selector).getBoundingClientRect();
      return {left: r.left, top: r.top, right: r.right, bottom: r.bottom};
    };
    return {caveat: box('.presenter-card .semantics'), exit: box('.stage-exit'),
      finding: box('.presenter-findings article'), width: innerWidth, height: innerHeight};
  });
  check(stageGeometry.caveat.top >= 0 && stageGeometry.caveat.bottom < stageGeometry.finding.top, 'stage caveat overlays critical finding');
  check(stageGeometry.finding.bottom <= stageGeometry.exit.top, 'critical finding collides with Exit or falls below it');
  check(stageGeometry.exit.right <= 1920 && stageGeometry.exit.bottom <= 1080, 'stage Exit outside viewport');
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'stage horizontal overflow');
  await watermark();
  await page.screenshot({path: 'presenter-stage-caveat.png', fullPage: false});
  check(await page.locator('.reviewer-grid b').first().evaluate(el => getComputedStyle(el).fontSize) === '26px', 'recorded PR typography is not deployed');
  await page.locator('.stage-exit').click();
  await page.getByRole('heading', {name: 'Review a pull request', exact: true}).waitFor();
  check(await page.locator('.presenter-stage').count() === 0, 'Exit link did not leave stage view');
  await page.getByRole('link', {name: 'Stage view', exact: true}).click();
  await page.locator('.presenter-stage').waitFor();
  await page.keyboard.press('Escape');
  await page.getByRole('heading', {name: 'Review a pull request', exact: true}).waitFor();
  check(await page.locator('.presenter-stage').count() === 0, 'Escape did not leave stage view');
  await page.getByRole('link', {name: 'Full dashboard', exact: true}).click();
  await page.getByRole('heading', {name: 'Agentic gates — execution evidence', exact: true}).waitFor();
  check(await page.evaluate(() => new URL(location.href).searchParams.get('present') === '0'), 'advanced view did not remain reachable');
  findingMessage = 'LOCAL TEST FIXTURE: visitor-supplied text reaches an HTML sink.';
  snapshotOverride = {
    commit: null, commits: [], execution: null, execution_status: null, execution_started: null, selection_state: 'unavailable',
    selection_error: 'LOCAL TEST FIXTURE: ListPipelineExecutions ThrottlingException',
    findings: {tier1: null, tier2: null, tier3: null},
    review_evidence: {tier1: {state: 'unavailable', reason: 'LOCAL TEST FIXTURE: execution history read failed'}},
    pipelines: {[pipeline]: {name: pipeline, stages: [], error: 'ListPipelineExecutions ThrottlingException'}},
  };
  await page.goto(`http://127.0.0.1:5178/?commit=${sha}&pr=7&repo=artifact`);
  await page.getByRole('combobox', {name: 'Deployment revision', exact: true}).waitFor();
  const selectedRevision = page.locator('select').nth(1).locator('option:checked');
  check((await selectedRevision.innerText()).includes('execution history unavailable'), 'throttled revision labeled absent');
  check(!(await selectedRevision.innerText()).includes('not found'), 'failed history read became not found');
  check((await page.getByRole('alert').innerText()).includes('ThrottlingException'), 'actual lookup error hidden');
  check(await page.getByRole('heading', {name: 'Review unavailable', exact: true}).isVisible(), 'unavailable execution became a passing review');
  await watermark();
  await page.screenshot({path: 'presenter-revision-unavailable.png', fullPage: false});
  await page.getByRole('link', {name: 'Full dashboard', exact: true}).click();
  const fullRevision = page.getByRole('button', {name: /Select revision/});
  await fullRevision.waitFor();
  check((await fullRevision.innerText()).includes('execution history unavailable'), 'full view lost unavailable explicit revision');
  check(!(await fullRevision.innerText()).includes('Latest execution'), 'full view substituted latest for failed explicit lookup');
  snapshotOverride.selection_state = 'not_found';
  snapshotOverride.selection_error = 'No retained execution found for requested revision';
  await page.getByRole('link', {name: 'Presenter view', exact: true}).click();
  await page.getByRole('combobox', {name: 'Deployment revision', exact: true}).waitFor();
  check((await selectedRevision.innerText()).includes('not found in retained history'), 'confirmed history miss not distinguished from unavailable');
  check(errors.length === 0, errors.join('\n'));
  return ({result: 'PASS', assertions: checkCount, geometry, consoleErrors: errors, fixture: true});
}
