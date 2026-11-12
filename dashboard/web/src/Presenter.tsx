import type { Snapshot, Pipeline } from './types';
import { useEffect } from 'react';
import { HorseMark, PersonaSigil } from './art';
import { blockingLabel, currentReviews, dateTime, evidenceLabel, prResult, readableMessage, reviewLabel, revisionUrl, selectionUrl, unlistedRevisionLabel } from './state';
import { ExecutionSelector, PipelineEvidenceDetails, PipelineReviewAttempts, PrEvidenceDetails } from './EvidenceDetails';
import { signOut } from './auth';
import './presenter.css';

const statusText = (status?: string) => ({ Succeeded: 'Succeeded', Failed: 'Failed',
  InProgress: 'In progress', NotStarted: 'Not started' }[status ?? ''] ?? 'Unavailable');

function healthStatus(snap: Snapshot) {
  const health = snap.health;
  const mismatched = (health?.execution_id && snap.execution !== health.execution_id)
    || (health?.revision && snap.commit?.sha !== health.revision)
    || (health?.repo && snap.selected_repo !== health.repo);
  if (mismatched) return { state: 'unavailable', label: 'Health evidence unavailable',
    reason: 'Health evidence does not match the selected repository, execution or revision.', mismatched: true };
  if (!health) return { state: 'unavailable',
    label: 'Health evidence unavailable', reason: 'Health evidence was not returned for this execution.' };
  if (!health.state || !health.label?.trim() || !health.reason?.trim() || dateTime(health.observed_at) === 'Unavailable')
    return { state: 'unavailable', label: 'Health evidence unavailable',
      reason: 'Health evidence is incomplete: status, reason, or observation time unavailable.' };
  return { state: health.state, label: health.label, reason: health.reason || 'Health reason unavailable.' };
}

function EvidenceLink({ url, children }: { url?: string; children: React.ReactNode }) {
  if (!url || !/^https:\/\//i.test(url)) return <span>{children} · link unavailable</span>;
  return <a href={url} target="_blank" rel="noreferrer">{children} ↗</a>;
}

export function HealthEvidence({ snap }: { snap: Snapshot }) {
  const status = healthStatus(snap);
  const health = status.mismatched ? undefined : snap.health;
  const deployment = health?.deployment;
  const rollback = health?.rollback;
  const current = health?.current;
  const weights = Object.entries(current?.weights ?? {});
  return <details className="health-evidence" key={`${snap.selected_repo}:${snap.execution ?? ''}:${snap.commit?.sha ?? ''}`}>
    <summary><span>Health evidence</span><b data-health-state={status.state}>{status.label}</b></summary>
    <div className="health-content">
      <section aria-label="Selected execution health history">
        <h4>Selected execution · deployment history</h4>
        <p>{status.reason}</p>
        <dl className="health-facts">
          <div><dt>Repository</dt><dd>{health?.repo ?? snap.selected_repo ?? 'Unavailable'}</dd></div>
          <div><dt>Deployment target</dt><dd>{health?.target ?? 'Unavailable'}</dd></div>
          <div><dt>Execution</dt><dd>{health?.execution_id ?? snap.execution ?? 'Unavailable'}</dd></div>
          <div><dt>Evidence revision</dt><dd>{health?.revision ?? 'Unavailable'}</dd></div>
          <div><dt>Evidence binding</dt><dd>{health?.binding ?? 'Unavailable'}</dd></div>
          <div><dt>Observed at</dt><dd>{dateTime(health?.observed_at)}</dd></div>
        </dl>
        {deployment ? <div className="health-record">
          <EvidenceLink url={deployment.url}>{deployment.service ?? 'CodeDeploy'} deployment {deployment.id || 'ID unavailable'}</EvidenceLink>
          <p><b>{deployment.status || 'Status unavailable'}</b>
            {health?.kind !== 'codebuild' && <>{' · Version '}{deployment.original_version ?? 'unavailable'} → {deployment.target_version ?? 'unavailable'}</>}</p>
          <p className="muted">Started {dateTime(deployment.started)} · Completed {dateTime(deployment.completed)}</p>
          {health?.kind !== 'codebuild' && <p>{deployment.alarm_triggered === true ? 'Deployment alarm trigger recorded'
            : deployment.alarm_triggered === false ? 'No deployment alarm trigger recorded' : 'Deployment alarm trigger evidence unavailable'}</p>
          }
        </div> : <p>Deployment history unavailable.</p>}
        {rollback ? <div className="health-record">
          <EvidenceLink url={rollback.url}>CodeDeploy rollback {rollback.id || 'ID unavailable'}</EvidenceLink>
          <p><b>{rollback.status || 'Status unavailable'}</b>{' · Target version '}{rollback.target_version ?? 'unavailable'}</p>
        </div> : health?.kind !== 'codebuild' && <p>No rollback evidence returned.</p>}
      </section>
      {health?.kind !== 'codebuild' && <section aria-label="Current live health">
        <h4>Current live state · as of {dateTime(health?.observed_at)}</h4>
        <p className="health-caveat">Current alarm OK and the live alias do not prove this selected execution was healthy.</p>
        {current ? <div className="health-record">
          <p><b>Alias {current.alias || 'unavailable'} → version {current.version || 'unavailable'}</b></p>
          <p>Live revision: <code>{current.revision || 'Unavailable'}</code></p>
          <p>{current.matches_selected_revision === true ? 'Live alias matches selected revision'
            : current.matches_selected_revision === false ? 'Live alias differs from selected revision' : 'Live alias revision match unavailable'}</p>
          {current.weights ? <p>{weights.length ? 'Additional traffic weights: ' +
            weights.map(([version, weight]) => `v${version}: ${Number.isFinite(weight) ? `${Number((weight * 100).toFixed(2))}%` : 'unavailable'}`).join(' · ')
            : 'No additional traffic weights reported.'}</p> : <p>Traffic weights unavailable.</p>}
        </div> : <p>Current live alias unavailable.</p>}
        {health?.alarms?.length ? health.alarms.map((alarm, index) => <article className="health-record" key={`${alarm.name}:${index}`}>
          <EvidenceLink url={alarm.url}>CloudWatch · {alarm.name || 'Alarm name unavailable'}</EvidenceLink>
          <p>Current alarm: <b data-alarm-state={alarm.state}>{alarm.state || 'Unavailable'}</b>
            {' · Updated '}{dateTime(alarm.updated)}</p>
          <p>{alarm.reason || 'Current alarm reason unavailable.'}</p>
          <details className="alarm-history">
            <summary>Alarm event history · {alarm.transitions?.length ? `${alarm.transitions.length} returned` : 'unavailable'}</summary>
            <p className="muted">Events describe their displayed times; the current alarm state is separate.</p>
            {alarm.transitions?.length ? <ol>{alarm.transitions.map((event, eventIndex) => <li key={`${event.at}:${eventIndex}`}>
              <time>{dateTime(event.at)}</time><b data-alarm-state={event.state}>{event.state || 'Unavailable'}</b>
              <p>{event.summary || 'Event summary unavailable.'}</p>
            </li>)}</ol> : <p>No alarm events returned. This does not establish a healthy historical run.</p>}
          </details>
        </article>) : <p>Current alarm evidence unavailable.</p>}
      </section>}
      {!!health?.errors?.length && <section className="health-errors" aria-label="Health evidence retrieval errors">
        <h4>Evidence retrieval errors</h4><ul>{health.errors.map((error, i) => <li key={i}>{error}</li>)}</ul>
      </section>}
    </div>
  </details>;
}

export function ReleaseFlow({ pipeline, snap }: { pipeline?: Pipeline; snap: Snapshot }) {
  const stage = (name: string) => pipeline?.error ? undefined : pipeline?.stages.find(s => s.name === name);
  const deployService = snap.repos?.find(r => r.key === snap.selected_repo)?.deploy_service ?? 'Deployment action';
  const health = healthStatus(snap);
  const steps = [
    ['Source', 'GitHub revision', statusText(stage('Source')?.status)],
    ['Automated checks', 'AWS CodeBuild', statusText(stage('AutomatedGates')?.status)],
    ['AI review', 'Findings + rule policy', evidenceLabel(snap.review_evidence?.tier1)],
    ['Approval', 'Human decision in this sample', statusText(stage('Approval')?.status)],
    ['Deployment', deployService, statusText(stage('Deploy')?.status)],
    ['Health', snap.health?.service ?? 'Amazon CloudWatch', health.label],
  ];
  return <ol className="release-flow" aria-label="Primary release path">{steps.map(([title, sub, status]) =>
    <li key={title}><strong>{title}</strong><span>{sub}</span>
      <b data-state={title === 'Health' ? undefined : status} data-health-state={title === 'Health' ? health.state : undefined}>{status}</b></li>)}</ol>;
}

export function Presenter({ snap, mode, receivedAt, onCommit, onRepo, onPr, onClosed, showClosed, commit, pr,
  review, onReview, execution, onExecution, reviewBuild, onReviewBuild }: {
  snap: Snapshot; mode: string; receivedAt?: string; commit?: string; pr?: number; showClosed: boolean;
  review?: number; onReview: (value?: number) => void; execution?: string; onExecution: (value?: string) => void;
  reviewBuild?: string; onReviewBuild: (value?: string) => void;
  onCommit: (value?: string) => void; onRepo: (value?: string) => void;
  onPr: (value?: number) => void; onClosed: (value: boolean) => void;
}) {
  const focusPr = new URLSearchParams(location.search).get('focus') === 'pr';
  const focusRelease = new URLSearchParams(location.search).get('focus') === 'release';
  const stage = focusPr && new URLSearchParams(location.search).get('stage') === '1';
  const exitStage = selectionUrl(location.search, { stage: false });
  useEffect(() => {
    if (!stage) return;
    const exit = (event: KeyboardEvent) => {
      if (event.key === 'Escape') window.location.assign(exitStage);
    };
    window.addEventListener('keydown', exit);
    return () => window.removeEventListener('keydown', exit);
  }, [stage, exitStage]);
  const focusParams = new URLSearchParams(location.search);
  if (focusPr) focusParams.delete('focus'); else focusParams.set('focus', 'pr');
  const releaseParams = new URLSearchParams(location.search);
  if (focusRelease) releaseParams.delete('focus'); else releaseParams.set('focus', 'release');
  const pipeline = snap.pipelines[snap.tiers?.tier1 ?? ''];
  const evidence = snap.review_evidence?.tier1;
  const report = snap.findings.tier1;
  const d = snap.pr.detail;
  const prs = [...snap.pr.open, ...(showClosed ? snap.pr.closed ?? [] : [])];
  const href = revisionUrl(snap, snap.commit?.sha);
  const prHref = revisionUrl(snap, d?.pr.head);
  const failures = snap.failures.filter(f => f.pipeline === pipeline?.name);
  const findings = [...(d?.findings ?? [])].sort((a, b) =>
    Number(b.blocking && !b.outdated) - Number(a.blocking && !a.outdated));
  const excerpt = (value: string) => {
    const plain = readableMessage(value);
    return plain.length > 200 ? plain.slice(0, 200).replace(/\s+\S*$/, '') + '…' : plain;
  };
  return <main className={`presenter${focusPr ? ' presenter-pr-focus' : ''}${focusRelease ? ' presenter-release-focus' : ''}${stage ? ' presenter-stage' : ''}`}>
    {stage && <a className="stage-exit" href={exitStage}>Exit stage view · Esc</a>}
    <header className="presenter-heading"><div><p className="eyebrow">CI/CD ON AWS · THE FALL OF TROY</p>
      <h1>{focusPr ? 'Review a pull request' : focusRelease ? 'Inspect a release' : 'AI reviews. Your rules decide.'}</h1></div><nav aria-label="Dashboard views">
      <a href={'?' + focusParams.toString()}>
        {focusPr ? 'Release overview' : 'Focus on PR'}</a>
      <a href={'?' + releaseParams.toString()}>{focusRelease ? 'Overview' : 'Focus on release'}</a>
      {focusPr && <a href={selectionUrl(location.search, { stage: true })}>Stage view</a>}
      <a href={selectionUrl(location.search, { present: false })}>Full dashboard</a>
      {snap.site && <a href={snap.site} target="_blank" rel="noreferrer"><HorseMark size={28} /> Open {snap.selected_repo === 'road' ? 'dashboard' : 'Troy'} ↗</a>}
      <button type="button" className="sign-out" onClick={() => { void signOut(); }}>Sign out</button>
    </nav></header>
    <div className="presenter-controls">
      <label>Repository<select value={snap.selected_repo} onChange={e => onRepo(e.target.value)}>
        {snap.repos?.map(r => <option key={r.key} value={r.key}>{r.label}</option>)}
      </select></label>
      <label>Deployment revision<select value={commit ?? ''} onChange={e => onCommit(e.target.value || undefined)}>
        <option value="">Latest execution</option>
        {commit && !snap.commits.some(c => c.sha === commit) && <option value={commit}>{commit} — {unlistedRevisionLabel(snap)}</option>}
        {snap.commits.map(c => <option key={c.sha} value={c.sha}>{c.sha.slice(0, 8)} · {c.message}</option>)}
      </select></label>
      <ExecutionSelector snap={snap} execution={execution} onExecution={onExecution} />
      <div className="connection"><b>Connection: {mode === 'polling' ? 'refreshing every 5 s' : mode}</b>
        <span>Received {dateTime(receivedAt)}</span></div>
    </div>
    {snap.selection_error && <div className="presenter-warning" role="alert">{snap.selection_error}</div>}
    <section className="execution-strip" aria-label="Selected deployment execution">
      <div><span>DEPLOYMENT REVISION</span>{href ? <a href={href} target="_blank" rel="noreferrer">{snap.commit?.sha?.slice(0, 12)} ↗</a> : <b>Unavailable</b>}</div>
      <div><span>EXECUTION STARTED</span><b>{dateTime(snap.execution_started)}</b></div>
      <div><span>PIPELINE · {snap.execution?.slice(0, 8) ?? 'NO EXECUTION'}</span><b>{pipeline?.name ?? 'Unavailable'}</b></div>
      <div><span>EXECUTION STATUS</span><b>{statusText(snap.execution_status ?? undefined)}</b></div>
    </section>
    <ReleaseFlow pipeline={pipeline} snap={snap} />
    <div className="presenter-columns">
      <section className="presenter-card" aria-labelledby="pr-heading">
        <p className="eyebrow">01 · GITHUB PULL REQUEST</p><h2 id="pr-heading">Review where you work</h2>
        <p className="semantics">PR checks report results. Merge protection is not verified for this demo repository.</p>
        <div className="pr-controls"><label>Pull request<select aria-label="Pull request" value={pr ?? d?.pr.number ?? ''}
          onChange={e => onPr(e.target.value ? Number(e.target.value) : undefined)}>
          <option value="">Select a pull request</option>
          {d && !prs.some(p => p.number === d.pr.number) && <option value={d.pr.number}>#{d.pr.number} · {d.pr.title}</option>}
          {prs.map(p => <option key={p.number} value={p.number}>#{p.number} · {p.title}</option>)}</select></label>
          <label className="checkbox"><input type="checkbox" checked={showClosed} onChange={e => onClosed(e.target.checked)} />Include closed</label></div>
        <h3 data-state={prResult(snap)}>{prResult(snap)}</h3>
        {snap.pr.evidence?.state === 'unavailable' && <p>{snap.pr.evidence.reason}</p>}
        {d && <><p className="revision-relation"><a href={d.pr.url} target="_blank" rel="noreferrer">PR #{d.pr.number} ↗</a>
          {' · Head '}{prHref ? <a href={prHref}>{d.pr.head.slice(0, 12)}</a> : d.pr.head.slice(0, 12)}
          {d.pr.state && <>{' · '}{d.pr.state}</>}
          {' · '}{d.pr.head === snap.commit?.sha ? 'Same revision as deployment' : 'Different revision from deployment'}</p>
          <div className="check-list">{d.pr.checks?.length ? d.pr.checks.map(c => <a key={c.name} href={c.url} target="_blank" rel="noreferrer">
            {c.name}: <b>{c.conclusion ?? c.status}</b></a>) : <span>Check evidence missing</span>}</div>
          <div className="reviewer-grid">{snap.panel_meta.map(m => {
            const r = [...currentReviews(d)].reverse().find(r => r.persona === m.name);
            return <div key={m.name}><span><PersonaSigil name={m.name} size={22} />{m.name.replace(' Review Agent', '')}</span>
              <b>{reviewLabel(r)}</b></div>;
          })}</div>
          <div className="presenter-findings">{findings.slice(0, 1).map((f, i) => <article key={i}>
            <strong>{f.rule_id} · {f.blocking ? 'blocking rule' : 'advisory rule'}</strong>
            <span>{f.path}:{f.line ?? '?'}</span>{focusPr && <p>{excerpt(f.message)}</p>}</article>)}
            {findings.length > 0 && <p className="preview-note">Preview · {findings.length} finding{findings.length === 1 ? '' : 's'}. Complete rationale in current head details below.</p>}</div>
          <PrEvidenceDetails snap={snap} review={review} onReview={onReview} />
          <p className="muted">PR updated {dateTime(d.pr.updated)}</p></>}
      </section>
      <section className="presenter-card" aria-labelledby="deployment-heading">
        <p className="eyebrow">02 · ONE RELEASE PIPELINE</p><h2 id="deployment-heading">Deployment gates enforce the stop</h2>
        <p className="semantics">CodeBuild checks → human approval → deployment. Models supply findings; policy evaluates them.</p>
        <HealthEvidence snap={snap} />
        <h3 data-state={evidenceLabel(evidence)}>{evidenceLabel(evidence)}</h3><p>{evidence?.reason ?? 'Execution-bound review evidence unavailable'}</p>
        <div className="reviewer-grid">{snap.panel_meta.map(m => {
          const a = report?.agents.find(a => a.name === m.name);
          return <div key={m.name}><span><PersonaSigil name={m.name} size={22} />{m.name.replace(' Review Agent', '')}</span>
            <b>{a?.error ? 'Review error' : a?.verdict ?? evidenceLabel(evidence)}</b><small>{blockingLabel(m.blocking)}</small></div>;
        })}</div>
        <p className="muted">{evidence?.policy_sha256
          ? `Review policy: ${evidence.policy_origin ?? 'origin unavailable'} · SHA-256 ${evidence.policy_sha256.slice(0, 12)} · baseline ${evidence.baseline_revision?.slice(0, 8) ?? evidence.baseline_kind ?? 'unavailable'}. `
          : ''}Rule labels: {snap.policy_metadata?.source ?? 'policy metadata unavailable'}.</p>
        {failures.slice(0, 1).map((f, i) => <div className="presenter-warning" key={i}>
          <strong>{f.stage} / {f.action}: {f.gate_headline ?? 'Failed'}</strong>
          {focusRelease && <p>{(f.gate_reason?.[0] ?? f.log?.[0] ?? f.reason ?? 'Failure detail unavailable').slice(0, 260)}</p>}
        </div>)}
        <PipelineEvidenceDetails report={report} failures={failures} execution={snap.execution} revision={snap.commit?.sha} evidence={evidence} />
        <PipelineReviewAttempts snap={snap} reviewBuild={reviewBuild} onReviewBuild={onReviewBuild} />
        {snap.approval && <div className="presenter-warning"><strong>Waiting for human approval</strong><p>Pending since {dateTime(snap.approval.since)}</p></div>}
        {pipeline && <a href={pipeline.console} target="_blank" rel="noreferrer">Inspect pipeline execution ↗</a>}
      </section>
    </div>
    <footer>Review evidence can be incomplete or unavailable. Tests, scanners, and deployment safeguards remain necessary.</footer>
  </main>;
}
