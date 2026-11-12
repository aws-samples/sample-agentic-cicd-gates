import type { ReactNode } from 'react';
import type { Snapshot, Review, PrFinding, Finding, Report, Failure, Evidence } from './types';
import { currentReviews, dateTime, evidenceLabel, readableMessage, resolveReview, reviewLabel, revisionUrl, selectedReviewAttempt, unlistedRevisionLabel } from './state';
import './evidence-details.css';

function SourceLink({ url, children }: { url?: string; children: ReactNode }) {
  return url && /^https:\/\//i.test(url)
    ? <a href={url} target="_blank" rel="noreferrer">{children} ↗</a>
    : <span>{children} · link unavailable</span>;
}

export function FindingDetails({ findings }: { findings: (PrFinding | Finding)[] }) {
  return <div className="finding-details">{findings.map((f, i) => <article key={i}>
    <strong>{f.rule_id} · {f.blocking ? 'blocking rule' : 'advisory rule'}</strong>
    <p className="report-meta">{'persona' in f ? f.persona : f.agent}
      {' · '}{f.severity || 'Severity unavailable'} · confidence {f.confidence ?? 'unavailable'}
      {'outdated' in f && f.outdated ? ' · Outdated inline location' : ''}</p>
    <p className="finding-path"><SourceLink url={'url' in f ? f.url : undefined}>
      {f.path || 'Path unavailable'}:{f.line ?? '?'}</SourceLink></p>
    <p className="finding-message">{readableMessage(f.message)}</p>
  </article>)}</div>;
}

function ReportDetails({ report, snap, fallbackFindings }: {
  report: Review; snap: Snapshot; fallbackFindings?: PrFinding[];
}) {
  const findings = report.findings ?? fallbackFindings;
  // Use the publisher's link verbatim only when it agrees with the report identity.
  const workflowUrl = report.report_body?.match(/\[Workflow run\]\((https:\/\/github\.com\/[^)\s]+)\)/)?.[1];
  const repo = snap.repos?.find(r => r.key === snap.selected_repo)?.repo
    ?? snap.repo[snap.selected_repo ?? 'artifact'];
  const expectedRun = repo && report.run_id && report.run_attempt
    ? `https://github.com/${repo}/actions/runs/${report.run_id}/attempts/${report.run_attempt}` : undefined;
  return <div className="report-details">
    <h4>{report.persona} · {reviewLabel(report)}</h4>
    {report.evidence && <p className="report-caveat">Publication evidence: {evidenceLabel(report.evidence)} · {report.evidence.reason}</p>}
    {report.error && <p className="report-error">{report.evidence && report.evidence.state !== 'available' ? 'Report detail' : 'Review error'}: {readableMessage(report.error)}</p>}
    <dl className="report-facts">
      <div><dt>Review verdict</dt><dd>{report.verdict || 'Unavailable'}</dd></div>
      <div><dt>GitHub review state</dt><dd>{report.state || 'Unavailable'}</dd></div>
      <div><dt>Report head</dt><dd><SourceLink url={revisionUrl(snap, report.commit_id)}>{report.commit_id || 'Unavailable'}</SourceLink></dd></div>
      <div><dt>Workflow run / attempt</dt><dd>{report.run_id || 'Unavailable'} / {report.run_attempt ?? 'Unavailable'}
        {expectedRun && workflowUrl === expectedRun && <> · <SourceLink url={workflowUrl}>Workflow run</SourceLink></>}</dd></div>
      <div><dt>Submitted</dt><dd>{dateTime(report.submitted)}</dd></div>
      <div><dt>Review IDs / parts</dt><dd>{report.review_ids?.join(', ') || report.id || 'Unavailable'}</dd></div>
      <div><dt>Reported model / thinking</dt><dd>{report.model || 'Unavailable'} / {report.thinking || 'Unavailable'}</dd></div>
      <div><dt>Reported findings</dt><dd>{report.total ?? 'Unavailable'} total · {report.blocking ?? 'Unavailable'} blocking
        {' · '}{report.suppressed ?? 'Unavailable'} suppressed</dd></div>
    </dl>
    {report.state === 'DISMISSED' && <p className="report-caveat">
      Dismissed on GitHub; this is the original published verdict. Dismissal actor, time and reason were not returned.
    </p>}
    <SourceLink url={report.url}>Source review</SourceLink>
    {findings?.length ? <FindingDetails findings={findings} />
      : <p>{findings ? 'No findings returned for this report. The verdict and any review error remain separate.'
        : 'Structured findings unavailable for this report.'}</p>}
    <details className="source-report">
      <summary>Source report · complete published text</summary>
      {report.report_body ? <pre>{report.report_body}</pre>
        : <p>Published report text unavailable from this server. Inspect the source review for additional detail.</p>}
    </details>
  </div>;
}

export function PrEvidenceDetails({ snap, review, onReview }: {
  snap: Snapshot; review?: number; onReview: (value?: number) => void;
}) {
  const detail = snap.pr.detail;
  if (!detail) return <p>Review history unavailable until a PR is selected.</p>;
  const current = currentReviews(detail);
  const history = detail.history;
  const selected = resolveReview(history, review);
  const currentFindings = detail.findings ?? [];
  return <div className="review-evidence" key={`${snap.selected_repo}:${detail.pr.number}`}>
    <details className="current-report-disclosure">
      <summary>Current head · complete review details</summary>
      <div className="evidence-scroll" tabIndex={0} role="region" aria-label="Current head review details">
        {!current.length && <p>No current review reports returned.</p>}
        {current.map((r, i) => <ReportDetails key={r.id ?? i} report={r} snap={snap}
          fallbackFindings={currentFindings.filter(f => f.persona === r.persona)} />)}
        {!!currentFindings.filter(f => !current.some(r => r.persona === f.persona)).length &&
          <FindingDetails findings={currentFindings.filter(f => !current.some(r => r.persona === f.persona))} />}
      </div>
    </details>
    <details className="review-history" open={review !== undefined || undefined}>
      <summary>Review history · {history === undefined ? 'unavailable' : `${history.length} reports`}</summary>
      <div className="history-content">
        <p className="report-caveat">Historical reports do not change the current head’s result above.</p>
        {history === undefined ? <p>Review history unavailable from this server. Current reviews are not a complete history.</p>
          : !history.length ? <p>No retained review reports returned for this PR.</p> : null}
        <label>Review report<select value={selected?.id ?? review ?? ''} onChange={e => onReview(e.target.value ? Number(e.target.value) : undefined)}>
          <option value="">Choose a report</option>
          {review !== undefined && !selected && <option value={review}>{review} · report unavailable</option>}
          {history?.map(r => <option key={r.id} value={r.id}>
            {r.persona.replace(' Review Agent', '')} · {r.verdict} · {r.is_current ? 'Current' : 'Historical'}
            {r.state === 'DISMISSED' ? ' · Dismissed' : ''} · {r.commit_id.slice(0, 8)}
            {' · Run '}{r.run_id ?? '?'} / {r.run_attempt ?? '?'} · {dateTime(r.submitted)} · Review {r.id}
          </option>)}
        </select></label>
        {review !== undefined && !selected && <p role="status">Selected review {review} unavailable in the returned history. No other report has been substituted.</p>}
        {selected && <div className="evidence-scroll selected-review" tabIndex={0} role="region" aria-label="Selected review report" key={selected.id}>
          <p className="report-caveat">{selected.is_current ? 'Current head report' : 'Historical report'}
            {selected.history_reason ? ` · ${selected.history_reason}` : ''}</p>
          <ReportDetails report={selected} snap={snap} />
        </div>}
      </div>
    </details>
  </div>;
}

export function ExecutionSelector({ snap, execution, onExecution }: {
  snap: Snapshot; execution?: string; onExecution: (value?: string) => void;
}) {
  return <label className="execution-selector">Pipeline execution<select value={execution ?? ''}
    onChange={e => onExecution(e.target.value || undefined)}>
    <option value="">Follow selected revision / latest</option>
    {snap.executions === undefined && <option disabled>Execution history unavailable from this server</option>}
    {execution && !snap.executions?.some(e => e.execution_id === execution) &&
      <option value={execution}>{execution} · {unlistedRevisionLabel(snap)}</option>}
    {snap.executions?.map(e => <option key={e.execution_id} value={e.execution_id}>
      {dateTime(e.started)} · {e.status} · {e.sha.slice(0, 8)} · {e.execution_id}
    </option>)}
  </select></label>;
}

export function PipelineReviewAttempts({ snap, reviewBuild, onReviewBuild }: {
  snap: Snapshot; reviewBuild?: string; onReviewBuild: (value?: string) => void;
}) {
  const attempts = snap.review_attempts;
  const historyEvidence = snap.review_attempts_evidence;
  const incompleteHistory = historyEvidence && historyEvidence.state !== 'available';
  const { member, report, evidence } = selectedReviewAttempt(snap, reviewBuild);
  return <details className="pipeline-review-attempts" open={reviewBuild !== undefined || undefined}>
    <summary>Review attempts · {attempts === undefined ? 'unavailable' : `${attempts.length} builds`}{incompleteHistory ? ' · history incomplete' : ''}</summary>
    <div className="history-content">
      <p className="report-caveat">Attempts belong to the selected primary execution. Older reports do not change its current verdict.</p>
      {historyEvidence && <p className="report-caveat">Attempt history evidence: {evidenceLabel(historyEvidence)} · {historyEvidence.reason}</p>}
      {attempts === undefined && <p>Review attempt history unavailable from this server.</p>}
      {attempts?.length === 0 && !incompleteHistory && <p>No retained review attempts returned for this execution.</p>}
      <label>Review attempt<select value={reviewBuild ?? ''} onChange={e => onReviewBuild(e.target.value || undefined)}>
        <option value="">Choose a build attempt</option>
        {reviewBuild && !member && <option value={reviewBuild}>{reviewBuild} · attempt unavailable</option>}
        {attempts?.map(a => <option key={a.build_id} value={a.build_id}>
          {a.is_current === true ? 'Current' : a.is_current === false ? 'Historical' : 'Relationship unavailable'}
          {' · '}{a.status || 'Status unavailable'} · {dateTime(a.started)} · {a.build_id}
        </option>)}
      </select></label>
      {reviewBuild && <div className="selected-build" key={reviewBuild}>
        <p className="report-caveat">{member?.is_current === true ? 'Current review attempt'
          : member?.is_current === false ? 'Historical review attempt' : 'Review attempt relationship unavailable'}</p>
        <dl className="report-facts">
          <div><dt>Build ID</dt><dd>{reviewBuild}</dd></div>
          <div><dt>Action execution ID</dt><dd>{member?.action_execution_id || 'Unavailable'}</dd></div>
          <div><dt>Build status</dt><dd>{member?.status || 'Unavailable'}</dd></div>
          <div><dt>Started / ended</dt><dd>{dateTime(member?.started)} / {dateTime(member?.ended)}</dd></div>
        </dl>
        {member && <SourceLink url={member.url}>Source build attempt</SourceLink>}
        <PipelineEvidenceDetails report={report} evidence={evidence} execution={snap.execution}
          revision={snap.commit?.sha} title="Selected review attempt · complete report" expanded />
      </div>}
    </div>
  </details>;
}

export function PipelineEvidenceDetails({ report, failures = [], execution, revision, evidence, expanded, title = 'Complete pipeline review details' }: {
  report: Report; failures?: Failure[]; execution?: string | null; revision?: string;
  title?: string; evidence?: Evidence; expanded?: boolean;
}) {
  return <details className="pipeline-report-disclosure" key={`${execution}:${revision}`} open={expanded || undefined}>
    <summary>{title}</summary>
    <div className="evidence-scroll" tabIndex={0} role="region" aria-label={title}>
      <p className="report-meta">Selected execution: {execution || 'Unavailable'} · Revision: {revision || 'Unavailable'}</p>
      {evidence && <p>Review evidence: {evidenceLabel(evidence)} · {evidence.reason}</p>}
      {!report && <p>Review report unavailable for this selection.</p>}
      {report && <><p>Reported verdict: {report.verdict || 'Unavailable'}</p>
        {report.error && <p className="report-error">{report.error}</p>}
        {report.agents.map((a, i) => <article key={i}>
          <h4>{a.name} · {a.error ? 'Review error' : a.verdict || 'Verdict unavailable'}</h4>
          <p className="report-meta">Reported model: {a.model || 'Unavailable'} · Thinking: {a.thinking || 'Unavailable'}</p>
          {a.error && <p className="report-error">{a.error}</p>}
        </article>)}
        {report.findings.length ? <FindingDetails findings={report.findings} />
          : <p>No findings returned. Any review errors above still apply.</p>}
        <details className="source-report"><summary>Source pipeline report · complete returned data</summary>
          <pre>{report.report_body ?? JSON.stringify(report, null, 2)}</pre></details>
      </>}
      {failures.map((f, i) => <article key={i}>
        <h4>{f.stage} / {f.action} · {f.gate_headline || 'Failed'}</h4>
        {f.gate_reason?.map((reason, j) => <p className="finding-message" key={j}>{reason}</p>)}
        {f.reason && <p className="finding-message">{f.reason}</p>}
        {f.log?.length ? <pre>{f.log.join('\n')}</pre> : null}
        <SourceLink url={f.url}>Source action</SourceLink>
      </article>)}
    </div>
  </details>;
}
