import type { Snapshot, Evidence, Review, ReviewHistory } from './types';

export function revisionUrl(snap: Pick<Snapshot, 'repos' | 'selected_repo' | 'repo'>, sha?: string | null): string | undefined {
  const repo = snap.repos?.find(r => r.key === snap.selected_repo)?.repo
    ?? snap.repo[snap.selected_repo ?? 'artifact'];
  if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo) || !sha || !/^[a-f0-9]{7,40}$/i.test(sha)) return undefined;
  return `https://github.com/${repo}/commit/${sha}`;
}
export function evidenceLabel(e?: Evidence): string {
  return ({ passed: 'Passed', blocked: 'Blocked', blocked_error: 'Blocked — review error',
    unavailable: 'Review unavailable', expired: 'Evidence expired', missing: 'Evidence missing',
    not_reviewed: 'Not reviewed', reviewing: 'Review in progress', available: 'Available' } as Record<string, string>)[e?.state ?? ''] ?? 'Review unavailable';
}
export const blockingLabel = (blocking?: boolean | null) =>
  blocking === true ? 'Can block by rule' : blocking === false ? 'Advisory rules' : 'Rule policy unavailable';

export function unlistedRevisionLabel(snap?: Pick<Snapshot, 'selection_state'> | null) {
  // Absence from a list is not proof of absence from retained execution history.
  return snap?.selection_state === 'not_found' ? 'not found in retained history' : 'execution history unavailable';
}

export function initialSelection(search: string) {
  const p = new URLSearchParams(search);
  const pr = p.get('pr');
  const review = p.get('review');
  return { commit: p.get('commit') || undefined, repo: p.get('repo') || undefined,
    pr: pr && /^\d+$/.test(pr) ? Number(pr) : undefined,
    review: review && /^[1-9]\d*$/.test(review) && Number.isSafeInteger(Number(review)) ? Number(review) : undefined,
    execution: p.get('execution') || undefined,
    review_build: p.get('review_build') || undefined,
    closed: p.get('closed') !== '0', history: p.get('history') === '1', present: p.get('present') !== '0' };
}
export type Selection = ReturnType<typeof initialSelection>;
export function changeSelection(s: Selection, change: Partial<Selection>): Selection {
  const next = { ...s, ...change };
  if ('repo' in change && change.repo !== s.repo)
    return { ...next, commit: undefined, execution: undefined, review_build: undefined, pr: undefined, review: undefined };
  if ('pr' in change && change.pr !== s.pr) next.review = undefined;
  if ('commit' in change) { next.execution = undefined; next.review_build = undefined; }
  if ('execution' in change) { next.commit = undefined; next.review_build = undefined; }
  return next;
}
export function selectionUrl(search: string, values: Record<string, string | number | boolean | undefined>): string {
  const p = new URLSearchParams(search);
  for (const [key, value] of Object.entries(values)) {
    if ((key === 'present' || key === 'closed') && value === false) p.set(key, '0');
    else if (value === undefined || value === false || value === '') p.delete(key);
    else p.set(key, value === true ? '1' : String(value));
  }
  return `?${p}`;
}
export function prResult(snap: Snapshot): string {
  if (snap.pr.evidence?.state === 'unavailable') return 'Review unavailable';
  const d = snap.pr.detail;
  if (!d) return 'No PR selected';
  if (d.review_running) return 'Review in progress';
  const reviews = snap.panel_meta.map(m => [...currentReviews(d)].reverse().find(r => r.persona === m.name));
  if (reviews.some(r => r?.evidence && r.evidence.state !== 'available'))
    return reviews.some(r => r?.evidence?.state === 'missing') ? 'Review evidence missing' : 'Review unavailable';
  if (reviews.some(r => r?.error || r?.verdict === 'BLOCKED_ERROR' || r?.verdict === 'ADVISORY_ERROR')) return 'Reports a review error';
  if (reviews.some(r => r?.verdict === 'FAIL')) return 'Reports blocking findings';
  if (!reviews.length || reviews.some(r => !r)) return 'Review evidence missing';
  if (reviews.some(r => r?.verdict !== 'PASS')) return 'Review unavailable';
  return 'Review reports PASS';
}
export function currentReviews(detail: NonNullable<Snapshot['pr']['detail']>): Review[] {
  return detail.reviews.filter(r => r.is_current !== false && r.state !== 'DISMISSED'
    && (!r.commit_id || r.commit_id === detail.pr.head));
}
export function resolveReview(history?: ReviewHistory[], review?: number): ReviewHistory | undefined {
  if (review === undefined) return undefined;
  const primary = history?.find(r => r.id === review);
  if (primary) return primary;
  const aliases = history?.filter(r => r.review_ids?.includes(review)) ?? [];
  return aliases.length === 1 ? aliases[0] : undefined;
}
export function selectedReviewAttempt(snap: Snapshot, build?: string) {
  const member = snap.review_attempts?.find(a => a.build_id === build);
  const selected = snap.review_attempt;
  if (!build) return { member, report: null, evidence: undefined };
  const mismatch = selected && (selected.build_id !== build
    || (selected.evidence?.build_id && selected.evidence.build_id !== build)
    || (selected.evidence?.execution_id && selected.evidence.execution_id !== snap.execution)
    || (selected.evidence?.revision && selected.evidence.revision !== snap.commit?.sha));
  if (mismatch) return { member, report: null, evidence: {state: 'unavailable',
    reason: 'Returned review attempt does not match the requested build, execution or revision.'} };
  if (!member) return { member, report: null, evidence: {state: 'unavailable',
    reason: `Selected build ${build} is not in the returned attempts for this execution. ${selected?.evidence?.reason ?? snap.review_attempts_evidence?.reason ?? 'Attempt history may be unavailable.'}`} };
  if (!selected?.evidence) return { member, report: null, evidence: {state: 'unavailable',
    reason: 'Selected review attempt report unavailable from this server. The current report has not been substituted.'} };
  const readable = ['available', 'passed', 'blocked', 'blocked_error'].includes(selected.evidence.state);
  return { member, report: readable ? selected.report : null, evidence: selected.evidence };
}
export function reviewLabel(review?: Review): string {
  if (!review) return 'No review for this head';
  if (review.evidence && review.evidence.state !== 'available') return evidenceLabel(review.evidence);
  if (review.verdict === 'UNAVAILABLE') return 'Review unavailable';
  return review.error ? 'Review error' : review.verdict || 'Verdict unavailable';
}
export function readableMessage(value: string): string {
  return value.replace(/\\([\\`*_()[\]{}])/g, '$1')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'").replace(/&amp;/g, '&');
}
// An older server can silently ignore execution=. Never label its newest result
// as the requested historical run. PR evidence is independent and can still render.
export function bindExecution(snap: Snapshot, execution?: string, commit?: string): Snapshot {
  if (!execution || (snap.execution === execution && (!commit || snap.commit?.sha === commit))
    || (snap.selection_error && !snap.execution)) return snap;
  return { ...snap, selection_state: 'unavailable',
    selection_error: `Exact execution ${execution} unavailable: the server returned a different execution or revision.`,
    execution: null, execution_status: null, execution_started: null, commit: null,
    findings: { tier1: null, tier2: null, tier3: null }, panel_progress: null,
    review_evidence: {}, review_attempt: undefined, review_attempts: undefined, review_attempts_evidence: undefined,
    health: undefined, failures: [], approval: null, feed: [],
    pipelines: Object.fromEntries(Object.entries(snap.pipelines).map(([key, p]) =>
      [key, { ...p, stages: [], error: 'Exact execution evidence unavailable' }])) };
}
export function bindSelection(snap: Snapshot, selection: Partial<Selection>): Snapshot {
  const wrongRepo = !!selection.repo && snap.selected_repo !== selection.repo;
  const wrongRevision = !!selection.commit && snap.commit?.sha !== selection.commit;
  const wrongExecution = !!selection.execution && snap.execution !== selection.execution;
  const wrongPr = selection.pr !== undefined && snap.pr.detail?.pr.number !== selection.pr;
  if (!wrongRepo && !wrongRevision && !wrongExecution && !wrongPr) return snap;
  const reason = (!wrongRepo && snap.selection_error)
    || (wrongExecution && !wrongRepo
      ? `Exact execution ${selection.execution} unavailable: the server returned a different execution or revision.`
      : 'Returned evidence does not match the selected repository, revision, execution or pull request.');
  // A selector must never relabel another selection's successful evidence.
  return {
    ...snap, selected_repo: selection.repo ?? snap.selected_repo,
    selected_commit: selection.commit, selected_execution: selection.execution,
    selection_state: !wrongRepo && !snap.execution && snap.selection_state === 'not_found'
      ? 'not_found' : 'unavailable', selection_error: reason,
    commit: null, execution: null, execution_status: null, execution_started: null,
    live: false, findings: {tier1: null, tier2: null, tier3: null},
    panel_progress: null, review_evidence: {}, health: undefined,
    review_attempt: undefined, review_attempts: [], review_attempts_evidence: undefined,
    feed: [], failures: [], approval: null,
    // The PR has its own selector. Keep its correctly bound evidence when only
    // the deployment lookup failed, but never carry it across repositories.
    pr: wrongRepo || wrongPr
      ? {open: [], closed: [], detail: null, evidence: {state: 'unavailable', reason}}
      : snap.pr,
    pipelines: Object.fromEntries(Object.entries(snap.pipelines).map(([key, p]) =>
      [key, {...p, stages: [], error: reason}])),
    ...(wrongRepo ? {commits: [], executions: [], pipelines: {}, tiers: undefined, site: ''} : {}),
  };
}
export function dateTime(iso?: string | null): string {
  if (!iso) return 'Unavailable';
  let normalized = iso.replace(' ', 'T');
  if (!/(Z|[+-]\d{2}:?\d{2})$/.test(normalized)) normalized += 'Z';
  const d = new Date(normalized);
  return Number.isNaN(d.getTime()) ? 'Unavailable' : d.toLocaleString([], {
    year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short',
  });
}
