import {
  Alert, AppLayout, Badge, Box, Button, ColumnLayout, Container, ContentLayout,
  ExpandableSection, Grid, Header, Link, Select, SpaceBetween, Spinner,
  Pagination, StatusIndicator, Table, Toggle,
} from "@cloudscape-design/components";
import type { SelectProps, StatusIndicatorProps } from "@cloudscape-design/components";
import { Fragment, useEffect, useRef, useState } from "react";
import { HorseMark, PersonaSigil } from "./art";

/* ---------- types mirroring /api/snapshot ---------- */
import type { Pipeline, Agent, Finding, Report, PanelMeta, Progress, FeedItem, Snapshot, Failure, Evidence } from "./types";
import { bindSelection, changeSelection, currentReviews, reviewLabel, revisionUrl, evidenceLabel, blockingLabel, initialSelection, selectionUrl, unlistedRevisionLabel } from "./state";
import { Presenter, ReleaseFlow } from "./Presenter";
import { ExecutionSelector, PipelineEvidenceDetails, PipelineReviewAttempts, PrEvidenceDetails } from "./EvidenceDetails";
import { authorizedFetch, signOut } from "./auth";

/* Seat emoji come from the panel config the gate actually uses, not a literal
 * map keyed by name - renaming a seat in .reviewer.yaml used to silently drop
 * its icon here. */
function emojiFor(meta: PanelMeta[] | undefined, name?: string | null): string {
  if (!name) return "";
  return meta?.find((m) => m.name === name)?.emoji ?? "";
}

function stype(s?: string | null): StatusIndicatorProps.Type {
  switch (s) {
    case "Succeeded": case "success": case "PASS": return "success";
    case "Failed": case "failure": case "FAIL": case "BLOCKED_ERROR": case "Review error": return "error";
    case "ADVISORY_ERROR": case "Unavailable": case "Review unavailable": case "Evidence missing": return "warning";
    case "InProgress": case "in_progress": case "queued": case "running": return "in-progress";
    case "Info": return "info";
    case "Stopped": return "stopped";
    default: return "pending";
  }
}
const short = (sha?: string | null) => (sha ? sha.slice(0, 8) : "—");
/* Times are shown in the VIEWER's timezone in 12-hour form, because they get
 * read aloud in a room and compared against a wall clock. UTC is the transport,
 * never the display. With history on, the feed spans a whole day, so a bare time
 * is ambiguous - every list that can cross midnight carries the date too. */
const parseTs = (iso?: string | null): Date | null => {
  if (!iso) return null;
  // Timestamps arrive three ways: ISO with an offset or Z (most), the
  // "YYYY-MM-DD HH:MM:SS+00:00" space form when a datetime fell through
  // json.dumps(default=str) - which Safari refuses to parse - and, if a naive
  // datetime ever slips out, with no zone at all, which JS would read as LOCAL
  // and silently shift by the whole UTC offset. Normalise all three.
  let t = iso.includes("T") ? iso : iso.replace(" ", "T");
  if (!/(Z|[+-]\d{2}:?\d{2})$/.test(t)) t += "Z";        // the backend emits UTC
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? null : d;
};
const clock = (iso?: string | null) => {
  const d = parseTs(iso);
  return d ? d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit",
                                        second: "2-digit" }) : "";
};
/* Local calendar day, for deciding where one day ends and the next begins. */
const dayKey = (iso?: string | null) => {
  const d = parseTs(iso);
  return d ? d.toLocaleDateString([], { year: "numeric", month: "2-digit",
                                        day: "2-digit" }) : "";
};
const dayLabel = (iso?: string | null) => {
  const d = parseTs(iso);
  if (!d) return "";
  const now = new Date();
  const yest = new Date(now);
  yest.setDate(now.getDate() - 1);
  const k = dayKey(iso);
  if (k === dayKey(now.toISOString())) return "Today";
  if (k === dayKey(yest.toISOString())) return "Yesterday";
  return d.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
};
/* Date + time, for any row that can be older than today. */
const stamp = (iso?: string | null) => {
  const d = parseTs(iso);
  if (!d) return "";
  return `${d.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" })}, ${clock(iso)}`;
};

/* ---------- widgets ---------- */
function PipelineWidget({ p, title, subtitle }: { p?: Pipeline; title: string; subtitle: string }) {
  return (
    <Container fitHeight
      header={<Header variant="h2" description={subtitle}
        actions={p && <Link external href={p.console} variant="secondary">Console</Link>}>
        {title}
      </Header>}>
      {!p ? <Spinner /> : p.error ? <StatusIndicator type="error">{p.error}</StatusIndicator> : (
        <SpaceBetween size="s">
          {p.stages.map((s) => (
            <div key={s.name}>
              <StatusIndicator type={stype(s.status)}>{s.name}</StatusIndicator>
              <Box padding={{ left: "l" }} fontSize="body-s">
                {s.actions.map((a) => (
                  <div key={a.name}
                    style={{ display: "flex", justifyContent: "space-between",
                             alignItems: "baseline", gap: 12 }}>
                    <StatusIndicator type={stype(a.status)}>
                      {a.url ? <Link external fontSize="body-s" href={a.url}>{a.name}</Link> : a.name}
                    </StatusIndicator>
                    <Box color="text-body-secondary" fontSize="body-s"
                      fontWeight="normal">
                      <span style={{ fontVariantNumeric: "tabular-nums" }}>
                        {a.status === "NotStarted" ? "—" : clock(a.when)}
                      </span>
                    </Box>
                  </div>
                ))}
                {s.actions.filter((a) => a.status === "Failed" && a.reason).map((a) => (
                  <Box key={`${a.name}-why`} color="text-status-error" fontSize="body-s"
                    padding={{ top: "xxs" }}>
                    {a.name}: {a.reason!.slice(0, 220)}
                  </Box>
                ))}
              </Box>
            </div>
          ))}
        </SpaceBetween>
      )}
    </Container>
  );
}

function AgentCard({ meta, agent, prog, findings }: {
  meta: PanelMeta;
  agent?: Agent;
  prog?: { state: string; verdict?: string; blocking?: number; discovered?: number };
  findings: Finding[];
}) {
  const live = prog && prog.state !== "done";
  return (
    <SpaceBetween size="xxs">
      <Box variant="awsui-key-label">
        <SpaceBetween direction="horizontal" size="xxs">
          <PersonaSigil name={meta.name} size={15} />
          <span>{meta.name}</span>
        </SpaceBetween>
      </Box>
      {live ? (
        <StatusIndicator type={prog!.state === "running" ? "in-progress" : "pending"}>
          {prog!.state === "running" ? "reviewing the diff…" : "waiting for its turn"}
        </StatusIndicator>
      ) : (
        <StatusIndicator type={agent?.error ? "warning" : stype(prog?.verdict ?? agent?.verdict)}>
          {agent?.error ? "advisory error"
            : `${prog?.verdict ?? agent?.verdict ?? "—"}${(prog?.blocking ?? agent?.blocking ?? 0) > 0
              ? ` · ${prog?.blocking ?? agent?.blocking} blocking` : ""}`}
          {prog?.discovered != null ? ` · ${prog.discovered} discovered` : ""}
        </StatusIndicator>
      )}
      <SpaceBetween direction="horizontal" size="xxs">
        <Badge color="blue">{meta.model.replace(/^us\./, "")}</Badge>
        <Badge>{`thinking: ${meta.thinking}`}</Badge>
        <Badge color={meta.blocking ? "red" : "grey"}>{blockingLabel(meta.blocking)}</Badge>
      </SpaceBetween>
      <Box fontSize="body-s" color="text-body-secondary">
        Owns <Box variant="code" display="inline" fontSize="body-s">{meta.rules}</Box> — {meta.persona}
      </Box>
      {findings.length > 0 && (
        <ExpandableSection variant="footer"
          defaultExpanded={findings.some((f) => f.blocking)}
          headerText={`${findings.length} finding${findings.length > 1 ? "s" : ""}`
            + (findings.some((f) => f.blocking) ? " — why it blocked" : "")}>
          <SpaceBetween size="xs">
            {findings.map((f, i) => (
              <Box key={i} fontSize="body-s">
                <StatusIndicator type={f.blocking ? "error" : "info"}>{f.rule_id}</StatusIndicator>{" "}
                <Box variant="code" display="inline" fontSize="body-s">{f.path}:{f.line}</Box>
                {" "}(conf {f.confidence}) — {f.message}
              </Box>
            ))}
          </SpaceBetween>
        </ExpandableSection>
      )}
    </SpaceBetween>
  );
}

function PanelMatrix({ findings, meta, prog, evidence }: {
  findings: { tier1: Report; tier2: Report; tier3: Report };
  meta: PanelMeta[];
  prog: Progress;
  evidence?: Record<string, Evidence>;
}) {
  const tiers: { key: keyof typeof findings; label: string; sub: string }[] = [
    { key: "tier1", label: "Tier 1", sub: "our harness · CodeBuild" },
    { key: "tier2", label: "Tier 2", sub: "our harness · AgentCore" },
    { key: "tier3", label: "Tier 3", sub: "managed harness · Kiro" },
  ];
  const cell = (r: Report, name: string, tier: string) => {
    const live = tier === "tier1" && prog?.active ? prog.agents[name] : undefined;
    if (live && live.state !== "done") {
      return (
        <StatusIndicator type={live.state === "running" ? "in-progress" : "pending"}>
          {live.state === "running" ? "reviewing…" : "queued"}
        </StatusIndicator>
      );
    }
    if (!r) return <span title={evidence?.[tier]?.reason}>{evidenceLabel(evidence?.[tier])}</span>;
    const a = r.agents.find((x) => x.name === name);
    if (!a) return <Box color="text-body-secondary" fontSize="body-s">—</Box>;
    return (
      <SpaceBetween size="xxs">
        <StatusIndicator type={a.error ? "warning" : stype(a.verdict)}>
          {a.error ? "error" : a.verdict}{a.blocking > 0 ? ` · ${a.blocking} blocking` : ""}
        </StatusIndicator>
        {a.model && <Box fontSize="body-s" color="text-body-secondary">
          Reported model: {a.model}{a.model === "kiro-managed" ? " (identity unverified)" : ""}
        </Box>}
        {a.error && (
          <Box fontSize="body-s" color="text-status-warning">
            <span style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{a.error}</span>
          </Box>
        )}
      </SpaceBetween>
    );
  };
  const allFindings = tiers.flatMap((t) =>
    (findings[t.key]?.findings ?? []).map((f) => ({ ...f, tier: t.label })));

  return (
    <Container header={<Header variant="h2"
      description="Independent execution options matched to the selected revision. Managed models and configuration can differ.">
      The review panel
    </Header>}>
      <SpaceBetween size="m">
        <Table
          variant="embedded"
          items={meta}
          trackBy="name"
          columnDefinitions={[
            {
              id: "seat", header: "Configured reviewer (dashboard build)", width: 320,
              cell: (m) => (
                <SpaceBetween size="xxs">
                  <SpaceBetween direction="horizontal" size="xxs">
                    <PersonaSigil name={m.name} size={15} />
                    <Box fontWeight="bold">{m.name}</Box>
                    <Badge color={m.blocking ? "red" : "grey"}>
                      {blockingLabel(m.blocking)}
                    </Badge>
                  </SpaceBetween>
                  <Box fontSize="body-s" color="text-body-secondary">
                    owns <Box variant="code" display="inline" fontSize="body-s">{m.rules}</Box>
                    {" · "}{m.model.replace(/^us\./, "")} · thinking {m.thinking}
                  </Box>
                </SpaceBetween>
              ),
            },
            ...tiers.map((t) => ({
              id: t.key,
              header: (
                <SpaceBetween size="xxs">
                  <Box fontWeight="bold">{t.label}</Box>
                  <Box fontSize="body-s" color="text-body-secondary">{t.sub}</Box>
                </SpaceBetween>
              ),
              cell: (m: PanelMeta) => cell(findings[t.key], m.name, t.key),
            })),
          ]}
        />
        {allFindings.length > 0 && (
          <ExpandableSection variant="footer"
            defaultExpanded={allFindings.some((f) => f.blocking)}
            headerText={`Findings across tiers (${allFindings.length})`}>
            <SpaceBetween size="xs">
              {allFindings.map((f, i) => (
                <Box key={i} fontSize="body-s">
                  <SpaceBetween direction="horizontal" size="xxs">
                    <Badge color="grey">{f.tier}</Badge>
                    <PersonaSigil name={f.agent ?? ""} size={14} label />
                    <StatusIndicator type={f.blocking ? "error" : "info"}>{f.rule_id}</StatusIndicator>
                  </SpaceBetween>
                  <Box padding={{ left: "l" }} fontSize="body-s">
                    <Box variant="code" display="inline" fontSize="body-s">{f.path}:{f.line}</Box>
                    {" "}(conf {f.confidence}) — {f.message}
                  </Box>
                </Box>
              ))}
            </SpaceBetween>
          </ExpandableSection>
        )}
        <Box fontSize="body-s" color="text-body-secondary">
          Verdicts evaluate model findings against rule metadata. Models can miss or misclassify issues.
          Labels describe rules bundled with this dashboard; historical reviews may use another policy.
        </Box>
      </SpaceBetween>
    </Container>
  );
}

function PrWidget({ pr, selected, onSelect, meta, showClosed, onShowClosed, snap, review, onReview }: {
  pr: Snapshot["pr"]; selected?: number; onSelect: (n?: number) => void;
  meta?: PanelMeta[]; showClosed: boolean; onShowClosed: (v: boolean) => void;
  snap: Snapshot; review?: number; onReview: (value?: number) => void;
}) {
  const d = pr.detail;
  // Closed rows are appended rather than interleaved: the open ones are what a
  // reviewer can still act on, and in a quiet repository there are none - which
  // is the whole reason for the toggle, since the panel then has history to show
  // instead of an empty table.
  const items = showClosed ? [...pr.open, ...(pr.closed ?? [])] : pr.open;
  return (
    <Container header={<Header variant="h2"
      description="Pick a PR to drill into its checks and persona reviews"
      actions={
        <SpaceBetween direction="horizontal" size="m">
          <Toggle checked={showClosed} onChange={({ detail }) => onShowClosed(detail.checked)}>
            Include closed
          </Toggle>
          {d && <Link external href={d.pr.url}>Open PR #{d.pr.number}</Link>}
        </SpaceBetween>
      }>
      PR surface — GitHub
    </Header>}>
      <SpaceBetween size="m">
        <Box>Checks report results. Merge protection is not verified for this demo repository.</Box>
        {pr.evidence?.state === "unavailable" && <Alert type="warning">{pr.evidence.reason}</Alert>}
        {d && <Box>PR head {short(d.pr.head)} · updated {stamp(d.pr.updated)}. Current reviewer cards apply to this head; retained reports are separate below.</Box>}
        <Table
          variant="embedded"
          items={items}
          trackBy="number"
          selectionType="single"
          selectedItems={d ? items.filter((r) => r.number === d.pr.number) : []}
          onSelectionChange={({ detail }) => onSelect(detail.selectedItems[0]?.number)}
          ariaLabels={{ selectionGroupLabel: "Pull requests",
            itemSelectionLabel: (_, item) => `PR ${item.number}` }}
          columnDefinitions={[
            { id: "n", header: "#", cell: (i) => i.number, width: 60 },
            { id: "t", header: "Title", cell: (i) => i.title },
            // State as a WORD. A closed row that differed only by row colour
            // would fail the same A11Y-004 rule this panel enforces on others.
            { id: "s", header: "State", width: 100,
              cell: (i) => <Badge color={i.state === "open" ? "green"
                : i.state === "merged" ? "blue" : "grey"}>{i.state ?? "open"}</Badge> },
            // A closed pull request can be days old, so the date is not optional.
            { id: "u", header: "Updated", cell: (i) => stamp(i.updated), width: 170 },
          ]}
          empty={<Box textAlign="center" color="text-body-secondary">
            {showClosed ? "No pull requests on this repository"
              : "No open pull requests — turn on “Include closed” to see recent ones"}
          </Box>}
        />
        {d && (
          <SpaceBetween size="m">
            {/* Two rows, two different things - and readers took the top row
              * as "three of the four reviewers". Label them.
              * Counts come from the DATA, never typed out, because a hand-typed
              * "three lanes" or "four seats" is the exact failure that has bitten
              * this file five times. And not "Required checks": these repos are
              * private on a plan without branch protection, so the checks report
              * and Tier 1 is what refuses to deploy. */}
            <Box variant="awsui-key-label">
              Checks — {(d.pr.checks ?? []).length} gate lanes on this pull request
            </Box>
            <SpaceBetween direction="horizontal" size="m">
              {(d.pr.checks ?? []).map((c) => (
                <StatusIndicator key={c.name}
                  type={c.status !== "completed" ? "in-progress"
                    : stype(c.conclusion === "success" ? "Succeeded" : "Failed")}>
                  <Link external fontSize="body-s" href={c.url}>{c.name}</Link>
                </StatusIndicator>
              ))}
            </SpaceBetween>
            {d.review_running && (
              <StatusIndicator type="in-progress">panel reviewing this PR now…</StatusIndicator>
            )}
            {/* latest verdict per persona, newest last */}
            <Box variant="awsui-key-label">
              Review panel — {(meta ?? []).length} seats, all inside the{" "}
              <Box variant="code" display="inline">review</Box> check above
            </Box>
            <ColumnLayout columns={4} variant="text-grid">
              {/* Seats come from the panel config the gate runs. A literal array
                * here is what showed retired codenames next to identical fallback
                * icons: PersonaSigil matched none of them, so every seat drew the
                * default glyph. The comment at the top of this file warns about
                * exactly this failure and this array survived the rename anyway. */}
              {(meta ?? []).map((m) => m.name).map((name) => {
                const r = [...currentReviews(d)].reverse().find((x) => x.persona === name);
                return (
                  <div key={name}>
                    <Box variant="awsui-key-label">
                      <SpaceBetween direction="horizontal" size="xxs">
                        <PersonaSigil name={name} size={14} />
                        <span>{name}</span>
                      </SpaceBetween>
                    </Box>
                    {!r ? <Box color="text-body-secondary" fontSize="body-s">no review</Box> : (
                      <SpaceBetween size="xxs">
                        <StatusIndicator type={stype(reviewLabel(r))}>
                          {reviewLabel(r)}{(r.blocking ?? 0) > 0 ? ` · ${r.blocking} blocking` : ""}
                        </StatusIndicator>
                        <Box fontSize="body-s" color="text-body-secondary">
                          {r.total == null ? "Finding count unavailable" : `${r.total} finding${r.total === 1 ? "" : "s"}`}
                          {(r.suppressed ?? 0) > 0 ? ` · ${r.suppressed} below threshold` : ""}
                        </Box>
                        {r.model && <Badge color="blue">{r.model.replace(/^us\./, "")}</Badge>}
                        <Box fontSize="body-s" color="text-body-secondary">
                          {clock(r.submitted)} · <Link external fontSize="body-s" href={r.url}>review</Link>
                        </Box>
                      </SpaceBetween>
                    )}
                  </div>
                );
              })}
            </ColumnLayout>
            <PrEvidenceDetails snap={snap} review={review} onReview={onReview} />
          </SpaceBetween>
        )}
      </SpaceBetween>
    </Container>
  );
}

function FailureBanner({ failures }: { failures: Failure[] }) {
  if (!failures.length) return null;
  return (
    <Alert type="error" statusIconAriaLabel="Error"
      header={`Why this run failed — ${failures.length} failed action${failures.length > 1 ? "s" : ""}`}>
      <SpaceBetween size="s">
        {failures.map((f, i) => (
          <div key={i}>
            <Box fontWeight="bold" fontSize="body-s">
              {f.stage} / {f.action}{" "}
              {f.url && <Link external fontSize="body-s" href={f.url}>build</Link>}
            </Box>
            {/* The verdict first. A gate that blocked has a real reason - which
              * seat, which rule, where, and why - and a CI wrapper that merely
              * observed a nonzero exit. Leading with the wrapper tells the
              * reader nothing about their change. */}
            {f.gate_headline && (
              <Box fontWeight="bold" fontSize="body-s" color="text-status-error">
                {f.gate_headline}
              </Box>
            )}
            {(f.gate_reason ?? []).map((l, j) => (
              <Box key={j} fontSize="body-s" padding={{ top: "xxs" }}>
                <span style={{ overflowWrap: "anywhere" }}>{l}</span>
              </Box>
            ))}
            {f.reason && (
              <Box fontSize="body-s" color="text-body-secondary"
                   padding={{ top: f.gate_headline ? "xs" : "n" }}>
                {f.gate_headline ? "CI wrapper: " : ""}{f.reason}
              </Box>
            )}
            {(f.log ?? []).length > 0 && (
              <ExpandableSection variant="footer"
                defaultExpanded={!f.gate_headline}
                headerText="gate output">
                <Box variant="code" fontSize="body-s">
                  {f.log!.map((l, j) => <div key={j}>{l}</div>)}
                </Box>
              </ExpandableSection>
            )}
          </div>
        ))}
      </SpaceBetween>
    </Alert>
  );
}

/* Hover/focus/click detail for a feed row.
 *
 * The trigger is a real <button>, which is what makes it operable: a span with
 * role="button" and tabIndex=0 announces itself as a button but does nothing on
 * Enter or Space (WCAG 2.1.1). Pointer hover opens it as a convenience; click
 * and keyboard activation toggle it; Escape closes it and returns focus to the
 * trigger. It stays open while the pointer moves into the panel, which is the
 * "hoverable" requirement of WCAG 1.4.13.
 */
function DetailHover({ item, id, children }:
                     { item: FeedItem; id: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const closeTimer = useRef<number | undefined>(undefined);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const rows = item.detail ?? [];
  if (rows.length === 0) return <>{children}</>;

  const show = () => { window.clearTimeout(closeTimer.current); setOpen(true); };
  const hide = () => { closeTimer.current = window.setTimeout(() => setOpen(false), 160); };
  const dismiss = () => { window.clearTimeout(closeTimer.current); setOpen(false);
                          trigger.current?.focus(); };

  return (
    <span style={{ position: "relative", display: "block", maxWidth: "100%" }}
          onMouseEnter={show} onMouseLeave={hide}
          onKeyDown={(e) => { if (e.key === "Escape" && open) { e.stopPropagation(); dismiss(); } }}>
      <button ref={trigger} type="button"
              aria-expanded={open} aria-controls={id}
              onClick={() => setOpen((o) => !o)}
              onFocus={show}
              style={{
                background: "none", border: "none", padding: 0, margin: 0,
                font: "inherit", color: "inherit", textAlign: "left",
                cursor: "pointer", maxWidth: "100%",
                borderBottom: "1px dotted currentColor",
                overflowWrap: "anywhere", whiteSpace: "normal",
              }}>
        {children}
      </button>
      {open && (
        <div id={id} role="tooltip" onMouseEnter={show} onMouseLeave={hide}
             style={{
               position: "absolute", zIndex: 1000, top: "100%", left: 0, marginTop: 4,
               minWidth: 320, maxWidth: "min(560px, 90vw)", padding: "12px 14px",
               background: "#161d26", border: "1px solid #6e7681", borderRadius: 8,
               boxShadow: "0 4px 20px rgba(0,0,0,.55)", textAlign: "left",
               whiteSpace: "normal", overflowWrap: "anywhere",
             }}>
          <SpaceBetween size="xxs">
            {rows.map(([k, v], i) => (
              <div key={i} style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
                <span style={{ color: "#8d99a8", width: 132, flexShrink: 0,
                               fontSize: 12 }}>{k}</span>
                <span style={{ color: "#d1d5db", fontSize: 12, minWidth: 0,
                               overflowWrap: "anywhere",
                               fontFamily: /:\d+$/.test(k) ? "monospace" : undefined }}>{v}</span>
              </div>
            ))}
            {item.url && (
              <Box fontSize="body-s">
                <Link href={item.url} external target="_blank">Open in console</Link>
              </Box>
            )}
          </SpaceBetween>
        </div>
      )}
    </span>
  );
}

/* Day marker between runs of events. The LABEL carries the meaning, so the rule
 * beside it is decorative - which is why a faint overlay line is fine here and
 * would not be if the date were conveyed by the line alone. */
function DayDivider({ ts }: { ts: string }) {
  return (
    <div role="separator" aria-label={`Events on ${dayLabel(ts)}`}
         style={{ display: "flex", alignItems: "center", gap: 8, paddingTop: 6 }}>
      <Box fontSize="body-s" fontWeight="bold" color="text-body-secondary">
        {dayLabel(ts)}
      </Box>
      <span aria-hidden="true"
            style={{ flex: 1, borderTop: "1px solid rgba(255,255,255,0.14)" }} />
    </div>
  );
}

const FEED_PAGE = 20;

function FeedWidget({ feed, meta, showHistory, onShowHistory }: {
  feed: FeedItem[]; meta?: PanelMeta[];
  showHistory: boolean; onShowHistory: (v: boolean) => void;
}) {
  const [page, setPage] = useState(1);
  const pages = Math.max(1, Math.ceil(feed.length / FEED_PAGE));
  // Toggling history changes how much there is to page through, so start over
  // rather than leaving the viewer on a page that no longer exists.
  useEffect(() => { setPage(1); }, [showHistory]);
  const shown = feed.slice((page - 1) * FEED_PAGE, page * FEED_PAGE);
  return (
    <Container header={<Header variant="h2" counter={`(${feed.length})`}
      description="Deployment events follow the selected execution. PR events follow the selected pull request. Newest first."
      actions={
        <SpaceBetween direction="horizontal" size="m">
          <Toggle checked={showHistory} onChange={({ detail }) => onShowHistory(detail.checked)}>
            More events for this selection
          </Toggle>
          <Pagination currentPageIndex={page} pagesCount={pages}
            onChange={({ detail }) => setPage(detail.currentPageIndex)}
            ariaLabels={{ nextPageLabel: "Older events", previousPageLabel: "Newer events",
              pageLabel: (n) => `Page ${n} of live feedback` }} />
        </SpaceBetween>
      }>
      Live feedback
    </Header>}>
      {/* aria-live only makes sense on the newest page; announcing a re-render
        * of page 4 while someone reads history would be noise, not help. */}
      <div style={{ maxHeight: 520, overflowY: "auto" }} role="log"
           aria-live={page === 1 ? "polite" : "off"}>
        <SpaceBetween size="xs">
          {feed.length === 0 && <Box color="text-body-secondary">Waiting for events…</Box>}
          {shown.map((e, i) => {
            const prev = i > 0 ? shown[i - 1] : undefined;
            const newDay = !prev || dayKey(prev.ts) !== dayKey(e.ts);
            return (
            <Fragment key={`${e.ts}-${i}`}>
            {newDay && <DayDivider ts={e.ts} />}
            {/* Braces required: in JSX CHILDREN position a bare block comment is
              * literal TEXT, and this one rendered verbatim in the panel until it
              * was caught. It survived the day-divider refactor because it used
              * to sit in JS expression position, where it was a real comment.
              * Explicit flex row rather than a horizontal SpaceBetween: the text
              * cell needs min-width 0 so a long finding message wraps inside the
              * row instead of pushing past the container edge. */}
            <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
              <Box color="text-body-secondary" fontSize="body-s">
                <span style={{ whiteSpace: "nowrap" }}>{clock(e.ts)}</span>
              </Box>
              <span style={{ flexShrink: 0 }}>
                <Badge color={e.source === "PR" ? "green" : e.source === "PANEL" ? "blue" : "grey"}>{e.source}</Badge>
                {e.historic && <> <Badge color="grey">past run</Badge></>}
              </span>
              <Box fontSize="body-s">
                <div style={{ flex: 1, minWidth: 0 }}>
                  <DetailHover item={e} id={`feed-detail-${i}`}>
                    <StatusIndicator type={stype(e.status)}>
                      {e.persona ? `${emojiFor(meta, e.persona)} ` : ""}{e.text}
                    </StatusIndicator>
                  </DetailHover>
                </div>
              </Box>
            </div>
            </Fragment>
            );
          })}
        </SpaceBetween>
      </div>
    </Container>
  );
}

/* ---------- live snapshot: authenticated polling ---------- */
// Polling is the only transport. EventSource cannot send an Authorization
// header, and access tokens must not travel in URLs.
const POLL_MS = 5000;

function useLiveSnapshot(commit?: string, pr?: number, repo?: string, closed?: boolean, history?: boolean, execution?: string, reviewBuild?: string) {
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [mode, setMode] = useState<"connecting" | "polling">("connecting");
  const [receivedAt, setReceivedAt] = useState<string>();
  const [connectionError, setConnectionError] = useState<string>();
  useEffect(() => {
    let dead = false;
    let poll: number | undefined;
    let newestGenerated = -Infinity;
    const p = new URLSearchParams();
    for (const [key, value] of Object.entries({ commit, pr, repo, execution, review_build: reviewBuild, closed: closed ? '1' : undefined,
      history: history ? '1' : undefined })) {
      if (value) p.set(key, String(value));
    }
    setSnap(null);
    setMode('connecting');
    const receive = (data: Snapshot) => {
      if (dead) return;
      const generated = Date.parse(data.generated_at);
      if (Number.isFinite(generated) && generated < newestGenerated) return;
      if (Number.isFinite(generated)) newestGenerated = generated;
      setSnap(bindSelection(data, {repo, execution, commit, pr, review_build: reviewBuild}));
      setReceivedAt(new Date().toISOString());
      setConnectionError(undefined);
    };
    const fetchOnce = async () => {
      try {
        const r = await authorizedFetch(`/api/snapshot?${p}`, { signal: AbortSignal.timeout(15000) });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data: Snapshot = await r.json();
        if (!dead) receive(data);
      } catch {
        if (!dead) setConnectionError('Telemetry refresh unavailable; last received data may be stale');
      }
    };
    void fetchOnce().then(() => {
      if (dead) return;
      setMode('polling');
      poll = window.setInterval(fetchOnce, POLL_MS);
    });
    return () => { dead = true; window.clearInterval(poll); };
  }, [commit, pr, repo, closed, history, execution, reviewBuild]);
  return { snap, mode, receivedAt, connectionError };
}

/* ---------- app ---------- */
export default function App() {
  const [initial] = useState(() => initialSelection(location.search));
  const [selection, setSelection] = useState(initial);
  const { commit, repo, pr: prNum, review, execution, review_build: reviewBuild } = selection;
  const setCommit = (value?: string) => setSelection(s => changeSelection(s, { commit: value }));
  const setExecution = (value?: string) => setSelection(s => changeSelection(s, { execution: value }));
  const setPrNum = (value?: number) => setSelection(s => changeSelection(s, { pr: value }));
  const setReview = (value?: number) => setSelection(s => changeSelection(s, { review: value }));
  const [showClosed, setShowClosed] = useState(initial.closed);
  const [showHistory, setShowHistory] = useState(initial.history);
  const { snap, mode, receivedAt, connectionError } = useLiveSnapshot(commit, prNum, repo, showClosed, showHistory, execution, reviewBuild);
  // Pin the displayed parent execution when choosing an attempt from "latest",
  // so a later new execution cannot redirect this build's reload/deep link.
  const setReviewBuild = (value?: string) => setSelection(s => ({
    ...(value && snap?.execution ? changeSelection(s, {execution: snap.execution}) : s),
    review_build: value,
  }));
  const changeRepo = (value?: string) => setSelection(s => changeSelection(s, { repo: value }));
  useEffect(() => {
    window.history.replaceState(null, '', selectionUrl(location.search, {
      commit, repo, pr: prNum, review, execution, review_build: reviewBuild, closed: showClosed, history: showHistory,
    }));
  }, [commit, repo, prNum, review, execution, reviewBuild, showClosed, showHistory]);

  const commitOptions: SelectProps.Options = [
    { value: "", label: "Latest execution" },
    ...(commit && !snap?.commits.some(c => c.sha === commit) ? [{
      value: commit,
      label: `${short(commit)} · ${unlistedRevisionLabel(snap)}`,
      description: snap?.selection_error ?? undefined,
    }] : []),
    ...(snap?.commits ?? []).map((c) => ({
      value: c.sha,
      label: `${short(c.sha)} · ${c.message.slice(0, 60)}`,
      description: `${c.status} · ${stamp(c.started)}`,
    })),
  ];

  // Names come from the snapshot, which derives them from the same config that
  // built the pipelines dict. Hardcoding the artifact's three names here meant
  // every tier card spun forever whenever the road was selected: the payload was
  // correct and the lookup missed it. The fallback keeps an older payload (or a
  // future fourth tier) rendering instead of spinning.
  const names = snap?.tiers;
  const byTier = (n: 1 | 2 | 3) => {
    const key = names?.[`tier${n}` as "tier1" | "tier2" | "tier3"];
    if (key && snap?.pipelines[key]) return snap.pipelines[key];
    return Object.entries(snap?.pipelines ?? {})
      .find(([k]) => k.includes(`tier${n}`))?.[1];
  };
  const t1 = byTier(1);
  const t2 = byTier(2);
  const t3 = byTier(3);

  if (initial.present) return snap ? <Presenter snap={snap} mode={connectionError ?? mode} receivedAt={receivedAt}
    commit={commit} pr={prNum} showClosed={showClosed} onClosed={setShowClosed}
    onCommit={setCommit} onRepo={changeRepo} onPr={setPrNum}
    review={review} onReview={setReview} execution={execution} onExecution={setExecution}
    reviewBuild={reviewBuild} onReviewBuild={setReviewBuild} />
    : <main className="presenter"><h1>Loading execution evidence…</h1>{connectionError && <p role="alert">{connectionError}</p>}</main>;

  return (
    <AppLayout navigationHide toolsHide contentType="dashboard" content={
      <ContentLayout header={
        <Header variant="h1"
          description="One revision with execution-bound evidence. PR checks report findings; the primary CodeBuild pipeline enforces deployment gates. Hosting options are independent."
          actions={
            <SpaceBetween direction="horizontal" size="s">
              <StatusIndicator type={mode === "polling" ? "success" : "in-progress"}>
                Connection: {mode === "polling" ? `refreshing every ${POLL_MS / 1000} s` : "connecting"}
              </StatusIndicator>
              <Box color="text-body-secondary" fontSize="body-s" padding={{ top: "xxs" }}>
                Snapshot received {stamp(receivedAt)}
              </Box>
              {connectionError && <StatusIndicator type="warning">{connectionError}</StatusIndicator>}
              {snap?.degraded?.github && (
                <StatusIndicator type="warning">{snap.degraded.github}</StatusIndicator>
              )}
              <Button href={selectionUrl(location.search, { present: true })}>Presenter view</Button>
              {snap?.site && <Button href={snap?.site} iconName="external" target="_blank">
                <SpaceBetween direction="horizontal" size="xxs">
                  <HorseMark size={16} />
                  <span>Live site</span>
                </SpaceBetween>
              </Button>}
              <Button onClick={() => { void signOut(); }}>Sign out</Button>
            </SpaceBetween>
          }>
          Agentic gates — execution evidence
        </Header>}>
        {!snap ? (
          <Box textAlign="center" padding="xxl"><Spinner size="large" /> {connectionError ?? 'loading telemetry…'}</Box>
        ) : (
          <SpaceBetween size="l">
            <Container>
              <ReleaseFlow pipeline={t1} snap={snap} />
              {snap.selection_error && <Alert type="warning">{snap.selection_error}</Alert>}
            </Container>
            <FailureBanner failures={snap.failures ?? []} />
            {snap.approval && (
              <Alert type="warning" statusIconAriaLabel="Warning"
                header="Waiting on human approval — the person is above the agents"
                action={snap.approval.url && (
                  <Button href={snap.approval.url} iconName="external" target="_blank">
                    Approve in console
                  </Button>
                )}>
                The gates passed and {snap.approval.stage} / {snap.approval.action} has been
                pending since {stamp(snap.approval.since)}. Nothing deploys until a human says so.
              </Alert>
            )}
            <Container header={<Header variant="h2"
              description="Pick a revision to inspect its execution; connection freshness is separate">
              The commit
            </Header>}>
              <Grid gridDefinition={[{ colspan: { default: 12, s: 3 } },
                { colspan: { default: 12, s: 3 } }, { colspan: { default: 6, s: 2 } },
                { colspan: { default: 6, s: 2 } }, { colspan: { default: 6, s: 2 } }]}>
                <Select
                  data-testid="repo-select"
                  ariaLabel="Which repository to watch"
                  selectedOption={
                    (snap?.repos ?? []).map((r) => ({ label: r.label, value: r.key,
                      description: r.repo }))
                      .find((o) => o.value === (repo ?? snap?.selected_repo)) ?? null}
                  options={(snap?.repos ?? []).map((r) => ({
                    label: r.label, value: r.key, description: r.repo,
                    // Naming the boundary in the option itself, so choosing the
                    // road and seeing no tier cards reads as a fact rather than
                    // a broken board.
                    labelTag: r.deploys
                                      ? `PR + 3 tiers · deploys ${r.deploy_target}`
                                      : "PR + 3 tiers · gate only" }))}
                  onChange={({ detail }) => changeRepo(detail.selectedOption.value)}
                />
                <Select
                  selectedOption={commitOptions.flatMap((o) => "options" in o ? o.options! : [o])
                    .find((o) => (o as SelectProps.Option).value === (commit ?? "")) as SelectProps.Option ?? null}
                  onChange={({ detail }) => setCommit(detail.selectedOption.value || undefined)}
                  options={commitOptions}
                  placeholder="Latest execution"
                  ariaLabel="Select revision" />
                <div>
                  <Box variant="awsui-key-label">Message</Box>
                  <Box>{snap.commit?.message ?? "—"}</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">Execution</Box>
                  <SpaceBetween size="xxs">
                    <StatusIndicator type={stype(snap.execution_status)}>
                      {snap.execution_status ?? "—"}
                    </StatusIndicator>
                    <Box fontSize="body-s" color="text-body-secondary">
                      <Box variant="code" display="inline" fontSize="body-s">
                        {short(snap.execution)}
                      </Box>{" "}
                      {snap.live ? "· newest run" : "· replay"} · started {stamp(snap.execution_started)}
                    </Box>
                  </SpaceBetween>
                </div>
                <div>
                  <Box variant="awsui-key-label">Revision</Box>
                  {revisionUrl(snap, snap.commit?.sha) ? <Link external href={revisionUrl(snap, snap.commit?.sha)}>
                    <Box variant="code" display="inline">{short(snap.commit?.sha)}</Box>
                  </Link> : <span>Revision unavailable</span>}
                </div>
              </Grid>
              <ExecutionSelector snap={snap} execution={execution} onExecution={setExecution} />
            </Container>
            <Grid gridDefinition={[
              { colspan: { default: 12, m: 4 } },
              { colspan: { default: 12, m: 4 } },
              { colspan: { default: 12, m: 4 } },
            ]}>
              <PipelineWidget p={t1} title="Tier 1 — CodeBuild"
                subtitle="Gates in the pipeline's own compute; canary deploy tail" />
              <PipelineWidget p={t2} title="Tier 2 — AgentCore"
                subtitle="Same panel on Bedrock AgentCore Runtime behind a Lambda gate" />
              <PipelineWidget p={t3} title="Tier 3 — Kiro headless"
                subtitle="Same panel on a managed harness; we own no agent loop" />
            </Grid>
            <PanelMatrix findings={snap.findings} meta={snap.panel_meta}
              prog={snap.panel_progress} evidence={snap.review_evidence} />
            <Container header={<Header variant="h2">Complete execution reports</Header>}>
              <PipelineReviewAttempts snap={snap} reviewBuild={reviewBuild} onReviewBuild={setReviewBuild} />
              {(['tier1', 'tier2', 'tier3'] as const).map((tier, index) =>
                <PipelineEvidenceDetails key={tier} title={`Tier ${index + 1} · complete pipeline review details`}
                  report={snap.findings[tier]} failures={snap.failures.filter(f => f.pipeline === snap.tiers?.[tier])}
                  evidence={snap.review_evidence?.[tier]}
                  execution={snap.review_evidence?.[tier]?.execution_id ?? (tier === 'tier1' ? snap.execution : undefined)}
                  revision={snap.review_evidence?.[tier]?.revision ?? snap.commit?.sha} />)}
            </Container>
            <Grid gridDefinition={[
              { colspan: { default: 12, m: 6 } },
              { colspan: { default: 12, m: 6 } },
            ]}>
              <PrWidget pr={snap.pr} selected={prNum} onSelect={setPrNum} meta={snap.panel_meta}
                snap={snap} review={review} onReview={setReview}
                showClosed={showClosed} onShowClosed={(v) => { setShowClosed(v); if (!v) setPrNum(undefined); }} />
              <FeedWidget feed={snap.feed} meta={snap.panel_meta}
                showHistory={showHistory} onShowHistory={setShowHistory} />
            </Grid>
          </SpaceBetween>
        )}
      </ContentLayout>
    } />
  );
}
