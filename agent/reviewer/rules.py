"""Rules-as-code loader for the agentic review gate.

Rules are the ONLY source of blocking-ness (closed blocking list). The caller
is responsible for reading the YAML from the BASE ref of the change under
review; this module never touches git.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

import yaml

VALID_SEVERITIES = {"low", "medium", "high"}
VALID_FAIL_MODES = {"open", "closed"}

# Extended-thinking presets -> token budgets (Bedrock Converse `reasoningConfig`
# via additionalModelRequestFields). Names mirror common CLI levels.
THINKING_LEVELS = {
    "off": (None, 0),
    "low": ("low", 2048),
    "medium": ("medium", 8192),
    "high": ("high", 16384),
    "extra-high": ("xhigh", 32768),
    "max": ("max", 65536),
}


@dataclass(frozen=True)
class AgentConfig:
    """Reviewer agent identity + model settings (from .reviewer.yaml `agent:`).

    Config-as-code: this block travels in the guarded repo and is read from
    the BASE ref like the rules — a PR cannot swap its reviewer to a weaker
    model or strip its persona.
    """

    name: str = "Agentic Review Gate"
    persona: str = ""                  # one-line role statement shown in reviews
    model: str = ""                    # empty -> harness default
    thinking: str = "off"              # off|low|medium|high|extra-high
    emoji: str = "🤖"
    rules: tuple = ()          # rule-id prefixes owned; empty = all rules
    file_patterns: tuple = ()  # diff scope; empty = the whole diff

    @property
    def thinking_effort(self):
        """Adaptive-scheme effort value, or None when thinking is off."""
        return THINKING_LEVELS[self.thinking][0]

    @property
    def thinking_budget(self) -> int:
        """Legacy budget_tokens for enabled-type thinking."""
        return THINKING_LEVELS[self.thinking][1]


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str = "medium"
    blocking: bool = False
    file_patterns: tuple[str, ...] = ("**/*",)

    def matches_path(self, path: str) -> bool:
        return any(
            fnmatch.fnmatch(path, pat) or fnmatch.fnmatch("/" + path, pat)
            for pat in self.file_patterns
        )


@dataclass(frozen=True)
class RuleSet:
    version: int
    confidence_threshold: int = 80
    fail_mode: str = "open"
    max_findings: int = 25
    rules: tuple[Rule, ...] = field(default_factory=tuple)
    agent: AgentConfig = field(default_factory=AgentConfig)
    agents: tuple = ()             # full panel; agent == agents[0]

    def by_id(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    @property
    def has_blocking_rules(self) -> bool:
        return any(r.blocking for r in self.rules)


class RulesError(ValueError):
    """Invalid rules file. Callers decide fail-open/closed; we just refuse to guess."""


def load_rules(text: str) -> RuleSet:
    """Parse and validate a .reviewer.yaml document."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:  # pragma: no cover - message passthrough
        raise RulesError(f"rules file is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise RulesError("rules file must be a mapping with version: 1")

    defaults = doc.get("defaults") or {}
    threshold = int(defaults.get("confidence_threshold", 80))
    if not 0 <= threshold <= 100:
        raise RulesError("defaults.confidence_threshold must be 0-100")
    fail_mode = str(defaults.get("fail_mode", "open"))
    if fail_mode not in VALID_FAIL_MODES:
        raise RulesError(f"defaults.fail_mode must be one of {sorted(VALID_FAIL_MODES)}")
    max_findings = defaults.get("max_findings", 25)
    if type(max_findings) is not int or not 1 <= max_findings <= 1000:
        raise RulesError("defaults.max_findings must be an integer from 1 to 1000")

    rules: list[Rule] = []
    seen: set[str] = set()
    for i, raw in enumerate(doc.get("rules") or []):
        if not isinstance(raw, dict) or "id" not in raw or "description" not in raw:
            raise RulesError(f"rules[{i}] needs id and description")
        rid = str(raw["id"])
        if rid in seen:
            raise RulesError(f"duplicate rule id {rid}")
        seen.add(rid)
        severity = str(raw.get("severity", "medium"))
        if severity not in VALID_SEVERITIES:
            raise RulesError(f"rules[{i}].severity must be one of {sorted(VALID_SEVERITIES)}")
        patterns = tuple(str(p) for p in (raw.get("file_patterns") or ["**/*"]))
        rules.append(
            Rule(
                id=rid,
                description=str(raw["description"]),
                severity=severity,
                blocking=bool(raw.get("blocking", False)),
                file_patterns=patterns,
            )
        )
    if not rules:
        raise RulesError("rules file declares no rules")

    def _parse_agent(raw):
        if not isinstance(raw, dict):
            raise RulesError("agent must be a mapping")
        thinking = str(raw.get("thinking", "off"))
        if thinking not in THINKING_LEVELS:
            raise RulesError(
                f"agent.thinking must be one of {sorted(THINKING_LEVELS)}")
        scope = raw.get("rules") or []
        if not isinstance(scope, list):
            raise RulesError("agent.rules must be a list of rule-id prefixes")
        globs = raw.get("file_patterns") or []
        if not isinstance(globs, list):
            raise RulesError("agent.file_patterns must be a list of globs")
        return AgentConfig(
            name=str(raw.get("name", "Agentic Review Gate"))[:80],
            persona=str(raw.get("persona", ""))[:300],
            model=str(raw.get("model", "")),
            thinking=thinking,
            emoji=str(raw.get("emoji", "🤖"))[:8],
            rules=tuple(str(s) for s in scope),
            file_patterns=tuple(str(g) for g in globs),
        )

    raw_agents = doc.get("agents")
    if raw_agents is not None:
        if not isinstance(raw_agents, list) or not raw_agents:
            raise RulesError("agents must be a non-empty list")
        agents = tuple(_parse_agent(r) for r in raw_agents)
    else:
        agents = (_parse_agent(doc.get("agent") or {}),)
    for a in agents:
        # A seat whose prefixes own no rule can never block: it would PASS
        # every change while looking like a reviewer (a typo such as "A11y-").
        if a.rules and not any(r.id.startswith(p) for r in rules for p in a.rules):
            raise RulesError(f"agent {a.name!r}: rule prefixes {list(a.rules)} match no rule")
    agent = agents[0]

    return RuleSet(
        version=1,
        confidence_threshold=threshold,
        fail_mode=fail_mode,
        max_findings=max_findings,
        rules=tuple(rules),
        agent=agent,
        agents=agents,
    )
