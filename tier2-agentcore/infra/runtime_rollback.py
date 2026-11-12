"""Write a Tier 2 template that reverts ONLY the reviewer runtime's container image.

Restoring a Tier 2 stack's whole pre-deploy template would also restore its
pre-deploy gate Lambda. Before v2 that gate truncated diffs at 400,000
characters, read only nine extensions, and advanced the baseline after every
completed review, FAIL included, so a merge run or retry under it would accept
most of a large delta unread. This tool keeps the CURRENT template, gate
included, and changes one property: the AWS::BedrockAgentCore::Runtime's
AgentRuntimeArtifact, taken from the PREVIOUS template. The current gate then
refuses any delta over one chunk that comes back without chunk evidence, so a
large delta fails closed under the old image instead of passing.

    S=Tier2PipelineStack
    aws cloudformation get-template --stack-name $S --query TemplateBody --output json \\
      > /tmp/$S.current.json
    python tier2-agentcore/infra/runtime_rollback.py --current /tmp/$S.current.json \\
      --previous /tmp/$S.pre-deploy.min.json --out /tmp/$S.runtime-rollback.min.json
    aws cloudformation update-stack --stack-name $S \\
      --template-body file:///tmp/$S.runtime-rollback.min.json \\
      --parameters ParameterKey=BootstrapVersion,UsePreviousValue=true \\
      --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND

It reads and writes local files only, and refuses anything else it would change.
"""
import argparse
import copy
import json
import sys

RUNTIME = "AWS::BedrockAgentCore::Runtime"
MAX_TEMPLATE_BODY = 51_200  # CloudFormation's --template-body limit, in bytes


class RollbackError(ValueError):
    pass


def load(path):
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    # `get-template --output json` prints the body as an object, or as a string
    # holding it; a saved minified template is the object itself.
    doc = json.loads(doc) if isinstance(doc, str) else doc
    if not isinstance(doc, dict) or not isinstance(doc.get("Resources"), dict):
        raise RollbackError(f"{path}: not a CloudFormation template")
    return doc


def _runtime(template, label):
    found = [(lid, r) for lid, r in template["Resources"].items()
             if isinstance(r, dict) and r.get("Type") == RUNTIME]
    if len(found) != 1:
        raise RollbackError(f"{label} template has {len(found)} {RUNTIME} resources, expected 1")
    lid, resource = found[0]
    artifact = resource.get("Properties", {}).get("AgentRuntimeArtifact")
    if (not isinstance(artifact, dict) or set(artifact) != {"ContainerConfiguration"}
            or set(artifact["ContainerConfiguration"]) != {"ContainerUri"}):
        raise RollbackError(f"{label} runtime artifact is not one ContainerUri: {artifact!r}")
    return lid, artifact


def runtime_only(current, previous):
    """Return (template, old_uri, new_uri): `current` with the previous runtime image."""
    lid, artifact = _runtime(current, "current")
    previous_lid, previous_artifact = _runtime(previous, "previous")
    if lid != previous_lid:
        raise RollbackError(f"runtime logical IDs differ: {lid} vs {previous_lid}")
    if artifact == previous_artifact:
        raise RollbackError("the runtime already uses the previous image; nothing to roll back")
    out = copy.deepcopy(current)
    out["Resources"][lid]["Properties"]["AgentRuntimeArtifact"] = copy.deepcopy(previous_artifact)
    # Prove the edit: back out that one property and the rest is `current`, byte for byte.
    check = copy.deepcopy(out)
    check["Resources"][lid]["Properties"]["AgentRuntimeArtifact"] = artifact
    if json.dumps(check, sort_keys=True) != json.dumps(current, sort_keys=True):
        raise RollbackError("internal error: the edit changed more than the runtime image")
    return (out, previous_artifact["ContainerConfiguration"]["ContainerUri"],
            artifact["ContainerConfiguration"]["ContainerUri"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--current", required=True, help="the stack's template now (get-template)")
    parser.add_argument("--previous", required=True, help="the template saved before the deploy")
    parser.add_argument("--out", required=True, help="where to write the runtime-only rollback")
    args = parser.parse_args(argv)
    try:
        out, old_uri, new_uri = runtime_only(load(args.current), load(args.previous))
    except (OSError, ValueError) as exc:
        print(f"ROLLBACK TEMPLATE: REFUSED - {exc}")
        return 1
    body = json.dumps(out, separators=(",", ":"))
    if len(body.encode("utf-8")) > MAX_TEMPLATE_BODY:
        print(f"ROLLBACK TEMPLATE: REFUSED - {len(body)} bytes is over the "
              f"{MAX_TEMPLATE_BODY}-byte --template-body limit")
        return 1
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(body)
    print(f"ROLLBACK TEMPLATE: written to {args.out} ({len(body)} bytes); only the runtime image "
          f"changes, the gate and everything else stay as deployed.\n"
          f"  image now:  {json.dumps(new_uri)}\n  image after: {json.dumps(old_uri)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
