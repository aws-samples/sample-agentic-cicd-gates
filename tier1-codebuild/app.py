import aws_cdk as cdk
from tier1_stack import Tier1PipelineStack

app = cdk.App()
# Two trios run this stack: the artifact's (default id, deploys the site) and
# the road's own (-c stack_id=Tier1PipelineStackRoad -c gate_only=1), so the
# paved road is gated by the paved road. Default reproduces today exactly.
stack_id = app.node.try_get_context("stack_id") or "Tier1PipelineStack"
Tier1PipelineStack(app, stack_id,
                   env=cdk.Environment(region="us-west-2"))
app.synth()
