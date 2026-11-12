import aws_cdk as cdk
from tier2_stack import Tier2PipelineStack

app = cdk.App()
# Second trio gates the road itself: -c stack_id=Tier2PipelineStackRoad
# -c name_suffix=-road. Default reproduces today exactly.
_sid = app.node.try_get_context("stack_id") or "Tier2PipelineStack"
Tier2PipelineStack(app, _sid,
                   env=cdk.Environment(region="us-west-2"))
app.synth()
