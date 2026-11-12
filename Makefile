# Golden path. Prereqs: AWS creds, Python 3.12, Node (npx), finch or docker.
REGION ?= us-west-2
VENV := .venv/bin

.PHONY: venv deploy-tier1 deploy-tier2 eval test destroy

venv:
	python3 -m venv .venv && $(VENV)/pip install -q -r requirements.txt pytest==9.2.0

deploy-tier1: ## NEW Tier 1 stack reading the CodeCommit demo repo (never to update a GitHub-source stack: deploy/README.md)
	cd tier1-codebuild && npx -y aws-cdk@2.1144.0 deploy --require-approval never -c source=codecommit

deploy-tier2: ## NEW Tier 2 stack reading the CodeCommit demo repo (deploy tier1 first; never to update a GitHub-source stack: deploy/README.md)
	cd tier2-agentcore/infra && CDK_DOCKER=$${CDK_DOCKER:-finch} npx -y aws-cdk@2.1144.0 deploy --require-approval never -c source=codecommit

eval: ## Run the golden-set evals (precision/recall per rule)
	$(VENV)/python evals/run_evals.py --region $(REGION)

test: ## Offline unit tests (no AWS calls)
	$(VENV)/python -m pytest agent/tests -q

destroy: ## Tear everything down (demo app stack last since the pipeline made it)
	cd tier2-agentcore/infra && npx -y aws-cdk@2.1144.0 destroy --force -c source=codecommit || true
	cd tier1-codebuild && npx -y aws-cdk@2.1144.0 destroy --force -c source=codecommit || true
	aws cloudformation delete-stack --stack-name agentic-gates-demo-app --region $(REGION) || true
