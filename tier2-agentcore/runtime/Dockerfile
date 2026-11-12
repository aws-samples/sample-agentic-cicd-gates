# AgentCore Runtime container — linux/arm64 required by the service.
# Build context is the REPO ROOT (so we can copy the shared agent core once,
# instead of maintaining a second copy of the reviewer).
# Pinned by digest (Python 3.12.15 on Debian 13.7; arm64 manifest sha256:16bf2b5c...),
# the base this image was tested on; the tag alone moved between 2026-08-20 and
# 2026-10-06 (Python 3.12.14 on Debian 13.6 before). Raise it deliberately.
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f

WORKDIR /app
COPY tier2-agentcore/runtime/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The SAME reviewer package Tier 1 ships to CodeBuild as an S3 asset.
COPY agent/reviewer ./reviewer
# Tier 1's chunk planner and report folding, used for deltas over one chunk.
# Copied, not forked: the image is rebuilt from these files on every deploy.
COPY pipeline_tools/review_chunks.py agent/review_cli.py ./
COPY tier2-agentcore/runtime/handler.py .

ENV PYTHONUNBUFFERED=1
# HTTP protocol contract: GET /ping + POST /invocations on 8080.
EXPOSE 8080
CMD ["python", "handler.py"]
