# Read-only forensics MCP server image (linux/arm64 for Fargate ARM64). Serves the four
# audit-logged tools over MCP streamable HTTP so a judge's MCP client can connect to the deploy;
# the SELECT-only role, the SQL guard, and the read-only session are all enforced inside.
# Build from the REPO ROOT:
#   docker buildx build --platform linux/arm64 -f deploy/aws/docker/mcpserver.Dockerfile \
#     -t <ecr>/erasure-proof-mcpserver:<sha> .
FROM python:3.12-slim
WORKDIR /app
COPY services/mcpserver/pyproject.toml ./
COPY services/mcpserver/src ./src
COPY services/mcpserver/README.md* ./
RUN pip install --no-cache-dir . && useradd -r -u 10002 mcpserver
USER mcpserver
EXPOSE 8082
ENV MCP_TRANSPORT=streamable-http FASTMCP_HOST=0.0.0.0 FASTMCP_PORT=8082
CMD ["python", "-m", "forensics_mcp.server"]
