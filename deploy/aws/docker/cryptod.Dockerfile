# cryptod image (linux/arm64 for Fargate ARM64). Core extra only: no torch, the recorded
# golden run serves the inversion beat. Build from the REPO ROOT:
#   docker buildx build --platform linux/arm64 -f deploy/aws/docker/cryptod.Dockerfile \
#     -t <ecr>/erasure-proof-cryptod:<sha> .
FROM python:3.12-slim
WORKDIR /app
COPY services/cryptod/pyproject.toml ./
COPY services/cryptod/src ./src
COPY services/cryptod/README.md* ./
RUN pip install --no-cache-dir . && pip install --no-cache-dir "botocore[crt]"
# spikes/ golden run is served by the api via cryptod GET /invert; bake the recorded artifact.
COPY spikes/spike1_vec2text/golden_run.json /app/spikes/spike1_vec2text/golden_run.json
COPY deploy/aws/docker/entrypoint-cryptod.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && useradd -r -u 10001 cryptod
USER cryptod
EXPOSE 8081
ENTRYPOINT ["/entrypoint.sh"]
