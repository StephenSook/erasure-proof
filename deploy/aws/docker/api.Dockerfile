# Go API image (linux/arm64 for Fargate ARM64). Build from the REPO ROOT:
#   docker buildx build --platform linux/arm64 -f deploy/aws/docker/api.Dockerfile \
#     --build-arg GIT_SHA=$(git rev-parse --short HEAD) -t <ecr>/erasure-proof-api:<sha> .
FROM golang:1.25 AS build
WORKDIR /src
COPY services/api/go.mod services/api/go.sum ./
RUN go mod download
COPY services/api/ ./
ARG GIT_SHA=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/api ./cmd/api

# distroless/static ships the public CA bundle, which verifies CockroachDB Cloud Basic's
# publicly trusted TLS certs (sslmode=verify-full without a custom sslrootcert). If the DSN
# needs a cluster-specific CA instead, bake it here and reference it from the DSN.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /api
COPY db/queries /db/queries
ARG GIT_SHA=dev
ENV QUERIES_DIR=/db/queries GIT_SHA=${GIT_SHA} API_PORT=8080
EXPOSE 8080
ENTRYPOINT ["/api"]
