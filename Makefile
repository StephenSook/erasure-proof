# erasure-proof developer entry points. Quality over speed; every target is small and explicit.

CRDB_IMAGE ?= cockroachdb/cockroach:latest-v25.2
LOCAL_DSN  ?= postgresql://root@localhost:26260/erasure?sslmode=disable
COMPOSE    := docker compose -f docker-compose.crdb.yml

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: cluster-up
cluster-up: ## Start the local 3-node CockroachDB cluster + HAProxy (needs Docker)
	CRDB_IMAGE=$(CRDB_IMAGE) $(COMPOSE) up -d
	@echo "waiting for cluster..."
	@for i in $$(seq 1 40); do \
		docker exec roach1 ./cockroach sql --insecure -e "SELECT 1" >/dev/null 2>&1 && break; \
		sleep 2; done
	docker exec roach1 ./cockroach sql --insecure -e "CREATE DATABASE IF NOT EXISTS erasure"
	@echo "cluster up. balanced SQL endpoint: localhost:26260  console: localhost:8081"

.PHONY: cluster-down
cluster-down: ## Stop the local cluster and remove volumes
	$(COMPOSE) down -v

.PHONY: migrate
migrate: ## Apply db/migrations to the local cluster
	python3 spikes/spike3_nodekill/erase_driver.py migrate "$(LOCAL_DSN)"

.PHONY: spike2
spike2: ## Run spike 2 (C-SPANN index) against a DSN: make spike2 DSN=...
	python3 spikes/spike2_cspann/run.py "$(or $(DSN),$(LOCAL_DSN))"

.PHONY: spike3
spike3: ## Run spike 3 (atomic erasure surviving a node kill)
	./spikes/spike3_nodekill/run.sh

.PHONY: lint
lint: ## Run all linters (grows as services land)
	@echo "no service linters yet; see .github/workflows/ci.yml"

.PHONY: test
test: ## Run all tests (grows as services land)
	@echo "no service tests yet; see .github/workflows/ci.yml"

.PHONY: ai-tone
ai-tone: ## Fail if an em-dash appears in tracked text (AI-tone hygiene)
	@! git grep -nI $$'\xe2\x80\x94' -- ':!LICENSE' ':!*.svg' || \
		(echo "em-dash found above; replace per the AI-tone rule" && exit 1)
	@echo "ai-tone clean"
