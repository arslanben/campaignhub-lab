.PHONY: up down reset logs ps test solve debug help

up: ## Build and start the lab
	docker compose up -d --build

down: ## Stop the lab
	docker compose down

reset: ## Stop the lab and remove any leftover state
	docker compose down --remove-orphans

logs: ## Follow container logs
	docker compose logs -f --tail=200

ps: ## Show container status
	docker compose ps

test: ## Run smoke tests against a running lab
	bash tests/smoke.sh

solve: ## Run the reference solver (SPOILER — extracts flags over HTTP)
	python3 solve/solve.py

debug: ## Rebuild with host ports for panel internals (maintenance)
	docker compose -f docker-compose.yml -f docker-compose.debug.yml up -d --build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'
