# NLSN PCAP Monitor - Development Makefile

.PHONY: help build up down logs clean test

# Default target
.DEFAULT_GOAL := help

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m  # No Color

help: ## Show this help message
	@echo "$(BLUE)NLSN PCAP Monitor - Available Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

build: ## Build all Docker containers
	@echo "$(BLUE)Building all containers...$(NC)"
	docker-compose build

build-verification: ## Build only verification container
	@echo "$(BLUE)Building verification container...$(NC)"
	docker-compose build verification

build-honeypot: ## Build only honeypot container
	@echo "$(BLUE)Building honeypot container...$(NC)"
	docker-compose build honeypot

build-monitor: ## Build only Go monitor container
	@echo "$(BLUE)Building monitor container...$(NC)"
	docker-compose build monitor-go

build-engine: ## Build only Python engine container
	@echo "$(BLUE)Building engine container...$(NC)"
	docker-compose build engine-python

up: ## Start all services
	@echo "$(GREEN)Starting all services...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)Services started!$(NC)"
	@echo "API: http://localhost:8888"
	@echo "Verification: http://localhost:8000"

down: ## Stop all services
	@echo "$(YELLOW)Stopping all services...$(NC)"
	docker-compose down

restart: down up ## Restart all services

logs: ## Show logs from all services
	docker-compose logs -f

logs-verification: ## Show verification container logs
	docker-compose logs -f verification

logs-honeypot: ## Show honeypot container logs
	docker-compose logs -f honeypot

logs-monitor: ## Show Go monitor logs
	docker-compose logs -f monitor-go

logs-engine: ## Show Python engine logs
	docker-compose logs -f engine-python

status: ## Show status of all containers
	docker-compose ps

shell-verification: ## Open shell in verification container
	docker exec -it nlsn-verification bash

shell-honeypot: ## Open shell in honeypot container
	docker exec -it nlsn-honeypot sh

shell-monitor: ## Open shell in monitor container
	docker exec -it nlsn-monitor-go sh

shell-engine: ## Open shell in engine container
	docker exec -it nlsn-engine bash

clean: ## Remove all containers and volumes
	@echo "$(YELLOW)Removing all containers and volumes...$(NC)"
	docker-compose down -v
	@echo "$(GREEN)Cleanup complete$(NC)"

clean-build: clean build ## Clean and rebuild everything

test-go: ## Run Go tests
	@echo "$(BLUE)Running Go tests...$(NC)"
	cd core && go test ./... -v

test-python: ## Run Python tests
	@echo "$(BLUE)Running Python tests...$(NC)"
	cd engine && python -m pytest -v

test: test-go test-python ## Run all tests

fmt-go: ## Format Go code
	@echo "$(BLUE)Formatting Go code...$(NC)"
	cd core && go fmt ./...

fmt-python: ## Format Python code
	@echo "$(BLUE)Formatting Python code...$(NC)"
	cd engine && black . && isort .

lint-go: ## Lint Go code
	@echo "$(BLUE)Linting Go code...$(NC)"
	cd core && golangci-lint run

lint-python: ## Lint Python code
	@echo "$(BLUE)Linting Python code...$(NC)"
	cd engine && flake8 . && mypy .

deps-go: ## Download Go dependencies
	@echo "$(BLUE)Downloading Go dependencies...$(NC)"
	cd core && go mod download && go mod tidy

deps-python: ## Install Python dependencies
	@echo "$(BLUE)Installing Python dependencies...$(NC)"
	pip install -r requirements.txt

vpn-setup: ## Setup VPN configuration (interactive)
	@echo "$(BLUE)VPN Configuration Setup$(NC)"
	@echo ""
	@echo "1. Place your Surfshark .ovpn files in: verification-container/vpn-configs/"
	@echo "2. Create credentials file:"
	@cd verification-container/vpn-configs && \
		cp credentials.example credentials.txt && \
		echo "$(GREEN)Created credentials.txt - please edit with your VPN credentials$(NC)"

check-deps: ## Check if all dependencies are installed
	@echo "$(BLUE)Checking dependencies...$(NC)"
	@command -v docker >/dev/null 2>&1 || { echo "$(YELLOW)Docker not installed$(NC)"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || { echo "$(YELLOW)Docker Compose not installed$(NC)"; exit 1; }
	@echo "$(GREEN)✓ Docker and Docker Compose installed$(NC)"

db-shell: ## Open PostgreSQL shell
	docker exec -it nlsn-postgres psql -U nlsn -d nlsn_monitor

redis-cli: ## Open Redis CLI
	docker exec -it nlsn-redis redis-cli

health: ## Check health of all services
	@echo "$(BLUE)Checking service health...$(NC)"
	@echo ""
	@echo "Verification Container:"
	@curl -s http://localhost:8000/health | jq . || echo "$(YELLOW)Not responding$(NC)"
	@echo ""
	@echo "Engine API:"
	@curl -s http://localhost:8888/health | jq . || echo "$(YELLOW)Not responding$(NC)"

stats: ## Show resource usage statistics
	docker stats --no-stream

verify-test: ## Test verification with example.com
	@echo "$(BLUE)Testing multi-path verification...$(NC)"
	@curl -X POST http://localhost:8000/verify \
		-H "Content-Type: application/json" \
		-d '{"url": "https://example.com", "num_paths": 10, "timeout": 15}' \
		| jq .

dev-go: ## Run Go monitor locally (requires root)
	@echo "$(BLUE)Running Go monitor locally...$(NC)"
	cd core && sudo go run cmd/monitor/main.go

dev-python: ## Run Python engine locally
	@echo "$(BLUE)Running Python engine locally...$(NC)"
	cd engine && uvicorn api.server:app --reload --port 8888
