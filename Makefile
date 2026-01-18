SHELL := /bin/bash
BACKEND_DIR := backend
FRONTEND_DIR := frontend

.PHONY: backend-install frontend-install run-backend run-frontend run-db stop-db run deps

backend-install:
	@echo "Ensuring backend dependencies are present..."
	@cd $(BACKEND_DIR) && ./mvnw -q -DskipTests dependency:go-offline >/dev/null

frontend-install:
	@echo "Ensuring frontend dependencies are present..."
	@cd $(FRONTEND_DIR) && npm install >/dev/null

run-db:
	@cd $(BACKEND_DIR) && \
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
		COMPOSE_CMD="docker compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		COMPOSE_CMD="docker-compose"; \
	else \
		echo "Docker Compose is required to start PostgreSQL."; \
		exit 1; \
	fi; \
	CONTAINER_NAME="blog-postgres"; \
	if docker ps -a --format '{{.Names}}' | grep -Fxq "$$CONTAINER_NAME"; then \
		echo "Removing stale PostgreSQL container $$CONTAINER_NAME ..."; \
		docker rm -f "$$CONTAINER_NAME" >/dev/null 2>&1 || true; \
	fi; \
	$$COMPOSE_CMD -f docker-compose.yml down --remove-orphans >/dev/null 2>&1 || true; \
	echo "Starting PostgreSQL via $$COMPOSE_CMD ..."; \
	$$COMPOSE_CMD -f docker-compose.yml up -d postgres >/dev/null

stop-db:
	@cd $(BACKEND_DIR) && \
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
		COMPOSE_CMD="docker compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		COMPOSE_CMD="docker-compose"; \
	else \
		exit 0; \
	fi; \
	echo "Stopping PostgreSQL container..."; \
	$$COMPOSE_CMD -f docker-compose.yml down >/dev/null 2>&1 || true

run-backend: backend-install run-db
	@cd $(BACKEND_DIR) && ./mvnw spring-boot:run

run-frontend: frontend-install
	@cd $(FRONTEND_DIR) && npm run start

run: backend-install frontend-install run-db
	@echo "Starting backend + frontend (Ctrl+C to stop everything)..."
	@bash -lc 'trap "kill 0" EXIT; \
		(cd $(BACKEND_DIR) && ./mvnw spring-boot:run) & \
		(cd $(FRONTEND_DIR) && npm run start) & \
		wait'

deps: backend-install frontend-install
	@echo "Dependencies are ready."
