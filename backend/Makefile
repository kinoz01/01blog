HTTPS_PROPS=src/main/resources/application.properties
KEYSTORE_FILE=keystore.p12
KEYSTORE_PASS?=changeit
KEY_ALIAS?=blog-local
HTTPS_PORT?=8443
SECRETS_FILE?=.env.local

help:
	@echo "Available targets:"
	@echo "  make run         - load .env.local, start PostgreSQL (via Docker) and the Spring API"
	@echo "  make test        - run test scripts executing different API calls (use right arrow to go to next call)"
	@echo "  make https       - create a self-signed SSL certificate and enable HTTPS in application.properties"
	@echo "  make secrets     - generate .env.local with JWT secret and admin credentials"
	@echo "  make build       - compiles and packages the project"
	@echo "  make stop        - stops the Spring Boot app and dockerized database"

run: db-up
	@set -a; \
	if [ -f ".env.local" ]; then \
		echo "Loading environment variables from .env.local"; \
		. ./.env.local; \
	else \
		echo "No .env.local found; proceeding with existing environment, to generate automatically u might use the make secrets target"; \
	fi; \
	set +a; \
	./mvnw spring-boot:run 

stop: db-down

build:
	./mvnw clean package

test:
	./mvnw clean test

secrets:
	@set -e; \
	JWT_VALUE="$${JWT_SECRET_VALUE:-$$(openssl rand -base64 48)}"; \
	ADMIN_EMAIL_VALUE="$${ADMIN_EMAIL_VALUE:-admin@blog.dev}"; \
	ADMIN_PASSWORD_VALUE="$${ADMIN_PASSWORD_VALUE:-Admin123!}"; \
	DB_URL_VALUE="$${DATABASE_URL_VALUE:-jdbc:postgresql://localhost:5432/blog}"; \
	DB_USER_VALUE="$${DATABASE_USERNAME_VALUE:-postgres}"; \
	DB_PASS_VALUE="$${DATABASE_PASSWORD_VALUE:-postgres}"; \
	DB_DRIVER_VALUE="$${DATABASE_DRIVER_VALUE:-org.postgresql.Driver}"; \
	DB_DIALECT_VALUE="$${JPA_DIALECT_VALUE:-org.hibernate.dialect.PostgreSQLDialect}"; \
	echo "Writing secrets to $(SECRETS_FILE)"; \
	{ \
		echo "JWT_SECRET=$$JWT_VALUE"; \
		echo "ADMIN_EMAIL=$$ADMIN_EMAIL_VALUE"; \
		echo "ADMIN_PASSWORD=$$ADMIN_PASSWORD_VALUE"; \
		echo "DATABASE_URL=$$DB_URL_VALUE"; \
		echo "DATABASE_USERNAME=$$DB_USER_VALUE"; \
		echo "DATABASE_PASSWORD=$$DB_PASS_VALUE"; \
		echo "DATABASE_DRIVER=$$DB_DRIVER_VALUE"; \
		echo "JPA_DIALECT=$$DB_DIALECT_VALUE"; \
	} > $(SECRETS_FILE); \
	echo "Secrets saved. Load them with: \"set -a; . ./.env.local; set +a\" or use \"make run\" to load automatically."

https:
	@set -e; \
	if [ ! -f "$(KEYSTORE_FILE)" ]; then \
		echo "Generating PKCS12 keystore $(KEYSTORE_FILE)..."; \
		keytool -genkeypair \
			-alias $(KEY_ALIAS) \
			-keyalg RSA \
			-keysize 2048 \
			-storetype PKCS12 \
			-keystore $(KEYSTORE_FILE) \
			-validity 365 \
			-storepass $(KEYSTORE_PASS) \
		-dname "CN=localhost, OU=Blog, O=Blog, L=Local, S=Local, C=US"; \
	else \
		echo "$(KEYSTORE_FILE) already exists; skipping keytool."; \
	fi; \
	if ! grep -q "server\.ssl\.key-store=$(KEYSTORE_FILE)" "$(HTTPS_PROPS)"; then \
		echo "Appending HTTPS configuration to $(HTTPS_PROPS)..."; \
		printf "\n# Local HTTPS configuration\n" >> "$(HTTPS_PROPS)"; \
		printf "server.port=%s\n" "$(HTTPS_PORT)" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.enabled=true\n" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.key-store=%s\n" "$(KEYSTORE_FILE)" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.key-store-password=%s\n" "$(KEYSTORE_PASS)" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.key-store-type=PKCS12\n" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.key-alias=%s\n" "$(KEY_ALIAS)" >> "$(HTTPS_PROPS)"; \
	else \
		echo "HTTPS configuration already present in $(HTTPS_PROPS)."; \
	fi

db-up:
	@$(MAKE) _db-up

db-down:
	@$(MAKE) _db-down

_db-up:
	@set -e; \
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
		COMPOSE_CMD="docker compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		COMPOSE_CMD="docker-compose"; \
	else \
		echo "Docker Compose is required to start PostgreSQL automatically (install Docker Desktop or docker-compose)."; \
		exit 1; \
	fi; \
	echo "Starting PostgreSQL container using $$COMPOSE_CMD ..."; \
	$$COMPOSE_CMD up -d postgres; \
	echo "Database container is ready."

_db-down:
	@set -e; \
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
		COMPOSE_CMD="docker compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		COMPOSE_CMD="docker-compose"; \
	else \
		exit 0; \
	fi; \
	echo "Stopping PostgreSQL container..."; \
	$$COMPOSE_CMD down >/dev/null 2>&1 || true; \
	echo "PostgreSQL container stopped."
