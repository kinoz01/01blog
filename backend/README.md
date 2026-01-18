# Blog API

The Blog backend exposes secure authentication endpoints that power the social learning experience. It is a Spring Boot 3 service that ships with JWT authentication, relational storage (PostgreSQL or in-memory H2 for quick starts), rate limiting, and method-level authorization.

## Features

- **Auth & JWT** – `/api/auth/register`, `/api/auth/login`, and `/api/auth/me` issue signed tokens and return typed user profiles.
- **Role-aware users** – `USER` and `ADMIN` roles are persisted through Spring Data JPA entities.
- **Relational storage** – PostgreSQL by default (via `docker-compose`) powers the app locally; tests still use an in-memory H2 database.
- **Security hardened** – Spring Security, stateless sessions, bcrypt hashing, and a request throttling filter with centralized exception handling.
- **Posts + media** – Authenticated users can publish posts with up to 10 images/videos; uploads are validated via Apache Tika before being persisted to disk.

## Prerequisites

- Java 17+
- Maven 3.9+
- Node 20+ (for the frontend)
- Docker (optional, but recommended for the PostgreSQL container)

## Configuration

All secrets live in environment variables. Create `.env.local` with:

```bash
JWT_SECRET=<base64-encoded-secret>
ADMIN_EMAIL=admin@blog.dev
ADMIN_PASSWORD=Admin123!
DATABASE_URL=jdbc:postgresql://localhost:5432/blog     # optional when running with Docker
DATABASE_USERNAME=postgres                              # optional
DATABASE_PASSWORD=postgres                              # optional
DATABASE_DRIVER=org.postgresql.Driver                   # optional
JPA_DIALECT=org.hibernate.dialect.PostgreSQLDialect     # optional
```

Run `make secrets` to auto-generate `JWT_SECRET`, admin credentials, and the PostgreSQL connection settings used during `make run`.

Media uploads are saved under `app.media.storage-path` (default `backend/uploads`). Override this via the `MEDIA_STORAGE_PATH` env var if you want a different location. Static files are exposed via `/media/**`.

## Local development

### Make shortcuts (repo root)

Common workflows are wired up in the repository level `Makefile`:

```bash
make run-db         # start PostgreSQL via docker compose
make run-backend    # ensure deps + db, then run Spring Boot
make run-frontend   # ensure npm deps, then start Angular dev server
make run            # install deps, boot db, run both apps in one command
```

### 1. Start PostgreSQL

```bash
cd backend
make run  # spins up postgres via docker-compose and starts Spring Boot
```

The backend now targets PostgreSQL by default. `make run-db` (or `make run`) uses Docker Compose to start the `blog-postgres` container, and the application connects via the credentials stored in `.env.local`. Automated tests (`./mvnw clean test`) still use an embedded H2 database defined under `src/test/resources`.

### 2. Hit the API

Sample calls (HTTPie / curl):

```bash
# Register
http POST :8080/api/auth/register name="Casey Student" email="casey@example.com" password="Password123!"

# Log in
http POST :8080/api/auth/login email="casey@example.com" password="Password123!"

# Fetch your profile
http GET :8080/api/auth/me "Authorization:Bearer <token>"

# Publish a post with media
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -F "title=Weekly Update" \
  -F "description=Documenting what I built" \
  -F "media=@/path/to/screenshot.png" \
  http://localhost:8080/api/posts

`POST /api/posts` accepts up to 10 media files per post and rejects anything that isn't a real image or video (checked via Apache Tika). `GET /api/posts` returns the chronological feed used by the frontend home page.
```

`/api/auth/me` returns:

```json
{
  "id": "6cf0d1be-40c2-4a61-9a3d-03022c0946f0",
  "name": "Casey Student",
  "email": "casey@example.com",
  "role": "USER",
  "createdAt": "2024-05-01T15:22:01.901Z",
  "updatedAt": "2024-05-01T15:22:01.901Z"
}
```

### Database seeding

On startup the `DataInitializer` bean ensures there is always an administrative account using the configured `ADMIN_EMAIL`/`ADMIN_PASSWORD`. Use it to inspect user tables or to seed future features such as moderation.

### Useful tasks

| Command | Description |
| --- | --- |
| `./mvnw clean test` | Compile & run unit tests (uses H2). |
| `make run` | Load `.env.local`, boot PostgreSQL (Docker) and run the app. |
| `make stop` | Stop the Spring Boot process and dockerized database. |
| `make build` | Package the application jar. |
| `make https` | Generate a local PKCS12 keystore and enable HTTPS in `application.properties`. |

## Frontend pairing

The Angular client (in `/frontend`) expects the API at `http://localhost:8080/api` by default. Update `frontend/src/environments/environment.ts` if your backend listens elsewhere.

Run the UI next to the API:

```bash
cd frontend
npm install
npm run start  # serves at http://localhost:4200
```

You can now use the polished Bootstrap-driven login/sign-up experience powered by the endpoints above.
