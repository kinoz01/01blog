# Maaref Platform

A full-stack social learning platform with a Spring Boot backend and an Angular frontend. The project is split into two workspaces (`backend/` and `frontend/`) and coordinated via the repo-level `Makefile`.

## Architecture Overview

```
┌───────────────┐        JWT + REST        ┌────────────────┐
│  Angular 18   │  <--------------------> │  Spring Boot   │
│  (frontend)   │                         │  API layer     │
│               │   /media/** static      │                │
│ Bootstrap UI  │  <--------------------> │ Media storage  │
└──────┬────────┘                         └──────┬─────────┘
       │                                         │
       │ GraphQL? no (REST only)                 │
       │                                         ▼
       │                                PostgreSQL via Docker
       └──────────────> Users interact via browser <──────────────┘
```

- **Frontend** – Angular 18 + RxJS, styled with Bootstrap & Bootstrap Icons, talks to the backend through `/api/**`. Guards rely on JWT state stored in `localStorage`.
- **Backend** – Spring Boot 3 service with Spring Security, JWT auth, rate limiting, and layered services (controllers → services → repositories). Media uploads are persisted on disk and exposed under `/media/**`.
- **Database** – PostgreSQL (local instance provided via `docker-compose`), accessed with Spring Data JPA. A `DataInitializer` seeds the admin account.

## Setup Instructions

### Prerequisites

- Java 17+
- Maven 3.9+
- Node.js 20+ / npm 10+
- Docker + Docker Compose (recommended for PostgreSQL)

### 1. Clone & boot services

```bash
# Install dependencies and boot DB + backend + frontend
make run            # from repo root
```

This command loads `.env.local`, brings up the PostgreSQL container, runs the Spring Boot API on `:8080`, and starts Angular on `:4200`.

### 2. Run backend / frontend separately (optional)

```bash
# Database + API
cd backend
make run            # or ./mvnw spring-boot:run (ensure Postgres is running)

# Frontend
cd frontend
npm install
npm run start       # serves at http://localhost:4200
```

Environment variables live in `backend/.env.local` (see `backend/README.md` for details). The frontend points to `http://localhost:8080/api` via its environment config.

### 3. Useful make targets

| Command | Description |
| --- | --- |
| `make run-db` | Start only the PostgreSQL docker container |
| `make run-backend` | Run `./mvnw spring-boot:run` after ensuring DB is up |
| `make run-frontend` | Run `npm install && npm run start` |
| `make stop` | Stop backend process and dockerized DB |

## Technologies Used

### Backend
- Spring Boot 3 / Spring Web
- Spring Security with JWT (custom `JwtAuthenticationFilter` & `JwtService`)
- Spring Data JPA + PostgreSQL
- BCrypt password hashing
- Apache Tika for media validation
- Custom rate limiting filter, CORS config, and global exception handling

### Frontend
- Angular 18 (standalone components, router, guards)
- RxJS & HttpClient
- Bootstrap 5 & Bootstrap Icons
- SCSS theming, responsive layout

### Tooling & Ops
- Maven wrapper (`./mvnw`)
- npm / Angular CLI
- Docker + Docker Compose for Postgres
- Makefile scripts for unified workflows

Refer to `backend/README.md` for API-specific details and to the component-level documentation in `frontend/` for UI specifics.
