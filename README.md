# AI SOC Analyst

An AI-assisted Security Operations Center analyst platform.

> **Status: Phase 0 — Foundation.** This repository currently contains the monorepo
> scaffolding, local infrastructure, and health endpoints only. Authentication, AI/LLM
> features, RAG, and anomaly detection are deliberately not implemented yet.

## Stack

| Layer          | Technology                                  |
| -------------- | ------------------------------------------- |
| Frontend       | Next.js 15 (App Router), TypeScript, Tailwind CSS |
| Backend        | FastAPI, Python 3.11+, SQLAlchemy 2 (async)  |
| Database       | PostgreSQL 16 with `pgvector`                |
| Cache / queue  | Redis 7                                      |
| Migrations     | Alembic                                      |
| Local infra    | Docker Compose                               |

## Repository layout

```
.
├── backend/                  FastAPI service
│   ├── alembic/              Migration environment (no revisions yet)
│   ├── app/
│   │   ├── api/v1/           Versioned routers and endpoints
│   │   ├── core/             Settings and logging
│   │   ├── db/               SQLAlchemy engine/session, Redis client
│   │   ├── models/           ORM models (empty in Phase 0)
│   │   ├── schemas/          Pydantic request/response models
│   │   ├── services/         Business logic (empty in Phase 0)
│   │   └── main.py           Application factory
│   └── tests/
├── frontend/                 Next.js application
│   └── src/
│       ├── app/              App Router routes
│       ├── components/       React components
│       ├── lib/              API client, env accessors
│       └── types/            Shared TypeScript types
├── infra/postgres/init/      SQL run on first database init (extensions)
└── docker-compose.yml        PostgreSQL + pgvector, Redis
```

## Prerequisites

- Node.js 20+ and npm
- Python 3.11+
- Docker Desktop (for PostgreSQL and Redis)

## Getting started

### 1. Infrastructure

```bash
cp .env.example .env
docker compose up -d
```

This starts PostgreSQL (with `vector`, `uuid-ossp`, and `pg_trgm` extensions created on
first boot) on port `5432` and Redis on port `6379`.

### 2. Backend

```bash
cd backend
cp .env.example .env

python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate

pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

- API docs: http://localhost:8000/docs
- Liveness: http://localhost:8000/api/v1/health
- Readiness (checks PostgreSQL + Redis): http://localhost:8000/api/v1/ready

### 3. Frontend

```bash
cd frontend
cp .env.example .env.local

npm install
npm run dev
```

Open http://localhost:3000. The home page shows the live backend connection status.

## Environment variables

Each `.env.example` documents the variables for its scope. Never commit a real `.env`.

| File                   | Purpose                                            |
| ---------------------- | -------------------------------------------------- |
| `.env.example`         | Credentials and ports used by `docker-compose.yml`  |
| `backend/.env.example` | FastAPI settings, database and Redis connection     |
| `frontend/.env.example`| Public `NEXT_PUBLIC_*` values used by the browser    |

When running the backend inside Docker rather than on the host, set
`POSTGRES_HOST=postgres` and `REDIS_HOST=redis` so the service names resolve.

## Common commands

```bash
# Backend
pytest                                  # tests
ruff check .                            # lint
ruff format .                           # format
alembic revision --autogenerate -m "…"  # new migration
alembic upgrade head                    # apply migrations

# Frontend
npm run dev     # dev server
npm run build   # production build
npm run lint    # eslint
```

## Roadmap

Phase 0 (this commit) establishes the foundation. Subsequent phases add
authentication, alert ingestion, AI-assisted triage, RAG over threat intelligence,
and anomaly detection.
