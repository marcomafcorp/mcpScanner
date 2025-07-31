# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Security Scanner is a comprehensive security vulnerability assessment tool for Modular/Managed Control Planes (MCPs). It performs passive analysis (dependency & config inspection) and active testing (port probes, OWASP Top-10 style HTTP tests), generates CVSS-style severity scores with remediation advice, and presents results through a React dashboard.

## Tech Stack

### Backend
- **Python 3.11** with **FastAPI** framework
- **Poetry** for dependency management
- **SQLAlchemy 2 + Alembic** for database ORM and migrations
- **Celery + Redis** for async task processing
- **Security libraries**: python-nmap, scapy, bandit, OWASP Dependency-Check CLI wrapper

### Frontend
- **React 18 + Vite** with TypeScript
- **Tailwind CSS** for styling
- **Lucide-React** for icons
- **Recharts** for data visualization

### Database
- **PostgreSQL 15** (primary), **SQLite** (development)

## Common Commands

### Backend Commands
```bash
# Backend directory: backend/
cd backend

# Install dependencies
poetry install

# Run development server
poetry run uvicorn app.main:app --reload

# Run tests
poetry run pytest
poetry run pytest --cov=app --cov-report=html  # with coverage

# Database migrations
poetry run alembic upgrade head  # Apply migrations
poetry run alembic revision --autogenerate -m "Description"  # Create new migration

# Linting and formatting
poetry run ruff check .
poetry run black .
poetry run isort .

# Type checking
poetry run mypy app/
```

### Frontend Commands
```bash
# Frontend directory: frontend/
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Run tests
npm test
npm run test:coverage  # with coverage

# Linting
npm run lint
npm run lint:fix

# Type checking
npm run type-check
```

### Docker Commands
```bash
# Build and run all services
docker-compose up --build

# Run in detached mode
docker-compose up -d

# View logs
docker-compose logs -f [service_name]

# Stop all services
docker-compose down

# Reset database
docker-compose down -v  # Also removes volumes
```

### Git Commands
```bash
# IMPORTANT: After completing any full task, commit and push changes to GitHub
git add .
git commit -m "feat: describe the completed feature/task"
git push origin main

# Common git operations
git status  # Check current changes
git diff    # View unstaged changes
git log --oneline -10  # View recent commits
```

## High-Level Architecture

### Backend Architecture
The backend follows a modular architecture with clear separation of concerns:

- **`app/api/`**: REST API endpoints organized by feature domain
- **`app/core/`**: Core configurations, settings, and security utilities
- **`app/db/`**: Database models, sessions, and connection management
- **`app/models/`**: SQLAlchemy ORM models for database entities
- **`app/schemas/`**: Pydantic models for request/response validation
- **`app/services/`**: Business logic including scanner modules
- **`app/scanners/`**: Pluggable scanner modules (passive/active)
  - Each scanner implements a common interface for consistency
  - Scanners are registered in a central registry for discovery
- **`app/tasks/`**: Celery async tasks for long-running operations

### Frontend Architecture
The frontend uses a component-based architecture:

- **`src/components/`**: Reusable UI components organized by type
  - `common/`: Shared components (buttons, forms, etc.)
  - `layout/`: Layout components (AppLayout, Sidebar)
  - `ui/`: Feature-specific UI components
- **`src/pages/`**: Route-based page components
- **`src/services/`**: API client services and data fetching logic
- **`src/hooks/`**: Custom React hooks for shared logic
- **`src/types/`**: TypeScript type definitions

### Scanner Engine Architecture
The scanner engine is designed to be extensible:

1. **Scanner Registry**: Central registry for all scanner modules
2. **Base Scanner Interface**: All scanners implement common methods
3. **Result Pipeline**: Standardized processing of scan results
4. **CVSS Scoring**: Automated severity calculation based on findings
5. **Task Queue**: Celery manages long-running scans asynchronously

### Data Flow
1. User initiates scan via React dashboard
2. API validates request and queues scan task
3. Celery worker picks up task and executes scanners
4. Results are processed, scored, and stored in PostgreSQL
5. WebSocket updates provide real-time progress to dashboard
6. Dashboard displays findings with severity scores and remediation

## Key Design Patterns

- **Dependency Injection**: FastAPI's dependency system for DB sessions, auth
- **Repository Pattern**: Data access abstracted through repository classes
- **Plugin Architecture**: Scanners are pluggable modules with common interface
- **Async/Await**: Leveraged throughout for non-blocking operations
- **WebSocket**: Real-time communication for scan progress updates

## Implementation Status

The project is currently in planning phase with implementation divided into 5 phases:
1. Project Setup & Core Infrastructure
2. Scanner Engine & API
3. Auth, Security, and Compliance
4. Dashboard UI & Visualization
5. Documentation, Diagrams, and Finalization

Refer to `Implementation Plan/` directory for detailed phase descriptions and progress.