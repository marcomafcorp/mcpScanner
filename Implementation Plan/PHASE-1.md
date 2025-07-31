# Phase 1: Project Setup & Core Infrastructure

## Objectives
- Establish project structure and architecture
- Set up development environment and tooling
- Create core infrastructure components
- Implement basic CI/CD pipeline

## Todo List

### 1. Project Initialization
- [ ] Create monorepo structure with `backend`, `frontend`, and `docs` directories
- [ ] Initialize git repository
- [ ] Create `.gitignore` files for backend and frontend
- [ ] Set up project-wide README.md with setup instructions
- [ ] Define code style guidelines and conventions

### 2. Backend Setup
- [ ] Initialize Poetry project in `backend` directory
- [ ] Configure Poetry with required dependencies:
  - FastAPI, uvicorn, pydantic
  - SQLAlchemy, alembic
  - pytest, pytest-cov, pytest-asyncio
  - Security libraries: python-nmap, scapy, bandit
  - Other utilities: python-dotenv, pydantic-settings
- [ ] Set up FastAPI application structure:
  ```
  backend/
  ├── app/
  │   ├── __init__.py
  │   ├── main.py
  │   ├── core/
  │   │   ├── __init__.py
  │   │   ├── config.py
  │   │   └── settings.py
  │   ├── api/
  │   │   ├── __init__.py
  │   │   ├── deps.py
  │   │   └── routes/
  │   ├── db/
  │   │   ├── __init__.py
  │   │   ├── base.py
  │   │   └── session.py
  │   ├── models/
  │   ├── schemas/
  │   ├── services/
  │   └── utils/
  ├── pyproject.toml
  ├── poetry.lock
  ├── .env.example
  └── tests/
  ```
- [ ] Implement core configuration management (settings.py)
- [ ] Set up database connection and session management
- [ ] Create initial Alembic configuration for migrations
- [ ] Implement basic health check endpoint

### 3. Database Setup
- [ ] Define PostgreSQL and SQLite connection configurations
- [ ] Create initial database schema design
- [ ] Set up base SQLAlchemy models
- [ ] Implement database initialization script
- [ ] Create initial migration with Alembic

### 4. Frontend Setup
- [ ] Initialize Vite project with React and TypeScript
- [ ] Configure Tailwind CSS
- [ ] Set up folder structure:
  ```
  frontend/
  ├── src/
  │   ├── assets/
  │   ├── components/
  │   │   ├── common/
  │   │   ├── layout/
  │   │   └── ui/
  │   ├── hooks/
  │   ├── pages/
  │   ├── services/
  │   ├── types/
  │   ├── utils/
  │   ├── App.tsx
  │   └── main.tsx
  ├── package.json
  ├── tailwind.config.js
  ├── vite.config.ts
  ├── tsconfig.json
  ├── index.html
  └── .env.example
  ```
- [ ] Install required dependencies:
  - React Router DOM
  - Lucide React (icons)
  - Recharts
  - Axios/React Query
  - React Hook Form
  - Other utilities
- [ ] Set up basic theme configuration (dark mode with Tailwind)
- [ ] Create basic layout components (AppLayout, Sidebar)
- [ ] Implement placeholder pages for main navigation sections

### 5. Docker Setup
- [ ] Create Dockerfile for backend
- [ ] Create Dockerfile for frontend
- [ ] Set up docker-compose.yml with services:
  - Backend API
  - Frontend web server
  - PostgreSQL database
  - Redis (for Celery)
- [ ] Configure environment variables for each service
- [ ] Set up development and production configurations

### 6. CI/CD Setup
- [ ] Create GitHub Actions workflow for backend:
  - Run tests
  - Run linting and type checking
  - Build Docker image
- [ ] Create GitHub Actions workflow for frontend:
  - Run tests
  - Run linting and type checking
  - Build production assets
- [ ] Set up pre-commit hooks:
  - ruff (linting)
  - black (formatting)
  - isort (import sorting)

### 7. Testing Framework
- [ ] Set up pytest configuration for backend
- [ ] Create test fixtures for database and API
- [ ] Set up React Testing Library and Jest for frontend
- [ ] Create basic smoke tests for backend and frontend
- [ ] Set up test coverage reporting

## Tests to Validate Phase 1

### Backend Tests
1. **Configuration Test**
   - Verify environment variables are correctly loaded
   - Test configuration defaults and overrides
   - Verify development/production environment differentiation

2. **Database Connection Test**
   - Test database connection establishment
   - Verify migration setup works
   - Test session management and connection pooling

3. **API Health Check Test**
   - Test health check endpoint returns 200
   - Verify API version and status information
   - Test response format and content

### Frontend Tests
1. **Component Rendering Test**
   - Test base layout components render correctly
   - Verify routing setup works properly
   - Test dark theme implementation

2. **API Integration Test**
   - Mock API endpoints and test frontend service layer
   - Verify error handling for API calls
   - Test loading states for API interactions

### Infrastructure Tests
1. **Docker Compose Test**
   - Verify all services start correctly
   - Test inter-service communication
   - Verify environment variable passing between services

## Definition of Done
- Project structure established and documented
- All development environments can be set up with clear instructions
- Docker-compose successfully runs all services
- CI pipeline passes for both backend and frontend
- All tests pass with minimum 90% coverage for core components
