# MCP Security Scanner

A comprehensive security vulnerability assessment tool for Modular/Managed Control Planes (MCPs). This application performs both passive analysis (dependency & config inspection) and active testing (port probes, OWASP Top-10 style HTTP tests), generates CVSS-style severity scores with remediation advice, and presents results through a modern React dashboard.

## Features

- **Passive Security Analysis**
  - Dependency vulnerability scanning
  - Configuration security assessment
  - Code security analysis using industry-standard tools
  
- **Active Security Testing**
  - Port scanning and service enumeration
  - OWASP Top-10 vulnerability testing
  - Network security analysis
  
- **Comprehensive Reporting**
  - CVSS-style severity scoring
  - Detailed remediation recommendations
  - Real-time scan progress updates
  - Export results in multiple formats

## Tech Stack

- **Backend**: Python 3.11, FastAPI, SQLAlchemy, Celery
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS
- **Database**: PostgreSQL 15 (SQLite for development)
- **DevOps**: Docker, Docker Compose, GitHub Actions

## Prerequisites

- Python 3.11+
- Node.js 18+
- Docker and Docker Compose
- PostgreSQL 15 (optional for development, SQLite can be used)
- Redis (for Celery task queue)

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/marcomafcorp/mcpScanner.git
   cd mcpScanner
   ```

2. Copy environment files:
   ```bash
   cp backend/.env.example backend/.env
   cp frontend/.env.example frontend/.env
   ```

3. Start all services:
   ```bash
   docker-compose up --build
   ```

4. Access the application:
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

### Manual Setup

#### Backend Setup

1. Navigate to backend directory:
   ```bash
   cd backend
   ```

2. Install Poetry (if not already installed):
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

3. Install dependencies:
   ```bash
   poetry install
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. Run database migrations:
   ```bash
   poetry run alembic upgrade head
   ```

6. Start the development server:
   ```bash
   poetry run uvicorn app.main:app --reload
   ```

#### Frontend Setup

1. Navigate to frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Start the development server:
   ```bash
   npm run dev
   ```

## Development

### Running Tests

#### Backend Tests
```bash
cd backend
poetry run pytest
poetry run pytest --cov=app --cov-report=html  # With coverage
```

#### Frontend Tests
```bash
cd frontend
npm test
npm run test:coverage  # With coverage
```

### Code Quality

#### Backend
```bash
cd backend
poetry run ruff check .      # Linting
poetry run black .           # Formatting
poetry run mypy app/         # Type checking
```

#### Frontend
```bash
cd frontend
npm run lint                 # Linting
npm run lint:fix            # Auto-fix linting issues
npm run type-check          # Type checking
```

## Project Structure

```
mcpScanner/
├── backend/                 # FastAPI backend application
│   ├── app/                # Application code
│   │   ├── api/           # API endpoints
│   │   ├── core/          # Core configurations
│   │   ├── db/            # Database models and sessions
│   │   ├── models/        # SQLAlchemy models
│   │   ├── schemas/       # Pydantic schemas
│   │   ├── services/      # Business logic
│   │   └── scanners/      # Security scanner modules
│   └── tests/             # Backend tests
├── frontend/               # React frontend application
│   ├── src/               # Source code
│   │   ├── components/    # React components
│   │   ├── pages/        # Page components
│   │   ├── services/     # API services
│   │   └── types/        # TypeScript types
│   └── tests/            # Frontend tests
├── docs/                  # Documentation
└── docker-compose.yml     # Docker composition
```

## API Documentation

Once the backend is running, you can access:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or contributions, please visit:
https://github.com/marcomafcorp/mcpScanner/issues