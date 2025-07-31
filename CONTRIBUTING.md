# Contributing to MCP Security Scanner

## Code Style Guidelines

### General Principles
- Write clean, readable, and maintainable code
- Follow the DRY (Don't Repeat Yourself) principle
- Prefer composition over inheritance
- Write self-documenting code with clear variable and function names

### Python (Backend)

#### Style Guide
- Follow PEP 8 style guide
- Use type hints for all function parameters and return values
- Maximum line length: 88 characters (Black default)

#### Tools
- **Black**: Code formatting (automatically enforced)
- **Ruff**: Fast Python linter
- **isort**: Import sorting
- **mypy**: Static type checking

#### Naming Conventions
- Classes: `PascalCase`
- Functions/Variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_leading_underscore`

#### Example
```python
from typing import Optional, List
from pydantic import BaseModel

class UserProfile(BaseModel):
    """User profile data model."""
    
    user_id: int
    username: str
    email: str
    is_active: bool = True
    
    def get_display_name(self) -> str:
        """Return the user's display name."""
        return self.username.title()
```

### TypeScript/JavaScript (Frontend)

#### Style Guide
- Use TypeScript for all new code
- Prefer functional components with hooks
- Use arrow functions for component definitions
- Maximum line length: 100 characters

#### Tools
- **ESLint**: Linting with React and TypeScript rules
- **Prettier**: Code formatting
- **TypeScript**: Static type checking

#### Naming Conventions
- Components: `PascalCase`
- Functions/Variables: `camelCase`
- Constants: `UPPER_SNAKE_CASE`
- Types/Interfaces: `PascalCase` with `I` prefix for interfaces
- Files: `PascalCase` for components, `camelCase` for utilities

#### Example
```typescript
import React, { useState, useEffect } from 'react';

interface IUserProfileProps {
  userId: string;
  onUpdate?: (data: IUserData) => void;
}

interface IUserData {
  id: string;
  username: string;
  email: string;
  isActive: boolean;
}

export const UserProfile: React.FC<IUserProfileProps> = ({ userId, onUpdate }) => {
  const [userData, setUserData] = useState<IUserData | null>(null);
  
  useEffect(() => {
    // Fetch user data
  }, [userId]);
  
  return (
    <div className="user-profile">
      {/* Component content */}
    </div>
  );
};
```

### Git Commit Messages

Follow the Conventional Commits specification:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, missing semicolons, etc.)
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks
- `perf:` Performance improvements

Example:
```
feat: add user authentication endpoint
fix: resolve database connection timeout
docs: update API documentation for scan endpoints
```

### Testing

#### Backend Testing
- Write unit tests for all business logic
- Use pytest fixtures for test data
- Mock external dependencies
- Aim for >90% code coverage

#### Frontend Testing
- Write unit tests for utility functions
- Write integration tests for components
- Use React Testing Library
- Test user interactions and accessibility

### Documentation

- Add docstrings to all Python classes and functions
- Add JSDoc comments to TypeScript functions
- Keep README files up to date
- Document API endpoints with OpenAPI/Swagger
- Include examples in documentation

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes following the style guides
3. Write/update tests for your changes
4. Ensure all tests pass and coverage is maintained
5. Update documentation as needed
6. Submit a pull request with a clear description
7. Address review feedback promptly

### Pre-commit Hooks

The project uses pre-commit hooks to ensure code quality. Install them with:

```bash
pip install pre-commit
pre-commit install
```

Hooks will run automatically on commit and check:
- Code formatting (Black, Prettier)
- Linting (Ruff, ESLint)
- Import sorting (isort)
- Type checking (mypy, TypeScript)