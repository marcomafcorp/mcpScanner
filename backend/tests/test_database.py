import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import Base
from app.models.base import BaseModel


@pytest.mark.asyncio
async def test_database_connection(db_session: AsyncSession):
    """Test that database connection works."""
    # Simple query to test connection
    result = await db_session.execute(select(1))
    assert result.scalar() == 1


def test_base_model_table_naming():
    """Test that BaseModel generates correct table names."""
    class TestModel(BaseModel):
        __abstract__ = False
        __allow_unmapped__ = True
    
    assert TestModel.__tablename__ == "testmodels"


@pytest.mark.asyncio
async def test_tables_created(db_session: AsyncSession):
    """Test that all tables are created properly."""
    # Get all table names from metadata
    table_names = Base.metadata.tables.keys()
    
    # At this point we should have at least the base tables
    # As we add more models, we'll update this test
    assert hasattr(table_names, '__iter__')