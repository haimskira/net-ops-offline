from contextlib import contextmanager
from typing import Generator
import logging
from managers.models import db_sql

logger = logging.getLogger(__name__)

class BaseService:
    """
    Base service class providing transaction management and consistency.
    """
    
    @staticmethod
    @contextmanager
    def transaction() -> Generator:
        """
        Context manager for atomic database transactions.
        Auto-commits on success, rolls back on exception.
        """
        try:
            yield db_sql.session
            db_sql.session.commit()
        except Exception as e:
            db_sql.session.rollback()
            logger.error(f"Transaction failed: {str(e)}")
            raise e
