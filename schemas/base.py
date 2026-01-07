from pydantic import BaseModel, ConfigDict

class NetOpsBaseModel(BaseModel):
    """
    Base model for all NetOps schemas.
    Configured to strip whitespace and forbid extra fields to ensure strict validation.
    """
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra='forbid',
        from_attributes=True  # Allows mapping from SQLAlchemy models
    )
