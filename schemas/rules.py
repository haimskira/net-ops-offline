from typing import Optional, Literal
from pydantic import Field, field_validator
from schemas.base import NetOpsBaseModel
from schemas.objects import validate_rule_source_dest

class RuleCreateRequest(NetOpsBaseModel):
    rule_name: str = Field(..., min_length=1, max_length=100, pattern=r'^[a-zA-Z0-9 _\-]+$')
    source_ip: str
    destination_ip: str
    service_port: str
    protocol: Literal['tcp', 'udp'] = 'tcp'
    application: Optional[str] = 'any'
    from_zone: Optional[str] = 'any'
    to_zone: Optional[str] = 'any'
    tag: Optional[str] = None
    group_tag: Optional[str] = None
    duration_hours: int = Field(default=48, ge=1, le=720) # Max 30 days

    @field_validator('source_ip', 'destination_ip')
    def validate_ips(cls, v):
        if v.lower() == 'any':
            return 'any'
        return validate_rule_source_dest(v)

    @field_validator('service_port')
    def validate_port(cls, v):
        if v.lower() in ['any', 'application-default']:
            return v
        # Reuse the validator from objects
        from schemas.objects import validate_port_range
        return validate_port_range(v)
