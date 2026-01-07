from typing import Optional, List, Union, Literal
from pydantic import Field, field_validator, model_validator
import ipaddress
import re
from schemas.base import NetOpsBaseModel

# --- Shared Validators ---

def validate_ip_content(v: str) -> str:
    """Strict validation for Address Object VALUE (must be IP, CIDR, or FQDN)."""
    try:
        ipaddress.ip_interface(v)
        return v
    except ValueError:
        # Check strict FQDN (must have dots, e.g. host.local) or 'localhost'
        if v.lower() == 'localhost': return v
        # Require at least one dot for FQDN to distinguish from random strings
        if re.match(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', v):
            return v
        raise ValueError("Must be a valid IP address (1.1.1.1), CIDR (10.0.0.0/8), or FQDN (host.com)")

def validate_rule_source_dest(v: str) -> str:
    """Loose validation for Rule Source/Dest (IP, CIDR, or Object Name)."""
    try:
        ipaddress.ip_interface(v)
        return v
    except ValueError:
        # Allow valid Object Names (including Groups)
        # Pattern: Alphanumeric, underscores, hyphens, dots, matching spaces.
        # CRITICAL: Prevent partial IP matches or "999.999.999" from passing as object name if they look like IPs.
        # If it looks like an IP (digts and dots only), reject it.
        if re.match(r'^[\d\.]+$', v):
             raise ValueError("Invalid IP address format")

        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._\-\s]*[a-zA-Z0-9]$', v) or re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_\-\s]*$', v):
            return v
        raise ValueError("Must be a valid IP, CIDR, or existing Object Name")

def validate_port_range(v: str) -> str:
    """Validates port format: '80', '80-8080', '80,443' OR Service Name."""
    if not v or 'undefined' in v.lower():
        raise ValueError("Invalid port value")
    
    # 1. Check if it's a valid service name (allow spaces) BEFORE stripping
    if re.match(r'^[a-zA-Z][a-zA-Z0-9_\-\s]*$', v):
        return v.strip()

    clean = v.replace(" ", "")
    
    # 1. Check if it's a valid service name (legacy check after strip, probably redundant but safe)
    if re.match(r'^[a-zA-Z][a-zA-Z0-9_\-]*$', clean):
        return clean

    # 2. Check strict port syntax (Ranges allowed: '80', '80-8080', '80,443')
    if not re.match(r'^\d+(-\d+)?(,\d+(-\d+)?)*$', clean):
        raise ValueError("Invalid format. Use ports (80), ranges (80-81), or lists (80,443)")
    
    parts = clean.split(',')
    for p in parts:
        if '-' in p:
            start, end = map(int, p.split('-'))
            if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                 raise ValueError(f"Ports {start}-{end} out of range (1-65535)")
            if start >= end:
                raise ValueError(f"Invalid range {start}-{end} (Start must be less than End)")
        else:
            if not p.isdigit() or not (1 <= int(p) <= 65535):
                raise ValueError(f"Port {p} is out of valid range (1-65535)")
    return clean

    return clean

def validate_reserved_names(v: str) -> str:
    if v.lower() == 'test':
        raise ValueError("The name 'test' is reserved by the Firewall and cannot be used.")
    return v

# --- Address Objects ---

class AddressObjectCreate(NetOpsBaseModel):
    name: str = Field(..., min_length=1, max_length=63, pattern=r'^[a-zA-Z0-9_\-\. ]+$')
    type: Literal['address', 'address-group']
    value: str
    prefix: Optional[str] = None
    description: Optional[str] = None
    protocol: Optional[str] = None # Ignored for addresses, but allowed to prevent frontend errors

    @field_validator('name')
    def validate_name_strict(cls, v):
        return validate_reserved_names(v)

    @field_validator('value')
    def validate_content(cls, v, info):
        # We need to check 'type' but field_validators run per field.
        # We'll do a basic check here or use model_validator for dependent logic.
        return v

    @model_validator(mode='after')
    def validate_type_logic(self):
        if self.type == 'address':
            # If it looks like a group (comma separated), reject
            if ',' in self.value:
                raise ValueError("Address objects cannot contain commas. Use address-group.")
            
            # Simple IP/FQDN check
            validate_ip_content(self.value)
            # FQDN is handled inside validate_ip_content now
        
        elif self.type == 'address-group':
            members = [m.strip() for m in self.value.split(',') if m.strip()]
            if not members:
                raise ValueError("Address Group must have at least one member")
        
        return self

# --- Service Objects ---

class ServiceObjectCreate(NetOpsBaseModel):
    name: str = Field(..., min_length=1, max_length=63, pattern=r'^[a-zA-Z0-9_\-\. ]+$')
    type: Literal['service', 'service-group']
    protocol: Literal['tcp', 'udp', 'sctp'] = 'tcp'
    value: str # Port or Members
    prefix: Optional[str] = None # Ignored for services, allowed for frontend compatibility

    @field_validator('name')
    def validate_name_strict(cls, v):
        return validate_reserved_names(v)
    
    @field_validator('protocol', mode='before')
    def set_default_proto(cls, v):
        return v or 'tcp'

    @model_validator(mode='after')
    def validate_service_logic(self):
        if self.type == 'service':
            validate_port_range(self.value)
        elif self.type == 'service-group':
            members = [m.strip() for m in self.value.split(',') if m.strip()]
            if not members:
                raise ValueError("Service Group must have at least one member")
        return self
