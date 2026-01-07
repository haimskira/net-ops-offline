from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class Switch(Base):
    __tablename__ = "switches"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, unique=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    model = Column(String)
    os_version = Column(String)
    serial_number = Column(String)
    uptime = Column(String)
    is_stack = Column(Boolean, default=False)
    stack_member_count = Column(Integer, default=1)
    
    # Aggregated Stats
    active_ports_count = Column(Integer, default=0)
    err_disabled_count = Column(Integer, default=0)
    mab_failed_count = Column(Integer, default=0)
    
    last_updated = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Switch(hostname={self.hostname}, ip={self.ip_address})>"

class TopologyLink(Base):
    __tablename__ = "topology_links"

    id = Column(Integer, primary_key=True, index=True)
    source_hostname = Column(String, index=True) # Switch.hostname
    target_hostname = Column(String) # Remote Device ID
    local_port = Column(String)
    remote_port = Column(String)

    def __repr__(self):
        return f"<Link({self.source_hostname}:{self.local_port} -> {self.target_hostname}:{self.remote_port})>"
