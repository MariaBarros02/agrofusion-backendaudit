from sqlalchemy import Column, String, DateTime, Integer, Text
from app.core.database import Base


class AfAuditLog(Base):

    __tablename__ = "af_audit_log"

    audit_id = Column(Integer, primary_key=True, index=True)

    tenant_id = Column(Integer)

    actor_id = Column(String)

    external_project_id = Column(Integer)

    trace_id = Column(String)

    project_id = Column(Integer)

    device_info = Column(String)

    target_json = Column(Text)

    diff_json = Column(Text)

    created_at = Column(DateTime)

    actor_ip = Column(String)

    session_id = Column(String)

    action_term_id = Column(Integer)

    at = Column(DateTime)

    action_code = Column(String)

    outcome = Column(String)

    module_code = Column(String)

    payload_hash = Column(String)

    digital_signature = Column(String)