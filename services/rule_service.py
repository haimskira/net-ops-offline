from datetime import datetime
import re
from schemas.rules import RuleCreateRequest
from managers.models import db_sql, RuleRequest, SecurityRule, AuditLog
from services.base_service import BaseService
from services.fw_service import FwService, CustomSecurityRule
from panos.policies import Rulebase
from panos.objects import ServiceObject as PanService

class RuleService(BaseService):
    
    @classmethod
    def create_request(cls, data: RuleCreateRequest, user: str):
        # Check for duplicates
        existing = RuleRequest.query.filter_by(
            source_ip=data.source_ip, destination_ip=data.destination_ip, 
            service_port=data.service_port, status='Pending'
        ).first()
        if existing:
            raise ValueError(f"Duplicate request exists (ID: {existing.id})")

        with cls.transaction():
            req = RuleRequest(
                rule_name=data.rule_name,
                requested_by=user,
                from_zone=data.from_zone,
                to_zone=data.to_zone,
                source_ip=data.source_ip,
                destination_ip=data.destination_ip,
                service_port=data.service_port,
                protocol=data.protocol,
                application=None if data.application == 'not-applicable' else data.application,
                tag=data.tag,
                group_tag=data.group_tag,
                duration_hours=data.duration_hours,
                status='Pending',
                request_time=datetime.now()
            )
            db_sql.session.add(req)

            # Log Activity
            db_sql.session.add(AuditLog(
                user=user,
                action="REQUEST_RULE",
                resource_type="rule",
                resource_name=data.rule_name,
                details=f"Src: {data.source_ip} Dst: {data.destination_ip} Svc: {data.service_port}"
            ))

        return req

    @classmethod
    def approve_request(cls, request_id: int, admin_user: str):
        """Approves rule, creates Service Object if needed, pushes to FW."""
        req = RuleRequest.query.get(request_id)
        if not req or req.status != 'Pending':
            raise ValueError("Invalid request")

        fw = FwService.get_connection()
        
        # Ensure Service Port Object exists
        svc_str = str(req.service_port or 'application-default').strip()
        svc_name = svc_str # Default

        if svc_str not in ['any', 'application-default'] and re.match(r'^\d', svc_str):
            # It's a number, so we need an object
            svc_name = f"service-{req.protocol}-{svc_str}"
            try:
                p_svc = PanService(svc_name, protocol=req.protocol, destination_port=svc_str)
                fw.add(p_svc)
                p_svc.create() 
            except Exception:
                pass 

        # Clean Name
        clean_name = re.sub(r'[^a-zA-Z0-9_\-]', '', req.rule_name.replace(' ', '_'))
        final_name = (clean_name if clean_name and clean_name[0].isalpha() else f"R_{clean_name}")[:63]

        app_val = req.application or 'any'
        if not app_val: app_val = 'any'

        print(f"DEBUG FW CREATE: Rule={final_name}, Svc={svc_name}, App={app_val}")

        # FW Rule
        rb = Rulebase()
        fw.add(rb)
        
        # PREVENT MERGE CONFLICTS:
        # Strategy: Create a temporary object with the same name, attach to device, and delete.
        # This forces a delete API call for this object's XPATH without needing to 'find' it first.
        try:
            temp_rule_for_deletion = CustomSecurityRule(name=final_name)
            rb.add(temp_rule_for_deletion)
            temp_rule_for_deletion.delete()
            # Remove from local tree so it doesn't conflict with the new one we are about to add
            rb.remove(temp_rule_for_deletion)
        except Exception as e:
            # If it doesn't exist, this might throw an error (depending on SDK/FW version), or just work.
            # We log but continue.
            print(f"DEBUG FW DELETE INFO: {str(e)}")
            # Ensure it's removed from local tree in case delete failed but add succeeded
            if temp_rule_for_deletion in rb.children:
                rb.remove(temp_rule_for_deletion)

        # Now create the real new rule
        fw_rule = CustomSecurityRule(
            name=final_name,
            fromzone=[req.from_zone], tozone=[req.to_zone],
            source=[req.source_ip], destination=[req.destination_ip],
            application=[app_val], service=[svc_name],
            action='allow',
            tag=[req.tag] if req.tag and req.tag != "None" else [],
            group_tag=req.group_tag
        )
        rb.add(fw_rule)
        fw_rule.create()

        # Update DB
        with cls.transaction():
            # Inventory Sync
            if not SecurityRule.query.filter_by(name=final_name).first():
                db_sql.session.add(SecurityRule(
                    name=final_name, from_zone=req.from_zone, to_zone=req.to_zone, 
                    action='allow', tag_name=req.tag
                ))
            
            req.status = 'Approved'
            req.final_rule_name = final_name
            req.processed_by = admin_user
            
            db_sql.session.add(AuditLog(
                user=admin_user, action="APPROVE_RULE", 
                resource_type="Security Rule", resource_name=final_name,
                details=f"Src: {req.source_ip} Dst: {req.destination_ip}"
            ))

    @classmethod
    def reject_request(cls, request_id: int, admin_user: str, reason: str):
        with cls.transaction():
            req = RuleRequest.query.get(request_id)
            if not req: raise ValueError("Not found")
            req.status = 'Rejected'
            req.admin_notes = reason
            req.processed_by = admin_user
            
            db_sql.session.add(AuditLog(
                user=admin_user, action="REJECT_RULE", 
                resource_type="Rule Request", resource_name=req.rule_name,
                details=f"Reason: {reason}"
            ))

    @classmethod
    def update_request(cls, request_id: int, data: RuleCreateRequest, user: str):
        with cls.transaction():
            req = RuleRequest.query.get(request_id)
            if not req: raise ValueError("Request not found")
            if req.status != 'Pending': raise ValueError("Cannot update processed request")
            
            # Update fields
            req.rule_name = data.rule_name
            req.from_zone = data.from_zone
            req.to_zone = data.to_zone
            req.source_ip = data.source_ip
            req.destination_ip = data.destination_ip
            req.service_port = data.service_port
            req.application = data.application
            
            db_sql.session.add(AuditLog(
                user=user, action="UPDATE_RULE_REQUEST", 
                resource_type="Rule Request", resource_name=req.rule_name,
                details=f"Updated by admin"
            ))
