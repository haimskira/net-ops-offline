from datetime import datetime
from typing import List, Optional
from schemas.objects import AddressObjectCreate, ServiceObjectCreate
from managers.models import db_sql, ObjectRequest, AddressObject, ServiceObject, AuditLog
from services.base_service import BaseService
from services.fw_service import FwService
from panos.objects import (
    AddressObject as PanAddress, AddressGroup as PanAddressGroup,
    ServiceObject as PanService, ServiceGroup as PanServiceGroup
)

class ObjectService(BaseService):
    
    @classmethod
    def create_request(cls, data: list[AddressObjectCreate] | AddressObjectCreate | ServiceObjectCreate, user: str):
        """Creates a new object request."""
        # Check if data is list or single (API might send one)
        # We assume single for now based on schema
        with cls.transaction():
            req = ObjectRequest(
                name=data.name,
                obj_type=data.type,
                value=data.value,
                prefix=data.prefix if hasattr(data, 'prefix') else None,
                protocol=data.protocol if hasattr(data, 'protocol') else None,
                requested_by=user,
                status='Pending',
                request_time=datetime.now()
            )
            db_sql.session.add(req)
            
            # Log Activity
            db_sql.session.add(AuditLog(
                user=user,
                action="REQUEST_OBJECT",
                resource_type=data.type,
                resource_name=data.name,
                details=f"Value: {data.value}"
            ))
            
        return req

    @classmethod
    def approve_request(cls, request_id: int, admin_user: str):
        """Approves request, pushes to FW, and updates local Inventory."""
        req = ObjectRequest.query.get(request_id)
        if not req or req.status != 'Pending':
            raise ValueError("Invalid or processed request")

        fw = FwService.get_connection()
        
        try:
            # 1. Framework Object Creation
            if req.obj_type == 'address':
                val = f"{req.value}/{req.prefix}" if req.prefix else (req.value if '/' in req.value else f"{req.value}/32")
                fw_obj = PanAddress(req.name, value=val)
                db_obj = AddressObject(name=req.name, value=val, type='host', is_group=False)
            
            elif req.obj_type == 'address-group':
                members = [m.strip() for m in req.value.split(',')]
                fw_obj = PanAddressGroup(req.name, static_value=members)
                db_obj = AddressObject(name=req.name, type='group', is_group=True)
            
            elif req.obj_type == 'service':
                fw_obj = PanService(req.name, protocol=req.protocol, destination_port=req.value)
                db_obj = ServiceObject(name=req.name, protocol=req.protocol, port=req.value)
            
            elif req.obj_type == 'service-group':
                members = [m.strip() for m in req.value.split(',')]
                fw_obj = PanServiceGroup(req.name, value=members)
                db_obj = ServiceObject(name=req.name, is_group=True)
            
            else:
                raise ValueError("Unknown object type")

            # 2. Push to Fw with Find-Delete check
            # PREVENT MERGE/DUPLICATE ERRORS
            try:
                # Based on type, determine class for dummy object
                cls_map = {
                    'address': PanAddress,
                    'address-group': PanAddressGroup,
                    'service': PanService,
                    'service-group': PanServiceGroup
                }
                target_cls = cls_map.get(req.obj_type)
                
                # Robust Delete Strategy: Create dummy, attach, delete.
                # This explicitly sends delete command for the name, clearing conflict.
                if target_cls:
                    print(f"DEBUG OBJECT: Attempting cleanup of {req.name}")
                    dummy = target_cls(req.name)
                    fw.add(dummy)
                    try:
                        dummy.delete()
                    except Exception as e:
                        # Ignore "not found" errors, log others
                        print(f"DEBUG OBJECT: Signup cleanup result: {str(e)}")
                    # Remove from tree so it doesn't conflict with real add
                    if dummy in fw.children:
                        fw.remove(dummy)
                    else:
                        print("DEBUG OBJECT WARNING: Dummy object not in fw.children")

            except Exception as e:
                print(f"DEBUG OBJECT DELETE ERROR: {e}")

            print(f"DEBUG OBJECT: Creating {req.name} Type={req.obj_type} Val={req.value}")
            fw.add(fw_obj)
            fw_obj.create()
            print(f"DEBUG OBJECT: Success created {req.name}")



            # 3. Update Local DB (Transaction)
            with cls.transaction():
                # Avoid duplicates
                if isinstance(db_obj, AddressObject):
                    if not AddressObject.query.filter_by(name=req.name).first():
                        db_sql.session.add(db_obj)
                else:
                    if not ServiceObject.query.filter_by(name=req.name).first():
                        db_sql.session.add(db_obj)

                req.status = 'Approved'
                req.processed_by = admin_user
                
                # Audit
                db_sql.session.add(AuditLog(
                    user=admin_user, 
                    action="APPROVE_OBJECT", 
                    resource_type=f"Object: {req.obj_type}", 
                    resource_name=req.name, 
                    details=f"Value: {req.value}"
                ))

        except Exception as e:
            raise Exception(f"Failed to approve object: {str(e)}")

    @classmethod
    def reject_request(cls, request_id: int, admin_user: str, reason: str):
        with cls.transaction():
            req = ObjectRequest.query.get(request_id)
            if not req: raise ValueError("Request not found")
            
            req.status = 'Rejected'
            req.processed_by = admin_user
            req.admin_notes = reason
            
            db_sql.session.add(AuditLog(
                user=admin_user, action="REJECT_OBJECT", 
                resource_type=req.obj_type, resource_name=req.name, 
                details=f"Reason: {reason}"
            ))

    @classmethod
    def update_request(cls, request_id: int, data: dict, user: str):
        # Data is dict because it might be partial or mixed types, 
        # but better to validate using Schema if possible. 
        # For simplicity in this fix, we'll update directly but safeguard status.
        with cls.transaction():
            req = ObjectRequest.query.get(request_id)
            if not req: raise ValueError("Not found")
            if req.status != 'Pending': raise ValueError("Cannot edit processed object")
            
            req.name = data.get('name', req.name)
            req.value = data.get('value', req.value)
            # data.get returns None if missing, so checking explicit key presence might be safer 
            # but frontend sends all fields usually.
            
            # Simple updates
            if 'prefix' in data: req.prefix = data.get('prefix')
            if 'protocol' in data: req.protocol = data.get('protocol')
            
            db_sql.session.add(AuditLog(
                user=user, action="UPDATE_OBJECT_REQUEST", 
                resource_type="Object Request", resource_name=req.name,
                details="Admin update"
            ))
