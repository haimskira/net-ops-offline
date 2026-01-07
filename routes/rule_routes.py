from flask import Blueprint, request, jsonify, session
from schemas.rules import RuleCreateRequest
from services.rule_service import RuleService
from services.fw_service import FwService
from managers.models import RuleRequest

try:
    from pydantic import ValidationError
except ImportError:
    ValidationError = ValueError

rules_bp = Blueprint('rules', __name__)

def get_user():
    return session.get('user', 'Unknown')

@rules_bp.route('/create-rule', methods=['POST'])
def create_rule():
    try:
        # Validate
        validated = RuleCreateRequest(**request.json)
        # Execute
        RuleService.create_request(validated, get_user())
        return jsonify({"status": "success", "message": "Rule request submitted"})
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Validation Error: " + str(e)}), 422
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



@rules_bp.route('/update-pending-rule/<int:rule_id>', methods=['POST'])
def update_pending_rule(rule_id):
    if not session.get('is_admin'): return jsonify({"message": "Unauthorized"}), 403
    try:
        # Validate using same schema as create
        validated = RuleCreateRequest(**request.json)
        RuleService.update_request(rule_id, validated, get_user())
        return jsonify({"status": "success", "message": "Rule updated"})
    except ValidationError as e:
        return jsonify({"status": "error", "message": str(e)}), 422
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@rules_bp.route('/approve-single-rule/<int:rule_id>', methods=['POST'])
def approve_single_rule(rule_id):
    if not session.get('is_admin'): return jsonify({"message": "Unauthorized"}), 403
    try:
        print(f"DEBUG APPROVE: Approving Rule ID {rule_id}")
        RuleService.approve_request(rule_id, get_user())
        print(f"DEBUG APPROVE: Success Rule ID {rule_id}")
        return jsonify({"status": "success", "message": "Rule approved"})
    except Exception as e:
        print(f"DEBUG APPROVE: Error {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@rules_bp.route('/reject-single-rule/<int:rule_id>', methods=['POST'])
def reject_single_rule(rule_id):
    if not session.get('is_admin'): return jsonify({"message": "Unauthorized"}), 403
    try:
        reason = request.json.get('reason', 'Admin rejected')
        print(f"DEBUG REJECT: Rejecting Rule ID {rule_id} Reason: {reason}")
        RuleService.reject_request(rule_id, get_user(), reason)
        return jsonify({"status": "success", "message": "Rule rejected"})
    except Exception as e:
        print(f"DEBUG REJECT: Error {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@rules_bp.route('/check-shadow', methods=['POST'])
def check_shadow():
    try:
        # Using Service Logic directly
        data = request.json
        
        # 1. Primary Check: Real-time Firewall Policy Match (API)
        res = FwService.verify_policy_match(
            source=data.get('source_ip'),
            dest=data.get('destination_ip'),
            from_zone=data.get('from_zone', 'any'),
            to_zone=data.get('to_zone', 'any'),
            service_port=data.get('service_port', 'application-default'),
            application=data.get('application', 'any'),
            protocol=data.get('protocol', 'tcp')
        )
        
        if res.get('exists'):
            return jsonify({
                "status": "shadowed", 
                "message": f"Shadowed by rule: {res.get('rule')}",
                "rules": [res.get('rule')],
                "action": res.get('action')
            })
            
        # 2. Secondary Check: Local DB Logic (Dual Verification)
        # This catches cases like FQDNs where API might fail due to resolution issues
        local_res = FwService.check_shadow_rule(
            source=data.get('source_ip'),
            dest=data.get('destination_ip'),
            from_zone=data.get('from_zone', 'any'),
            to_zone=data.get('to_zone', 'any'),
            service_port=data.get('service_port', 'application-default'),
            application=data.get('application', 'any')
        )

        if local_res.get('exists'):
             return jsonify({
                "status": "shadowed", 
                "message": f"Shadowed by rule: {local_res.get('rule')}",
                "rules": [local_res.get('rule')],
                "action": local_res.get('action')
            })

        return jsonify({"status": "clear"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Read Routes ---
@rules_bp.route('/get-admin-view-rules')
def get_admin_view_rules():
    if not session.get('is_admin'): return jsonify({"message": "Unauthorized"}), 403
    reqs = RuleRequest.query.order_by(RuleRequest.request_time.desc()).all()
    # Manual serialization or use schema dump
    return jsonify([{
        "id": r.id, "rule_name": r.rule_name, "requested_by": r.requested_by,
        "source_ip": r.source_ip, "destination_ip": r.destination_ip,
        "service_port": r.service_port, "application": r.application or 'any',
        "status": r.status,
        "request_time": r.request_time.strftime("%Y-%m-%d %H:%M")
    } for r in reqs])

@rules_bp.route('/get-my-requests')
def get_my_requests():
    reqs = RuleRequest.query.filter_by(requested_by=get_user()).order_by(RuleRequest.request_time.desc()).all()
    return jsonify([{
        "id": r.id, 
        "rule_name": r.rule_name, 
        "status": r.status,
        "source": r.source_ip, 
        "destination": r.destination_ip,
        "service_port": r.service_port,
        "protocol": r.protocol or "tcp",
        "time": r.request_time.strftime("%Y-%m-%d %H:%M"),
        "admin_notes": r.admin_notes
    } for r in reqs])
