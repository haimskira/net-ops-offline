"""
Expert Full-Stack Software Architecture: Operations & Monitoring Routes.
Handles Deep Object Resolution for Hover Tooltips and Smart Search.
Zero Truncation Policy: Full Functional File.
"""

# 1. Standard Library Imports
import logging
import time
import traceback
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

# 2. Third-Party Library Imports
import requests
from flask import Blueprint, Response, jsonify, render_template, request, session
from sqlalchemy.orm import joinedload, selectinload  # הוספת selectinload לטעינת חברי קבוצה

# 3. Pan-OS / Firewall SDK Imports (Aliases to prevent SQLAlchemy conflicts)
from panos.network import Zone
from panos.objects import (
    AddressGroup as PanAddressGroup, 
    AddressObject as PanAddressObject, 
    ServiceObject as PanServiceObject, 
    ServiceGroup as PanServiceGroup,  # הוספת הייבוא החסר
    Tag as PanTag,
    ApplicationObject as PanApplicationObject
)
from managers.models import Zone, Tag
from panos.policies import SecurityRule as PanSecurityRule, Rulebase

# 4. Local Application Imports (Project Specific)
from config import Config
from managers.data_manager import db # Keep if used for caching
from services.fw_service import FwService
from services.sync_service import SyncService
from managers.models import (
    AddressObject, 
    AuditLog, 
    SecurityRule, 
    ServiceObject, 
    ApplicationObject,
    TrafficLog, 
    db_sql,
    rule_app_map,
    RuleRequest,
    ObjectRequest
)
# Sync service imported above

# Initialize the Ops Blueprint
ops_bp = Blueprint('ops', __name__)

def get_username():
    return session.get('user', 'Unknown')

# --------------------------------------------------------------------------
# I. Helper Functions (Deep Resolution Logic)
# --------------------------------------------------------------------------

def resolve_object_content(obj: Any, depth: int = 0) -> List[str]:
    """
    פונקציה רקורסיבית ששולפת את התוכן הטכני (IP/Port/App).
    מעודכנת לפתרון בעיית ה-ANY בקבוצות ע"י שליפה רקורסיבית של חברים.
    """
    if not obj or depth > 5: 
        return []
        
    if not getattr(obj, 'is_group', False):
        val = getattr(obj, 'value', '') or getattr(obj, 'port', '')
        # logging.info(f"RESOLVER-DEBUG: Leaf '{obj.name}' Val: {val}")
        if val and str(val).lower() not in ['any', 'group', 'application-default']:
            return [str(val)]
        return []
    
    res = []
    members = getattr(obj, 'members', [])
    # logging.info(f"RESOLVER-DEBUG: Group '{obj.name}' Depth: {depth} Members: {len(members)}")
    for m in members:
        res.extend(resolve_object_content(m, depth + 1))
        
    return list(set(res))

# --------------------------------------------------------------------------
# II. View Routes (Template Rendering)
# --------------------------------------------------------------------------

@ops_bp.route('/log-viewer')
def log_viewer_page() -> str:
    """Renders the Live Traffic Log Viewer."""
    return render_template('log_viewer.html')

@ops_bp.route('/audit-logs')
def audit_logs_page() -> Union[str, Response]:
    """רק אדמין יכול לראות לוגי מערכת."""
    if not session.get('is_admin'):
        return render_template('error.html', message="Access to audit logs is reserved for administrators only"), 403
    try:
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
        return render_template('audit.html', logs=logs)
    except Exception as e:
        logging.error(f"Audit Log Fetch Error: {str(e)}")
        return render_template('audit.html', logs=[])

@ops_bp.route('/policy-inventory')
def policy_inventory_page() -> str:
    """Renders the Firewall Policy Inventory dashboard (Open to all authenticated users)."""
    return render_template('policy_viewer.html')

# --------------------------------------------------------------------------
# III. API Routes - Logging (Database Driven)
# --------------------------------------------------------------------------

@ops_bp.route('/get-live-logs')
def get_live_logs() -> Response:
    """Fetches traffic logs from the dedicated logs database bind."""
    try:
        logs = TrafficLog.query.order_by(TrafficLog.id.desc()).limit(100).all()
        formatted = []
        for log in logs:
            formatted.append({
                "time": log.time,
                "source": log.source,
                "destination": log.destination,
                "src_zone": log.src_zone or 'N/A',
                "dst_zone": log.dst_zone or 'N/A',
                "app": log.app or 'any',
                "protocol": log.protocol or 'tcp',
                "dst_port": str(log.dst_port or 'any'),
                "action": log.action or 'allow'
            })
        return jsonify(formatted)
    except Exception as e:
        logging.error(f"API Log Fetch Error: {str(e)}")
        return jsonify([])

@ops_bp.route('/api/clear-logs', methods=['POST'])
def clear_logs() -> Response:
    """Clears the traffic logs table in the database (Admin only)."""
    if not session.get('is_admin'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    try:
        db_sql.session.query(TrafficLog).delete()
        db_sql.session.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------------------------
# IV. API Routes - Inventory & Advanced Resolution
# --------------------------------------------------------------------------

@ops_bp.route('/get-all-policies')
def get_all_policies() -> Response:
    """
    שליפת חוקים עם טעינה עמוקה של חברי קבוצות למניעת באג ה-ANY.
    משתמש ב-selectinload כדי למשוך את ה-members של ה-ServiceObject וה-AddressObject.
    """
    try:
        # Temporarily removing eager loading to debug empty members issue
        # rules = SecurityRule.query.options(
        #     joinedload(SecurityRule.sources).selectinload(AddressObject.members),
        #     joinedload(SecurityRule.destinations).selectinload(AddressObject.members),
        #     joinedload(SecurityRule.services).selectinload(ServiceObject.members),
        #     joinedload(SecurityRule.applications)
        # ).all()
        
        # Lazy loading fallback
        logging.info("Fetching all policies (Lazy Loading v5 - Session Remove)...")
        db_sql.session.remove() # Completely remove session to ensure fresh connection from pool
        rules = SecurityRule.query.all()
        logging.info(f"Fetched {len(rules)} rules.")
        
        formatted_rules = []
        for r in rules:
            def format_collection(obj_list):
                if not obj_list: return []
                output = []
                seen = set()

                def add_obj(obj_to_add):
                    if obj_to_add.name in seen: return
                    seen.add(obj_to_add.name)
                    
                    # Resolve members for tooltip content (value)
                    tech_vals = resolve_object_content(obj_to_add)
                    
                    # Return clean list of values (e.g. IPs)
                    if tech_vals:
                         val_str = "\n".join(tech_vals)
                    else:
                         val_str = obj_to_add.name
                    
                    output.append({
                        "name": obj_to_add.name,
                        "value": val_str,
                        "is_group": getattr(obj_to_add, 'is_group', False)
                    })

                # Fix: Do NOT expand groups in the table itself. 
                # Just add the group object. 'resolve_object_content' inside 'add_obj' 
                # will handle fetching the members for the tooltip.
                for o in obj_list:
                    add_obj(o)
                    
                return output

            formatted_rules.append({
                "name": r.name,
                "from": r.from_zone or 'any',
                "to": r.to_zone or 'any',
                "sources": format_collection(r.sources),
                "destinations": format_collection(r.destinations),
                "services": format_collection(r.services),
                "applications": format_collection(r.applications),
                "action": r.action or 'allow'
            })
        
        response = jsonify(formatted_rules)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return response
    except Exception as e:
        logging.error(f"Inventory Fetch Error: {str(e)}")
        return jsonify([]), 500
    

@ops_bp.route('/get-params', methods=['GET'])
def get_params() -> Response:
    """Fetches metadata (Zones, Apps, Tags) from Local DB (Zero Dependency)."""
    try:
        from managers.models import AddressObject, ServiceObject, ApplicationObject, Zone
        from sqlalchemy import or_

        # 1. Fetch Zones
        zones = [z.name for z in Zone.query.order_by(Zone.name).all()]
        if 'any' not in zones: zones.insert(0, 'any')

        # 2. Fetch Services
        # Services (excluding groups first)
        services = [s.name for s in ServiceObject.query.filter_by(is_group=False).order_by(ServiceObject.name).all()]
        # Service Groups
        svc_groups = [g.name for g in ServiceObject.query.filter_by(is_group=True).order_by(ServiceObject.name).all()]
        
        full_svc_list = sorted(services + svc_groups)
        if 'application-default' not in full_svc_list: full_svc_list.insert(0, 'application-default')
        if 'any' not in full_svc_list: full_svc_list.insert(0, 'any')

        # 3. Fetch Addresses
        addr_objs = AddressObject.query.filter_by(is_group=False).all()
        addr_groups = AddressObject.query.filter_by(is_group=True).all()
        
        address_map = {a.name: a.value for a in addr_objs}
        full_addr_list = sorted([a.name for a in addr_objs] + [g.name for g in addr_groups])
        
        # 4. Fetch Applications (The Fix!)
        # Fetching everything. Frontend slicing limits display, but data must be there.
        # DB now contains all custom + predefined apps.
        apps = [a.name for a in ApplicationObject.query.order_by(ApplicationObject.name).all()]
        if 'any' not in apps: apps.insert(0, 'any')
        
        # 5. Tags (Synced from DB)
        tags = sorted([t.name for t in Tag.query.order_by(Tag.name).all()])
        if not tags: tags = [] 

        response_data = {
            "status": "success", 
            "zones": zones, 
            "services": full_svc_list, 
            "addresses": full_addr_list,
            "address_map": address_map,
            "address_groups": sorted([g.name for g in addr_groups]),
            "applications": apps, 
            "tags": tags
        }
        
        return jsonify(response_data)
    except Exception as e:
        logging.error(f"Get Params DB Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------------------------
# V. API Routes - Commit & Job Control
# --------------------------------------------------------------------------

@ops_bp.route('/commit', methods=['POST'])
def commit_changes() -> Response:
    """Triggers a configuration commit on the firewall."""
    logging.info("COMMIT: Received commit request.")
    if not session.get('is_admin'):
        logging.warning("COMMIT: Unauthorized attempt.")
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    try:
        logging.info("COMMIT: Connecting to Firewall...")
        fw = FwService.get_connection()
        logging.info("COMMIT: Connection OK. Sending commit...")
        job_id = fw.commit(sync=False)
        
        if job_id is None:
            logging.info("COMMIT: No changes to commit (Job ID is None).")
            return jsonify({"status": "success", "message": "There is nothing to commit."})

        logging.info(f"COMMIT: Success! Job ID: {job_id}")
        return jsonify({"status": "success", "message": f"Commit sent! (Job ID {job_id})."})
    except Exception as e:
        err_msg = str(e)
        logging.error(f"COMMIT: Error - {err_msg}")
        if "705" in err_msg or "704" in err_msg:
            return jsonify({"status": "success", "message": "Commit is already running in background."})
        return jsonify({"status": "error", "message": f"Commit Failed: {err_msg}"}), 500

@ops_bp.route('/job-status/<int:job_id>')
def get_job_status(job_id: int) -> Response:
    """Monitors job progress via Firewall XML API."""
    try:
        url = f"https://{Config.FW_IP}/api/?type=op&cmd=<show><jobs><id>{job_id}</id></jobs></show>&key={Config.API_KEY}"
        r = requests.get(url, verify=False, timeout=10)
        root = ET.fromstring(r.text)
        job = root.find(".//job")
        if job is not None:
            return jsonify({
                "status": job.findtext("status"),
                "progress": job.findtext("progress"),
                "result": job.findtext("result")
            })
        return jsonify({"status": "not_found"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@ops_bp.route('/debug-sync')
def debug_sync_route():
    """Debug route to test DB linking logic directly."""
    try:
        from services.sync_service import SyncService
        mock_fw = None # Not needed for mock sync
        mgr = SyncService(mock_fw)
        
        # 1. Clear DB
        db_sql.session.expunge_all()
        mgr._clear_database()
        
        # 2. Insert Objects
        from config import Config
        Config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        
        addr_data = [{'name': 'Host-A', 'value': '1.1.1.1'}, {'name': 'Host-B', 'value': '2.2.2.2'}]
        group_data = [{'name': 'Group-Test', 'static': ['Host-A', 'Host-B']}]
        
        # 3. Running Sync Parts Manually
        print("DEBUG: Running Sync Address Objects...")
        addr_map = mgr.sync_address_objects(addr_data, group_data)
        print(f"DEBUG: Addr Map: {addr_map}")
        
        print("DEBUG: Linking Groups...")
        mgr.link_address_groups(group_data, addr_map)
        
        db_sql.session.commit()
        
        # 4. Verification
        g_obj = AddressObject.query.filter_by(name='Group-Test').first()
        members = [m.name for m in g_obj.members]
        return jsonify({
            "status": "success",
            "group": "Group-Test",
            "members_found": members,
            "expected": ['Host-A', 'Host-B'],
            "match": sorted(members) == sorted(['Host-A', 'Host-B'])
        })
    except Exception as e:
         return jsonify({"status": "error", "message": str(e), "trace": traceback.format_exc()})


# --------------------------------------------------------------------------
# VI. Utility Tools (Match, Zone Detect & Sync)
# --------------------------------------------------------------------------

@ops_bp.route('/run-policy-match', methods=['POST'])
def run_policy_match() -> Response:
    """
    Tests traffic against the firewall. 
    Dynamic XML: Omit <from>/<to> tags if zones are empty, mimicking CLI behavior.
    """
    data = request.json or {}
    try:
        source = data.get("source_ip", "").strip()
        destination = data.get("destination_ip", "").strip()
        from_zone = data.get("from_zone", "").strip()
        to_zone = data.get("to_zone", "").strip()
        port = data.get("port", "443").strip()
        protocol = data.get("protocol", "6").strip()

        # בניית XML דינמי - השמטת תגיות אם הערך ריק או 'any'
        zone_tags = ""
        if from_zone and from_zone.lower() != 'any':
            zone_tags += f"<from>{from_zone}</from>"
        if to_zone and to_zone.lower() != 'any':
            zone_tags += f"<to>{to_zone}</to>"

        cmd = (f"<test><security-policy-match>"
               f"{zone_tags}"
               f"<source>{source}</source><destination>{destination}</destination>"
               f"<protocol>{protocol}</protocol><destination-port>{port}</destination-port>"
               f"<application>any</application>"
               f"</security-policy-match></test>")
        
        # בניית ה-URL עם vsys1 להבטחת הקשר חיפוש נכון
        url = f"https://{Config.FW_IP}/api/?type=op&cmd={cmd}&key={Config.API_KEY}&vsys=vsys1"
        
        r = requests.get(url, verify=False, timeout=15)
        xml_root = ET.fromstring(r.text)
        
        if xml_root.get('status') == 'error':
            return jsonify({"status": "error", "message": xml_root.findtext(".//msg") or "FW Error"}), 400

        entry = xml_root.find(".//entry")
        if entry is not None:
            return jsonify({
                "status": "success", "match": True, 
                "rule_name": entry.get("name"), "action": entry.findtext("action") or "allow",
                "source": source, "destination": destination
            })
            
        return jsonify({"status": "success", "match": False, "source": source, "destination": destination})
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
@ops_bp.route('/api/detect-zone', methods=['GET'])
def detect_zone() -> Response:
    """Predicts firewall zone for an IP based on local interface subnet mapping."""
    user_input = request.args.get('ip')
    if not user_input:
        return jsonify({"status": "error", "message": "Missing input"}), 400
    try:
        from services.fw_service import FwService
        zone = FwService.detect_zone(user_input)
        return jsonify({"status": "success", "zone": zone}) if zone else jsonify({"status": "unknown"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@ops_bp.route('/api/sync/firewall', methods=['POST'])
def trigger_firewall_sync() -> Response:
    """סנכרון ידני של בסיס הנתונים מול הפיירוול (Admin only)."""
    if not session.get('is_admin'):
        return jsonify({"status": "error", "message": "Admin only"}), 403
    try:
        fw = FwService.get_connection()
        rb = Rulebase()
        fw.add(rb)
        
        # שליפת אובייקטים וקבוצות שירותים/כתובות לסנכרון מלא
        addr_objs = PanAddressObject.refreshall(fw)
        addr_groups = PanAddressGroup.refreshall(fw)
        svc_objs = PanServiceObject.refreshall(fw)
        svc_groups = PanServiceGroup.refreshall(fw)
        rules_objs = PanSecurityRule.refreshall(rb)
        
        found_apps = set()
        for r in rules_objs:
            apps = r.application
            if isinstance(apps, list): found_apps.update(apps)
            elif apps: found_apps.add(apps)
        
        apps_payload = [{"name": app, "value": "System", "is_group": False} for app in found_apps]

        fw_config = {
            'address': [obj.about() for obj in addr_objs],
            'address-group': [obj.about() for obj in addr_groups],
            'service': [obj.about() for obj in svc_objs],
            'service-group': [obj.about() for obj in svc_groups],
            'rules': [obj.about() for obj in rules_objs],
            'applications': apps_payload
        }

        sync_mgr = SyncService(fw)
        if sync_mgr.sync_all(fw_config):
            db_sql.session.add(AuditLog(user=get_username(), action="MANUAL_SYNC", resource_name="Inventory"))
            db_sql.session.commit()
            return jsonify({"status": "success", "message": "Sync completed successfully!"})
        return jsonify({"status": "error", "message": "Sync failed"}), 409
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --------------------------------------------------------------------------
# III. Dashboard Data Aggregation APIs
# --------------------------------------------------------------------------

@ops_bp.route('/api/dashboard/operational')
def dashboard_operational():
    """Returns Operational Health metrics: connection, sync time, db size."""
    try:
        # 1. Firewall Connection Status
        fw_status = FwService.check_connection()
        
        # 2. Last Sync Time (Mocked for now or fetched from a service state if available)
        last_sync = "Just now" 
        
        # 3. Database Health (Use Config.DATA_DIR directly)
        db_path = Config.DATA_DIR / 'netops.db'
        db_size_mb = 0
        if db_path.exists():
            db_size_mb = round(db_path.stat().st_size / (1024 * 1024), 2)
            
        return jsonify({
            "fw_connection": fw_status,
            "last_sync": last_sync,
            "db_size_mb": db_size_mb,
            "status": "Healthy" if fw_status and db_size_mb < 100 else "Warning"
        })
    except Exception as e:
        logging.error(f"Dashboard Ops Error: {e}")
        return jsonify({"error": str(e)}), 500

@ops_bp.route('/api/dashboard/work-queue')
def dashboard_work_queue():
    """Returns Pending Tasks counts. Filters by user if not admin."""
    from managers.models import RuleRequest, ObjectRequest
    try:
        user = session.get('user')
        is_admin = session.get('is_admin')

        rule_query = RuleRequest.query.filter_by(status='Pending')
        obj_query = ObjectRequest.query.filter_by(status='Pending')

        if not is_admin:
            rule_query = rule_query.filter_by(requested_by=user)
            obj_query = obj_query.filter_by(requested_by=user)

        pending_rules = rule_query.count()
        pending_objects = obj_query.count()
        
        from datetime import timedelta
        week_ahead = datetime.utcnow() + timedelta(days=7)
        expiring_count = SecurityRule.query.filter(
            SecurityRule.expire_at != None,
            SecurityRule.expire_at <= week_ahead
        ).count()
        
        return jsonify({
            "pending_rules": pending_rules,
            "pending_objects": pending_objects,
            "expiring_rules": expiring_count
        })
    except Exception as e:
        logging.error(f"Dashboard Queue Error: {e}")
        return jsonify({"error": str(e)}), 500

@ops_bp.route('/api/dashboard/traffic')
def dashboard_traffic():
    """Returns aggregated traffic stats for charts."""
    from sqlalchemy import func
    try:
        # 1. Top 5 Apps
        top_apps = db_sql.session.query(
            TrafficLog.app, func.count(TrafficLog.id).label('count')
        ).group_by(TrafficLog.app).order_by(func.count(TrafficLog.id).desc()).limit(5).all()
        
        # 2. Action Ratio (Allow vs Deny)
        actions = db_sql.session.query(
            TrafficLog.action, func.count(TrafficLog.id)
        ).group_by(TrafficLog.action).all()
        
        # 3. Top Talkers (Sources)
        top_sources = db_sql.session.query(
            TrafficLog.source, func.count(TrafficLog.id)
        ).group_by(TrafficLog.source).order_by(func.count(TrafficLog.id).desc()).limit(5).all()

        return jsonify({
            "top_apps": [{"name": r[0], "count": r[1]} for r in top_apps] if top_apps else [],
            "actions": {r[0]: r[1] for r in actions} if actions else {"allow": 0, "deny": 0},
            "top_sources": [{"ip": r[0], "count": r[1]} for r in top_sources] if top_sources else []
        })
    except Exception as e:
        logging.error(f"Dashboard Traffic Error: {e}")
        return jsonify({"error": str(e)}), 500

@ops_bp.route('/api/dashboard/security')
def dashboard_security():
    """Returns Security & Audit stats. Filters by user context."""
    from sqlalchemy import func
    try:
        user = session.get('user')
        is_admin = session.get('is_admin')

        # 1. Recent Actions Ticker
        # We aggregate AuditLogs + RuleRequests + ObjectRequests to ensure the list is populated
        
        # A. Audit Logs
        audit_query = AuditLog.query
        if not is_admin:
            audit_query = audit_query.filter_by(user=user)
        audits = audit_query.order_by(AuditLog.timestamp.desc()).limit(10).all()

        activity_list = []
        for a in audits:
            activity_list.append({
                "user": a.user,
                "action": a.action,
                "time_obj": a.timestamp,
                "time": a.timestamp.strftime('%Y-%m-%d %H:%M'),
                "details": (a.details[:50] + '...') if a.details else ''
            })

        # B. Rule Requests (Historical Fallback)
        rule_query = RuleRequest.query
        if not is_admin:
            rule_query = rule_query.filter_by(requested_by=user)
        rules = rule_query.order_by(RuleRequest.request_time.desc()).limit(5).all()
        
        for r in rules:
            activity_list.append({
                "user": r.requested_by,
                "action": "REQUEST_RULE (Legacy)",
                "time_obj": r.request_time,
                "time": r.request_time.strftime('%Y-%m-%d %H:%M'),
                "details": f"Rule: {r.rule_name} ({r.status})"
            })

        # C. Object Requests (Historical Fallback)
        obj_query = ObjectRequest.query
        if not is_admin:
            obj_query = obj_query.filter_by(requested_by=user)
        objs = obj_query.order_by(ObjectRequest.request_time.desc()).limit(5).all()

        for o in objs:
             activity_list.append({
                "user": o.requested_by,
                "action": "REQUEST_OBJECT (Legacy)",
                "time_obj": o.request_time,
                "time": o.request_time.strftime('%Y-%m-%d %H:%M'),
                "details": f"Obj: {o.name} ({o.status})"
            })

        # D. Sort and deduplicate (roughly, though IDs differ) - we just sort by time
        activity_list.sort(key=lambda x: x['time_obj'], reverse=True)
        recent_logs = activity_list[:10]
         
        # Ensure 'recent_logs' is compatible with frontend loop which expects dictionary properties
        # The frontend uses dot notation? dashboard.html: l.action. 
        # Wait, Python dictionaries are NOT objects in Jinja unless passed as such, 
        # BUT this is returning JSON to frontend JS. JS parses JSON to objects.
        # Frontend JS (dashboard.html): data.recent_actions.map(l => l.action ...)
        # So returning a list of dicts is PERFECT.
        
        # We need to remove 'time_obj' before sending JSON
        final_recent = []
        for item in recent_logs:
             item.pop('time_obj', None)
             final_recent.append(item)

        
        # 2. Top Admins (Activity Count)
        # Only visible to Admins
        top_admins = []
        if is_admin:
            top_admins = db_sql.session.query(
                AuditLog.user, func.count(AuditLog.id)
            ).group_by(AuditLog.user).order_by(func.count(AuditLog.id).desc()).limit(3).all()
        
        return jsonify({
            "recent_actions": final_recent,
            "top_admins": [{"user": r[0], "count": r[1]} for r in top_admins]
        })
    except Exception as e:
        logging.error(f"Dashboard Security Error: {e}")
        return jsonify({"error": str(e)}), 500

@ops_bp.route('/dashboard')
def dashboard_page():
    """Renders the main dashboard page."""
    return render_template('dashboard.html')