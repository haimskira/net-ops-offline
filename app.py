"""
Expert Full-Stack Software Architecture: Main Entry Point.
Implements Flask app with background workers for Syslog and Firewall Sync.
Fixes: Missing service-group/apps in sync payload & Application Context.
"""

import os
import threading
import socket
import logging
import time
from datetime import datetime
from typing import List

from flask import Flask, redirect, url_for, session, request
from sqlalchemy import event
from sqlalchemy.engine import Engine

# ייבוא מודולים פנימיים
from config import Config
from managers.models import db_sql, TrafficLog
from services.fw_service import FwService
from services.sync_service import SyncService

# Blueprints
from routes.auth_routes import auth_bp
from routes.main_routes import main_bp
from routes.rule_routes import rules_bp
from routes.object_routes import objects_bp
from routes.ops_routes import ops_bp
from routes.admin_routes import admin_bp
from routes.net_mgmt_routes import net_mgmt_bp

# הגדרות לוגים
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
werkzeug_log = logging.getLogger('werkzeug')
werkzeug_log.setLevel(logging.ERROR)

app = Flask(__name__)
app.config.from_object(Config)

# --------------------------------------------------------------------------
# 1. אופטימיזציה ל-SQLite
# --------------------------------------------------------------------------

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """מגדיר WAL Mode לשיפור ביצועי כתיבה במקביל."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
    except Exception as e:
        logger.warning(f"Could not set SQLite PRAGMAs: {e}")
    finally:
        cursor.close()

# --------------------------------------------------------------------------
# 2. תשתית מסד הנתונים
# --------------------------------------------------------------------------
def initialize_infrastructure():
    """מאתחל נתיבים, יוצר טבלאות וטוען קונפיגורציה ראשונית."""
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if db_uri.startswith('sqlite:///'):
        db_path = db_uri.replace('sqlite:///', '')
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    db_sql.init_app(app)

    with app.app_context():
        db_sql.create_all()
        try:
            # load_app_ids() # Moved away or deprecated
            # Config.validate_config()
            logger.info("✅ Database & Infrastructure Ready.")
        except Exception as e:
            logger.error(f"❌ Initialization Warning: {e}")

initialize_infrastructure()

app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(rules_bp)
app.register_blueprint(objects_bp)
app.register_blueprint(ops_bp)
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(net_mgmt_bp)

# --------------------------------------------------------------------------
# 3. מנגנון סנכרון אוטומטי (Background Sync) - מתוקן
# --------------------------------------------------------------------------
def auto_sync_worker(flask_app: Flask) -> None:
    """
    Thread לסנכרון מול ה-Firewall API.
    מתוקן: שולח את כל האובייקטים הנדרשים כדי למנוע הופעת ANY בחוקים.
    """
    from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup
    from panos.policies import SecurityRule, Rulebase

    logger.info("🚀 Background Sync Worker initialized.")

    while True:
        with flask_app.app_context():
            try:
                start_time = datetime.now()
                fw = FwService.get_connection()
                rb = Rulebase()
                fw.add(rb)

                # שליפת נתונים גולמיים
                addr_objs = AddressObject.refreshall(fw)
                addr_groups = AddressGroup.refreshall(fw)
                svc_objs = ServiceObject.refreshall(fw)
                svc_groups = ServiceGroup.refreshall(fw)
                rules_objs = SecurityRule.refreshall(rb)

                # חילוץ אפליקציות מהחוקים (מכיוון שאין App.refreshall פשוט)
                found_apps = set()
                for r in rules_objs:
                    apps = r.application
                    if isinstance(apps, list): found_apps.update(apps)
                    elif apps: found_apps.add(apps)
                
                apps_payload = [{"name": app, "description": "System", "is_group": False} 
                               for app in found_apps if app and app.lower() != 'any']

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
                    duration = (datetime.now() - start_time).total_seconds()
                    logger.info(f"✅ Auto-Sync success ({duration:.2f}s). Rules: {len(rules_objs)}")
                else:
                    logger.warning("⏳ Sync skipped (Lock active).")

            except Exception as e:
                logger.error(f"❌ Sync Worker Error: {str(e)}")

        time.sleep(300)

# --------------------------------------------------------------------------
# 4. ניהול לוגים (Syslog & Retention)
# --------------------------------------------------------------------------
def syslog_listener(flask_app: Flask) -> None:
    """מאזין ללוגים ב-UDP ומבצע Batch Insert."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', Config.SYSLOG_PORT))
        logger.info(f"📡 Syslog Listener active on port {Config.SYSLOG_PORT}")
    except Exception as e:
        logger.error(f"❌ Syslog Bind Error: {e}")
        return

    log_batch: List[TrafficLog] = []
    last_flush = time.time()

    while True:
        try:
            sock.settimeout(2.0)
            try:
                data, addr = sock.recvfrom(4096)
                msg = data.decode('utf-8', errors='ignore')
                # logger.info(f"DEBUG SYSLOG: Received from {addr}: {msg[:50]}...") # Verbose
                
                if 'TRAFFIC' in msg:
                    parts = msg.split(',')
                    if len(parts) > 30:
                        new_entry = TrafficLog(
                            time=datetime.now().strftime("%H:%M:%S"),
                            source=parts[7], destination=parts[8],
                            app=parts[14], dst_port=parts[25],
                            src_zone=parts[16], dst_zone=parts[17],
                            protocol=parts[29], action=parts[30]
                        )
                        log_batch.append(new_entry)
                        # logger.info(f"DEBUG SYSLOG: Parsed Log {new_entry.source} -> {new_entry.destination}")
                    else:
                         logger.warning(f"DEBUG SYSLOG: Message too short ({len(parts)} parts): {msg[:100]}")
                else:
                    logger.debug("DEBUG SYSLOG: Non-TRAFFIC message ignored.")
            except socket.timeout: pass

            if len(log_batch) >= 50 or (time.time() - last_flush > 10 and log_batch):
                with flask_app.app_context():
                    db_sql.session.bulk_save_objects(log_batch)
                    db_sql.session.commit()
                log_batch = []
                last_flush = time.time()
        except Exception as e:
            logger.error(f"❌ Syslog Error: {e}")

# --------------------------------------------------------------------------
# 5. הגנת גישה והרצה
# --------------------------------------------------------------------------
@app.before_request
def require_login():
    # logger.info(f"Checking access for endpoint: {request.endpoint}")
    allowed = ['auth.login', 'static', 'ops.debug_sync_route']
    if 'user' not in session and request.endpoint not in allowed:
        return redirect(url_for('auth.login'))


# --------------------------------------------------------------------------
# 6. תחזוקת מסד נתונים (Maintenance Worker)
# --------------------------------------------------------------------------
def maintenance_worker(flask_app: Flask) -> None:
    """
    Thread לתחזוקה תקופתית:
    1. בדיקת גודל קובץ לוגים (Traffic Logs).
    2. מחיקת רשומות ישנות אם חורג מהגודל המוגדר.
    3. ביצוע VACUUM לשחרור מקום בדיסק.
    """
    from sqlalchemy import text
    
    logger.info("🛠️ Maintenance Worker initialized.")
    
    # בדיקה ראשונה אחרי 10 שניות (כדי לא להעמיס בעלייה), אח"כ כל 10 דקות
    time.sleep(10)
    
    while True:
        try:            
            log_db_path = Config.DATA_DIR / 'traffic_logs.db'
            
            if log_db_path.exists():
                size_mb = log_db_path.stat().st_size / (1024 * 1024)
                limit_mb = getattr(Config, 'LOGS_DB_MAX_MB', 100) # Default 100MB
                
                if size_mb > limit_mb:
                    logger.warning(f"⚠️ Traffic DB size ({size_mb:.2f}MB) exceeds limit ({limit_mb}MB). Starting cleanup...")
                    
                    with flask_app.app_context():
                        # 1. מחיקת רשומות ישנות - השארת 100,000 אחרונים
                        # שליפת ה-ID המקסימלי
                        max_id_res = db_sql.session.execute(text("SELECT MAX(id) FROM traffic_logs"), bind_arguments={'bind': db_sql.get_engine(bind='logs')}).scalar()
                        
                        if max_id_res:
                            cutoff_id = max_id_res - 100000
                            if cutoff_id > 0:
                                logger.info(f"🧹 Deleting logs with ID < {cutoff_id}...")
                                # שימוש ב-bind ספציפי ללוגים
                                db_sql.session.execute(
                                    text(f"DELETE FROM traffic_logs WHERE id < {cutoff_id}"),
                                    bind_arguments={'bind': db_sql.get_engine(bind='logs')}
                                )
                                db_sql.session.commit()
                                logger.info("✅ Cleanup complete.")
                                
                                # 2. ביצוע VACUUM להקטנת הקובץ פיזית
                                logger.info("🧽 Running VACUUM on traffic_logs (this may take a while)...")
                                try:
                                    # VACUUM לא יכול לרוץ בתוך טרנזקציה פתוחה בדרך כלל, תלוי דרייבר
                                    # ב-SQLAlchemy עם bind=logs
                                    engine = db_sql.get_engine(bind='logs')
                                    with engine.connect() as conn:
                                        conn.execute(text("VACUUM"))
                                    logger.info("✨ VACUUM complete. Disk space reclaimed.")
                                except Exception as v_err:
                                    logger.error(f"❌ VACUUM Failed: {v_err}")
                            else:
                                logger.info("ℹ️ Not enough logs to purge yet.")
                        else:
                            logger.info("ℹ️ Traffic log table appears empty.")

            else:
                logger.debug("Maintenance: Traffic DB file not found yet.")

        except Exception as e:
            logger.error(f"❌ Maintenance Worker Error: {e}")
        
        # הרצה כל 10 דקות
        time.sleep(600)

if __name__ == '__main__':
    threads = [
        threading.Thread(target=syslog_listener, args=(app,), name="SyslogThread", daemon=True),
        threading.Thread(target=auto_sync_worker, args=(app,), name="SyncThread", daemon=True),
        threading.Thread(target=maintenance_worker, args=(app,), name="MaintThread", daemon=True)
    ]
    for t in threads: t.start()
    app.run(debug=True, host='0.0.0.0', port=5100, use_reloader=False)