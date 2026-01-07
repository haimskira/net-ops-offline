from app import app
from services.fw_service import FwService
from services.sync_service import SyncService
from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, Rulebase
import logging
import time
from datetime import datetime

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def force_sync():
    with app.app_context():
        print("--- FORCE SYNC STARTED ---")
        try:
            start_time = datetime.now()
            fw = FwService.get_connection()
            rb = Rulebase()
            fw.add(rb)

            print("1. Fetching Raw Data from FW...")
            addr_objs = AddressObject.refreshall(fw)
            addr_groups = AddressGroup.refreshall(fw)
            svc_objs = ServiceObject.refreshall(fw)
            svc_groups = ServiceGroup.refreshall(fw)
            rules_objs = SecurityRule.refreshall(rb)
            
            print(f"   Fetched: {len(addr_objs)} Addr, {len(addr_groups)} Groups, {len(rules_objs)} Rules")

            # App Logic
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

            print("2. Running SyncService...")
            sync_mgr = SyncService(fw)
            
            if sync_mgr.sync_all(fw_config):
                duration = (datetime.now() - start_time).total_seconds()
                print(f"✅ Sync SUCCESS ({duration:.2f}s)")
            else:
                print("❌ Sync FAILED (Check logs)")

        except Exception as e:
            print(f"CRITICAL ERROR: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    # Ensure logs show up
    logging.getLogger().addHandler(logging.StreamHandler())
    force_sync()
