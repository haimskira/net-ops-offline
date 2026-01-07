import logging
import threading
import time
from typing import Dict, List, Any
from datetime import datetime

from managers.models import (
    db_sql, AddressObject, ServiceObject, ApplicationObject, SecurityRule,
    NetworkInterface, address_group_members, service_group_members,
    rule_source_map, rule_dest_map, rule_service_map, rule_app_map
)
from panos.firewall import Firewall

class SyncService:
    """
    Service for Stateless Synchronization between PAN-OS and SQLite.
    Migrated from SyncManager.
    """
    _sync_lock = threading.Lock()
    _last_sync_time: float = 0
    
    def __init__(self, fw_connection: Firewall):
        self.fw = fw_connection

    def sync_all(self, fw_config: Dict[str, List[Dict[str, Any]]]) -> bool:
        if not self._sync_lock.acquire(blocking=False):
            logging.warning("Sync in progress...")
            return False
            
        try:
            logging.info("Starting Sync...")
            db_sql.session.expunge_all()
            
            with db_sql.session.no_autoflush:
                self._clear_database()
                
                # Create Base Objects
                addr_map = self.sync_address_objects(fw_config.get('address', []), fw_config.get('address-group', []))
                svc_map = self.sync_service_objects(fw_config.get('service', []), fw_config.get('service-group', []))
                app_map = self.sync_application_objects(fw_config.get('applications', []) or fw_config.get('application', []))
                
                db_sql.session.flush()

                # Link Groups
                self.link_address_groups(fw_config.get('address-group', []), addr_map)
                self.link_service_groups(fw_config.get('service-group', []), svc_map)
                db_sql.session.flush()

                # Sync Rules
                self.sync_security_rules(fw_config.get('rules', []), addr_map, svc_map, app_map)

                # Topology
                self.sync_network_topology()

            db_sql.session.commit()
            self._last_sync_time = time.time()
            return True
        except Exception as e:
            db_sql.session.rollback()
            logging.error(f"Sync Failed: {str(e)}")
            return False
        finally:
            self._sync_lock.release()

    def _clear_database(self):
        db_sql.session.execute(address_group_members.delete())
        db_sql.session.execute(service_group_members.delete())
        db_sql.session.execute(rule_source_map.delete())
        db_sql.session.execute(rule_dest_map.delete())
        db_sql.session.execute(rule_service_map.delete())
        db_sql.session.execute(rule_app_map.delete())
        db_sql.session.query(SecurityRule).delete()
        db_sql.session.query(AddressObject).delete()
        db_sql.session.query(ServiceObject).delete()
        db_sql.session.query(ApplicationObject).delete()
        db_sql.session.flush()

    def sync_address_objects(self, addr_list, group_list):
        name_to_id = {}
        # Objects
        for item in addr_list:
            name = item.get('name')
            if not name or name.lower() in name_to_id: continue
            # Correctly extract value, prioritizing 'value' key
            val = item.get('value')
            if not val:
                val = (item.get('ip-netmask') or item.get('ip_netmask') or item.get('fqdn') or 'any')
            
            if isinstance(val, list): val = val[0]
            obj = AddressObject(name=name, type='host', value=str(val), is_group=False)
            db_sql.session.add(obj)
            name_to_id[name.lower()] = obj

        # Groups
        for g in group_list:
            name = g.get('name')
            if not name or name.lower() in name_to_id: continue
            obj = AddressObject(name=name, is_group=True, type='group', value='group')
            db_sql.session.add(obj)
            name_to_id[name.lower()] = obj
            
        db_sql.session.flush()
        return {name: obj.id for name, obj in name_to_id.items()}

    def link_address_groups(self, group_list, addr_map):
        links = []
        logging.info(f"Linking {len(group_list)} Address Groups...")
        for g in group_list:
            g_name = g.get('name', '')
            pid = addr_map.get(g_name.lower())
            
            # Support both 'static' (API) and 'static_value' (some SDK versions)
            members = g.get('static') or g.get('static_value') or []
            
            if not pid:
                logging.warning(f"Group '{g_name}' not found in addr_map (Keys: {list(addr_map.keys())[:5]}...)")
                continue
                
            if isinstance(members, str): members = [members]
            
            if members:
                 # logging.info(f"Group '{g_name}' has {len(members)} members. Processing...")
                 pass
            
            for m in members:
                mid = addr_map.get(m.lower())
                if mid: 
                    links.append({'parent_id': pid, 'member_id': mid})
                else:
                    # logging.warning(f"  -> Member '{m}' not found in addr_map for Group '{g_name}'")
                    pass

        if links: 
            # logging.info(f"Inserting {len(links)} group associations into DB.")
            db_sql.session.execute(address_group_members.insert(), links)
        else:
            logging.warning("No associations created during link_address_groups!")

    def sync_service_objects(self, svc_list, group_list):
        name_to_id = {}
        for item in svc_list:
            name = item.get('name')
            if not name or name.lower() in name_to_id: continue
            port = item.get('destination-port') or 'any'
            obj = ServiceObject(name=name, protocol=item.get('protocol', 'tcp'), port=str(port), is_group=False)
            db_sql.session.add(obj)
            name_to_id[name.lower()] = obj
        
        for g in group_list:
            name = g.get('name')
            if not name or name.lower() in name_to_id: continue
            obj = ServiceObject(name=name, is_group=True, port='group', protocol='mixed')
            db_sql.session.add(obj)
            name_to_id[name.lower()] = obj
        
        db_sql.session.flush()
        return {name: obj.id for name, obj in name_to_id.items()}

    def link_service_groups(self, group_list, svc_map):
        links = []
        for g in group_list:
            g_name = g.get('name', '')
            pid = svc_map.get(g_name.lower())
            
            # Support multiple key variations for members
            members = g.get('members') or g.get('static') or []
            if isinstance(members, str): members = [members]
            
            if not members:
                 # logging.debug(f"Service Group '{g_name}' has no members to link.")
                 pass

            count = 0
            for m in members:
                mid = svc_map.get(m.lower())
                if pid and mid: 
                    links.append({'parent_id': pid, 'member_id': mid})
                    count += 1
            
            if count > 0:
                pass
                # logging.info(f"Linked {count} members for Service Group '{g_name}'")

        if links: 
            db_sql.session.execute(service_group_members.insert(), links)
            logging.info(f"Inserted {len(links)} Service Group associations.")

    def sync_application_objects(self, app_list):
        name_to_id = {}
        for item in app_list:
            name = item.get('name')
            if not name or name.lower() in name_to_id: continue
            obj = ApplicationObject(name=name, is_group=item.get('is_group', False), value=item.get('description', name))
            db_sql.session.add(obj)
            db_sql.session.flush()
            name_to_id[name.lower()] = obj.id
        return name_to_id

    def sync_security_rules(self, rules_list, addr_map, svc_map, app_map):
        processed = set()
        for r in rules_list:
            name = r.get('name')
            if not name or name.lower() in processed: continue
            processed.add(name.lower())
            
            f_raw = r.get('fromzone') or ['any']
            t_raw = r.get('tozone') or ['any']
            
            rule = SecurityRule(
                name=name, 
                from_zone=str(f_raw[0]) if f_raw else 'any', 
                to_zone=str(t_raw[0]) if t_raw else 'any',
                action=r.get('action', 'allow')
            )
            db_sql.session.add(rule)
            db_sql.session.flush()
            
            self._bulk_link(rule.id, r.get('source', []), addr_map, rule_source_map, 'address_id')
            self._bulk_link(rule.id, r.get('destination', []), addr_map, rule_dest_map, 'address_id')
            self._bulk_link(rule.id, r.get('service', []), svc_map, rule_service_map, 'service_id')
            self._bulk_link(rule.id, r.get('application', []), app_map, rule_app_map, 'app_id')

    def _bulk_link(self, rid, names, obj_map, table, col):
        if not names: return
        if isinstance(names, str): names = [names]
        links = []
        for n in set(names):
            oid = obj_map.get(n.lower())
            if oid: links.append({'rule_id': rid, col: oid})
        if links: db_sql.session.execute(table.insert(), links)

    def sync_network_topology(self):
        try:
            db_sql.session.query(NetworkInterface).delete()
            intf_res = self.fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet")
            intf_root = ET.fromstring(intf_res) if isinstance(intf_res, (str, bytes)) else intf_res
            
            iface_map = {}
            for entry in intf_root.findall(".//entry"):
                ip_entry = entry.find(".//layer3/units/entry/ip/entry")
                if ip_entry is not None: iface_map[entry.get('name')] = ip_entry.get('name')

            zone_res = self.fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/network/zone")
            zone_root = ET.fromstring(zone_res) if isinstance(zone_res, (str, bytes)) else zone_res

            for zone in zone_root.findall(".//entry"):
                z_name = zone.get('name')
                for member in zone.findall(".//network/layer3/member"):
                    if member.text in iface_map:
                        db_sql.session.add(NetworkInterface(name=member.text, subnet=iface_map[member.text], zone_name=z_name))
        except Exception:
            pass
