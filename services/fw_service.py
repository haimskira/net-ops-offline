import re
import logging
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from netaddr import IPNetwork, IPAddress, IPRange, IPSet, AddrFormatError
from sqlalchemy import func

from config import Config
from managers.models import db_sql, AddressObject, ServiceObject, SecurityRule as DBSecurityRule, NetworkInterface
from services.base_service import BaseService

class CustomSecurityRule(SecurityRule):
    """PAN-OS SecurityRule extended with group-tag support."""
    def __init__(self, *args, **kwargs):
        self._group_tag = kwargs.pop('group_tag', None)
        super(CustomSecurityRule, self).__init__(*args, **kwargs)

    def element_str(self) -> str:
        root = super(CustomSecurityRule, self).element_str()
        if isinstance(root, (bytes, str)):
            root = ET.fromstring(root)
        if self._group_tag:
            gt = ET.Element('group-tag')
            gt.text = self._group_tag
            root.append(gt)
        return ET.tostring(root)

class FwService(BaseService):
    """
    Service Layer for Firewall Operations.
    Handles connection, logic engines (Shadow, Zones), and execution.
    """

    @staticmethod
    def get_connection() -> Firewall:
        if not Config.FW_IP or not Config.API_KEY:
            raise ValueError("Firewall configuration missing (IP/Key)")
        return Firewall(Config.FW_IP, api_key=Config.API_KEY, verify=False, timeout=60)

    @staticmethod
    def check_connection() -> bool:
        """Verifies actual connectivity to the Firewall."""
        try:
            fw = FwService.get_connection()
            # Minimal lightweight call to verify auth and reachability
            fw.refresh_system_info() 
            return True
        except Exception:
            return False

    @staticmethod
    def sanitize_ip(val: str) -> str:
        # Don't strip characters aggressively, it turns "app-v1" into "1" which is wrong.
        # Just strip whitespace and let IPNetwork handle validation.
        if not val: return ""
        return val.strip()

    @classmethod
    def parse_ip_to_set(cls, ip_str: str) -> IPSet:
        ip_str = cls.sanitize_ip(ip_str.strip())
        try:
            if '-' in ip_str:
                s, e = ip_str.split('-')
                return IPSet(IPRange(IPAddress(s.strip()), IPAddress(e.strip())))
            if ip_str:
                return IPSet(IPNetwork(ip_str if '/' in ip_str else f"{ip_str}/32"))
        except (AddrFormatError, ValueError):
            pass
        return IPSet()

    @classmethod
    def flatten_address(cls, obj_name: str, depth: int = 0) -> IPSet:
        """Recursively resolves objects to IPSet."""
        if depth > 10 or not obj_name: return IPSet()
        if obj_name.lower() == 'any': return IPSet(['0.0.0.0/0'])

        # Case-insensitive lookup to ensure we find the object even if casing differs
        db_obj = AddressObject.query.filter(func.lower(AddressObject.name) == obj_name.lower()).first()
        if not db_obj:
            return cls.parse_ip_to_set(obj_name)

        if db_obj.is_group:
            combined = IPSet()
            for m in db_obj.members:
                combined.update(cls.flatten_address(m.name, depth + 1))
            return combined
        
        return cls.parse_ip_to_set(db_obj.value or obj_name)

    @classmethod
    def resolve_group_members(cls, obj_name: str, depth: int = 0) -> set:
        """Recursively returns a set of all member object names."""
        if depth > 10 or not obj_name: return set()
        
        # Case-insensitive lookup
        db_obj = AddressObject.query.filter(func.lower(AddressObject.name) == obj_name.lower()).first()
        if not db_obj: return {obj_name} # It is a leaf (IP or Unknown Name)

        if db_obj.is_group:
            combined = set()
            # If the group itself is used, include it? Maybe not necessary for subset check if we expand everything.
            combined.add(db_obj.name) 
            for m in db_obj.members:
                combined.update(cls.resolve_group_members(m.name, depth + 1))
            return combined
        
        return {db_obj.name}

    @classmethod
    def resolve_service_to_ports(cls, obj_name: str, depth: int = 0) -> set:
        """
        Recursively resolves Service Objects to a Set of (Protocol, StartPort, EndPort) tuples.
        Returns 'UNIVERSAL' string if it covers everything (any/application-default).
        """
        if depth > 10: return set()
        if not obj_name: return {'UNIVERSAL'}
        
        lower_name = obj_name.lower()
        if lower_name in ('any', 'application-default'): return {'UNIVERSAL'}

        # DB Lookup
        svc = ServiceObject.query.filter(func.lower(ServiceObject.name) == lower_name).first()
        
        if not svc:
            # If not in DB, assume it's a raw port number (e.g. "8080") default TCP
            # or try to parse "tcp/80" if that format is used? 
            # For now, simplistic numeric handling:
            if obj_name.isdigit():
                p = int(obj_name)
                return {('tcp', p, p), ('udp', p, p)} # ambiguous, matching both? Or default TCP? Defaulting to TCP usually safe.
            return set()

        if svc.is_group:
            combined = set()
            for m in svc.members:
                res = cls.resolve_service_to_ports(m.name, depth + 1)
                if 'UNIVERSAL' in res: return {'UNIVERSAL'}
                combined.update(res)
            return combined
        
        # Single Object
        # Parse Port Range "80" or "80-90"
        proto = svc.protocol.lower() if svc.protocol else 'tcp'
        val = svc.port if svc.port else '0'
        
        # Determine strict range
        start, end = 0, 65535
        if '-' in val:
            parts = val.split('-')
            try: start, end = int(parts[0]), int(parts[1])
            except: pass
        elif val.isdigit():
             try: start = end = int(val)
             except: pass
        
        return {(proto, start, end)}

    @classmethod
    def is_service_subset(cls, sub_set: set, super_set: set) -> bool:
        """
        Checks if sub_set is visually 'covered' by super_set.
        Handles 'UNIVERSAL' logic.
        """
        if 'UNIVERSAL' in super_set: return True
        if 'UNIVERSAL' in sub_set: return False # Specific cannot cover Any
        
        if not sub_set: return True # Empty request is trivially covered? Or error? Assuming True.

        # For every range in Sub, must be fully covered by SOME range in Super with same Proto
        for (p_sub, s_sub, e_sub) in sub_set:
            covered = False
            for (p_sup, s_sup, e_sup) in super_set:
                if p_sub == p_sup and s_sup <= s_sub and e_sup >= e_sub:
                    covered = True
                    break
            if not covered: return False
        
        return True

    @classmethod
    def check_shadow_rule(cls, source: str, dest: str, from_zone: str, to_zone: str, service_port: str = 'any', application: str = 'any') -> Dict[str, Any]:
        """
        Advanced Set-Theory Shadow Detection Engine.
        Returns shadowed rule details if the REQUEST is a SUBSET of an EXISTING RULE.
        """
        # 1. Normalize Request
        # Address: IPSet
        req_src_set = cls.flatten_address(source)
        req_dst_set = cls.flatten_address(dest)
        
        # Service: Set<(proto, start, end)>
        req_svc_set = cls.resolve_service_to_ports(service_port)
        
        # App: Set<str>
        req_app = (application.lower() or 'any')
        req_app_set = {req_app}

        query = DBSecurityRule.query.filter_by(disabled=False)
        # Zone Filter (Exact or Any)
        if from_zone and from_zone != 'any':
             query = query.filter(DBSecurityRule.from_zone.in_([from_zone, 'any']))
        if to_zone and to_zone != 'any':
             query = query.filter(DBSecurityRule.to_zone.in_([to_zone, 'any']))

        for rule in query.all():
            # Action Check: Only concerned if Action is ALLOW (User wants to know if they perform duplicated work)
            # Or DENY (User wants to know if they are blocked).
            # Returning ANY match that covers the traffic.
            
            # --- Source Check ---
            rule_src_set = IPSet()
            if not rule.sources: # Any
                pass # Implicitly Universal, handled by logic: if empty, assume ANY (0.0.0.0/0)
                rule_src_set.add('0.0.0.0/0')
            else:
                for s in rule.sources: rule_src_set.update(cls.flatten_address(s.name))
            
            # If request source is NOT a subset of rule source, split.
            if not req_src_set.issubset(rule_src_set): continue

            # --- Destination Check ---
            rule_dst_set = IPSet()
            if not rule.destinations:
                rule_dst_set.add('0.0.0.0/0')
            else:
                 for d in rule.destinations: rule_dst_set.update(cls.flatten_address(d.name))
            
            if not req_dst_set.issubset(rule_dst_set): continue

            # --- Application Check ---
            rule_apps = {a.name.lower() for a in rule.applications}
            if not rule_apps or 'any' in rule_apps:
                pass # Rule covers all apps
            else:
                if 'any' in req_app_set: continue # Request is wildcard, Rule is specific -> Not Covered
                if not req_app_set.issubset(rule_apps): continue

            # --- Service Check ---
            rule_svc_set = set()
            if not rule.services:
                rule_svc_set.add('UNIVERSAL')
            else:
                for s in rule.services:
                    rule_svc_set.update(cls.resolve_service_to_ports(s.name))
            
            svc_subset = cls.is_service_subset(req_svc_set, rule_svc_set)
            
            # DEBUG LOG START
            if rule.name.lower() == 'exact-duplicate-candidate': # Trace specific rule or all?
                 pass
            logging.info(f"SHADOW TRACE: Rule={rule.name} | Action={rule.action} | Apps={rule_apps} vs Req={req_app_set} | SvcMatch={svc_subset}")
            # DEBUG LOG END

            if not svc_subset: continue

            # If we are here, ALL conditions are Subsets. SHADOW DETECTED.
            return {
                "exists": True, 
                "rule": rule.name, 
                "action": rule.action,
                "message": f"Shadowed by {rule.name}"
            }

        return {"exists": False}

    @classmethod
    def verify_policy_match(cls, source: str, dest: str, from_zone: str, to_zone: str, 
                          service_port: str = 'any', application: str = 'any', protocol: str = 'tcp') -> Dict[str, Any]:
        """
        Executes a real-time policy match on the Firewall via API.
        Resolves object names to IPs before sending.
        """
        # 1. Resolve Objects to IPs
        # We take the first IP in the set to test with.
        src_set = cls.flatten_address(source)
        dst_set = cls.flatten_address(dest)
        
        real_src = str(next(src_set.iter_cidrs())).split('/')[0] if src_set else source
        real_dst = str(next(dst_set.iter_cidrs())).split('/')[0] if dst_set else dest
        
        # 2. Build XML Command
        zone_tags = ""
        if from_zone and from_zone.lower() != 'any':
             zone_tags += f"<from>{from_zone}</from>"
        if to_zone and to_zone.lower() != 'any':
             zone_tags += f"<to>{to_zone}</to>"

        # Handle app/service
        app_tag = f"<application>{application if application and application != 'not-applicable' else 'any'}</application>"
        
        # Parse port & protocol
        real_port = service_port
        real_proto = protocol 
        
        if service_port.lower() == 'any' or service_port == 'application-default':
             real_port = '443'
        else:
             # Resolve Service Object Name to Port AND Protocol
             real_port, real_proto = cls.resolve_service_details(service_port, protocol)
        
        proto_tag = f"<protocol>{real_proto}</protocol>" 

        cmd = (f"<test><security-policy-match>"
               f"{zone_tags}"
               f"<source>{real_src}</source><destination>{real_dst}</destination>"
               f"{proto_tag}<destination-port>{real_port}</destination-port>"
               f"{app_tag}"
               f"</security-policy-match></test>")

        try:
            logging.info(f"MATCH CMD: {cmd}")
            fw = cls.get_connection()
            # Explicitly pass vsys1 as per ops_routes.py example
            res = fw.op(cmd=cmd, vsys='vsys1', cmd_xml=False)
            
            # Parse result
            root = res if isinstance(res, ET.Element) else ET.fromstring(res)
            
            entry = root.find(".//entry")
            if entry is not None:
                rule_name = entry.get("name")
                action = entry.findtext("action")
                logging.info(f"MATCH RESULT: Rule={rule_name}, Action={action}")
                
                # If action is allow, it IS a shadow (traffic allowed).
                # UPDATE: User wants to block if ANY rule exists (Allow OR Deny)
                # if action == 'allow':
                return {"exists": True, "rule": rule_name, "action": action}
            
            logging.info("MATCH RESULT: No match found.")
            return {"exists": False}

        except Exception as e:
            return {"exists": False, "error": str(e)}
