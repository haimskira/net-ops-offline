import re
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
    def check_shadow_rule(cls, source: str, dest: str, from_zone: str, to_zone: str, service_port: str = 'any', application: str = 'any') -> Dict[str, Any]:
        """
        Advanced Policy Match Engine.
        Returns passing rule if traffic is already allowed.
        """
        # 1. IP Based Matching
        src_set = cls.flatten_address(source)
        dst_set = cls.flatten_address(dest)
        
        # 2. Name Based Matching (Fallback for FQDNs/Groups without IPs)
        src_names = cls.resolve_group_members(source)
        dst_names = cls.resolve_group_members(dest)

        query = DBSecurityRule.query.filter_by(disabled=False)
        if from_zone and from_zone != 'any':
            query = query.filter(DBSecurityRule.from_zone.in_([from_zone, 'any']))
        if to_zone and to_zone != 'any':
            query = query.filter(DBSecurityRule.to_zone.in_([to_zone, 'any']))

        for rule in query.all():
            # Source Check
            ip_match_src = False
            name_match_src = False

            if not rule.sources: # Any
                ip_match_src = True
                name_match_src = True
            else:
                # IP Check
                if src_set:
                     r_src_ip = IPSet()
                     for s in rule.sources: r_src_ip.update(cls.flatten_address(s.name))
                     if src_set.issubset(r_src_ip): ip_match_src = True

                # Name Check (If IP check failed or empty)
                if not ip_match_src:
                     r_src_names = set()
                     for s in rule.sources: r_src_names.update(cls.resolve_group_members(s.name))
                     
                     # Check if Input members are subset of Rule members
                     # e.g. Input={Host-A}, Rule={Group-X (contains Host-A)} -> Subset True
                     if src_names and src_names.issubset(r_src_names): 
                        name_match_src = True
            
            if not ip_match_src and not name_match_src: continue

            # Dest Check
            ip_match_dst = False
            name_match_dst = False

            if not rule.destinations: # Any
                ip_match_dst = True
                name_match_dst = True
            else:
                 # IP Check
                 if dst_set:
                     r_dst_ip = IPSet()
                     for d in rule.destinations: r_dst_ip.update(cls.flatten_address(d.name))
                     if dst_set.issubset(r_dst_ip): ip_match_dst = True
                 
                 # Name Check
                 if not ip_match_dst:
                     r_dst_names = set()
                     for d in rule.destinations: r_dst_names.update(cls.resolve_group_members(d.name))
                     if dst_names and dst_names.issubset(r_dst_names):
                        name_match_dst = True
            
            if not ip_match_dst and not name_match_dst: continue

            # --- Application Check ---
            # If the RULE implies 'any' application (empty or explicit 'any'), it covers everything.
            # If the REQUEST is 'any', it is only covered if the RULE is 'any'.
            
            rule_apps = [a.name.lower() for a in rule.applications]
            rule_has_any_app = not rule_apps or 'any' in rule_apps
            
            req_app = (application or 'any').lower()

            # If rule is specific, but request is 'any', rule DOES NOT cover the request (only partially).
            # We are looking for "Is the request FULLY shadowed by this rule?"
            if not rule_has_any_app:
                 # Rule is specific (e.g. 'ssh'). Request is 'any' -> Not shadowed.
                 if req_app == 'any': continue
                 # Rule is specific (e.g. 'ssh'). Request is 'ssl' -> Not shadowed.
                 if req_app not in rule_apps: continue

            # --- Service Check ---
            # If no services linked, treat as ANY/Application-Default
            if not rule.services:
                 return {"exists": True, "rule": rule.name, "action": rule.action}

            rule_services = [s.name.lower() for s in rule.services]
            if 'any' in rule_services or 'application-default' in rule_services:
                return {"exists": True, "rule": rule.name, "action": rule.action}
            
            input_svc = service_port.lower()
            if input_svc in rule_services:
                 return {"exists": True, "rule": rule.name, "action": rule.action}

            # If we reached here, IP matched but Service/App didn't. Continue to next rule.
            continue

        return {"exists": False}

    @classmethod
    def detect_zone(cls, ip_input: str) -> Optional[str]:
        """Maps IP to Zone using DB Topology."""
        target = cls.flatten_address(ip_input)
        if not target: return None

        interfaces = NetworkInterface.query.all()
        detected = set()

        for cidr in target.iter_cidrs():
            for iface in interfaces:
                if not iface.subnet: continue
                if cidr in IPNetwork(iface.subnet) or IPNetwork(iface.subnet) in cidr:
                    detected.add(iface.zone_name)
                    break 
        
        return list(detected)[0] if detected else None

    @classmethod
    def resolve_service_details(cls, service_name: str, default_proto: str = 'tcp') -> tuple[str, str]:
        """Resolves a Service Object name to its (port, protocol). Fallback to defaults."""
        if not service_name: return '443', default_proto
        
        # If already numeric, return as is with default proto
        if service_name.isdigit(): return service_name, default_proto
        
        # Look up in DB
        svc = ServiceObject.query.filter(func.lower(ServiceObject.name) == service_name.lower()).first()
        if svc:
            # If Group, resolve first member recursively
            if svc.is_group:
                if svc.members:
                     # Recursive call for the first member
                     return cls.resolve_service_details(svc.members[0].name, default_proto)
                # Empty group? Fallback to name (or 443?)
                return service_name, default_proto

            # Prefer DB protocol if available, else default
            proto = svc.protocol if svc.protocol else default_proto
            
            # Prefer DB port if valid, else object name
            port = svc.port if (svc.port and svc.port.lower() != 'any') else service_name
            return port, proto
            
        return service_name, default_proto # Fallback

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
