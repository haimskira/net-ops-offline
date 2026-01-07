from netmiko import ConnectHandler, file_transfer
from config import Config
import re
import logging

logger = logging.getLogger(__name__)

class SwitchClient:
    def __init__(self, ip, username=None, password=None, secret=None):
        self.ip = ip
        self.username = username or Config.SWITCH_USER
        self.password = password or Config.SWITCH_PASS
        self.secret = secret or Config.SWITCH_ENABLE
        self.device_type = "cisco_ios"
        
    def _get_connection(self):
        return {
            "device_type": self.device_type,
            "host": self.ip,
            "username": self.username,
            "password": self.password,
            "secret": self.secret,
        }

    def collect_data(self):
        data = {
            "hostname": None,
            "model": None,
            "version": None,
            "serial": None,
            "uptime": None,
            "is_stack": False,
            "stack_member_count": 1,
            "active_ports": 0,
            "err_disabled": 0,
            "is_stack": False,
            "stack_member_count": 1,
            "active_ports": 0,
            "err_disabled": 0,
            "mab_failed": 0,
            "neighbors": []
        }
        
        try:
            with ConnectHandler(**self._get_connection()) as net_connect:
                net_connect.enable()
                
                # 1. Show Version (Hostname, OS, Uptime, Serial Fallback)
                output_ver = net_connect.send_command("show version")
                data.update(self._parse_version(output_ver))
                
                # 1.1 Show Inventory (Better Model/PID detection)
                output_inv = net_connect.send_command("show inventory")
                data.update(self._parse_inventory(output_inv))
                
                # 2. Check Stack
                output_stack = net_connect.send_command("show switch detail")
                # If command fails (invalid input), it's likely not a stackable switch or just standalone
                if "Invalid input" not in output_stack:
                    data.update(self._parse_stack(output_stack))
                
                # 3. Active Ports (Up/Up)
                output_ip_int = net_connect.send_command("show ip int brief")
                data["active_ports"] = output_ip_int.count("up                    up") # simple count
                
                # 4. Err-Disabled
                output_err = net_connect.send_command("show interfaces status err-disabled")
                # Count lines that are not header
                lines = output_err.strip().splitlines()
                if len(lines) > 1: # Header is usually the first line
                    # Filter out headers if needed, but simplistic count:
                    data["err_disabled"] = sum(1 for line in lines if "err-disabled" in line)

                # 5. MAB Failures
                # 'show authentication sessions status authz-failed' or parsing 'show authentication sessions'
                output_mab = net_connect.send_command("show authentication sessions")
                data["mab_failed"] = output_mab.count("Authz Failed") + output_mab.count("Authc Failed")

                # 6. Topology (CDP)
                output_cdp = net_connect.send_command("show cdp neighbors detail")
                data["neighbors"] = self._parse_cdp_neighbors(output_cdp)

        except Exception as e:
            logger.error(f"Failed to connect to {self.ip}: {e}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to connect to {self.ip}: {e}")
            return None
            
        return data

    def run_command(self, command):
        try:
            with ConnectHandler(**self._get_connection()) as net_connect:
                net_connect.enable()
                output = net_connect.send_command(command)
                return output
        except Exception as e:
            logger.error(f"Command execution failed on {self.ip}: {e}")
            raise e

    def connect_interactive(self):
        """
        Establishes a persistent connection and returns the net_connect object
        with an open interactive shell. 
        Caller is responsible for closing the connection/socket.
        """
        try:
            net_connect = ConnectHandler(**self._get_connection())
            net_connect.enable()
            # Find raw channel
            return net_connect
        except Exception as e:
            logger.error(f"Interactive connection failed to {self.ip}: {e}")
            raise e

    def copy_file(self, source_file, dest_fs="flash:"):
        """
        Copies a file to the switch using SCP.
        Requires 'ip scp server enable' on the switch.
        """
        try:
            conn_params = self._get_connection()
            # Netmiko's file_transfer handles the connect itself usually or takes a connection
            # We'll establishing a connection and pass it.
            
            with ConnectHandler(**conn_params) as net_connect:
                net_connect.enable()
                
                # Check directly
                transfer_result = file_transfer(
                    net_connect,
                    source_file=source_file,
                    dest_file=source_file.split('\\')[-1].split('/')[-1], # basename
                    file_system=dest_fs,
                    direction='put',
                    overwrite_file=False
                )
                
                return f"File Transferred: {transfer_result['file_exists']} (Verified: {transfer_result['file_verified']})"
                
        except Exception as e:
             logger.error(f"SCP Transfer failed to {self.ip}: {e}")
             raise e

    def _parse_version(self, output):
        res = {}
        # Simple regexes - adjust as needed for specific IOS versions
        
        # Uptime
        uptime_match = re.search(r"uptime is (.*)", output)
        if uptime_match:
            res["uptime"] = uptime_match.group(1).strip()
            
        # Version
        ver_match = re.search(r"Cisco IOS Software.*Version ([^,]+),", output)
        if not ver_match:
             ver_match = re.search(r"Version ([^ ]+)", output)
        if ver_match:
            res["version"] = ver_match.group(1)

        # Model and Serial strings in show version are tricky, often multiple for stacks.
        # We'll grab the first Processor board ID for serial and Model from 'cisco WS-C...'
        
        # Model
        model_match = re.search(r"[Cc]isco ([\w-]+) .*,", output)
        if model_match:
             res["model"] = model_match.group(1)
             
        # Serial
        serial_match = re.search(r"Processor board ID (\w+)", output)
        if serial_match:
            res["serial"] = serial_match.group(1)
            
        # Hostname
        host_match = re.search(r"(\S+) uptime is", output)
        if host_match:
            res["hostname"] = host_match.group(1)
            
        return res

    def _parse_inventory(self, output):
        res = {}
        # Parse PID: WS-C...
        # PID: WS-C2960X-24PS-L , VID: V05 , SN: ...
        # We want the first PID usually, or the one corresponding to the chassis ("1")
        
        # Regex to find PID
        pid_match = re.search(r'PID: ([\w-]+)', output)
        if pid_match:
            res["model"] = pid_match.group(1)
            
        # Also Serial is often better here
        sn_match = re.search(r'SN: ([\w]+)', output)
        if sn_match:
            res["serial"] = sn_match.group(1)
            
        return res

    def _parse_stack(self, output):
        res = {"is_stack": False, "stack_member_count": 1}
        # Look for "Switch/Stack Mac Address" or table with Switch# Role Mac Address...
        if "Switch#" in output and "Role" in output:
             # Count lines starting with a digit
             members = [line for line in output.splitlines() if re.match(r"^\s*\d+\s+", line)]
             res["stack_member_count"] = len(members)
             if len(members) > 1:
                 res["is_stack"] = True
             else:
                 res["is_stack"] = False
        return res

    def _parse_cdp_neighbors(self, output):
        links = []
        # output is 'show cdp neighbors detail'
        # Blocks are separated by dashes usually.
        # We need Device ID, Interface (Local), Port ID (Remote)
        
        # Regex is safer on chunks.
        chunks = re.split(r"-{10,}", output)
        
        for chunk in chunks:
            if not chunk.strip(): continue
            
            # Device ID
            dev_match = re.search(r"Device ID: ([\w\.-]+)", chunk)
            if not dev_match: continue
            target_host = dev_match.group(1)
            
            # Local Interface
            local_match = re.search(r"Interface: ([\w\/\s]+),", chunk)
            
            # Remote Port
            remote_match = re.search(r"Port ID \(outgoing port\): ([\w\/\s]+)", chunk)
            
            if local_match and remote_match:
                # Cleanup names (GigabitEthernet1/0/1 -> Gi1/0/1 if wanted, but full is fine)
                links.append({
                    "target_hostname": target_host.split('.')[0], # Remove domain if present
                    "local_port": local_match.group(1).strip(),
                    "remote_port": remote_match.group(1).strip()
                })
                
        return links

if __name__ == "__main__":
    # Test with one IP if needed (dummy call)
    pass
