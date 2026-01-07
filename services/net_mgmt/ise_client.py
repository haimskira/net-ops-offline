import requests
import json
from requests.auth import HTTPBasicAuth
import urllib3
from config import Config

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ISEClient:
    def __init__(self):
        self.base_url = f"https://{Config.ISE_IP}:9060/ers/config"
        self.auth = HTTPBasicAuth(Config.ISE_USER, Config.ISE_PASSWORD)
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def get_network_devices(self):
        """
        Fetches all network devices from ISE.
        Returns a list of dictionaries with 'name' and 'ip_address'.
        """
        url = f"{self.base_url}/networkdevice"
        devices = []
        try:
            # Need to handle pagination if there are many devices, but starting simple
            page = 1
            while True:
                response = requests.get(
                    f"{url}?page={page}&size=100", 
                    auth=self.auth, 
                    headers=self.headers, 
                    verify=False
                )
                response.raise_for_status()
                data = response.json()
                
                if "SearchResult" in data and "resources" in data["SearchResult"]:
                    for resource in data["SearchResult"]["resources"]:
                        # We need to fetch details for each device to get the IP effectively 
                        # OR check if it's in the summary. ERS summary usually has ID, Name. 
                        # Often need to get by ID to get IP, but let's check first if we can optimize.
                        # Actually 'networkdevice' list in ERS might not include IP in the summary.
                        # We'll fetch details for each to be sure or use a filtered query if possible.
                        # Optimization: Fetch detail only if needed.
                        
                        device_id = resource["id"]
                        device_details = self._get_device_details(device_id)
                        if device_details:
                           devices.append(device_details)
                    
                    # Check for next page
                    if "nextPage" not in data["SearchResult"] or not data["SearchResult"]["nextPage"]:
                        break
                    page += 1
                else:
                    break
                    
        except requests.exceptions.RequestException as e:
            print(f"Error fetching devices from ISE: {e}")
            
        return devices

    def _get_device_details(self, device_id):
        url = f"{self.base_url}/networkdevice/{device_id}"
        try:
            response = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            if response.status_code == 200:
                d = response.json().get("NetworkDevice", {})
                
                # Extract IP (it can be in 'NetworkDeviceIPList' or simple 'ipaddress' field depending on version)
                ip_list = d.get("NetworkDeviceIPList", [])
                ip_address = None
                if ip_list:
                    ip_address = ip_list[0].get("ipaddress")
                
                name = d.get("name")
                
                if ip_address and name:
                     return {"name": name, "ip": ip_address}
        except Exception as e:
            print(f"Error details for {device_id}: {e}")
        return None

if __name__ == "__main__":
    # Test run
    client = ISEClient()
    devs = client.get_network_devices()
    print(f"Found {len(devs)} devices:")
    for d in devs:
        print(d)
