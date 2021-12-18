from collections import namedtuple
import requests
import xml.etree.ElementTree as ET

# Disable SSL certificate verification warnings
requests.packages.urllib3.disable_warnings()


class Panorama:
    def __init__(self, api_key, panorama, verify=False):
        self.api_key = api_key
        self.panorama = panorama
        self.base_url = f"https://{self.panorama}/api/?"
        self.verify = verify
        self.headers = {"Content-Type": "application/xml"}
        self.firewall_details = ""

    def get_firewall_details(self):
        if not self.firewall_details:
            params = {
                "key": self.api_key,
                "type": "op",
                "cmd": "<show><devices><connected></connected></devices></show>",
            }

            try:
                response = requests.get(
                    f"{self.base_url}",
                    params=params,
                    headers=self.headers,
                    verify=self.verify,
                    timeout=15,
                )
            except:
                print(f"Unable to connect (get_firewall_details): {self.host}")
                return

            self.firewall_details = response.text

        return self.firewall_details

    def get_firewalls(self, state="any"):
        if not self.firewall_details:
            self.get_firewall_details()

        firewalls = ET.fromstring(self.firewall_details).findall("result/devices/entry")
        firewalls = sorted(firewalls, key=self.sort_none_last)

        hostnames = list()
        for fw in firewalls:
            if (hostname := fw.find("hostname")) is not None:
                fw_state = fw.find("ha/state")
                # Set state to active for standalone firewalls
                fw_state = fw_state.text if fw_state is not None else "active"
                if fw_state in state or state == "any":
                    hostnames.append(f"{hostname.text.lower()}.wsgc.com")
                else:
                    continue

        return hostnames

    def sort_none_last(self, e):
        if (hostname := e.find("hostname")) is not None:
            hostname = hostname.text
        return (hostname is None, hostname)
