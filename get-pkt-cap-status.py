#!/usr/bin/env python3.8

import json
import os
import re
import requests
import sys
import threading
import time

from netmiko import ConnectHandler, ssh_exception

from panorama import Panorama


def import_env(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    else:
        return None


def parse_pkt_cap_status(firewall, data):
    # Check to see if a packet capture is running
    enabled = re.search(r"Packet capture\n\s{2}Enabled:\s+.(yes|no)", data, flags=re.M)
    enabled = enabled.group(1) if enabled is not None else ""
    if enabled == "yes":
        # Parse packet filters
        packet_filter = re.search(
            r"Packet filter\n\s{2}Enabled:\s+.(?:yes|no)\n\s{2}Match.*?\n\s{2}(Index.*non-IP)",
            data,
            flags=re.M | re.S,
        )
        if packet_filter:
            packet_filter = [e.strip() for e in packet_filter.group(1).split("\n")]
            packet_filter = [
                ", ".join(x) for x in zip(packet_filter[0::2], packet_filter[1::2])
            ]
            packet_filter = [f"```{e}```" for e in packet_filter]
        else:
            packet_filter = ""

        results = {
            "Firewall": firewall,
            "Enabled": enabled,
            "Filter": "\n".join(packet_filter),
        }

        return results


def get_pkt_cap_status(fw, user, pw):
    PAN = {
        "device_type": "paloalto_panos",
        "host": fw,
        "username": user,
        "password": pw,
        "conn_timeout": 60,
    }
    # TODO: Add `show admins` and parse
    commands = ["debug dataplane packet-diag show setting"]

    output = list()
    try:
        with ConnectHandler(**PAN) as net_connect:
            for cmd in commands:
                output.append(
                    net_connect.send_command(
                        cmd,
                        strip_prompt=True,
                        strip_command=True,
                        expect_string=r">",
                    )
                )
    except ssh_exception.NetmikoAuthenticationException:
        sys.stderr.write(f"Authentication failed: {fw}\n")
    except ssh_exception.NetmikoTimeoutException:
        sys.stderr.write(f"Connection timed out: {fw}\n")
    except Exception as e:
        sys.stderr.write(f"{fw}:\n{e}")

    return output


def send_slack_msg(data, webhook):
    firewall = data["Firewall"]
    filter = f"\n{data['Filter']}" if data["Filter"] else " None"
    data = json.dumps(
        {
            "text": f"{data['Firewall']}: Packet capture is running",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Device Name:* <https://{firewall}|{firewall}>\n*Description:* Packet capture is running\n*Packet Filters:*{filter}",
                    },
                }
            ],
        },
    )

    response = requests.post(
        webhook,
        data=data,
        headers={"Content-Type": "application/json"},
        verify=True,
        timeout=15,
    )
    response.raise_for_status()


def worker(fw, user, pw, webhook):
    pkt_cap_status = get_pkt_cap_status(fw, user, pw)
    if pkt_cap_status:
        pkt_cap_status = parse_pkt_cap_status(fw, pkt_cap_status[0])
        if pkt_cap_status:
            send_slack_msg(pkt_cap_status, webhook)


def main():
    t1_start = time.time()

    global table_rows
    env = import_env("env.json")

    panorama = Panorama(env["panorama_api_key"], env["panorama"])
    firewalls = panorama.get_firewalls()

    worker_threads = []
    for fw in firewalls:
        t = threading.Thread(
            target=worker,
            args=(fw, env["user"], env["password"], env["slack_webhook"]),
        )
        worker_threads.append(t)
        t.start()

    for t in worker_threads:
        t.join()

    t1_stop = time.time()
    print(f"\n Took {t1_stop-t1_start :.3f} seconds to complete")


if __name__ == "__main__":
    main()