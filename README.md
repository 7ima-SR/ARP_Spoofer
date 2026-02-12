# ARP Tool - Engineered Edition

![Built With](https://img.shields.io/badge/Built%20With-Python-blue?style=flat-square)
![Library](https://img.shields.io/badge/Library-Scapy-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Author](https://img.shields.io/badge/Author-Hima-red?style=flat-square)
![ARP Tool](https://img.shields.io/badge/status-experimental-orange)  

A professional and modular ARP tool in Python, designed for **educational and testing purposes**.  
It supports both **ARP spoofing** and **ARP detection mode**, with MAC caching and structured JSON logging.

> ⚠️ Only use in a controlled environment or with explicit permission. Unauthorized ARP attacks are illegal.

---

## Features

- ✅ **Spoof Mode**
  - Send ARP replies to a target and gateway to perform ARP spoofing.
  - Automatic MAC caching for efficiency.
  - Structured JSON logging for all spoofed packets.
- ✅ **Detection Mode**
  - Monitor the network for ARP spoofing attempts.
  - Alert if a device’s MAC changes unexpectedly.
  - Structured JSON logging for all detected events.
- ✅ **Root Privileges Check**
  - Ensures the script is run with root/admin rights.
- ✅ **Customizable Interface**
  - Choose which network interface to use.
- ✅ **Modular Architecture**
  - Class-based: `ARPEngine`, `MACCache`, `JSONLogger`.
- ✅ **Graceful Shutdown**
  - Restores network ARP tables when interrupted.

---

## Requirements

- Python 3.8+  
- **Scapy** library:  
  ```bash
  pip install scapy
  ```

- termcolor and pyfiglet for colored CLI and banner:
    ```bash
    pip install termcolor pyfiglet
   ```

---

## Using

- ### 1️⃣Spoof Mode (Default)
    ```bash
    sudo python3 tool.py -t <TARGET_IP> -g <GATEWAY_IP> -i <INTERFACE>
    ```


- Example:
    ```bash
    sudo python3 tool.py -t 192.168.1.10 -g 192.168.1.1 -i eth0
    ```
    - -t / --target : IP of the victim device

    - -g / --gateway : IP of the gateway/router

    - -i / --interface : Network interface to use

- The tool will send spoofed ARP packets every 2 seconds and log the events in arp_tool.log.

---

- ### 2️⃣ Detection Mode
    ```bash
    sudo python3 tool.py -m detect -i <INTERFACE>
    ```

- Example:
    ```bash
    sudo python3 tool.py -m detect -i eth0
    ```

- Monitors the network for ARP spoofing attempts.

- Logs all alerts and new devices in structured JSON format.

---

## Logging

- All events are logged in JSON format (arp_tool.log) with:

```json
{
  "timestamp": "2026-02-12T20:10:11",
  "level": "INFO",
  "message": "Spoofed packet sent",
  "extra": {
    "target": "192.168.1.10",
    "spoofed_as": "192.168.1.1"
  }
}
```

- INFO → Successful packet sent or network restored

- WARNING → Could not retrieve MAC address

- ALERT → Detected ARP spoofing attempt

---

## Notes

- Ensure IP forwarding is enabled if you want traffic to continue flowing:
    ```bash
    echo 1 > /proc/sys/net/ipv4/ip_forward
    ```


- Stop the script with Ctrl+C to restore the ARP table automatically.

- Use in virtual lab environments (VMware, VirtualBox, or isolated lab network).

---

## Advanced Usage Ideas

- Integrate with ELK Stack or SIEM for real-time network monitoring.

- Add multiple targets or subnet scanning.

- Implement threading for concurrent spoofing or detection.

- Extend structured logging for analytics.


---

## ⚠️ Disclaimer

- This tool is for educational and authorized security testing only. Do not scan networks without proper permission.

---

## ⭐ Enterprise / Research Edition (Private)

- An extended private version is available for:

- Academic research

- Security lab environments

- Advanced defensive simulations

- Red & Blue team training setups

- Contact for details and access.

---

## 📜 License

- This project is licensed under the MIT License.

## 📧 Contact

- Made with ❤️ by 7ima-SR

- 🌐 Website: https://ibrahim-elsaied.netlify.app/