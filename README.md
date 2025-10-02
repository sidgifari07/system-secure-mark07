# System Secure Script 🛡️
**By Sid Gifari**  
*Gifari Industries – BD Cyber Security Team*  

Telegram: [@sidgifari](https://t.me/sidgifari)

---

## Overview
**System Secure Script** is a comprehensive Windows system security and anonymization tool.  
It is designed to **enhance privacy, randomize identifiers, and prepare machines for secure deployment**.

Ideal for:
- Cybersecurity professionals
- IT administrators
- Penetration testers

This tool helps **obfuscate system fingerprints** and **automate post-deployment hardening**.

---

## Features

### MAC Address Randomization
- Randomizes MAC addresses for wired, wireless, or all physical adapters
- Supports multiple methods: **PowerShell**, **Registry**, and **Device Manager**
- Automatic verification of new MAC addresses

### Network Configuration
- Assigns a random **IPv6 ULA** to the active network adapter
- Randomizes **DNS servers** for IPv4 and IPv6 from multiple trusted providers
- Ensures **unique network configuration per session**

### System Identifiers & Machine GUID
- Generates and sets a new **Machine GUID** in the registry
- Optionally renames the machine with a randomized hostname
- Logs current and new identifiers for auditing

### SID Regeneration
- Cleans up leftover **Sysprep logs** and XML files
- Generates a new **machine SID** via Sysprep
- Schedules **post-reboot verification** to confirm changes

### Robust Logging
- Tracks MAC changes, DNS configuration, Machine GUID updates, and SID regeneration

---

## Screenshots

<img src="https://github.com/user-attachments/assets/c8339464-e1fe-41f8-b873-5b442692837f" width="400" />

<img src="https://github.com/user-attachments/assets/1225ae69-009f-444e-98d6-d1a520c7e29a" width="700" />

<img src="https://github.com/user-attachments/assets/ba95d2ff-9457-4c15-9fa1-34be2411d49b" width="700" />

---

## How to Run
1. **Right-click** on the script file
2. Follow the on-screen prompts:
   - Type `yes` to proceed
   - Type `A` for advanced options


## Demo / Walkthrough Video

[![Watch the video on YouTube](https://img.youtube.com/vi/Hc1B5MA4E7o/0.jpg)](https://www.youtube.com/watch?v=Hc1B5MA4E7o)

**[Watch on YouTube →](https://www.youtube.com/watch?v=Hc1B5MA4E7o)**

