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



Benefits of the System Secure Script
🛡️ Complete System Anonymity & Security
1. Network Identity Protection
MAC Address Randomization: Changes both Wi-Fi and Ethernet MAC addresses

Prevents device tracking across networks

Bypasses MAC filtering restrictions

Enhances privacy on public networks

Uses locally administered MAC addresses (02:XX:XX:XX:XX:XX) that can't be traced to manufacturer

2. Advanced DNS Protection
Massive DNS Server Pool: 60+ IPv4 and 40+ IPv6 DNS servers

Geographic Diversity: Servers from multiple countries and providers

Automatic Rotation: Randomly selects different DNS servers each time

Hostinger Geofeed Integration: Additional IP ranges from global hosting provider

Benefits:

Prevents DNS-based tracking

Bypasses geographic restrictions

Enhances browsing privacy

Improves DNS resolution reliability

3. IP Address & Subnet Mask Randomization
Dynamic Subnet Configuration: Randomly assigns from 9 different subnet masks

Automatic IP Generation: Creates appropriate IP addresses for each subnet

Benefits:

Makes network fingerprinting difficult

Prevents IP-based correlation attacks

Enhances local network privacy

Useful for penetration testing and security research

🔄 System Identity Protection
4. Machine GUID Regeneration
Complete GUID Reset: Deletes and regenerates Windows MachineGuid

Registry Modification: Changes cryptographic machine identity

Benefits:

Prevents software licensing tracking

Resets Windows activation fingerprint

Defeats hardware-based DRM systems

Creates new system identity for forensic purposes

5. Computer Name Randomization
Dynamic Hostname Generation: Creates random computer names (SID-XXXXXXXX)

Benefits:

Prevents network identification

Enhances corporate network privacy

Useful for red team operations

Resets system naming for clean slate

6. SID Regeneration via Sysprep
Complete System SID Reset: Uses Microsoft Sysprep tool

Machine & User SID Regeneration: Creates new security identifiers

Benefits:

Complete system identity reset

Prevents SID-based tracking

Essential for forensic anonymity

Creates genuinely new system instance

🌐 Advanced Network Features
7. IPv6 ULA Address Assignment
Unique Local Addresses: Generates random IPv6 ULA addresses (fd00::/8)

Benefits:

Enhances IPv6 privacy

Prevents IPv6 address tracking

Provides additional network layer

Future-proofs privacy protection

8. Comprehensive Network Detection
Smart Adapter Identification: Automatically detects wired vs wireless adapters

Physical Adapter Filtering: Excludes virtual/VPN adapters

Benefits:

Targeted configuration

Prevents configuration conflicts

Ensures only real hardware is modified

Reduces system instability risk
[![Watch the video on YouTube](https://img.youtube.com/vi/Hc1B5MA4E7o/0.jpg)](https://www.youtube.com/watch?v=Hc1B5MA4E7o)
## Demo / Walkthrough Video
**[Watch on YouTube →](https://www.youtube.com/watch?v=Hc1B5MA4E7o)**

