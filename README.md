System Secure Script By Sid Gifari
From Gifari Industries - BD Cyber Security Team 
telegram
@sidgifari
how to run
right click=mouse
<img width="393" height="181" alt="image" src="https://github.com/user-attachments/assets/c8339464-e1fe-41f8-b873-5b442692837f" />

type=yes
<img width="1077" height="632" alt="image" src="https://github.com/user-attachments/assets/1225ae69-009f-444e-98d6-d1a520c7e29a" />

A comprehensive Windows system security and anonymization tool designed to enhance privacy, randomize identifiers, and prepare machines for secure deployment. Ideal for cybersecurity professionals, IT admins, and penetration testers looking to obfuscate system fingerprints or automate post-deployment hardening.

Features

MAC Address Randomization

Randomizes MAC addresses for wired, wireless, or all physical adapters.

Supports multiple methods: PowerShell, registry, and Device Manager.

Automatic verification of new MAC addresses after change.

Network Configuration

Assigns a random IPv6 ULA (/64) to the active network adapter.

Randomizes DNS servers for IPv4 and IPv6 from multiple trusted providers.

Ensures unique DNS selection and network configuration per session.

System Identifiers & Machine GUID

Generates and sets a new Machine GUID in the registry.

Optionally renames the machine with a randomized hostname.

Logs current and new identifiers for auditing purposes.

SID Regeneration

Cleans up leftover Sysprep logs and XML files.

Generates new machine SID via Sysprep, ensuring a fully unique system identity.

Schedules post-reboot verification to confirm changes.

Robust Logging

Logs all actions to %TEMP%\secure.log.

Tracks MAC changes, DNS configuration, Machine GUID updates, and SID regeneration.

Admin-Elevation Handling

Automatically prompts for administrative privileges if required.

Supports unattended or confirmed execution modes.

Flexible Usage

Run the full security script or target specific operations:

Wi-Fi MAC only: --wifi-only

Wired MAC only: --wired-only

All physical adapters: --all-mac / --physical-mac

Post-reboot verification: --post-reboot

Skip confirmation prompts: --yes
