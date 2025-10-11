import ctypes
import subprocess
import random
import sys
import os
import time
import json
from datetime import datetime
import uuid
import shutil
import argparse
import stat
import re
import winreg
import ipaddress
import requests
from typing import List, Tuple, Set

# =========================
# Config / Constants
# =========================
LOG_FILE = os.path.join(os.getenv("TEMP") or ".", "secure.log")
SCHEDULED_TASK_NAME = "SecureRotationTask"
TEMP_DIR = os.getenv("TEMP") or "."

# Add subnet mask constants
SUBNET_MASKS = [
    "255.255.255.0",    # /24 - Most common for home networks
    "255.255.0.0",      # /16 - Large networks
    "255.255.255.128",  # /25 - Medium networks
    "255.255.255.192",  # /26 - Small networks
    "255.255.255.240",  # /28 - Very small networks
    "255.255.255.248",  # /29 - Tiny networks
    "255.255.255.252",  # /30 - Point-to-point
    "255.255.254.0",    # /23 - Large subnets
    "255.255.252.0",    # /22 - Very large subnets
    "255.255.248.0",    # /21 - Extra large subnets
]

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_as_admin() -> bool:
    try:
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        return int(ret) > 32
    except Exception as e:
        print(f"[ERROR] Failed to elevate privileges: {e}")
        return False

# Enhanced DNS server lists with comprehensive Hostinger geofeed data
DNS_V4 = [
    # Major Public DNS Services
    "1.1.1.1", "1.0.0.1",  # Cloudflare
    "8.8.8.8", "8.8.4.4",  # Google
    "9.9.9.9", "149.112.112.112",  # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "64.6.64.6", "64.6.65.6",  # Verisign
    "84.200.69.80", "84.200.70.40",  # DNS.WATCH
    "8.26.56.26", "8.20.247.20",  # Comodo
    "195.46.39.39", "195.46.39.40",  # SafeDNS
    "76.76.19.19", "76.223.122.150",  # Alternate DNS
    "94.140.14.14", "94.140.15.15",  # AdGuard DNS
    "185.228.168.9", "185.228.168.10",  # CleanBrowsing
    "76.76.2.0", "76.76.10.0",  # ControlD
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",  # Level3
    "209.244.0.3", "209.244.0.4",  # Level3
    "216.146.35.35", "216.146.36.36",  # Dyn
    "37.235.1.174", "37.235.1.177",  # FreeDNS
    "198.101.242.72", "23.253.163.53",  # Alternate DNS
    "156.154.70.1", "156.154.71.1",  # Neustar
    "176.103.130.130", "176.103.130.131",  # AdGuard
    "199.85.126.10", "199.85.127.10",  # Norton
    "81.218.119.11", "209.88.198.133",  # GreenTeamDNS
    "195.46.39.40", "195.46.39.41",  # SafeDNS
    "205.210.42.205", "64.68.200.200",  # OpenNIC
    "202.83.95.229", "202.83.95.227",  # NICT
    "203.112.2.4", "203.112.2.5",  # BSNL
    "203.80.96.10", "203.80.96.9",  # STC
    "218.248.255.212", "218.102.23.228",  # RailTel
    # Additional global DNS servers
    "45.90.28.0", "45.90.30.0",  # NextDNS
    "185.222.222.222", "185.184.222.222",  # DNS for Family
    "80.80.80.80", "80.80.81.81",  # Freenom World
    "89.233.43.71", "91.239.100.100",  # UncensoredDNS
    "5.2.75.75", "5.2.75.76",  # German DNS
    "194.150.168.168", "194.150.169.168",  # German DNS
    "87.118.100.175", "87.118.101.175",  # German DNS
    "212.51.137.101", "212.51.137.102",  # Swiss DNS
    "77.109.148.136", "77.109.149.136",  # Swiss DNS
    "91.217.137.37", "91.217.137.38",  # Czech DNS
    "188.93.95.95", "188.93.95.96",  # Polish DNS
    "193.58.251.251", "193.58.251.252",  # Russian DNS
    "109.69.8.51", "109.69.8.52",  # Italian DNS
    "156.154.70.22", "156.154.71.22",  # Neustar
    "203.80.96.10", "203.80.96.9",  # Middle East
    "202.12.27.33", "202.12.27.34",  # Japan
    "210.138.175.244", "210.138.175.245",  # Japan
    "219.100.37.10", "219.100.37.20",  # New Zealand
    "202.67.240.222", "202.67.240.221",  # Philippines
    "164.124.101.2", "203.248.252.2",  # South Korea
    "168.126.63.1", "168.126.63.2",  # South Korea
    "202.46.32.19", "202.46.32.20",  # Thailand
    "203.80.96.10", "203.80.96.9",  # Saudi Arabia
    "196.3.58.12", "196.3.59.12",  # South Africa
    "200.7.84.10", "200.7.84.11",  # Brazil
    "200.42.160.68", "200.42.160.69",  # Argentina
    "190.64.58.21", "190.64.58.22",  # Uruguay
    "200.48.225.130", "200.48.225.131",  # Peru
    "190.122.186.17", "190.122.186.18",  # Colombia
    "200.31.248.130", "200.31.248.131",  # Chile
    "201.218.154.1", "201.218.154.2",  # Panama
    "200.33.171.11", "200.33.171.12",  # Mexico
]

DNS_V6 = [
    # Major Public DNS Services
    "2606:4700:4700::1111", "2606:4700:4700::1001",  # Cloudflare
    "2001:4860:4860::8888", "2001:4860:4860::8844",  # Google
    "2620:fe::fe", "2620:fe::9",  # Quad9
    "2620:119:35::35", "2620:119:53::53",  # OpenDNS
    "2001:1608:10:25::1c04:b12f", "2001:1608:10:25::9249:d69b",  # DNS.WATCH
    "2a0d:2a00:1::2", "2a0d:2a00:1::1",  # CleanBrowsing
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",  # AdGuard
    "2620:74:1b::1:1", "2620:74:1c::2:2",  # Verisign
    "2001:67c:28a4::", "2001:67c:28a4::1",  # Freenom World
    "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff",  # Yandex
    "2a0d:2a00:2::", "2a0d:2a00:2::1",  # CleanBrowsing Family
    # Additional global IPv6 DNS servers
    "2001:678:68::", "2001:678:6c::",  # German DNS
    "2001:678:78::", "2001:678:7c::",  # German DNS
    "2001:1900:3001:11::c", "2001:1900:3001:11::d",  # Global DNS
    "2001:1900:3001:12::c", "2001:1900:3001:12::d",  # Global DNS
    "2001:1900:3001:13::c", "2001:1900:3001:13::d",  # Global DNS
    "2001:1900:3001:14::c", "2001:1900:3001:14::d",  # Global DNS
    "2001:1900:3001:15::c", "2001:1900:3001:15::d",  # Global DNS
    "2001:1900:3001:16::c", "2001:1900:3001:16::d",  # Global DNS
    "2001:1900:3001:17::c", "2001:1900:3001:17::d",  # Global DNS
    "2001:1900:3001:18::c", "2001:1900:3001:18::d",  # Global DNS
    "2001:1900:3001:19::c", "2001:1900:3001:19::d",  # Global DNS
    "2001:1900:3001:20::c", "2001:1900:3001:20::d",  # Global DNS
    "2606:4700:4700::1112", "2606:4700:4700::1002",  # Cloudflare Secondary
    "2001:4860:4860::8889", "2001:4860:4860::8845",  # Google Secondary
    "2620:fe::10", "2620:fe::11",  # Quad9 Secondary
    "2620:119:35::36", "2620:119:53::54",  # OpenDNS Secondary
    "2a00:5a60::ad1:ff", "2a00:5a60::ad2:ff",  # AdGuard EU
    "2a0d:2a00:1::3", "2a0d:2a00:1::4",  # CleanBrowsing Secondary
    "2001:678:68::1", "2001:678:6c::1",  # German DNS Secondary
    "2001:678:78::1", "2001:678:7c::1",  # German DNS Secondary
    "2001:1608:10:25::2", "2001:1608:10:25::3",  # DNS.WATCH Secondary
    "2a02:6b8::feed:1ff", "2a02:6b8:0:1::feed:1ff",  # Yandex Secondary
    "2606:4700:4700::64", "2606:4700:4700::6400",  # Cloudflare Malware
    "2001:4860:4860::6464", "2001:4860:4860::64",  # Google Malware
    "2620:fe::fe:11", "2620:fe::fe:12",  # Quad9 Malware
    "2620:119:35::35:11", "2620:119:53::53:11",  # OpenDNS Family
]

NUM_IPV4_DNS = 10
NUM_IPV6_DNS = 10

# =========================
# Helper Functions
# =========================

def log_message(message: str):
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    except Exception:
        pass
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] {message}"
    print(msg)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass

def run_powershell(cmd: str, timeout=60):
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "PowerShell command timed out"
    except Exception as e:
        return -1, "", f"PowerShell execution failed: {str(e)}"

def banner():
    """Display banner."""
    print(rf"""
███╗   ███╗ █████╗ ██████╗ ██╗  ██╗      ██████╗ ███████╗
████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝     ██╔═████╗╚════██║
██╔████╔██║███████║██████╔╝█████╔╝█████╗██║██╔██║    ██╔╝
██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗╚════╝████╔╝██║   ██╔╝ 
██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗     ╚██████╔╝   ██║  
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝      ╚═════╝    ╚═╝  
System Secure Script By Sid Gifari
From Gifari Industries - BD Cyber Security Team                                

███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗    ███████╗██╗██████╗ 
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ██╔════╝██║██╔══██╗
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗█████╗███████╗██║██║  ██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝╚════╝╚════██║██║██║  ██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ███████║██║██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝╚═╝╚═════╝ 
                                                                        
Logs saved to: {LOG_FILE}
""")

# =========================
# Subnet Mask Functions - ADDED
# =========================

def is_network_working(adapter_name: str) -> bool:
    """Check if network is working by testing connectivity."""
    try:
        # Test DNS resolution
        ps_cmd = """
        $success = $false
        try {
            $result = Resolve-DnsName -Name "google.com" -ErrorAction SilentlyContinue
            if ($result) { $success = $true }
        } catch {}
        Write-Output $success
        """
        rc, out, err = run_powershell(ps_cmd)
        if rc == 0 and "True" in out:
            return True
        
        # Test ping to reliable IP
        ps_cmd = """
        $success = $false
        try {
            $result = Test-NetConnection -ComputerName "1.1.1.1" -Port 53 -InformationLevel Quiet -ErrorAction SilentlyContinue
            if ($result -eq $true) { $success = $true }
        } catch {}
        Write-Output $success
        """
        rc, out, err = run_powershell(ps_cmd)
        return rc == 0 and "True" in out
        
    except Exception:
        return False

def restore_network_connectivity(adapter_name: str) -> bool:
    """Restore network connectivity by reverting to DHCP if needed."""
    try:
        log_message(f"Checking network connectivity for {adapter_name}...")
        
        if is_network_working(adapter_name):
            log_message(f"Network is working for {adapter_name}")
            return True
        
        log_message(f"Network not working for {adapter_name}, restoring connectivity...")
        
        # Method 1: Release and renew DHCP
        ps_cmd = """
        $adapter = Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue
        if ($adapter) {{
            # Set to DHCP
            Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -Dhcp Enabled
            # Release and renew
            ipconfig /release && ipconfig /renew
            Write-Output "SUCCESS"
        }}
        """.format(adapter_name=adapter_name)
        rc, out, err = run_powershell(ps_cmd, timeout=30)
        
        if rc == 0:
            time.sleep(5)  # Wait for DHCP
            if is_network_working(adapter_name):
                log_message(f"Successfully restored network connectivity for {adapter_name} via DHCP")
                return True
        
        # Method 2: Reset TCP/IP stack
        log_message(f"Trying TCP/IP reset for {adapter_name}...")
        ps_cmd = """
        netsh int ip reset reset.log
        netsh winsock reset
        Write-Output "SUCCESS"
        """
        rc, out, err = run_powershell(ps_cmd)
        
        if rc == 0:
            time.sleep(3)
            # Restart adapter
            ps_cmd = """
            Restart-NetAdapter -Name '{adapter_name}' -Confirm:$false
            Start-Sleep -Seconds 10
            Write-Output "RESTARTED"
            """.format(adapter_name=adapter_name)
            rc, out, err = run_powershell(ps_cmd)
            
            if is_network_working(adapter_name):
                log_message(f"Successfully restored network connectivity for {adapter_name} via TCP/IP reset")
                return True
        
        log_message(f"Failed to restore network connectivity for {adapter_name}")
        return False
        
    except Exception as e:
        log_message(f"Error restoring network connectivity: {e}")
        return False

def get_random_subnet_mask() -> str:
    """Get a random subnet mask from the available options."""
    return random.choice(SUBNET_MASKS)

def get_subnet_mask_prefix_length(subnet_mask: str) -> int:
    """Convert subnet mask to prefix length."""
    try:
        # Count the number of set bits in the subnet mask
        octets = subnet_mask.split('.')
        binary_str = ''.join([bin(int(octet))[2:].zfill(8) for octet in octets])
        return binary_str.count('1')
    except Exception as e:
        log_message(f"Error converting subnet mask {subnet_mask} to prefix length: {e}")
        return 24  # Default to /24

def set_static_ip_config(adapter_name: str, ip_address: str, subnet_mask: str, gateway: str = None):
    """Set static IP configuration for an adapter using netsh."""
    try:
        # Build the netsh command
        if gateway:
            cmd = f'netsh interface ip set address name="{adapter_name}" static {ip_address} {subnet_mask} {gateway} 1'
        else:
            cmd = f'netsh interface ip set address name="{adapter_name}" static {ip_address} {subnet_mask}'
        
        log_message(f"Executing: {cmd}")
        
        # Execute using subprocess
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            log_message(f"Successfully set static IP {ip_address}/{subnet_mask} on {adapter_name}")
            if gateway:
                log_message(f"Gateway set to: {gateway}")
            return True
        else:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            log_message(f"netsh command failed (code {result.returncode}): {error_msg}")
            return False
            
    except subprocess.TimeoutExpired:
        log_message("netsh command timed out")
        return False
    except Exception as e:
        log_message(f"Exception in set_static_ip_config: {e}")
        return False

def configure_subnet_for_adapter(adapter_name: str):
    """Configure subnet mask and random IP for an adapter."""
    try:
        subnet_mask = get_random_subnet_mask()
        
        log_message(f"Configuring subnet for {adapter_name}: Subnet={subnet_mask}")
        
        # Set static IP configuration
        success = set_static_ip_config(adapter_name, subnet_mask)
        
        if success:
            log_message(f"Successfully configured subnet for {adapter_name}")
            return True
        else:
            log_message(f"Failed to configure subnet for {adapter_name}, reverting to DHCP")
            # Revert to DHCP if static configuration fails
            ps_cmd = f"""
            Set-NetIPInterface -InterfaceAlias '{adapter_name}' -Dhcp Enabled
            Write-Output "SUCCESS"
            """
            rc, out, err = run_powershell(ps_cmd)
            if rc == 0:
                log_message(f"Reverted {adapter_name} to DHCP")
            return False
            
    except Exception as e:
        return False

# =========================
# Network Detection Functions
# =========================

def get_all_network_adapters():
    """Get all network adapters with detailed information."""
    ps_cmd = """
    $adapters = Get-NetAdapter -Physical | Where-Object {
        $_.InterfaceDescription -notmatch 'Virtual|VMware|Hyper-V|TAP|Tunnel|Loopback'
    } | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, 
       @{Name="InterfaceIndex"; Expression={$_.ifIndex}},
       @{Name="ConnectorPresent"; Expression={$_.ConnectorPresent}},
       @{Name="MediaType"; Expression={$_.MediaType}},
       @{Name="InterfaceGuid"; Expression={$_.InterfaceGuid}}
    
    # Get IP configuration for each adapter
    $result = @()
    foreach ($adapter in $adapters) {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $dnsClient = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        
        $result += [PSCustomObject]@{
            Name = $adapter.Name
            Description = $adapter.InterfaceDescription
            Status = $adapter.Status
            MacAddress = $adapter.MacAddress
            LinkSpeed = $adapter.LinkSpeed
            InterfaceIndex = $adapter.InterfaceIndex
            ConnectorPresent = $adapter.ConnectorPresent
            MediaType = $adapter.MediaType
            InterfaceGuid = $adapter.InterfaceGuid
            IPAddress = if ($ipConfig) { $ipConfig.IPAddress } else { $null }
            DNSServers = if ($dnsClient) { $dnsClient.ServerAddresses } else { @() }
            HasIP = [bool]($ipConfig -and $ipConfig.IPAddress)
            SubnetMask = if ($ipConfig) { $ipConfig.PrefixLength } else { $null }
        }
    }
    $result | ConvertTo-Json -Depth 3
    """
    
    try:
        rc, out, err = run_powershell(ps_cmd)
        if rc == 0 and out:
            adapters = json.loads(out)
            if isinstance(adapters, dict):
                return [adapters]
            return adapters
    except Exception as e:
        log_message(f"Error getting network adapters: {e}")
    
    return []

def detect_network_interfaces():
    """Detect all network interfaces including wired and wireless."""
    wifi_adapters = []
    wired_adapters = []
    
    adapters = get_all_network_adapters()
    
    for adapter in adapters:
        description = adapter.get('Description', '').lower()
        name = adapter.get('Name', '').lower()
        
        if any(x in description for x in ['wireless', 'wi-fi', 'wifi', '802.11']) or \
           any(x in name for x in ['wireless', 'wi-fi', 'wifi']):
            adapter['Type'] = 'Wireless'
            wifi_adapters.append(adapter)
        elif any(x in description for x in ['ethernet', 'lan', 'gigabit']) or \
             any(x in name for x in ['ethernet', 'lan']):
            adapter['Type'] = 'Wired'
            wired_adapters.append(adapter)
        else:
            adapter['Type'] = 'Unknown'
            # Default to wired for unknown physical adapters
            wired_adapters.append(adapter)
    
    return wifi_adapters, wired_adapters

# =========================
# MAC Address Functions
# =========================

def generate_random_mac_no_sep() -> str:
    """Generate random MAC address without separators."""
    first = random.randint(0x00, 0xFF)
    first = (first & 0b11111100) | 0b00000010  # ensure bits: xxxxxx10
    remaining = [random.randint(0x00, 0xFF) for _ in range(5)]
    mac_bytes = [first] + remaining
    return ''.join(f"{A:02X}" for A in mac_bytes)

def generate_mac_starting_02():
    """Generate a MAC address that begins with 02 (locally administered)."""
    remaining_bytes = [random.randint(0x00, 0xFF) for _ in range(5)]
    mac_bytes = [0xE0] + remaining_bytes
    return ''.join(f"{A:02X}" for A in mac_bytes)

def generate_random_mac() -> str:
    """Generate random MAC address using various methods."""
    methods = [
        generate_random_mac_no_sep,
        generate_mac_starting_02
    ]
    return random.choice(methods)()

def get_adapter_registry_path(adapter_name):
    """Find the registry path for the network adapter."""
    try:
        ps_cmd = f"""
        $adapter = Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue
        if ($adapter) {{
            $regPath = Get-ChildItem "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}" -Recurse |
                      Where-Object {{ 
                          (Get-ItemProperty -Path $_.PSPath -Name NetCfgInstanceId -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $adapter.InterfaceGuid.Guid
                      }} |
                      Select-Object -First 1 -ExpandProperty PSPath
            if ($regPath) {{ Write-Output $regPath }}
        }}
        """
        rc, out, err = run_powershell(ps_cmd)
        if rc == 0 and out:
            return out.strip()
    except Exception as e:
        log_message(f"Error finding registry path: {e}")
    return None

def change_mac_registry_method(adapter_name, new_mac):
    """Change MAC address via registry method."""
    try:
        reg_path = get_adapter_registry_path(adapter_name)
        if not reg_path:
            return False, "Could not find adapter registry path"
        
        # Convert registry path format
        if reg_path.startswith('Microsoft.PowerShell.Core\\Registry::'):
            reg_path = reg_path.replace('Microsoft.PowerShell.Core\\Registry::', '')
        
        # Set NetworkAddress in registry
        cmd = f'reg add "{reg_path}" /v NetworkAddress /t REG_SZ /d "{new_mac}" /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            return True, "MAC address set in registry"
        else:
            return False, f"Registry command failed: {result.stderr}"
            
    except Exception as e:
        return False, f"Registry method exception: {str(e)}"

def restart_network_adapter(adapter_name):
    """Restart network adapter using multiple methods."""
    methods = [
        ("PowerShell Restart-NetAdapter", f"Restart-NetAdapter -Name '{adapter_name}' -Confirm:$false"),
        ("Netsh disable/enable", f"""
        netsh interface set interface \"{adapter_name}\" admin=disable
        Start-Sleep -Seconds 2
        netsh interface set interface \"{adapter_name}\" admin=enable
        """),
    ]
    
    for method_name, cmd in methods:
        try:
            rc, out, err = run_powershell(cmd)
            if rc == 0:
                log_message(f"Adapter restarted using {method_name}")
                return True
        except Exception:
            continue
    
    return False

def _try_ps_set_netadapter(adapter_name, new_mac):
    """Try Set-NetAdapter method."""
    try:
        ps_cmd = f"Set-NetAdapter -Name '{adapter_name}' -MacAddress '{new_mac}' -ErrorAction Stop; Write-Output 'SUCCESS'"
        rc, out, err = run_powershell(ps_cmd)
        if "SUCCESS" in out:
            return True, "Set-NetAdapter succeeded"
        return False, f"Set-NetAdapter failed: {err}"
    except Exception as e:
        return False, f"Set-NetAdapter exception: {str(e)}"

def _try_ps_advanced_properties(adapter_name, new_mac):
    """Try Set-NetAdapterAdvancedProperty method."""
    try:
        ps_cmd = f"""
        $result = Set-NetAdapterAdvancedProperty -Name '{adapter_name}' -RegistryKeyword 'NetworkAddress' -RegistryValue '{new_mac}' -ErrorAction SilentlyContinue
        if ($?) {{ Write-Output 'SUCCESS' }} else {{ Write-Output 'FAILED' }}
        """
        rc, out, err = run_powershell(ps_cmd)
        if "SUCCESS" in out:
            return True, "Advanced properties method succeeded"
        return False, f"Advanced properties failed: {err}"
    except Exception as e:
        return False, f"Advanced properties exception: {str(e)}"

def set_mac_and_restart(adapter_name, new_mac):
    """
    Try multiple methods to set MAC address.
    Returns tuple (success_bool, details_message)
    """
    methods = [
        ("PowerShell Set-NetAdapter", lambda: _try_ps_set_netadapter(adapter_name, new_mac)),
        ("PowerShell Advanced Properties", lambda: _try_ps_advanced_properties(adapter_name, new_mac)),
        ("Registry Method", lambda: change_mac_registry_method(adapter_name, new_mac)),
    ]
    
    for method_name, method_func in methods:
        log_message(f"Trying {method_name} for MAC change...")
        success, message = method_func()
        if success:
            # Restart adapter after successful MAC change
            time.sleep(2)
            restart_success = restart_network_adapter(adapter_name)
            if restart_success:
                return True, f"{method_name}: {message} - Adapter restarted"
            else:
                return True, f"{method_name}: {message} - But failed to restart adapter"
    
    return False, "All MAC change methods failed"

def change_mac_for_adapter(adapter_name: str, mac_no_sep_value: str) -> tuple:
    """
    Attempt to set MAC for adapter_name to mac_no_sep_value (12 hex chars, no separators).
    Returns (success: bool, message: str).
    """
    # Normalize mac value
    mac_val = re.sub(r'[^0-9A-Fa-f]', '', mac_no_sep_value).upper()
    if len(mac_val) != 12:
        return False, "MAC value must be 12 hex digits (no separators)"

    formatted_mac = ':'.join([mac_val[i:i+2] for i in range(0, 12, 2)])
    
    # Get current MAC for logging
    try:
        ps_cmd = f"(Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue).MacAddress"
        rc, current_mac, err = run_powershell(ps_cmd)
        if rc == 0 and current_mac:
            log_message(f"Changing MAC for {adapter_name}: {current_mac} -> {formatted_mac}")
    except:
        pass

    return set_mac_and_restart(adapter_name, formatted_mac)

# =========================
# Specific MAC Change Functions
# =========================

def change_wifi_mac():
    """Change Wi-Fi MAC address specifically with enhanced error handling."""
    if not is_admin():
        print("This operation requires Administrator privileges.")
        return False

    print("Detecting Wi-Fi interfaces...")
    wifi_adapters, wired_adapters = detect_network_interfaces()
    
    if not wifi_adapters:
        print("Could not detect any Wi-Fi interfaces automatically.")
        return False

    success_count = 0
    for adapter in wifi_adapters:
        adapter_name = adapter['Name']
        print(f"Processing Wi-Fi adapter: '{adapter_name}'")
        
        new_mac = generate_mac_starting_02()
        formatted_mac = ':'.join([new_mac[i:i+2] for i in range(0, 12, 2)])
        print(f"Generated MAC: {formatted_mac}")
        print("Attempting to set MAC address using multiple methods...")

        success, info = set_mac_and_restart(adapter_name, formatted_mac)
        if success:
            print("SUCCESS:", info)
            log_message(f"Wi-Fi MAC changed successfully: {formatted_mac} on adapter {adapter_name}")
            success_count += 1
            
            # Verify the change
            time.sleep(3)
            try:
                ps_cmd = f"(Get-NetAdapter -Name '{adapter_name}').MacAddress"
                rc, verify_mac, err = run_powershell(ps_cmd)
                if rc == 0 and verify_mac:
                    print(f"Verified new MAC: {verify_mac}")
                    if verify_mac.replace(':', '').upper() == new_mac:
                        print("MAC address change verified!")
                    else:
                        print("Warning: MAC address may not have changed as expected")
            except:
                pass
        else:
            print("FAILED to set MAC. Details:")
            print(info)
            log_message(f"Wi-Fi MAC change failed for {adapter_name}: {info}")
    
    print(f"Wi-Fi MAC change completed: {success_count}/{len(wifi_adapters)} adapters changed")
    return success_count > 0

def change_wired_mac():
    """Change wired Ethernet MAC addresses."""
    if not is_admin():
        print("This operation requires Administrator privileges.")
        return False

    print("Detecting wired Ethernet interfaces...")
    wifi_adapters, wired_adapters = detect_network_interfaces()
    
    if not wired_adapters:
        print("Could not detect any wired Ethernet interfaces automatically.")
        return False

    success_count = 0
    for adapter in wired_adapters:
        adapter_name = adapter['Name']
        print(f"Processing wired adapter: '{adapter_name}'")
        
        new_mac = generate_random_mac_no_sep()
        formatted_mac = ':'.join([new_mac[i:i+2] for i in range(0, 12, 2)])
        print(f"Generated MAC: {formatted_mac}")
        print("Attempting to set MAC address using multiple methods...")

        success, info = change_mac_for_adapter(adapter_name, new_mac)
        if success:
            print("SUCCESS:", info)
            log_message(f"Wired MAC changed successfully: {formatted_mac} on adapter {adapter_name}")
            success_count += 1
            
            # Verify the change
            time.sleep(3)
            try:
                ps_cmd = f"(Get-NetAdapter -Name '{adapter_name}').MacAddress"
                rc, verify_mac, err = run_powershell(ps_cmd)
                if rc == 0 and verify_mac:
                    print(f"Verified new MAC: {verify_mac}")
            except:
                pass
        else:
            print("FAILED to set MAC. Details:")
            print(info)
            log_message(f"Wired MAC change failed for {adapter_name}: {info}")
    
    print(f"Wired MAC change completed: {success_count}/{len(wired_adapters)} adapters changed")
    return success_count > 0

def change_all_physical_mac():
    """Change MAC addresses for all physical network adapters (both wired and wireless)."""
    if not is_admin():
        print("This operation requires Administrator privileges.")
        return False

    print("Detecting all physical network interfaces...")
    wifi_adapters, wired_adapters = detect_network_interfaces()
    all_adapters = wifi_adapters + wired_adapters
    
    if not all_adapters:
        print("Could not detect any physical network interfaces.")
        return False

    print(f"Found {len(all_adapters)} physical adapters:")
    for adapter in all_adapters:
        print(f"  - {adapter['Name']} ({adapter['Type']}): {adapter.get('MacAddress', 'Unknown')}")

    success_count = 0
    for adapter in all_adapters:
        adapter_name = adapter['Name']
        adapter_type = adapter['Type']
        
        print(f"\nProcessing {adapter_type} adapter: '{adapter_name}'")
        
        if adapter_type == "Wireless":
            new_mac = generate_mac_starting_02()
        else:
            new_mac = generate_random_mac_no_sep()
            
        formatted_mac = ':'.join([new_mac[i:i+2] for i in range(0, 12, 2)])
        print(f"Generated MAC: {formatted_mac}")
        
        success, info = change_mac_for_adapter(adapter_name, new_mac)
        if success:
            print("SUCCESS:", info)
            log_message(f"{adapter_type} MAC changed successfully: {formatted_mac} on adapter {adapter_name}")
            success_count += 1
        else:
            print("FAILED to set MAC. Details:")
            print(info)
            log_message(f"{adapter_type} MAC change failed for {adapter_name}: {info}")
        
        time.sleep(2)  # Brief pause between adapter changes
    
    print(f"\nPhysical MAC change summary: {success_count}/{len(all_adapters)} adapters changed successfully")
    return success_count > 0

# =========================
# Network / DNS / IPv6 ULA
# =========================

def assign_ula(adapter_name: str):
    """Assign a random IPv6 ULA /64 address to the adapter."""
    try:
        # Generate a random ULA prefix (fd00::/8)
        random_bytes = os.urandom(5)
        ula_prefix = "fd{:02x}:{:02x}{:02x}".format(
            random_bytes[0], random_bytes[1], random_bytes[2]
        )
        
        ula_address = f"{ula_prefix}::1/64"

        # Assign the address using PowerShell
        ps_cmd = f"""
        $adapter = Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue
        if ($adapter) {{
            Remove-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv6 -Confirm:$false -ErrorAction SilentlyContinue
            New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv6 -IPAddress "{ula_address}" -PrefixLength 64 -ErrorAction SilentlyContinue
            Write-Output "SUCCESS"
        }}
        """
        
        rc, out, err = run_powershell(ps_cmd)
        if rc == 0 and "SUCCESS" in out:
            log_message(f"Assigned IPv6 ULA address: {ula_address}")
            return True
        else:
            log_message(f"Failed to assign ULA address via PowerShell: {err}")
            return False
            
    except Exception as e:
        log_message(f"Failed to assign ULA address: {e}")
        return False

def pick_unique(items: list, count: int) -> list:
    """Pick unique random items from a list."""
    if count >= len(items):
        return items.copy()
    return random.sample(items, count)

def set_ipv4_dns(adapter_name: str, servers: list):
    """Set IPv4 DNS servers for the specified adapter."""
    try:
        if not servers:
            # revert to DHCP
            ps_cmd = f"""
            Set-DnsClientServerAddress -InterfaceAlias '{adapter_name}' -ResetServerAddresses
            Write-Output "SUCCESS"
            """
            rc, out, err = run_powershell(ps_cmd)
            if rc == 0:
                log_message(f"Reverted IPv4 DNS to DHCP for {adapter_name}")
            return
        
        # Set static DNS servers
        servers_str = ",".join([f'"{s}"' for s in servers])
        ps_cmd = f"""
        Set-DnsClientServerAddress -InterfaceAlias '{adapter_name}' -ServerAddresses @({servers_str})
        Write-Output "SUCCESS"
        """
        
        rc, out, err = run_powershell(ps_cmd)
        if rc == 0:
            log_message(f"Set IPv4 DNS servers to: {', '.join(servers)}")
            return True
        else:
            log_message(f"Failed to set IPv4 DNS: {err}")
            return False
            
    except Exception as e:
        log_message(f"Failed to set IPv4 DNS: {e}")
        return False

def set_ipv6_dns(adapter_name: str, servers: list):
    """Set IPv6 DNS servers for the specified adapter."""
    try:
        if not servers:
            return True
            
        # Set IPv6 DNS servers
        servers_str = ",".join([f'"{s}"' for s in servers])
        ps_cmd = f"""
        Set-DnsClientServerAddress -InterfaceAlias '{adapter_name}' -ServerAddresses @({servers_str})
        Write-Output "SUCCESS"
        """
        
        rc, out, err = run_powershell(ps_cmd)
        if rc == 0:
            log_message(f"Set IPv6 DNS servers to: {', '.join(servers)}")
            return True
        else:
            log_message(f"Failed to set IPv6 DNS: {err}")
            return False
            
    except Exception as e:
        log_message(f"Failed to set IPv6 DNS: {e}")
        return False

def configure_network_settings():
    """Configure DNS and ULA for active network adapters."""
    log_message("Configuring network settings...")
    
    # Get all adapters
    adapters = get_all_network_adapters()
    if not adapters:
        log_message("No network adapters found. Skipping network configuration.")
        return False
    
    success_count = 0
    for adapter in adapters:
        adapter_name = adapter['Name']
        adapter_status = adapter.get('Status', 'Unknown')
        
        log_message(f"Configuring adapter: {adapter_name} (Status: {adapter_status})")
        
        # Configure subnet mask and random IP
        subnet_success = configure_subnet_for_adapter(adapter_name)
        
        # Configure DNS servers
        ipv4_dns = pick_unique(DNS_V4, NUM_IPV4_DNS)
        ipv6_dns = pick_unique(DNS_V6, NUM_IPV6_DNS)
        
        dns_success = True
        if ipv4_dns:
            if not set_ipv4_dns(adapter_name, ipv4_dns):
                dns_success = False
        
        if ipv6_dns:
            if not set_ipv6_dns(adapter_name, ipv6_dns):
                dns_success = False
        
        # Assign ULA address
        ula_success = assign_ula(adapter_name)
        
        if dns_success or ula_success or subnet_success:
            success_count += 1
            log_message(f"Successfully configured {adapter_name}")
        else:
            log_message(f"Failed to configure {adapter_name}")
    
    log_message(f"Network configuration completed: {success_count}/{len(adapters)} adapters configured")
    return success_count > 0

# =========================
# GUID / Hostname
# =========================

def generate_new_guid() -> str:
    """Generate a GUID with random words a-z and numbers 1-9."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ6789012345"
    part1 = ''.join(random.choices(chars, k=8))
    part2 = ''.join(random.choices(chars, k=4))
    part3 = ''.join(random.choices(chars, k=4))
    part4 = ''.join(random.choices(chars, k=4))
    part5 = ''.join(random.choices(chars, k=12))
    return f"{part1}-{part2}-{part3}-{part4}-{part5}"

def _current_machine_guid() -> str | None:
    """Get current machine GUID from registry."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return value
    except FileNotFoundError:
        return None
    except Exception:
        return None

def reset_computer_guid(new_guid: str) -> bool:
    """
    Delete old MachineGuid and set the provided new GUID.
    Requires Administrator.
    """
    reg_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
    try:
        old = _current_machine_guid()
        if old:
            log_message(f"[INFO] Existing MachineGuid: {old}")
            # Export the key for safety
            try:
                backup_path = os.path.join(TEMP_DIR, "MachineGuid_backup.reg")
                subprocess.run(["reg", "export", r"HKLM\SOFTWARE\Microsoft\Cryptography", backup_path, "/y"],
                               capture_output=True, text=True)
                log_message(f"[INFO] Exported backup to: {backup_path}")
            except Exception as be:
                log_message(f"[WARN] Could not export registry backup: {be}")

        # Delete old
        subprocess.run(["reg", "delete", reg_path, "/v", "MachineGuid", "/f"],
                       check=False, shell=False, capture_output=True, text=True)
        log_message("Old MachineGuid deleted (or not present).")

        # Set new
        subprocess.run(
            ["reg", "add", reg_path, "/v", "MachineGuid", "/t", "REG_SZ", "/d", new_guid, "/f"],
            check=True, shell=False, capture_output=True, text=True
        )
        log_message(f"New MachineGuid set to: {new_guid}")
        return True

    except subprocess.CalledProcessError as e:
        log_message(f"[ERROR] Failed to reset MachineGuid: {e}\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}")
        return False

def generate_machine_name() -> str:
    """Generate random machine name."""
    suffix = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ6789012345", k=8))
    return f"SID-{suffix}"

def set_machine_name(new_name: str) -> bool:
    """Set machine name."""
    try:
        current_name = subprocess.check_output("hostname", text=True).strip()
        if current_name.lower() == new_name.lower():
            log_message(f"Machine name already set to {new_name}")
            return True

        # Ask user yes/no
        choice = input(f"Do you want to rename the machine to '{new_name}'? [y/n]: ").strip().lower()
        if choice not in ("y", "yes"):
            log_message("Machine rename skipped by user.")
            return False

        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", f'Rename-Computer -NewName "{new_name}" -Force -PassThru'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            log_message(f"Machine name set to: {new_name}. Reboot required.")
            return True
        else:
            log_message(f"[ERROR] Rename failed: {result.stderr.strip() or result.stdout.strip()}")
            return False

    except subprocess.CalledProcessError as e:
        log_message("[ERROR] Failed to rename machine:")
        log_message(f"STDOUT: {e.stdout}")
        log_message(f"STDERR: {e.stderr}")
        return False

# =========================
# Sysprep / SID logic
# =========================

def cleanup_sysprep_logs_recursive():
    """Recursively delete leftover Sysprep XML and log files in Panther and ActionFiles."""
    targets = {"diagwrn.xml", "diagerr.xml", "setupact.txt", "setuperr.txt"}
    paths = [
        r"C:\Windows\System32\Sysprep\Panther",
        r"C:\Windows\System32\Sysprep\ActionFiles"
    ]

    for root_path in paths:
        if os.path.exists(root_path):
            for dirpath, dirnames, filenames in os.walk(root_path):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    if fname.lower().endswith(".xml") or fname.lower() in targets:
                        try:
                            # Take ownership and grant permissions
                            subprocess.run(["takeown", "/F", fpath, "/A"], check=False)
                            subprocess.run(["icacls", fpath, "/grant", "Administrators:F"], check=False)
                            os.chmod(fpath, stat.S_IWRITE)
                            os.remove(fpath)
                            log_message(f"Deleted Sysprep file: {fpath}")
                        except Exception as e:
                            log_message(f"[WARN] Failed to delete {fname} in {dirpath}: {e}")

def get_machine_sid_from_admin_sid() -> str:
    """Return base machine SID by finding local admin (-500) account SID."""
    try:
        script = (
            "$u = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }; "
            "if ($u) { $u.SID.Value }"
        )
        res = subprocess.run(["powershell.exe", "-NoProfile", "-Command", script], text=True, capture_output=True)
        sid = res.stdout.strip()
        if sid and sid.endswith("-500"):
            return sid.rsplit("-", 1)[0]
    except Exception:
        pass

    # Fallback to WMIC
    try:
        result = subprocess.run(
            ["wmic", "useraccount", "where", "localaccount='true'", "get", "name,sid"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and line.endswith("-500"):
                return line.split()[-1].rsplit("-", 1)[0]
        return "UNKNOWN"
    except subprocess.CalledProcessError as e:
        log_message(f"[WARN] Unable to query Administrator SID: {e}")
        return "UNKNOWN"

def try_log_psgetsid():
    """Log the machine SID and all local user SIDs using PowerShell."""
    try:
        # Machine SID
        machine_sid_cmd = (
            "Get-WmiObject Win32_ComputerSystem | "
            "Select-Object -ExpandProperty SID"
        )
        machine_result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", machine_sid_cmd],
            capture_output=True, text=True
        )
        machine_sid = machine_result.stdout.strip()
        if machine_sid:
            log_message(f"[INFO] Machine SID: {machine_sid}")
        else:
            log_message("[WARN] Could not retrieve machine SID via PowerShell.")

        # Local user SIDs
        users_sid_cmd = (
            "Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' | "
            "Select-Object Name,SID | "
            "ForEach-Object { \"$($_.Name) -> $($_.SID)\" }"
        )
        users_result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", users_sid_cmd],
            capture_output=True, text=True
        )
        users_sids = users_result.stdout.strip()
        if users_sids:
            log_message("[INFO] Local user SIDs:\n" + users_sids)
        else:
            log_message("[WARN] Could not retrieve local user SIDs.")

    except Exception as e:
        log_message(f"[WARN] Failed to get SIDs: {e}")

def schedule_post_reboot_verification() -> bool:
    script_path = os.path.abspath(sys.argv[0])
    python_exe = sys.executable
    task_cmd = f'"{python_exe}" "{script_path}" --post-reboot'
    subprocess.run(["schtasks", "/Delete", "/TN", SCHEDULED_TASK_NAME, "/F"], capture_output=True, text=True)
    create = subprocess.run(
        ["schtasks", "/Create", "/SC", "ONSTART", "/TN", SCHEDULED_TASK_NAME,
         "/TR", task_cmd, "/RL", "HIGHEST", "/RU", "SYSTEM"],
        capture_output=True, text=True
    )
    if create.returncode == 0:
        log_message(f"[INFO] Scheduled post-reboot verification task: {SCHEDULED_TASK_NAME}")
        return True
    else:
        log_message(f"[ERROR] Failed to create scheduled task: {create.stderr.strip() or create.stdout.strip()}")
        return False

def delete_scheduled_task():
    subprocess.run(["schtasks", "/Delete", "/TN", SCHEDULED_TASK_NAME, "/F"], capture_output=True, text=True)

def post_reboot_verification():
    log_message("=== Post-reboot verification start ===")
    try:
        new_machine_sid = get_machine_sid_from_admin_sid()
        log_message(f"[POST] Machine SID base: {new_machine_sid}")
    except Exception as e:
        log_message(f"[POST][WARN] Failed to retrieve machine SID: {e}")

    try:
        res = subprocess.run(
            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
            capture_output=True, text=True, check=True
        )
        guid = None
        for line in res.stdout.splitlines():
            if "MachineGuid" in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    guid = parts[-1]
                    break
        if guid:
            log_message(f"[POST] MachineGuid: {guid}")
        else:
            log_message("[POST][WARN] MachineGuid not found in registry output.")
    except subprocess.CalledProcessError as e:
        log_message(f"[POST][ERROR] Could not read MachineGuid: {e}")

    try:
        hostname = subprocess.check_output("hostname", text=True).strip()
        log_message(f"[POST] Hostname: {hostname}")
    except Exception as e:
        log_message(f"[POST][WARN] Failed to get hostname: {e}")

    try:
        delete_scheduled_task()
    except Exception as e:
        log_message(f"[POST][WARN] Failed to delete scheduled task: {e}")

    log_message("=== Post-reboot verification complete ===")

def run_sysprep(reboot: bool = True) -> bool:
    sysprep_path = r"C:\Windows\System32\Sysprep\sysprep.exe"
    if not os.path.exists(sysprep_path):
        log_message(f"[ERROR] Sysprep not found at {sysprep_path}")
        return False
    try:
        args = [sysprep_path, "/generalize", "/oobe", "/quiet"]
        args.append("/reboot" if reboot else "/shutdown")
        subprocess.run(args, check=True)
        log_message("Sysprep started (generalize + OOBE). System will restart.")
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"[ERROR] Sysprep execution failed: {e}")
        return False

def regenerate_sid_with_sysprep() -> bool:
    try:
        new_machine_sid = get_machine_sid_from_admin_sid()
        log_message(f"[INFO] Current Machine SID base: {new_machine_sid}")

        # Log machine and user SIDs
        try_log_psgetsid()

        # Cleanup old Sysprep logs and XML files
        cleanup_sysprep_logs_recursive()

        if not schedule_post_reboot_verification():
            log_message("[WARN] Post-reboot verification task not created; continuing anyway.")

        if run_sysprep(reboot=True):
            log_message("[SUCCESS] Sysprep executed. SID will be regenerated during reboot.")
            return True
        else:
            log_message("[ERROR] Sysprep execution failed.")
            return False
    except Exception as e:
        log_message(f"[ERROR] SID regeneration failed: {e}")
        return False

# =========================
# Missing Functions - ADDED
# =========================

def fetch_and_parse_hostinger_geofeed() -> Tuple[List[str], List[str]]:
    """Fetch Hostinger geofeed data and extract all IPv4 and IPv6 addresses."""
    ipv4_addresses = set()
    ipv6_addresses = set()
    
    try:
        log_message("Fetching Hostinger geofeed data from GitHub...")
        response = requests.get(
            "https://raw.githubusercontent.com/hostinger/geofeed/main/geofeed.csv",
            timeout=30,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        response.raise_for_status()
        
        lines = response.text.split('\n')
        log_message(f"Processing {len(lines)} lines from Hostinger geofeed")
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip() or line.startswith('#'):
                continue
                
            parts = line.split(',')
            if len(parts) >= 1:
                ip_range = parts[0].strip()
                
                try:
                    # Try to parse as individual IP address
                    ip = ipaddress.ip_address(ip_range)
                    if ip.version == 4:
                        ipv4_addresses.add(str(ip))
                    else:
                        ipv6_addresses.add(str(ip))
                    continue
                except ValueError:
                    pass
                
                try:
                    # Try to parse as network range
                    network = ipaddress.ip_network(ip_range, strict=False)
                    
                    if network.version == 4:
                        # For IPv4 networks, add multiple usable addresses
                        if network.num_addresses <= 256:
                            hosts = list(network.hosts())
                            if hosts:
                                for i in range(min(5, len(hosts))):
                                    ipv4_addresses.add(str(hosts[i]))
                                ipv4_addresses.add(str(hosts[-1]))
                        else:
                            ipv4_addresses.add(str(network.network_address + 1))
                            ipv4_addresses.add(str(network.broadcast_address - 1))
                    else:
                        # For IPv6 networks
                        if network.num_addresses > 1:
                            first_addr = network.network_address + 1
                            ipv6_addresses.add(str(first_addr))
                            if network.num_addresses > 10:
                                mid_addr = network.network_address + (network.num_addresses // 2)
                                ipv6_addresses.add(str(mid_addr))
                            last_addr = network.broadcast_address - 1
                            ipv6_addresses.add(str(last_addr))
                            
                except ValueError as e:
                    log_message(f"Line {line_num}: Could not parse '{ip_range}' - {e}")
                    continue
        
        log_message(f"Extracted {len(ipv4_addresses)} IPv4 addresses from Hostinger geofeed")
        log_message(f"Extracted {len(ipv6_addresses)} IPv6 addresses from Hostinger geofeed")
        
        return list(ipv4_addresses), list(ipv6_addresses)
        
    except requests.RequestException as e:
        log_message(f"Failed to fetch Hostinger geofeed: {e}")
        return [], []
    except Exception as e:
        log_message(f"Error processing Hostinger geofeed: {e}")
        return [], []

def get_comprehensive_dns_servers() -> Tuple[List[str], List[str]]:
    """Get comprehensive DNS server lists including base servers and Hostinger geofeed data."""
    comprehensive_ipv4 = DNS_V4.copy()
    comprehensive_ipv6 = DNS_V6.copy()
    
    hostinger_ipv4, hostinger_ipv6 = fetch_and_parse_hostinger_geofeed()
    
    for server in hostinger_ipv4:
        if server not in comprehensive_ipv4:
            comprehensive_ipv4.append(server)
    
    for server in hostinger_ipv6:
        if server not in comprehensive_ipv6:
            comprehensive_ipv6.append(server)
    
    log_message(f"Comprehensive DNS lists: {len(comprehensive_ipv4)} IPv4, {len(comprehensive_ipv6)} IPv6 servers available")
    
    if comprehensive_ipv4:
        log_message(f"Sample IPv4 servers: {comprehensive_ipv4[:5]}...")
    if comprehensive_ipv6:
        log_message(f"Sample IPv6 servers: {comprehensive_ipv6[:5]}...")
    
    return comprehensive_ipv4, comprehensive_ipv6

def configure_network_settings_comprehensive():
    """Configure DNS and ULA for active network adapters using comprehensive DNS lists."""
    log_message("Configuring network settings with comprehensive DNS servers...")
    
    comprehensive_ipv4, comprehensive_ipv6 = get_comprehensive_dns_servers()
    
    adapters = get_all_network_adapters()
    if not adapters:
        log_message("No network adapters found. Skipping network configuration.")
        return False
    
    num_ipv4_dns = random.randint(3, min(10, len(comprehensive_ipv4)))
    num_ipv6_dns = random.randint(3, min(10, len(comprehensive_ipv6)))
    
    log_message(f"Using {num_ipv4_dns} IPv4 and {num_ipv6_dns} IPv6 DNS servers per adapter")
    
    success_count = 0
    for adapter in adapters:
        adapter_name = adapter['Name']
        adapter_status = adapter.get('Status', 'Unknown')
        
        log_message(f"Configuring adapter: {adapter_name} (Status: {adapter_status})")
        
        # Configure subnet mask and random IP
        subnet_success = configure_subnet_for_adapter(adapter_name)
        
        ipv4_dns = pick_unique(comprehensive_ipv4, num_ipv4_dns)
        ipv6_dns = pick_unique(comprehensive_ipv6, num_ipv6_dns)
        
        log_message(f"Selected {len(ipv4_dns)} IPv4 DNS servers for {adapter_name}")
        if ipv4_dns:
            log_message(f"IPv4 DNS: {ipv4_dns}")
        
        log_message(f"Selected {len(ipv6_dns)} IPv6 DNS servers for {adapter_name}")
        if ipv6_dns:
            log_message(f"IPv6 DNS: {ipv6_dns}")
        
        dns_success = True
        if ipv4_dns:
            if not set_ipv4_dns(adapter_name, ipv4_dns):
                dns_success = False
                log_message(f"Failed to set IPv4 DNS for {adapter_name}")
            else:
                log_message(f"Successfully set IPv4 DNS for {adapter_name}")
        
        if ipv6_dns:
            if not set_ipv6_dns(adapter_name, ipv6_dns):
                dns_success = False
                log_message(f"Failed to set IPv6 DNS for {adapter_name}")
            else:
                log_message(f"Successfully set IPv6 DNS for {adapter_name}")
        
        ula_success = assign_ula(adapter_name)
        if ula_success:
            log_message(f"Successfully assigned ULA address for {adapter_name}")
        else:
            log_message(f"Failed to assign ULA address for {adapter_name}")
        
        if dns_success or ula_success or subnet_success:
            success_count += 1
            log_message(f"Successfully configured {adapter_name}")
        else:
            log_message(f"Failed to configure {adapter_name}")
    
    log_message(f"Comprehensive network configuration completed: {success_count}/{len(adapters)} adapters configured")
    return success_count > 0

# =========================
# Main
# =========================

def main():
    """Main function."""
    if not is_admin():
        print("[INFO] Not running as admin, attempting elevation...")
        if run_as_admin():
            sys.exit(0)
        else:
            print("[ERROR] Could not elevate privileges.")
            sys.exit(1)

    print("[INFO] Running with admin rights!")

    parser = argparse.ArgumentParser(description="System Secure Script - By Sid Gifari")
    parser.add_argument("--post-reboot", action="store_true", help="Run post-reboot verification (internal).")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument("--wifi-only", action="store_true", help="Only change Wi-Fi MAC address.")
    parser.add_argument("--wired-only", action="store_true", help="Only change wired Ethernet MAC address.")
    parser.add_argument("--all-mac", action="store_true", help="Change MAC addresses for all network adapters.")
    parser.add_argument("--physical-mac", action="store_true", help="Change MAC addresses for all physical adapters (wired + wireless).")
    parser.add_argument("--network-only", action="store_true", help="Only configure network settings (DNS/ULA).")
    parser.add_argument("--comprehensive-dns", action="store_true", help="Use comprehensive DNS servers including all Hostinger geofeed data.")
    parser.add_argument("--subnet-only", action="store_true", help="Only configure subnet masks and random IP addresses.")
    args = parser.parse_args()

    if args.post_reboot:
        post_reboot_verification()
        return

    banner()

    # Subnet-only configuration mode
    if args.subnet_only:
        if not is_admin():
            log_message("Admin privileges required for subnet configuration.")
            if run_as_admin():
                sys.exit(0)
            else:
                sys.exit(1)
        
        adapters = get_all_network_adapters()
        if not adapters:
            log_message("No network adapters found.")
            sys.exit(1)
            
        success_count = 0
        for adapter in adapters:
            adapter_name = adapter['Name']
            if configure_subnet_for_adapter(adapter_name):
                success_count += 1
                
        log_message(f"Subnet configuration completed: {success_count}/{len(adapters)} adapters configured")
        sys.exit(0 if success_count > 0 else 1)

    # Network-only configuration mode
    if args.network_only:
        if not is_admin():
            log_message("Admin privileges required for network configuration.")
            if run_as_admin():
                sys.exit(0)
            else:
                sys.exit(1)
        if args.comprehensive_dns:
            success = configure_network_settings_comprehensive()
        else:
            success = configure_network_settings()
        sys.exit(0 if success else 1)

    # Wi-Fi MAC change only mode
    if args.wifi_only:
        if not is_admin():
            log_message("Admin privileges required for Wi-Fi MAC change.")
            if run_as_admin():
                sys.exit(0)
            else:
                sys.exit(1)
        success = change_wifi_mac()
        sys.exit(0 if success else 1)

    # Wired MAC change only mode
    if args.wired_only:
        if not is_admin():
            log_message("Admin privileges required for wired MAC change.")
            if run_as_admin():
                sys.exit(0)
            else:
                sys.exit(1)
        success = change_wired_mac()
        sys.exit(0 if success else 1)

    # All MAC addresses change mode (physical adapters)
    if args.all_mac or args.physical_mac:
        if not is_admin():
            log_message("Admin privileges required for MAC address changes.")
            if run_as_admin():
                sys.exit(0)
            else:
                sys.exit(1)
        success = change_all_physical_mac()
        sys.exit(0 if success else 1)

    # Full system security mode
    if not args.yes:
        try:
            confirm = input("System Secure By root@Sid-Gifari=type (yes/no): ").strip().lower()
        except EOFError:
            confirm = "no"
        if confirm != "yes":
            log_message("Sysprep aborted by user.")
            print("[ERROR] Secure Failed: Aborted by user")
            sys.exit(1)

    if not is_admin():
        log_message("Not running as admin, attempting to elevate...")
        if run_as_admin():
            sys.exit(0)
        else:
            log_message("[ERROR] Admin privileges required.")
            sys.exit(1)

    # Randomize MAC addresses for all physical adapters (both wired and wireless)
    log_message("Randomizing MAC addresses for all physical network adapters...")
    change_all_physical_mac()

    # Configure network settings (DNS, ULA, and subnet masks)
    log_message("Configuring network settings...")
    if args.comprehensive_dns:
        configure_network_settings_comprehensive()
    else:
        configure_network_settings()

    # Reset MachineGuid (delete & set new)
    new_guid = generate_new_guid()
    if not reset_computer_guid(new_guid):
        log_message("[ERROR] Failed to update MachineGuid. Aborting.")
        sys.exit(1)

    # Rename machine
    new_name = generate_machine_name()
    set_machine_name(new_name)

    # Regenerate SID via Sysprep (will reboot)
    new_machine_sid = regenerate_sid_with_sysprep()
    if not new_machine_sid:
        log_message("[ERROR] Could not start SID regeneration process.")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()