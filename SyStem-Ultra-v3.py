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
LOG_FILE = ("secure.log")
SCHEDULED_TASK_NAME = "SIDRegenerationVerification"


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
        
SUBNET_MASKS = [
    "255.0.0.0",
    "255.128.0.0", 
    "255.192.0.0",

]

# HTTPS DNS Servers - IPv4
HTTPS_DNS_V4 = [
    "8.8.8.8",           # Google DNS (supports DNS-over-HTTPS)
    "1.1.1.1",           # Cloudflare DNS (supports DNS-over-HTTPS)
    "9.9.9.9",           # Quad9 DNS (supports DNS-over-HTTPS)
    "94.140.14.14",      # AdGuard DNS (supports DNS-over-HTTPS)
    "185.228.168.168",   # CleanBrowsing DNS (supports DNS-over-HTTPS)
    "76.76.19.19",       # Alternate DNS (supports DNS-over-HTTPS)
    "76.223.122.150",    # Alternate DNS (supports DNS-over-HTTPS)
    "208.67.222.222",    # OpenDNS (supports DNS-over-HTTPS)
    "8.26.56.26",        # Comodo Secure DNS
    "64.6.64.6",         # Verisign DNS
]

# HTTPS DNS Servers - IPv6
HTTPS_DNS_V6 = [
    "2001:4860:4860::8888",      # Google DNS
    "2606:4700:4700::1111",      # Cloudflare DNS
    "2620:fe::fe",               # Quad9 DNS
    "2a0d:2a00:1::",             # AdGuard DNS
    "2a0d:2a00:2::",             # AdGuard DNS
    "2606:4700:4700::1001",      # Cloudflare Family
    "2001:678:9d::1",            # Digitalcourage DNS
    "2a00:5a60::ad1:0ff",        # AdGuard Family
    "2a00:5a60::ad2:0ff",        # AdGuard Family
    "2a10:50c0::ad1:ff",         # AdGuard DNS
]

DNS_V4 = [
"1.1.1.1",
"1.1.1.2",
"1.1.1.3",
"1.1.1.4",
"1.1.1.5",
"1.1.1.6",
"1.1.1.7",
"1.1.1.8",
"1.1.1.9",
"1.1.1.10",
"1.1.1.11",
"1.1.1.12",
"1.1.1.13",
"1.1.1.14",
"1.1.1.15",
"1.1.1.16",
"1.1.1.17",
"1.1.1.18",
"1.1.1.19",
"1.1.1.20",
"1.1.1.21",
"1.1.1.22",
"1.1.1.23",
"1.1.1.24",
"1.1.1.25",
"1.1.1.26",
"1.1.1.27",
"1.1.1.28",
"1.1.1.29",
"1.1.1.30",
"1.1.1.31",
"1.1.1.32",
"1.1.1.33",
"1.1.1.34",
"1.1.1.35",
"1.1.1.36",
"1.1.1.37",
"1.1.1.38",
"1.1.1.39",
"1.1.1.40",
"1.1.1.41",
"1.1.1.42",
"1.1.1.43",
"1.1.1.44",
"1.1.1.45",
"1.1.1.46",
"1.1.1.47",
"1.1.1.48",
"1.1.1.49",
"1.1.1.50",
"1.1.1.51",
"1.1.1.52",
"1.1.1.53",
"1.1.1.54",
"1.1.1.55",
"1.1.1.56",

]

DNS_V6 = [
"fd1a:a3e:4165:4098:14d3:c2a8:1b0b:5bbb",
"fd1e:f55c:c372:fd64:a0f4:2444:8012:d0c3",
"fd31:5b76:34ec:7c73:4fa5:9c4:88e9:5d56",
"fd73:3be0:f642:57c9:29c7:73b9:566f:948",
"fd87:ad2b:59f2:db44:1da:cd47:efa1:7e5b",
"fd88:f15b:5c60:b905:1dfd:3e5d:459b:1947",
"fd96:80fc:c402:cc2d:a8bd:ca4b:9835:c016",
"fddf:851f:dfd5:f24b:3247:ef91:b434:592d",
"fde9:d1f5:3e35:645d:39bc:f8c:6f08:4b37",
"fdf4:2803:cae6:e79f:9476:d661:15a4:ffa6",

]

# Combine regular DNS with HTTPS DNS servers
ALL_DNS_V4 = DNS_V4 + HTTPS_DNS_V4
ALL_DNS_V6 = DNS_V6 + HTTPS_DNS_V6

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
                                

███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗      ███████╗██╗  ██╗██╗██╗     ██████╗ 
██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║      ██╔════╝██║  ██║██║██║     ██╔══██╗
███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║█████╗███████╗███████║██║██║     ██║  ██║
╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║╚════╝╚════██║██╔══██║██║██║     ██║  ██║
███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║      ███████║██║  ██║██║███████╗██████╔╝
╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝      ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝ 
                                                                                              
███╗   ███╗ █████╗ ██████╗ ██╗  ██╗      ██████╗  █████╗                                      
████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝     ██╔═████╗██╔══██╗                                     
██╔████╔██║███████║██████╔╝█████╔╝█████╗██║██╔██║╚█████╔╝                                     
██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗╚════╝████╔╝██║██╔══██╗                                     
██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗     ╚██████╔╝╚█████╔╝                                     
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝      ╚═════╝  ╚════╝                                      
                                                                                              
System Secure Script By Sid Gifari
From Gifari Industries - BD Cyber Security Team                                                                                              
                                                                                                                                                                     
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

def set_static_ip_config(adapter_name: str, subnet_mask: str, gateway: str = None):
    """Set static IP configuration for an adapter using netsh."""
    try:
        # Build the netsh command
        if gateway:
            cmd = f'netsh interface ip set address name="{adapter_name}" static {subnet_mask} {gateway} 1'
        else:
            cmd = f'netsh interface ip set address name="{adapter_name}" static {subnet_mask}'
        
        log_message(f"Executing: {cmd}")
        
        # Execute using subprocess
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            log_message(f"Successfully set static IP {subnet_mask} on {adapter_name}")
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
        
        # Configure DNS servers using combined list
        ipv4_dns = pick_unique(ALL_DNS_V4, NUM_IPV4_DNS)
        ipv6_dns = pick_unique(ALL_DNS_V6, NUM_IPV6_DNS)
        
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
    """Recursively delete leftover Sysprep XML and log files in Panther and ActionFiles, and remove empty folders."""
    targets = {"diagwrn.xml", "diagerr.xml", "setupact.txt", "setuperr.txt", "Microsoft", "pip", "Temp", 
               "Package Cache", "Packages", "D3DSCache", "ConnectedDevicesPlatform", "Programs"}
    paths = [
        r"C:\Windows\System32\Sysprep\Panther",
        r"C:\Windows\System32\Sysprep\ActionFiles",
        r"C:\Users\sidgi\AppData\Local"
    ]
    
    for root_path in paths:
        if os.path.exists(root_path):
            for dirpath, dirnames, filenames in os.walk(root_path, topdown=False):  # topdown=False to remove empty folders after files
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
                
                # Remove empty directories
                for dir_name in dirnames:
                    dir_to_remove = os.path.join(dirpath, dir_name)
                    try:
                        os.rmdir(dir_to_remove)
                        log_message(f"Deleted empty folder: {dir_to_remove}")
                    except OSError as e:
                        log_message(f"[WARN] Failed to delete folder {dir_to_remove}: {e}")

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
    comprehensive_ipv4 = ALL_DNS_V4.copy()
    comprehensive_ipv6 = ALL_DNS_V6.copy()
    
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
