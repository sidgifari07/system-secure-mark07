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
import random
# =========================
# Config / Constants
# =========================
LOG_FILE = os.path.join(os.getenv("TEMP") or ".", "secure.log")
SCHEDULED_TASK_NAME = "SecureRotationTask"
SCHEDULED_TASK_NAME_MAC = "SecureMACRandomize"
TEMP_DIR = os.getenv("TEMP") or "."



DNS_V4 = [
    "1.1.1.1", "1.0.0.1",                     # Cloudflare
    "8.8.8.8", "8.8.4.4",                     # Google
    "9.9.9.9", "149.112.112.112",             # Quad9
    "185.228.168.9", "185.228.168.10",        # CleanBrowsing
    "208.67.222.222", "208.67.220.220",       # OpenDNS
    "84.200.69.80", "84.200.70.40",           # DNS.WATCH
    "64.6.64.6", "64.6.65.6",                 # Verisign
    "8.26.56.26", "8.20.247.20",              # Comodo Secure DNS
    "195.46.39.39", "195.46.39.40",           # SafeDNS
    "76.76.19.19", "76.223.122.150",          # Alternate DNS
    "94.140.14.14", "94.140.15.15"            # AdGuard DNS
]

DNS_V6 = [
    "2606:4700:4700::1111", "2606:4700:4700::1001",  # Cloudflare
    "2001:4860:4860::8888", "2001:4860:4860::8844",  # Google
    "2620:fe::fe", "2620:fe::9",                     # Quad9
    "2a0d:2a00:1::2", "2a0d:2a00:1::1",             # CleanBrowsing
    "2620:119:35::35", "2620:119:53::53",           # OpenDNS
    "2001:1608:10:25::1c04:b12f", "2001:1608:10:25::9249:d69b",  # DNS.WATCH
    "2620:74:1b::1:1", "2620:74:1c::2:2",           # Verisign
    "2001:67c:28a4::", "2001:67c:28a4::1",          # Digitalcourage
    "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff", # Yandex DNS
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",       # AdGuard DNS
    "2a0d:2a00:2::", "2a0d:2a00:2::1"               # NextDNS
]

# Add CIDR notation
DNS_V4_CIDR = [ip + "/24" for ip in DNS_V4]
DNS_V6_CIDR = [ip + "/64" for ip in DNS_V6]

# Number of random servers to pick
NUM_IPV4_DNS = 10
NUM_IPV6_DNS = 10

# Random sample (no duplicates)
rand_v4_list = random.sample(DNS_V4_CIDR, min(NUM_IPV4_DNS, len(DNS_V4_CIDR)))
rand_v6_list = random.sample(DNS_V6_CIDR, min(NUM_IPV6_DNS, len(DNS_V6_CIDR)))



# =========================
# Helper Functions
# =========================

def is_admin() -> bool:
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_as_admin() -> bool:
    """Re-run the script with admin rights. Returns True if elevation was started."""
    try:
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        # ShellExecute returns >32 if successful
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        return int(ret) > 32
    except Exception as e:
        print(f"[ERROR] Failed to elevate privileges: {e}")
        return False

def log_message(message: str):
    """Log message to console and log file."""
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

def run_powershell(cmd):
    """Run a PowerShell command and return (returncode, stdout, stderr)."""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True, text=True, timeout=30
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

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
# Enhanced MAC Address Functions (All Physical Adapters)
# =========================

def get_all_physical_adapters() -> list:
    """
    Get all physical network adapters (both wired and wireless) that are not virtual.
    Returns list of adapter names.
    """
    ps_cmd = r"""
    $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.InterfaceDescription -notmatch 'Virtual|VMware|Hyper-V|Microsoft\sHyper-V|TAP|Tunnel|Loopback' -and
                    $_.InterfaceDescription -match 'Ethernet|Wireless|Wi-Fi|802.11|LAN|Network'
                } |
                Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
    $adapters | ConvertTo-Json -Compress
    """
    
    try:
        rc, out, err = run_powershell(ps_cmd)
        if rc == 0 and out:
            adapters = json.loads(out)
            if isinstance(adapters, dict):
                return [adapters]
            return adapters
    except Exception as e:
        log_message(f"Error getting physical adapters: {e}")
    
    # Fallback method
    try:
        ps_cmd_fallback = r"""
        Get-NetAdapter -Physical | Where-Object { 
            $_.InterfaceDescription -notmatch 'Virtual|VMware|Hyper-V' 
        } | Select-Object Name | ConvertTo-Json
        """
        rc, out, err = run_powershell(ps_cmd_fallback)
        if rc == 0 and out:
            adapters = json.loads(out)
            if isinstance(adapters, dict):
                return [adapters['Name']]
            return [adapter['Name'] for adapter in adapters]
    except Exception:
        pass
    
    return []

def detect_network_interfaces():
    """Detect all network interfaces including wired and wireless."""
    wifi_adapters = []
    wired_adapters = []
    
    try:
        ps_cmd = r"""
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                    Where-Object { $_.InterfaceDescription -notmatch 'Virtual|VMware|Hyper-V' }
        $results = @()
        foreach ($adapter in $adapters) {
            $type = "Unknown"
            if ($adapter.InterfaceDescription -match 'Wireless|Wi-Fi|802.11') {
                $type = "Wireless"
            } elseif ($adapter.InterfaceDescription -match 'Ethernet|LAN') {
                $type = "Wired"
            }
            $results += [PSCustomObject]@{
                Name = $adapter.Name
                Type = $type
                Description = $adapter.InterfaceDescription
                Status = $adapter.Status
                MacAddress = $adapter.MacAddress
            }
        }
        $results | ConvertTo-Json -Compress
        """
        
        rc, out, err = run_powershell(ps_cmd)
        if rc == 0 and out:
            adapters = json.loads(out)
            if isinstance(adapters, dict):
                adapters = [adapters]
            
            for adapter in adapters:
                if adapter['Type'] == 'Wireless':
                    wifi_adapters.append(adapter)
                elif adapter['Type'] == 'Wired':
                    wired_adapters.append(adapter)
                    
    except Exception as e:
        log_message(f"Error detecting network interfaces: {e}")
    
    return wifi_adapters, wired_adapters

def generate_random_mac_no_sep() -> str:
    """Generate random MAC address without separators."""
    # first byte: set locally administered (bit 1 = 1) and unicast (bit 0 = 0)
    first = random.randint(0x00, 0xFF)
    first = (first & 0b11111100) | 0b00000010  # ensure bits: xxxxxx10
    remaining = [random.randint(0x00, 0xFF) for _ in range(5)]
    mac_bytes = [first] + remaining
    return ''.join(f"{b:02X}" for b in mac_bytes)

def generate_mac_starting_02():
    """Generate a MAC address that begins with 02 (locally administered)."""
    remaining_bytes = [random.randint(0x00, 0xFF) for _ in range(5)]
    mac_bytes = [0x02] + remaining_bytes
    return ''.join(f"{b:02X}" for b in mac_bytes)

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

def change_mac_device_manager_method(adapter_name, new_mac):
    """Change MAC address using devcon utility (Device Manager method)."""
    try:
        # First get the device instance ID
        ps_cmd = f"""
        $adapter = Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue
        if ($adapter) {{ Write-Output $adapter.InterfaceDescription }}
        """
        rc, interface_desc, err = run_powershell(ps_cmd)
        
        if rc != 0 or not interface_desc:
            return False, "Could not get interface description"
        
        # Try to find devcon.exe in common locations
        devcon_paths = [
            r"C:\Windows\System32\devcon.exe",
            r"C:\Program Files (x86)\Windows Kits\10\Tools\x64\devcon.exe",
            r"C:\Program Files (x86)\Windows Kits\8.1\Tools\x64\devcon.exe"
        ]
        
        devcon = None
        for path in devcon_paths:
            if os.path.exists(path):
                devcon = path
                break
        
        if not devcon:
            return False, "devcon.exe not found"
        
        # Disable the adapter
        disable_cmd = f'"{devcon}" disable "@{interface_desc}"'
        result = subprocess.run(disable_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            return False, f"Failed to disable adapter: {result.stderr}"
        
        # Set MAC address in registry (we'll use the same registry method)
        success, msg = change_mac_registry_method(adapter_name, new_mac)
        if not success:
            # Re-enable adapter if MAC change failed
            enable_cmd = f'"{devcon}" enable "@{interface_desc}"'
            subprocess.run(enable_cmd, shell=True, capture_output=True, text=True)
            return False, msg
        
        # Re-enable the adapter
        enable_cmd = f'"{devcon}" enable "@{interface_desc}"'
        result = subprocess.run(enable_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            return True, "MAC changed successfully using Device Manager method"
        else:
            return False, f"Failed to re-enable adapter: {result.stderr}"
            
    except Exception as e:
        return False, f"Device Manager method exception: {str(e)}"

def restart_network_adapter(adapter_name):
    """Restart network adapter using multiple methods."""
    methods = [
        ("PowerShell Restart-NetAdapter", f"Restart-NetAdapter -Name '{adapter_name}' -Confirm:$false"),
        ("Netsh disable/enable", f"""
        netsh interface set interface \"{adapter_name}\" admin=disable
        Start-Sleep -Seconds 2
        netsh interface set interface \"{adapter_name}\" admin=enable
        """),
        ("WMI Method", f"""
        $adapter = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object {{ $_.NetConnectionId -eq '{adapter_name}' }}
        if ($adapter) {{
            $adapter.Disable()
            Start-Sleep -Seconds 2
            $adapter.Enable()
        }}
        """)
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
        ("Device Manager Method", lambda: change_mac_device_manager_method(adapter_name, new_mac))
    ]
    
    for method_name, method_func in methods:
        log_message(f"Trying {method_name} for MAC change...")
        success, message = method_func()
        if success:
            # Restart adapter after successful MAC change
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
            
            # Provide user with manual instructions
            print("\n" + "="*50)
            print("MANUAL FALLBACK INSTRUCTIONS:")
            print("1. Open Device Manager (devmgmt.msc)")
            print("2. Find your Wi-Fi adapter under 'Network adapters'")
            print("3. Right-click → Properties → Advanced tab")
            print("4. Look for 'Network Address' or 'Locally Administered Address'")
            print("5. Set value to:", formatted_mac)
            print("6. Disable and re-enable the adapter")
            print("="*50)
    
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

def randomize_all_mac_addresses():
    """Legacy function - alias for change_all_physical_mac."""
    return change_all_physical_mac()

# =========================
# Network / DNS / IPv6 ULA
# =========================

def get_connected_adapter_name() -> str:
    """Get the name of the first connected network adapter."""
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1 -ExpandProperty Name"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""

import os
import subprocess

def assign_ula(adapter_name: str):
    """Assign a random IPv6 ULA /64 address to the adapter."""
    try:
        # Generate a random ULA prefix (fd00::/8)
        random_bytes = os.urandom(5)
        ula_prefix = "fd{:02x}:{:02x}{:02x}::".format(
            random_bytes[0], random_bytes[1], random_bytes[2]
        )
        
        ula_address = f"{ula_prefix}1/64"

        # Assign the address
        subprocess.run(
            ["netsh", "interface", "ipv6", "add", "address", adapter_name, ula_address],
            check=True
        )
        log_message(f"Assigned IPv6 ULA address: {ula_address}")
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to assign ULA address: {e}")


def pick_unique(items: list, count: int) -> list:
    """Pick unique random items from a list."""
    if count >= len(items):
        return items.copy()
    return random.sample(items, count)

def set_ipv4_dns(adapter_name: str, servers: list):
    """Set IPv4 DNS servers for the specified adapter."""
    try:
        # Set to static primary first
        if not servers:
            # revert to DHCP
            subprocess.run(["netsh", "interface", "ipv4", "set", "dnsservers", "name="+adapter_name, "source=dhcp"], check=True)
            log_message(f"Reverted IPv4 DNS to DHCP for {adapter_name}")
            return
        # set primary
        subprocess.run(["netsh", "interface", "ipv4", "set", "dnsservers", "name="+adapter_name, "static", servers[0], "primary"], check=True)
        for i, srv in enumerate(servers[1:], start=2):
            subprocess.run(["netsh", "interface", "ipv4", "add", "dnsservers", "name="+adapter_name, srv, f"index={i}"], check=True)
        log_message(f"Set IPv4 DNS servers to: {', '.join(servers)}")
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to set IPv4 DNS: {e}")

def set_ipv6_dns(adapter_name: str, servers: list):
    """Set IPv6 DNS servers for the specified adapter."""
    try:
        # First clear existing DNS
        subprocess.run(
            ["netsh", "interface", "ipv6", "set", "dnsservers", 
             f'"{adapter_name}"', "static", "none"],
            check=False
        )
        
        # Set new DNS servers
        for i, server in enumerate(servers, 1):
            subprocess.run(
                ["netsh", "interface", "ipv6", "add", "dnsservers", 
                 f'"{adapter_name}"', server, str(i)],
                check=True
            )
        log_message(f"Set IPv6 DNS servers to: {', '.join(servers)}")
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to set IPv6 DNS: {e}")

# =========================
# GUID / Hostname
# =========================

def generate_new_guid() -> str:
    """Generate a GUID with random words a-z and numbers 1-9."""
    # Create a custom alphabet with letters a-z and numbers 1-9
    chars = "abcdefghijklmnopqrstuvwxyz123456789"
    
    # Generate each part of the GUID with random characters
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

import random
import subprocess

def generate_machine_name() -> str:
    """Generate random machine name."""
    suffix = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=5))
    return f"SidDesktop-{suffix}"

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

import os
import stat
import subprocess

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

import subprocess

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
# Windows Firewall Security
# =========================

def configure_windows_firewall():
    """Enable and configure Windows Firewall for all profiles."""
    try:
        log_message("[INFO] Configuring Windows Firewall...")

        # Enable Firewall for Domain, Private, and Public profiles
        profiles = ["Domain", "Private", "Public"]
        for profile in profiles:
            cmd = f"Set-NetFirewallProfile -Profile {profile} -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow"
            rc, out, err = run_powershell(cmd)
            if rc == 0:
                log_message(f"[INFO] Firewall enabled for {profile} profile. Inbound blocked, Outbound allowed.")
            else:
                log_message(f"[WARN] Could not configure {profile} profile: {err}")

        # Enable logging for dropped packets
        cmd_logging = r"""
        Set-NetFirewallProfile -Profile Domain,Private,Public -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384 -LogAllowed True -LogBlocked True
        """
        rc, out, err = run_powershell(cmd_logging)
        if rc == 0:
            log_message("[INFO] Firewall logging configured.")
        else:
            log_message(f"[WARN] Failed to configure firewall logging: {err}")

    except Exception as e:
        log_message(f"[ERROR] Windows Firewall configuration failed: {e}")

# =========================
# Main
# =========================

def main():
    """Main function."""
    if not is_admin():
        print("[INFO] Not running as admin, attempting elevation...")
        if run_as_admin():
            sys.exit(0)  # exit original, elevated instance continues
        else:
            print("[ERROR] Could not elevate privileges.")
            sys.exit(1)

    # === main script logic starts here ===
    print("[INFO] Running with admin rights!")

    parser = argparse.ArgumentParser(description="System Secure Script - By Sid Gifari")
    parser.add_argument("--post-reboot", action="store_true", help="Run post-reboot verification (internal).")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument("--wifi-only", action="store_true", help="Only change Wi-Fi MAC address.")
    parser.add_argument("--wired-only", action="store_true", help="Only change wired Ethernet MAC address.")
    parser.add_argument("--all-mac", action="store_true", help="Change MAC addresses for all network adapters.")
    parser.add_argument("--physical-mac", action="store_true", help="Change MAC addresses for all physical adapters (wired + wireless).")
    args = parser.parse_args()

    if args.post_reboot:
        post_reboot_verification()
        return

    banner()
    # Configure Windows Firewall for added security
    configure_windows_firewall()
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
            sys.exit(0)  # elevated instance will continue with same args
        else:
            log_message("[ERROR] Admin privileges required.")
            sys.exit(1)

    # Randomize MAC addresses for all physical adapters (both wired and wireless)
    log_message("Randomizing MAC addresses for all physical network adapters...")
    change_all_physical_mac()

    adapter = get_connected_adapter_name()
    if adapter:
        log_message(f"Using network adapter: {adapter}")
        assign_ula(adapter)

        ipv4_dns = pick_unique(DNS_V4, NUM_IPV4_DNS)
        ipv6_dns = pick_unique(DNS_V6, NUM_IPV6_DNS)

        if ipv4_dns:
            set_ipv4_dns(adapter, ipv4_dns)
        if ipv6_dns:
            set_ipv6_dns(adapter, ipv6_dns)
    else:
        log_message("[WARN] No active network adapter detected. Skipping DNS/ULA configuration.")

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