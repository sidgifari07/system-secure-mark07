"""
System Secure Script - By Sid Gifari
From Gifari Industries - BD Cyber Security Team

UPGRADED VERSION - Production-ready hardening & network randomization
"""

import ctypes
import subprocess
import random
import sys
import os
import time
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import uuid
import shutil
import argparse
import stat
import re
import winreg
import ipaddress
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Set, Optional, Dict, Any

# =========================
# Config / Constants
# =========================
LOG_FILE = os.path.join(os.getenv("TEMP") or ".", "secure.log")
SCHEDULED_TASK_NAME = "SecureRotationTask"
TEMP_DIR = os.getenv("TEMP") or "."

# Subnet masks by prefix length (/21 - /30)
SUBNET_MASKS = [
    "255.255.255.0",    # /24
    "255.255.0.0",      # /16
    "255.255.255.128",  # /25
    "255.255.255.192",  # /26
    "255.255.255.240",  # /28
    "255.255.255.248",  # /29
    "255.255.255.252",  # /30
    "255.255.254.0",    # /23
    "255.255.252.0",    # /22
    "255.255.248.0",    # /21
]

# Private IPv4 ranges for random IP generation
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_log_lock = threading.Lock()
_logger: Optional[logging.Logger] = None


# =========================
# Logging Setup
# =========================
def setup_logging(level: str = "INFO") -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger

    os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)
    logger = logging.getLogger("secure")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    # Rotating file handler (5 MB x 3 backups)
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024,
                             backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)

    logger.handlers.clear()
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.propagate = False

    _logger = logger
    return logger


def log_message(message: str, level: str = "info"):
    log = setup_logging()
    with _log_lock:
        getattr(log, level.lower(), log.info)(message)


# =========================
# Admin / Elevation
# =========================
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


# =========================
# DNS Server Lists
# =========================
DNS_V4 = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "64.6.64.6", "64.6.65.6", "84.200.69.80", "84.200.70.40",
    "8.26.56.26", "8.20.247.20", "195.46.39.39", "195.46.39.40",
    "76.76.19.19", "76.223.122.150", "94.140.14.14", "94.140.15.15",
    "185.228.168.9", "185.228.168.10", "76.76.2.0", "76.76.10.0",
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
    "209.244.0.3", "209.244.0.4", "216.146.35.35", "216.146.36.36",
    "37.235.1.174", "37.235.1.177", "198.101.242.72", "23.253.163.53",
    "156.154.70.1", "156.154.71.1", "176.103.130.130", "176.103.130.131",
    "199.85.126.10", "199.85.127.10", "81.218.119.11", "209.88.198.133",
    "195.46.39.40", "195.46.39.41", "205.210.42.205", "64.68.200.200",
    "202.83.95.229", "202.83.95.227", "203.112.2.4", "203.112.2.5",
    "203.80.96.10", "203.80.96.9", "218.248.255.212", "218.102.23.228",
    "45.90.28.0", "45.90.30.0", "185.222.222.222", "185.184.222.222",
    "80.80.80.80", "80.80.81.81", "89.233.43.71", "91.239.100.100",
    "5.2.75.75", "5.2.75.76", "194.150.168.168", "194.150.169.168",
    "87.118.100.175", "87.118.101.175", "212.51.137.101", "212.51.137.102",
    "77.109.148.136", "77.109.149.136", "91.217.137.37", "91.217.137.38",
    "188.93.95.95", "188.93.95.96", "193.58.251.251", "193.58.251.252",
    "109.69.8.51", "109.69.8.52", "156.154.70.22", "156.154.71.22",
    "202.12.27.33", "202.12.27.34", "210.138.175.244", "210.138.175.245",
    "219.100.37.10", "219.100.37.20", "202.67.240.222", "202.67.240.221",
    "164.124.101.2", "203.248.252.2", "168.126.63.1", "168.126.63.2",
    "202.46.32.19", "202.46.32.20", "196.3.58.12", "196.3.59.12",
    "200.7.84.10", "200.7.84.11", "200.42.160.68", "200.42.160.69",
    "190.64.58.21", "190.64.58.22", "200.48.225.130", "200.48.225.131",
    "190.122.186.17", "190.122.186.18", "200.31.248.130", "200.31.248.131",
    "201.218.154.1", "201.218.154.2", "200.33.171.11", "200.33.171.12",
]

DNS_V6 = [
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2620:fe::fe", "2620:fe::9",
    "2620:119:35::35", "2620:119:53::53",
    "2001:1608:10:25::1c04:b12f", "2001:1608:10:25::9249:d69b",
    "2a0d:2a00:1::2", "2a0d:2a00:1::1",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
    "2620:74:1b::1:1", "2620:74:1c::2:2",
    "2001:67c:28a4::", "2001:67c:28a4::1",
    "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff",
    "2a0d:2a00:2::", "2a0d:2a00:2::1",
    "2001:678:68::", "2001:678:6c::",
    "2001:678:78::", "2001:678:7c::",
    "2001:1900:3001:11::c", "2001:1900:3001:11::d",
    "2001:1900:3001:12::c", "2001:1900:3001:12::d",
    "2606:4700:4700::1112", "2606:4700:4700::1002",
    "2001:4860:4860::8889", "2001:4860:4860::8845",
    "2a00:5a60::ad1:ff", "2a00:5a60::ad2:ff",
    "2a0d:2a00:1::3", "2a0d:2a00:1::4",
    "2606:4700:4700::64", "2606:4700:4700::6400",
    "2001:4860:4860::6464", "2001:4860:4860::64",
]

NUM_IPV4_DNS = 10
NUM_IPV6_DNS = 10


# =========================
# Helpers
# =========================
def run_powershell(cmd: str, timeout: int = 60) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "PowerShell command timed out"
    except Exception as e:
        return -1, "", f"PowerShell execution failed: {e}"


def banner():
    print(rf"""
███╗   ███╗ █████╗ ██████╗ ██╗  ██╗      ██████╗ ███████╗
████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝     ██╔═████╗╚════██║
██╔████╔██║███████║██████╔╝█████╔╝█████╗██║██╔██║    ██╔╝
██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗╚════╝████╔╝██║   ██╔╝
██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗     ╚██████╔╝   ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝      ╚═════╝    ╚═╝
System Secure Script By Sid Gifari
From Gifari Industries - BD Cyber Security Team
Logs saved to: {LOG_FILE}
""")


# =========================
# Subnet / IP Configuration
# =========================
def is_network_working(adapter_name: str) -> bool:
    """Check if network is working by testing connectivity."""
    try:
        ps_cmd = """
        try {
            $r = Resolve-DnsName -Name "google.com" -ErrorAction SilentlyContinue -QuickTimeout
            if ($r) { Write-Output 'True'; exit }
        } catch {}
        try {
            $t = Test-NetConnection -ComputerName "1.1.1.1" -Port 53 -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($t) { Write-Output 'True'; exit }
        } catch {}
        Write-Output 'False'
        """
        rc, out, _ = run_powershell(ps_cmd, timeout=20)
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

        ps_cmd = f"""
        $adapter = Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue
        if ($adapter) {{
            Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -Dhcp Enabled -ErrorAction SilentlyContinue
            ipconfig /release "{adapter_name}" | Out-Null
            ipconfig /renew "{adapter_name}" | Out-Null
            Write-Output "SUCCESS"
        }}
        """
        rc, out, _ = run_powershell(ps_cmd, timeout=45)

        if rc == 0:
            time.sleep(6)
            if is_network_working(adapter_name):
                log_message(f"Successfully restored network connectivity for {adapter_name}")
                return True

        log_message(f"Trying TCP/IP reset for {adapter_name}...")
        run_powershell("netsh int ip reset reset.log; netsh winsock reset", timeout=60)
        time.sleep(3)
        run_powershell(f"Restart-NetAdapter -Name '{adapter_name}' -Confirm:$false", timeout=60)
        time.sleep(8)

        ok = is_network_working(adapter_name)
        if ok:
            log_message(f"Restored connectivity for {adapter_name} via reset")
        else:
            log_message(f"Failed to restore connectivity for {adapter_name}", "error")
        return ok

    except Exception as e:
        log_message(f"Error restoring network connectivity: {e}", "error")
        return False


def get_random_subnet_mask() -> str:
    return random.choice(SUBNET_MASKS)


def subnet_mask_to_prefix(subnet_mask: str) -> int:
    try:
        octets = subnet_mask.split('.')
        bits = ''.join(bin(int(o))[2:].zfill(8) for o in octets)
        return bits.count('1')
    except Exception:
        return 24


def random_private_ip(prefix_len: int) -> str:
    """Generate a random private IPv4 address usable within a /prefix_len network."""
    base_net = random.choice(PRIVATE_RANGES)
    # Use a random subnet of the requested prefix within the base range
    if prefix_len < base_net.prefixlen:
        prefix_len = base_net.prefixlen
    # Choose a random subnet
    subnets = list(base_net.subnets(new_prefix=prefix_len))
    chosen = random.choice(subnets)
    hosts = list(chosen.hosts())
    if hosts:
        # Prefer not to grab the first host to reduce collisions with gateway
        return str(random.choice(hosts[1:])) if len(hosts) > 1 else str(hosts[0])
    return str(chosen.network_address + 1)


def get_adapter_ipv4_config(adapter_name: str) -> Dict[str, Any]:
    """Return current IPv4 config: IP, mask, gateway, dhcp status."""
    ps_cmd = f"""
    $ip = Get-NetIPAddress -InterfaceAlias '{adapter_name}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    $gw = Get-NetRoute -InterfaceAlias '{adapter_name}' -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
    $iface = Get-NetIPInterface -InterfaceAlias '{adapter_name}' -AddressFamily IPv4 -ErrorAction SilentlyContinue
    [PSCustomObject]@{{
        IPAddress = if ($ip) {{ $ip.IPAddress }} else {{ $null }}
        PrefixLength = if ($ip) {{ $ip.PrefixLength }} else {{ $null }}
        Gateway = if ($gw) {{ $gw.NextHop }} else {{ $null }}
        Dhcp = if ($iface) {{ $iface.Dhcp }} else {{ $null }}
    }} | ConvertTo-Json -Compress
    """
    try:
        rc, out, _ = run_powershell(ps_cmd, timeout=20)
        if rc == 0 and out:
            return json.loads(out)
    except Exception:
        pass
    return {}


def set_static_ip_config(adapter_name: str, ip_address: str,
                         subnet_mask: str, gateway: Optional[str] = None) -> bool:
    """Set static IP configuration using netsh (with proper validation)."""
    try:
        # Validate IP
        ipaddress.ip_address(ip_address)

        if gateway:
            cmd = (f'netsh interface ip set address name="{adapter_name}" '
                   f'static {ip_address} {subnet_mask} {gateway} 1')
        else:
            cmd = (f'netsh interface ip set address name="{adapter_name}" '
                   f'static {ip_address} {subnet_mask}')

        log_message(f"Executing: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=30)

        if result.returncode == 0:
            log_message(f"Set static IP {ip_address}/{subnet_mask} on {adapter_name}")
            return True
        log_message(f"netsh failed ({result.returncode}): {result.stderr.strip()}", "error")
        return False
    except subprocess.TimeoutExpired:
        log_message("netsh command timed out", "error")
        return False
    except Exception as e:
        log_message(f"Exception in set_static_ip_config: {e}", "error")
        return False


def configure_subnet_for_adapter(adapter_name: str,
                                  dry_run: bool = False,
                                  preserve_gateway: bool = True) -> bool:
    """
    Configure a random private IP + subnet mask on the adapter.
    Preserves the existing default gateway (so internet still works).
    Rolls back to DHCP on failure.
    """
    try:
        current = get_adapter_ipv4_config(adapter_name)
        old_ip = current.get("IPAddress")
        old_gw = current.get("Gateway")

        subnet_mask = get_random_subnet_mask()
        prefix_len = subnet_mask_to_prefix(subnet_mask)
        new_ip = random_private_ip(prefix_len)

        gateway = old_gw if (preserve_gateway and old_gw) else None

        log_message(f"Subnet config for {adapter_name}: {new_ip}/{prefix_len} "
                    f"(mask={subnet_mask}) gw={gateway or 'none'}")

        if dry_run:
            log_message(f"[DRY-RUN] Would set {adapter_name} to {new_ip}/{prefix_len}")
            return True

        # Apply
        success = set_static_ip_config(adapter_name, new_ip, subnet_mask, gateway)

        if success:
            # Connectivity check
            time.sleep(2)
            if is_network_working(adapter_name):
                log_message(f"Subnet configured & connectivity verified for {adapter_name}")
                return True
            log_message(f"Connectivity lost on {adapter_name}, rolling back...", "warn")
            # Rollback: revert to DHCP
            run_powershell(
                f"Set-NetIPInterface -InterfaceAlias '{adapter_name}' -Dhcp Enabled "
                f"-ErrorAction SilentlyContinue; "
                f"ipconfig /renew \"{adapter_name}\" | Out-Null",
                timeout=45
            )
            time.sleep(5)
            if is_network_working(adapter_name):
                log_message(f"Rolled back {adapter_name} to DHCP (connectivity restored)")
                return False

        # Fallback: hard reset
        log_message(f"Static config failed on {adapter_name}, reverting to DHCP...", "warn")
        run_powershell(
            f"Set-NetIPInterface -InterfaceAlias '{adapter_name}' -Dhcp Enabled "
            f"-ErrorAction SilentlyContinue; "
            f"ipconfig /renew \"{adapter_name}\" | Out-Null",
            timeout=45
        )
        return False

    except Exception as e:
        log_message(f"configure_subnet_for_adapter error: {e}", "error")
        return False


# =========================
# Network Detection
# =========================
def get_all_network_adapters(only_up: bool = False) -> List[Dict[str, Any]]:
    """Get all physical network adapters."""
    ps_cmd = """
    $adapters = Get-NetAdapter -Physical | Where-Object {
        $_.InterfaceDescription -notmatch 'Virtual|VMware|Hyper-V|TAP|Tunnel|Loopback|Bluetooth'
    } | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed,
       @{Name="InterfaceIndex"; Expression={$_.ifIndex}},
       @{Name="MediaType"; Expression={$_.MediaType}},
       @{Name="InterfaceGuid"; Expression={$_.InterfaceGuid}}

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
            MediaType = $adapter.MediaType
            InterfaceGuid = $adapter.InterfaceGuid
            IPAddress = if ($ipConfig) { $ipConfig.IPAddress } else { $null }
            DNSServers = if ($dnsClient) { $dnsClient.ServerAddresses } else { @() }
            HasIP = [bool]($ipConfig -and $ipConfig.IPAddress)
        }
    }
    $result | ConvertTo-Json -Depth 3
    """
    try:
        rc, out, err = run_powershell(ps_cmd, timeout=30)
        if rc == 0 and out:
            adapters = json.loads(out)
            if isinstance(adapters, dict):
                adapters = [adapters]
            if only_up:
                adapters = [a for a in adapters if a.get("Status") == "Up"]
            return adapters
    except Exception as e:
        log_message(f"Error getting network adapters: {e}", "error")
    return []


def detect_network_interfaces(only_up: bool = False) -> Tuple[List[Dict], List[Dict]]:
    """Return (wifi_adapters, wired_adapters)."""
    wifi, wired = [], []
    for adapter in get_all_network_adapters(only_up=only_up):
        desc = (adapter.get("Description") or "").lower()
        name = (adapter.get("Name") or "").lower()
        if any(x in desc for x in ("wireless", "wi-fi", "wifi", "802.11")) or \
           any(x in name for x in ("wireless", "wi-fi", "wifi")):
            adapter["Type"] = "Wireless"
            wifi.append(adapter)
        elif any(x in desc for x in ("ethernet", "lan", "gigabit")) or \
             any(x in name for x in ("ethernet", "lan")):
            adapter["Type"] = "Wired"
            wired.append(adapter)
        else:
            adapter["Type"] = "Unknown"
            wired.append(adapter)
    return wifi, wired


# =========================
# MAC Address
# =========================
def generate_random_mac_no_sep() -> str:
    """Generate a locally-administered unicast MAC (no separators)."""
    first = random.randint(0x00, 0xFF)
    first = (first & 0b11111100) | 0b00000010  # ensure unicast + locally-administered
    remaining = [random.randint(0x00, 0xFF) for _ in range(5)]
    return ''.join(f"{b:02X}" for b in [first] + remaining)


def generate_mac_starting_02() -> str:
    """MAC starting with 02 (locally administered)."""
    return "02" + ''.join(f"{random.randint(0x00, 0xFF):02X}" for _ in range(5))


def generate_random_mac() -> str:
    return random.choice([generate_random_mac_no_sep, generate_mac_starting_02])()


def get_adapter_registry_path(adapter_name: str) -> Optional[str]:
    """Find the registry path for the network adapter's driver key."""
    try:
        ps_cmd = f"""
        $adapter = Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue
        if ($adapter) {{
            $guid = $adapter.InterfaceGuid
            $base = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}'
            Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {{
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($props.NetCfgInstanceId -eq $guid) {{ Write-Output $_.PSPath }}
            }}
        }}
        """
        rc, out, _ = run_powershell(ps_cmd, timeout=20)
        if rc == 0 and out:
            path = out.strip().splitlines()[0].strip()
            if path.startswith("Microsoft.PowerShell.Core\\Registry::"):
                path = path.replace("Microsoft.PowerShell.Core\\Registry::", "")
            return path
    except Exception as e:
        log_message(f"Error finding registry path: {e}", "error")
    return None


def change_mac_registry_method(adapter_name: str, new_mac: str) -> Tuple[bool, str]:
    try:
        reg_path = get_adapter_registry_path(adapter_name)
        if not reg_path:
            return False, "Could not find adapter registry path"
        cmd = f'reg add "{reg_path}" /v NetworkAddress /t REG_SZ /d "{new_mac}" /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return True, "MAC set in registry"
        return False, f"reg failed: {result.stderr.strip()}"
    except Exception as e:
        return False, f"Registry method exception: {e}"


def restart_network_adapter(adapter_name: str) -> bool:
    methods = [
        ("Restart-NetAdapter", f"Restart-NetAdapter -Name '{adapter_name}' -Confirm:$false"),
        ("netsh disable/enable",
         f'netsh interface set interface "{adapter_name}" admin=disable; '
         f'Start-Sleep -Seconds 2; '
         f'netsh interface set interface "{adapter_name}" admin=enable'),
    ]
    for name, cmd in methods:
        try:
            rc, _, _ = run_powershell(cmd, timeout=60)
            if rc == 0:
                log_message(f"Adapter restarted via {name}")
                return True
        except Exception:
            continue
    return False


def _try_ps_set_netadapter(adapter_name: str, new_mac: str) -> Tuple[bool, str]:
    try:
        ps_cmd = (f"Set-NetAdapter -Name '{adapter_name}' -MacAddress '{new_mac}' "
                  f"-ErrorAction Stop; Write-Output 'SUCCESS'")
        rc, out, err = run_powershell(ps_cmd, timeout=30)
        if "SUCCESS" in out:
            return True, "Set-NetAdapter succeeded"
        return False, f"Set-NetAdapter failed: {err}"
    except Exception as e:
        return False, f"Set-NetAdapter exception: {e}"


def _try_ps_advanced_properties(adapter_name: str, new_mac: str) -> Tuple[bool, str]:
    try:
        ps_cmd = (f"Set-NetAdapterAdvancedProperty -Name '{adapter_name}' "
                  f"-RegistryKeyword 'NetworkAddress' -RegistryValue '{new_mac}' "
                  f"-ErrorAction SilentlyContinue; "
                  f"if ($?) {{ Write-Output 'SUCCESS' }} else {{ Write-Output 'FAILED' }}")
        rc, out, err = run_powershell(ps_cmd, timeout=30)
        if "SUCCESS" in out:
            return True, "Advanced properties method succeeded"
        return False, f"Advanced properties failed: {err}"
    except Exception as e:
        return False, f"Advanced properties exception: {e}"


def set_mac_and_restart(adapter_name: str, new_mac: str) -> Tuple[bool, str]:
    methods = [
        ("PowerShell Set-NetAdapter", lambda: _try_ps_set_netadapter(adapter_name, new_mac)),
        ("PowerShell Advanced Properties", lambda: _try_ps_advanced_properties(adapter_name, new_mac)),
        ("Registry Method", lambda: change_mac_registry_method(adapter_name, new_mac)),
    ]
    for name, fn in methods:
        log_message(f"Trying {name} for MAC change...")
        success, message = fn()
        if success:
            time.sleep(2)
            if restart_network_adapter(adapter_name):
                return True, f"{name}: {message} - Adapter restarted"
            return True, f"{name}: {message} - Adapter restart failed"
    return False, "All MAC change methods failed"


def change_mac_for_adapter(adapter_name: str, mac_no_sep: str) -> Tuple[bool, str]:
    mac_val = re.sub(r'[^0-9A-Fa-f]', '', mac_no_sep).upper()
    if len(mac_val) != 12:
        return False, "MAC must be 12 hex digits"
    formatted = ':'.join(mac_val[i:i+2] for i in range(0, 12, 2))

    # Log current MAC
    try:
        ps_cmd = f"(Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue).MacAddress"
        rc, cur, _ = run_powershell(ps_cmd, timeout=10)
        if rc == 0 and cur:
            log_message(f"Changing MAC {adapter_name}: {cur} -> {formatted}")
    except Exception:
        pass
    return set_mac_and_restart(adapter_name, formatted)


# =========================
# Wi-Fi / Wired MAC change entry points
# =========================
def change_wifi_mac(dry_run: bool = False) -> bool:
    if not is_admin():
        print("This operation requires Administrator privileges.")
        return False

    wifi, _ = detect_network_interfaces()
    if not wifi:
        print("Could not detect any Wi-Fi interfaces.")
        return False

    ok = 0
    for adapter in wifi:
        name = adapter["Name"]
        print(f"Processing Wi-Fi adapter: '{name}'")
        new_mac = generate_mac_starting_02()
        formatted = ':'.join(new_mac[i:i+2] for i in range(0, 12, 2))
        print(f"Generated MAC: {formatted}")

        if dry_run:
            print(f"[DRY-RUN] Would set {name} MAC to {formatted}")
            ok += 1
            continue

        success, info = set_mac_and_restart(name, formatted)
        if success:
            print("SUCCESS:", info)
            log_message(f"Wi-Fi MAC changed: {formatted} on {name}")
            ok += 1
            # Verify
            time.sleep(3)
            rc, verify, _ = run_powershell(
                f"(Get-NetAdapter -Name '{name}').MacAddress", timeout=10
            )
            if rc == 0 and verify:
                print(f"Verified new MAC: {verify}")
        else:
            print("FAILED:", info)
            log_message(f"Wi-Fi MAC change failed on {name}: {info}", "error")

    print(f"Wi-Fi MAC change: {ok}/{len(wifi)} adapters changed")
    return ok > 0


def change_wired_mac(dry_run: bool = False) -> bool:
    if not is_admin():
        print("This operation requires Administrator privileges.")
        return False

    _, wired = detect_network_interfaces()
    if not wired:
        print("Could not detect any wired interfaces.")
        return False

    ok = 0
    for adapter in wired:
        name = adapter["Name"]
        print(f"Processing wired adapter: '{name}'")
        new_mac = generate_random_mac_no_sep()
        formatted = ':'.join(new_mac[i:i+2] for i in range(0, 12, 2))
        print(f"Generated MAC: {formatted}")

        if dry_run:
            print(f"[DRY-RUN] Would set {name} MAC to {formatted}")
            ok += 1
            continue

        success, info = change_mac_for_adapter(name, new_mac)
        if success:
            print("SUCCESS:", info)
            log_message(f"Wired MAC changed: {formatted} on {name}")
            ok += 1
        else:
            print("FAILED:", info)
            log_message(f"Wired MAC change failed on {name}: {info}", "error")

    print(f"Wired MAC change: {ok}/{len(wired)} adapters changed")
    return ok > 0


def change_all_physical_mac(dry_run: bool = False) -> bool:
    if not is_admin():
        print("This operation requires Administrator privileges.")
        return False

    wifi, wired = detect_network_interfaces()
    all_adapters = wifi + wired
    if not all_adapters:
        print("Could not detect any physical network interfaces.")
        return False

    print(f"Found {len(all_adapters)} physical adapters:")
    for a in all_adapters:
        print(f"  - {a['Name']} ({a['Type']}): {a.get('MacAddress', 'Unknown')}")

    ok = 0
    for adapter in all_adapters:
        name = adapter["Name"]
        atype = adapter["Type"]
        print(f"\nProcessing {atype} adapter: '{name}'")

        new_mac = generate_mac_starting_02() if atype == "Wireless" \
            else generate_random_mac_no_sep()
        formatted = ':'.join(new_mac[i:i+2] for i in range(0, 12, 2))
        print(f"Generated MAC: {formatted}")

        if dry_run:
            print(f"[DRY-RUN] Would set {name} MAC to {formatted}")
            ok += 1
            continue

        success, info = change_mac_for_adapter(name, new_mac)
        if success:
            print("SUCCESS:", info)
            log_message(f"{atype} MAC changed: {formatted} on {name}")
            ok += 1
        else:
            print("FAILED:", info)
            log_message(f"{atype} MAC change failed on {name}: {info}", "error")
        time.sleep(2)

    print(f"\nPhysical MAC change: {ok}/{len(all_adapters)} adapters changed")
    return ok > 0


# =========================
# DNS / ULA
# =========================
def assign_ula(adapter_name: str, dry_run: bool = False) -> bool:
    try:
        b = os.urandom(5)
        ula_prefix = f"fd{b[0]:02x}:{b[1]:02x}{b[2]:02x}"
        ula_address = f"{ula_prefix}::1/64"

        if dry_run:
            log_message(f"[DRY-RUN] Would assign ULA {ula_address} to {adapter_name}")
            return True

        ps_cmd = f"""
        $adapter = Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue
        if ($adapter) {{
            Remove-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv6 -Confirm:$false -ErrorAction SilentlyContinue
            New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv6 -IPAddress "{ula_address}" -PrefixLength 64 -ErrorAction SilentlyContinue
            Write-Output "SUCCESS"
        }}
        """
        rc, out, err = run_powershell(ps_cmd, timeout=30)
        if rc == 0 and "SUCCESS" in out:
            log_message(f"Assigned ULA: {ula_address} to {adapter_name}")
            return True
        log_message(f"ULA assignment failed for {adapter_name}: {err}", "warn")
        return False
    except Exception as e:
        log_message(f"ULA error: {e}", "error")
        return False


def pick_unique(items: List[str], count: int) -> List[str]:
    if count >= len(items):
        return list(items)
    return random.sample(items, count)


def set_ipv4_dns(adapter_name: str, servers: List[str], dry_run: bool = False) -> bool:
    try:
        if not servers:
            if dry_run:
                return True
            ps_cmd = (f"Set-DnsClientServerAddress -InterfaceAlias '{adapter_name}' "
                      f"-ResetServerAddresses; Write-Output 'SUCCESS'")
            rc, _, _ = run_powershell(ps_cmd, timeout=20)
            return rc == 0

        if dry_run:
            log_message(f"[DRY-RUN] Would set IPv4 DNS on {adapter_name}: {servers}")
            return True

        s = ",".join(f'"{x}"' for x in servers)
        ps_cmd = (f"Set-DnsClientServerAddress -InterfaceAlias '{adapter_name}' "
                  f"-ServerAddresses @({s}); Write-Output 'SUCCESS'")
        rc, out, err = run_powershell(ps_cmd, timeout=30)
        if rc == 0 and "SUCCESS" in out:
            log_message(f"IPv4 DNS set on {adapter_name}: {servers}")
            return True
        log_message(f"Failed IPv4 DNS on {adapter_name}: {err}", "warn")
        return False
    except Exception as e:
        log_message(f"IPv4 DNS error: {e}", "error")
        return False


def set_ipv6_dns(adapter_name: str, servers: List[str], dry_run: bool = False) -> bool:
    try:
        if not servers:
            return True
        if dry_run:
            log_message(f"[DRY-RUN] Would set IPv6 DNS on {adapter_name}: {servers}")
            return True

        s = ",".join(f'"{x}"' for x in servers)
        ps_cmd = (f"Set-DnsClientServerAddress -InterfaceAlias '{adapter_name}' "
                  f"-ServerAddresses @({s}); Write-Output 'SUCCESS'")
        rc, out, err = run_powershell(ps_cmd, timeout=30)
        if rc == 0 and "SUCCESS" in out:
            log_message(f"IPv6 DNS set on {adapter_name}: {servers}")
            return True
        log_message(f"Failed IPv6 DNS on {adapter_name}: {err}", "warn")
        return False
    except Exception as e:
        log_message(f"IPv6 DNS error: {e}", "error")
        return False


def fetch_and_parse_hostinger_geofeed() -> Tuple[List[str], List[str]]:
    v4, v6 = set(), set()
    try:
        log_message("Fetching Hostinger geofeed...")
        r = requests.get(
            "https://raw.githubusercontent.com/hostinger/geofeed/main/geofeed.csv",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        r.raise_for_status()
        for line in r.text.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split(",")
            if not parts:
                continue
            addr = parts[0].strip()
            try:
                ip = ipaddress.ip_address(addr)
                (v4 if ip.version == 4 else v6).add(str(ip))
                continue
            except ValueError:
                pass
            try:
                net = ipaddress.ip_network(addr, strict=False)
                if net.version == 4:
                    if net.num_addresses <= 256:
                        for h in list(net.hosts())[:5]:
                            v4.add(str(h))
                    else:
                        v4.add(str(net.network_address + 1))
                        v4.add(str(net.broadcast_address - 1))
                else:
                    v6.add(str(net.network_address + 1))
                    v6.add(str(net.broadcast_address - 1))
            except ValueError:
                continue
        log_message(f"Hostinger geofeed: {len(v4)} IPv4, {len(v6)} IPv6")
    except Exception as e:
        log_message(f"Hostinger fetch failed: {e}", "warn")
    return list(v4), list(v6)


def get_comprehensive_dns_servers() -> Tuple[List[str], List[str]]:
    v4, v6 = list(DNS_V4), list(DNS_V6)
    hv4, hv6 = fetch_and_parse_hostinger_geofeed()
    v4.extend(x for x in hv4 if x not in v4)
    v6.extend(x for x in hv6 if x not in v6)
    log_message(f"Comprehensive DNS: {len(v4)} IPv4, {len(v6)} IPv6")
    return v4, v6


def _configure_one_adapter(adapter: Dict, opts: Dict) -> bool:
    """Configure a single adapter (used by both sync & parallel paths)."""
    name = adapter["Name"]
    log_message(f"Configuring adapter: {name} (Status: {adapter.get('Status')})")

    results = []

    # 1) Subnet / IP
    if not opts["skip_subnet"]:
        results.append(configure_subnet_for_adapter(
            name, dry_run=opts["dry_run"], preserve_gateway=True
        ))

    # 2) DNS
    if opts["ipv4_dns"]:
        results.append(set_ipv4_dns(name, opts["ipv4_dns"], dry_run=opts["dry_run"]))
    if opts["ipv6_dns"]:
        results.append(set_ipv6_dns(name, opts["ipv6_dns"], dry_run=opts["dry_run"]))

    # 3) ULA
    if not opts["skip_ula"]:
        results.append(assign_ula(name, dry_run=opts["dry_run"]))

    # 4) Restore connectivity if broken
    if not opts["dry_run"] and not opts["no_restore"]:
        if not is_network_working(name):
            restore_network_connectivity(name)

    return any(results)


def configure_network_settings(comprehensive: bool = False,
                               dry_run: bool = False,
                               dns_count: Optional[int] = None,
                               skip_ula: bool = False,
                               skip_subnet: bool = False,
                               no_restore: bool = False,
                               parallel: bool = True,
                               target_names: Optional[Set[str]] = None) -> bool:
    log_message("Configuring network settings...")

    if comprehensive:
        v4_pool, v6_pool = get_comprehensive_dns_servers()
    else:
        v4_pool, v6_pool = list(DNS_V4), list(DNS_V6)

    adapters = get_all_network_adapters()
    if target_names:
        adapters = [a for a in adapters if a["Name"] in target_names]
    if not adapters:
        log_message("No matching network adapters found.")
        return False

    n_v4 = dns_count or random.randint(3, min(10, len(v4_pool)))
    n_v6 = dns_count or random.randint(3, min(10, len(v6_pool)))

    def worker(adapter):
        opts = {
            "dry_run": dry_run,
            "skip_ula": skip_ula,
            "skip_subnet": skip_subnet,
            "no_restore": no_restore,
            "ipv4_dns": pick_unique(v4_pool, n_v4),
            "ipv6_dns": pick_unique(v6_pool, n_v6),
        }
        try:
            return adapter["Name"], _configure_one_adapter(adapter, opts)
        except Exception as e:
            log_message(f"Worker failed for {adapter['Name']}: {e}", "error")
            return adapter["Name"], False

    ok = 0
    if parallel and len(adapters) > 1:
        with ThreadPoolExecutor(max_workers=min(4, len(adapters))) as ex:
            futures = {ex.submit(worker, a): a for a in adapters}
            for fut in as_completed(futures):
                _, success = fut.result()
                if success:
                    ok += 1
    else:
        for a in adapters:
            _, success = worker(a)
            if success:
                ok += 1

    log_message(f"Network configuration: {ok}/{len(adapters)} adapters configured")
    return ok > 0


# =========================
# GUID / Hostname
# =========================
def generate_new_guid() -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ6789012345"
    parts = [8, 4, 4, 4, 12]
    return "-".join(''.join(random.choices(chars, k=n)) for n in parts)


def _current_machine_guid() -> Optional[str]:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography", 0,
                            winreg.KEY_READ) as key:
            v, _ = winreg.QueryValueEx(key, "MachineGuid")
            return v
    except Exception:
        return None


def reset_computer_guid(new_guid: str, dry_run: bool = False) -> bool:
    reg_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
    try:
        old = _current_machine_guid()
        if old:
            log_message(f"Existing MachineGuid: {old}")
            try:
                backup = os.path.join(TEMP_DIR, "MachineGuid_backup.reg")
                subprocess.run(
                    ["reg", "export", r"HKLM\SOFTWARE\Microsoft\Cryptography",
                     backup, "/y"], capture_output=True, text=True
                )
                log_message(f"Backup exported to {backup}")
            except Exception as e:
                log_message(f"Backup export failed: {e}", "warn")

        if dry_run:
            log_message(f"[DRY-RUN] Would set MachineGuid to {new_guid}")
            return True

        subprocess.run(["reg", "delete", reg_path, "/v", "MachineGuid", "/f"],
                       capture_output=True, text=True)
        subprocess.run(["reg", "add", reg_path, "/v", "MachineGuid",
                        "/t", "REG_SZ", "/d", new_guid, "/f"],
                       capture_output=True, text=True, check=True)
        log_message(f"MachineGuid set to {new_guid}")
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"MachineGuid reset failed: {e}", "error")
        return False


def generate_machine_name() -> str:
    suffix = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ6789012345", k=8))
    return f"SID-{suffix}"


def set_machine_name(new_name: str, dry_run: bool = False,
                     assume_yes: bool = False) -> bool:
    try:
        cur = subprocess.check_output("hostname", text=True).strip()
        if cur.lower() == new_name.lower():
            log_message(f"Machine name already {new_name}")
            return True
        if dry_run:
            log_message(f"[DRY-RUN] Would rename {cur} -> {new_name}")
            return True
        if not assume_yes:
            choice = input(f"Rename machine to '{new_name}'? [y/n]: ").strip().lower()
            if choice not in ("y", "yes"):
                log_message("Rename skipped by user.")
                return False
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", f'Rename-Computer -NewName "{new_name}" -Force -PassThru'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            log_message(f"Machine name set to {new_name} (reboot required)")
            return True
        log_message(f"Rename failed: {result.stderr or result.stdout}", "error")
        return False
    except Exception as e:
        log_message(f"Rename exception: {e}", "error")
        return False


# =========================
# Sysprep / SID
# =========================
def cleanup_sysprep_logs_recursive():
    targets = {"diagwrn.xml", "diagerr.xml", "setupact.txt", "setuperr.txt"}
    paths = [
        r"C:\Windows\System32\Sysprep\Panther",
        r"C:\Windows\System32\Sysprep\ActionFiles",
    ]
    for root in paths:
        if not os.path.exists(root):
            continue
        for dp, _, files in os.walk(root):
            for fn in files:
                fp = os.path.join(dp, fn)
                if fn.lower().endswith(".xml") or fn.lower() in targets:
                    try:
                        subprocess.run(["takeown", "/F", fp, "/A"], check=False)
                        subprocess.run(["icacls", fp, "/grant", "Administrators:F"],
                                       check=False)
                        os.chmod(fp, stat.S_IWRITE)
                        os.remove(fp)
                        log_message(f"Deleted Sysprep file: {fp}")
                    except Exception as e:
                        log_message(f"Could not delete {fp}: {e}", "warn")


def get_machine_sid_from_admin_sid() -> str:
    try:
        script = ("$u = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }; "
                  "if ($u) { $u.SID.Value }")
        res = subprocess.run(["powershell.exe", "-NoProfile", "-Command", script],
                             text=True, capture_output=True)
        sid = res.stdout.strip()
        if sid and sid.endswith("-500"):
            return sid.rsplit("-", 1)[0]
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["wmic", "useraccount", "where", "localaccount='true'", "get", "name,sid"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and line.endswith("-500"):
                return line.split()[-1].rsplit("-", 1)[0]
    except Exception as e:
        log_message(f"Could not query admin SID: {e}", "warn")
    return "UNKNOWN"


def try_log_psgetsid():
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty SID"],
            capture_output=True, text=True
        )
        if r.stdout.strip():
            log_message(f"Machine SID: {r.stdout.strip()}")
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' | "
             "ForEach-Object { \"$($_.Name) -> $($_.SID)\" }"],
            capture_output=True, text=True
        )
        if r.stdout.strip():
            log_message("Local user SIDs:\n" + r.stdout.strip())
    except Exception as e:
        log_message(f"SID log failed: {e}", "warn")


def schedule_post_reboot_verification() -> bool:
    script_path = os.path.abspath(sys.argv[0])
    python_exe = sys.executable
    task_cmd = f'"{python_exe}" "{script_path}" --post-reboot'
    subprocess.run(["schtasks", "/Delete", "/TN", SCHEDULED_TASK_NAME, "/F"],
                   capture_output=True, text=True)
    create = subprocess.run(
        ["schtasks", "/Create", "/SC", "ONSTART", "/TN", SCHEDULED_TASK_NAME,
         "/TR", task_cmd, "/RL", "HIGHEST", "/RU", "SYSTEM"],
        capture_output=True, text=True
    )
    if create.returncode == 0:
        log_message(f"Scheduled post-reboot task: {SCHEDULED_TASK_NAME}")
        return True
    log_message(f"Failed to create task: {create.stderr or create.stdout}", "error")
    return False


def delete_scheduled_task():
    subprocess.run(["schtasks", "/Delete", "/TN", SCHEDULED_TASK_NAME, "/F"],
                   capture_output=True, text=True)


def post_reboot_verification():
    log_message("=== Post-reboot verification start ===")
    try:
        log_message(f"[POST] Machine SID base: {get_machine_sid_from_admin_sid()}")
    except Exception as e:
        log_message(f"[POST] SID retrieval failed: {e}", "warn")
    try:
        r = subprocess.run(
            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
            capture_output=True, text=True, check=True
        )
        for line in r.stdout.splitlines():
            if "MachineGuid" in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    log_message(f"[POST] MachineGuid: {parts[-1]}")
                    break
    except Exception as e:
        log_message(f"[POST] MachineGuid read failed: {e}", "warn")
    try:
        log_message(f"[POST] Hostname: {subprocess.check_output('hostname', text=True).strip()}")
    except Exception as e:
        log_message(f"[POST] hostname read failed: {e}", "warn")
    try:
        delete_scheduled_task()
    except Exception as e:
        log_message(f"[POST] Task delete failed: {e}", "warn")
    log_message("=== Post-reboot verification complete ===")


def run_sysprep(reboot: bool = True) -> bool:
    path = r"C:\Windows\System32\Sysprep\sysprep.exe"
    if not os.path.exists(path):
        log_message(f"Sysprep not found at {path}", "error")
        return False
    try:
        args = [path, "/generalize", "/oobe", "/quiet"]
        args.append("/reboot" if reboot else "/shutdown")
        subprocess.run(args, check=True)
        log_message("Sysprep started.")
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"Sysprep failed: {e}", "error")
        return False


def regenerate_sid_with_sysprep(dry_run: bool = False) -> bool:
    try:
        log_message(f"Current Machine SID base: {get_machine_sid_from_admin_sid()}")
        try_log_psgetsid()
        cleanup_sysprep_logs_recursive()

        if dry_run:
            log_message("[DRY-RUN] Would schedule post-reboot + run Sysprep")
            return True

        if not schedule_post_reboot_verification():
            log_message("Post-reboot task not created; continuing.", "warn")
        return run_sysprep(reboot=True)
    except Exception as e:
        log_message(f"SID regeneration failed: {e}", "error")
        return False


# =========================
# Main
# =========================
def main():
    parser = argparse.ArgumentParser(description="System Secure Script (Upgraded)")
    parser.add_argument("--post-reboot", action="store_true",
                        help="Run post-reboot verification (internal).")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview changes without applying.")
    parser.add_argument("--wifi-only", action="store_true")
    parser.add_argument("--wired-only", action="store_true")
    parser.add_argument("--all-mac", "--physical-mac", dest="all_mac",
                        action="store_true", help="Change MACs on all physical adapters.")
    parser.add_argument("--network-only", action="store_true")
    parser.add_argument("--subnet-only", action="store_true")
    parser.add_argument("--comprehensive-dns", action="store_true")
    parser.add_argument("--dns-count", type=int, default=None,
                        help="How many DNS servers per adapter (default: 3-10).")
    parser.add_argument("--skip-ula", action="store_true")
    parser.add_argument("--skip-subnet", action="store_true")
    parser.add_argument("--skip-mac", action="store_true")
    parser.add_argument("--skip-guid", action="store_true")
    parser.add_argument("--skip-sysprep", action="store_true")
    parser.add_argument("--no-restore", action="store_true",
                        help="Skip network connectivity restoration.")
    parser.add_argument("--adapters", type=str, default=None,
                        help="Comma-separated adapter names to target.")
    parser.add_argument("--serial", action="store_true",
                        help="Disable parallel adapter configuration.")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARN", "ERROR"])
    args = parser.parse_args()

    setup_logging(args.log_level)

    # Internal: post-reboot
    if args.post_reboot:
        post_reboot_verification()
        return

    # Elevate for any mutating operation
    needs_admin = not args.dry_run and (
        args.wifi_only or args.wired_only or args.all_mac or
        args.network_only or args.subnet_only or
        (not any([args.wifi_only, args.wired_only, args.all_mac,
                  args.network_only, args.subnet_only]))
    )
    if needs_admin and not is_admin():
        log_message("Elevating to Administrator...")
        if run_as_admin():
            sys.exit(0)
        log_message("Elevation failed.", "error")
        sys.exit(1)

    banner()
    target_names = set(x.strip() for x in args.adapters.split(",")) \
        if args.adapters else None

    # Subnet-only
    if args.subnet_only:
        adapters = get_all_network_adapters()
        if target_names:
            adapters = [a for a in adapters if a["Name"] in target_names]
        if not adapters:
            log_message("No matching adapters.", "error")
            sys.exit(1)
        ok = 0
        for a in adapters:
            if configure_subnet_for_adapter(a["Name"], dry_run=args.dry_run):
                ok += 1
        log_message(f"Subnet config: {ok}/{len(adapters)}")
        sys.exit(0 if ok else 1)

    # Network-only
    if args.network_only:
        ok = configure_network_settings(
            comprehensive=args.comprehensive_dns,
            dry_run=args.dry_run,
            dns_count=args.dns_count,
            skip_ula=args.skip_ula,
            skip_subnet=args.skip_subnet,
            no_restore=args.no_restore,
            parallel=not args.serial,
            target_names=target_names,
        )
        sys.exit(0 if ok else 1)

    # MAC-only modes
    if args.wifi_only:
        sys.exit(0 if change_wifi_mac(dry_run=args.dry_run) else 1)
    if args.wired_only:
        sys.exit(0 if change_wired_mac(dry_run=args.dry_run) else 1)
    if args.all_mac:
        sys.exit(0 if change_all_physical_mac(dry_run=args.dry_run) else 1)

    # Full flow
    if not args.yes and not args.dry_run:
        try:
            confirm = input("System Secure By root@Sid-Gifari=type (yes/no): ").strip().lower()
        except EOFError:
            confirm = "no"
        if confirm != "yes":
            log_message("Aborted by user.")
            print("[ERROR] Secure Failed: Aborted by user")
            sys.exit(1)

    # 1) MAC randomization
    if not args.skip_mac:
        log_message("Randomizing MACs on all physical adapters...")
        change_all_physical_mac(dry_run=args.dry_run)

    # 2) Network config
    log_message("Configuring network settings...")
    configure_network_settings(
        comprehensive=args.comprehensive_dns,
        dry_run=args.dry_run,
        dns_count=args.dns_count,
        skip_ula=args.skip_ula,
        skip_subnet=args.skip_subnet,
        no_restore=args.no_restore,
        parallel=not args.serial,
        target_names=target_names,
    )

    # 3) GUID
    if not args.skip_guid:
        new_guid = generate_new_guid()
        if not reset_computer_guid(new_guid, dry_run=args.dry_run):
            log_message("MachineGuid update failed. Aborting.", "error")
            sys.exit(1)

    # 4) Hostname
    new_name = generate_machine_name()
    set_machine_name(new_name, dry_run=args.dry_run, assume_yes=args.yes)

    # 5) Sysprep
    if not args.skip_sysprep and not args.dry_run:
        if not regenerate_sid_with_sysprep(dry_run=False):
            log_message("SID regeneration failed.", "error")
            sys.exit(1)
    elif args.dry_run and not args.skip_sysprep:
        log_message("[DRY-RUN] Would regenerate SID via Sysprep")

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
    except Exception as e:
        log_message(f"Fatal: {e}", "error")
        sys.exit(1)
