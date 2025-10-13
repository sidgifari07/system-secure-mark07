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
        
# Add subnet mask constants
SUBNET_MASKS = [
"255.255.77.1",
"255.255.77.2",
"255.255.77.3",
"255.255.77.4",
"255.255.77.5",
"255.255.77.6",
"255.255.77.7",
"255.255.77.8",
"255.255.77.9",
"255.255.77.10",
"255.255.77.11",
"255.255.77.12",
"255.255.77.13",
"255.255.77.14",
"255.255.77.15",
"255.255.77.16",
"255.255.77.17",
"255.255.77.18",
"255.255.77.19",
"255.255.77.20",
"255.255.77.21",
"255.255.77.22",
"255.255.77.23",
"255.255.77.24",
"255.255.77.25",
"255.255.77.26",
"255.255.77.27",
"255.255.77.28",
"255.255.77.29",
"255.255.77.30",
"255.255.77.31",
"255.255.77.32",
"255.255.77.33",
"255.255.77.34",
"255.255.77.35",
"255.255.77.36",
"255.255.77.37",
"255.255.77.38",
"255.255.77.39",
"255.255.77.40",
"255.255.77.41",
"255.255.77.42",
"255.255.77.43",
"255.255.77.44",
"255.255.77.45",
"255.255.77.46",
"255.255.77.47",
"255.255.77.48",
"255.255.77.49",
"255.255.77.50",
"255.255.77.51",
"255.255.77.52",
"255.255.77.53",
"255.255.77.54",
"255.255.77.55",
"255.255.77.56",
"255.255.77.57",
"255.255.77.58",
"255.255.77.59",
"255.255.77.60",
"255.255.77.61",
"255.255.77.62",
"255.255.77.63",
"255.255.77.64",
"255.255.77.65",
"255.255.77.66",
"255.255.77.67",
"255.255.77.68",
"255.255.77.69",
"255.255.77.70",
"255.255.77.71",
"255.255.77.72",
"255.255.77.73",
"255.255.77.74",
"255.255.77.75",
"255.255.77.76",

]

DNS_V4 = [
"112.122.707.1",
"112.122.707.2",
"112.122.707.3",
"112.122.707.4",
"112.122.707.5",
"112.122.707.6",
"112.122.707.7",
"112.122.707.8",
"112.122.707.9",
"112.122.707.10",
"112.122.707.11",
"112.122.707.12",
"112.122.707.13",
"112.122.707.14",
"112.122.707.15",
"112.122.707.16",
"112.122.707.17",
"112.122.707.18",
"112.122.707.19",
"112.122.707.20",
"112.122.707.21",
"112.122.707.22",
"112.122.707.23",
"112.122.707.24",
"112.122.707.25",
"112.122.707.26",
"112.122.707.27",
"112.122.707.28",
"112.122.707.29",
"112.122.707.30",
"112.122.707.31",
"112.122.707.32",
"112.122.707.33",
"112.122.707.34",
"112.122.707.35",
"112.122.707.36",
"112.122.707.37",
"112.122.707.38",
"112.122.707.39",
"112.122.707.40",
"112.122.707.41",
"112.122.707.42",
"112.122.707.43",
"112.122.707.44",
"112.122.707.45",
"112.122.707.46",
"112.122.707.47",
"112.122.707.48",
"112.122.707.49",
"112.122.707.50",
"112.122.707.51",
"112.122.707.52",
"112.122.707.53",
"112.122.707.54",
"112.122.707.55",
"112.122.707.56",
"112.122.707.57",
"112.122.707.58",
"112.122.707.59",
"112.122.707.60",
"112.122.707.61",
"112.122.707.62",
"112.122.707.63",
"112.122.707.64",
"112.122.707.65",
"112.122.707.66",
"112.122.707.67",
"112.122.707.68",
"112.122.707.69",
"112.122.707.70",
"112.122.707.71",
"112.122.707.72",
"112.122.707.73",
"112.122.707.74",
"112.122.707.75",
"112.122.707.76",
"112.122.707.77",
"112.122.707.78",
"112.122.707.79",
"112.122.707.80",
"112.122.707.81",
"112.122.707.82",
"112.122.707.83",
"112.122.707.84",
"112.122.707.85",
"112.122.707.86",
"112.122.707.87",
"112.122.707.88",
"112.122.707.89",
"112.122.707.90",
"112.122.707.91",
"112.122.707.92",
"112.122.707.93",
"112.122.707.94",
"112.122.707.95",
"112.122.707.96",
"112.122.707.97",
"112.122.707.98",
"112.122.707.99",
"112.122.707.100",
"112.122.707.101",
"112.122.707.102",
"112.122.707.103",
"112.122.707.104",
"112.122.707.105",
"112.122.707.106",
"112.122.707.107",
"112.122.707.108",
"112.122.707.109",
"112.122.707.110",
"112.122.707.111",
"112.122.707.112",
"112.122.707.113",
"112.122.707.114",
"112.122.707.115",
"112.122.707.116",
"112.122.707.117",
"112.122.707.118",
"112.122.707.119",
"112.122.707.120",
"112.122.707.121",
"112.122.707.122",
"112.122.707.123",
"112.122.707.124",
"112.122.707.125",
"112.122.707.126",
"112.122.707.127",
"112.122.707.128",
"112.122.707.129",
"112.122.707.130",
"112.122.707.131",
"112.122.707.132",
"112.122.707.133",
"112.122.707.134",
"112.122.707.135",
"112.122.707.136",
"112.122.707.137",
"112.122.707.138",
"112.122.707.139",
"112.122.707.140",
"112.122.707.141",
"112.122.707.142",
"112.122.707.143",
"112.122.707.144",
"112.122.707.145",
"112.122.707.146",
"112.122.707.147",
"112.122.707.148",
"112.122.707.149",
"112.122.707.150",
"112.122.707.151",
"112.122.707.152",
"112.122.707.153",
"112.122.707.154",
"112.122.707.155",
"112.122.707.156",
"112.122.707.157",
"112.122.707.158",
"112.122.707.159",
"112.122.707.160",
"112.122.707.161",
"112.122.707.162",
"112.122.707.163",
"112.122.707.164",
"112.122.707.165",
"112.122.707.166",
"112.122.707.167",
"112.122.707.168",
"112.122.707.169",
"112.122.707.170",
"112.122.707.171",
"112.122.707.172",
"112.122.707.173",
"112.122.707.174",
"112.122.707.175",
"112.122.707.176",
"112.122.707.177",
"112.122.707.178",
"112.122.707.179",
"112.122.707.180",
"112.122.707.181",
"112.122.707.182",
"112.122.707.183",
"112.122.707.184",
"112.122.707.185",
"112.122.707.186",
"112.122.707.187",
"112.122.707.188",
"112.122.707.189",
"112.122.707.190",
"112.122.707.191",
"112.122.707.192",
"112.122.707.193",
"112.122.707.194",
"112.122.707.195",
"112.122.707.196",
"112.122.707.197",
"112.122.707.198",
"112.122.707.199",
"112.122.707.200",
"112.122.707.201",
"112.122.707.202",
"112.122.707.203",
"112.122.707.204",
"112.122.707.205",
"112.122.707.206",
"112.122.707.207",
"112.122.707.208",
"112.122.707.209",
"112.122.707.210",
"112.122.707.211",
"112.122.707.212",
"112.122.707.213",
"112.122.707.214",
"112.122.707.215",
"112.122.707.216",
"112.122.707.217",
"112.122.707.218",
"112.122.707.219",
"112.122.707.220",
"112.122.707.221",
"112.122.707.222",
"112.122.707.223",
"112.122.707.224",
"112.122.707.225",
"112.122.707.226",
"112.122.707.227",
"112.122.707.228",
"112.122.707.229",
"112.122.707.230",
"112.122.707.231",
"112.122.707.232",
"112.122.707.233",
"112.122.707.234",
"112.122.707.235",
"112.122.707.236",
"112.122.707.237",
"112.122.707.238",
"112.122.707.239",
"112.122.707.240",
"112.122.707.241",
"112.122.707.242",
"112.122.707.243",
"112.122.707.244",
"112.122.707.245",
"112.122.707.246",
"112.122.707.247",
"112.122.707.248",
"112.122.707.249",
"112.122.707.250",
"112.122.707.251",
"112.122.707.252",
"112.122.707.253",
"112.122.707.254",
"112.122.707.255",

]

DNS_V6 = [
"fd06:b7c7:971b:1d7:97c0:3999:1515:2b51",
"fd07:bceb:a1d9:66c7:6bfb:33c7:3998:40dc",
"fd08:c152:aece:a100:9430:615:acab:7404",
"fd0a:97a5:8462:e98e:88a6:6105:94b3:a5f1",
"fd0a:cd38:f6f9:d4b8:ca2c:ed3b:2995:bc87",
"fd0a:eb61:30ef:b0ba:3768:6e57:96f8:2bfa",
"fd0c:1f8:efd8:3e52:6e6d:5ea1:f7ec:f20b",
"fd0e:66aa:f700:5bd4:a986:fcaa:368a:2df6",
"fd0e:d44a:ae44:be8b:c825:987e:690b:208e",
"fd10:a4c6:c966:9d47:329:6050:921f:70d4",
"fd10:f1ef:579:5c24:ac92:e76:ab2d:6948",
"fd1b:fb3b:1f26:63cb:4f48:d3a:7df7:e769",
"fd1d:93d8:be21:43a0:8dff:74a6:99d1:811a",
"fd20:5ee8:a467:b577:6606:a9b7:397a:7be",
"fd24:9cfa:65af:f7a5:215e:8521:fb10:e5bc",
"fd29:4aa7:b00:c5ee:a3ba:b41c:80f4:c391",
"fd2e:b60b:4595:7d04:7629:c7d9:ebda:89",
"fd30:8206:e9bb:a1b9:df9c:5280:625a:c103",
"fd31:fb61:5b19:a2c4:4b3f:aa31:d72b:d2ed",
"fd37:3356:d9d9:c431:9d94:888a:a740:9921",
"fd37:78c6:3933:b0b4:2aaf:e35d:6743:6a37",
"fd37:a894:8946:3fa1:b4fb:22f4:f00b:c90d",
"fd3e:e8a5:76f3:abcb:84da:bd01:5049:d171",
"fd41:4173:547:6afb:76f2:38cf:c94f:c2a7",
"fd42:4f12:f929:ced4:719f:d6e5:8847:d4d2",
"fd45:4f36:8887:5da7:1af2:3402:a84e:c707",
"fd46:f1c6:c38f:834c:93a3:b00b:36fb:ffc",
"fd47:d3a5:e25c:9c1d:6bf4:cd9d:2e98:1a70",
"fd49:6551:bc20:1702:ae8e:fb21:53:8416",
"fd4c:39d3:903e:d832:2baf:fc6e:e877:5d20",
"fd4c:6abd:514c:ed92:b604:e84d:b5f9:4a9c",
"fd4c:efd6:c3aa:9727:8d70:be2c:c4dd:450c",
"fd4d:7c36:8cbe:2a30:31d9:bfec:1e2f:ad35",
"fd56:1b85:dade:d542:127f:7172:2256:544",
"fd56:4b0:29be:7375:86bc:3ac4:7c97:4072",
"fd57:8c30:31c2:5301:2666:ae3f:3d8b:59b0",
"fd58:8f9c:2ecb:d77d:d415:4fac:3cfb:9ad6",
"fd5c:eb4f:c31b:d8b2:4bb8:31b1:885b:b928",
"fd5d:ce73:bb0a:e8b4:3b4d:f966:738f:3ed9",
"fd61:ecf2:2ae:84a1:f3f6:d585:541:718f",
"fd63:b7bf:d9b6:57a2:dbdf:5d7c:7fd5:1090",
"fd64:8466:241:42d7:b213:ef9b:b8cc:8e8e",
"fd64:c8d0:6c8e:2a3:c058:d658:82ce:28a2",
"fd67:8f8c:3ef6:bc9c:cb5c:ee73:96a5:88ee",
"fd69:4e31:7dab:7eff:9e97:58ee:d6a1:97b5",
"fd6a:bae0:22fc:2fa7:1104:38cb:4dfa:74ad",
"fd6d:1414:1e9c:4413:3d7d:7a85:2ec3:9a",
"fd79:bc3b:9409:239:efb3:22b:3473:f45d",
"fd7a:4588:b07e:74b7:a21b:a4ad:6364:9282",
"fd7f:b4d0:beaf:5ede:4cf7:43b1:f8b3:e0d6",
"fd80:4966:a455:c9c3:77b8:abef:e5e1:d27c",
"fd81:f6a5:2f55:a78d:be8f:e55:75de:1e2",
"fd82:8cfa:fe:8315:1c7d:6cc9:d132:a92e",
"fd86:84f8:ec6d:96c:8014:2d77:3159:20b5",
"fd89:2673:9cbf:3ac8:8af1:4ae1:4ec3:ed3",
"fd8b:7b00:f1ac:4605:3ae0:8c86:695a:bbe9",
"fd8c:cce1:5753:77ea:6128:8a40:7753:964",
"fd8f:c57:8e62:9b0f:31f6:c342:e613:49b1",
"fd90:b204:d249:d7fb:ae8:df97:41b9:5a39",
"fd95:2130:d5e8:79cb:98c1:e8de:9f4f:58e4",
"fd95:75f0:e5bb:ee7a:4ac4:69d3:b120:8c16",
"fd96:11cd:8091:e22a:a440:6b8f:7830:340c",
"fd96:a199:ce1f:7744:532c:e123:1f1b:8ecf",
"fd96:bedb:23ff:9d53:ad98:ed3a:6fa:c499",
"fd97:31a4:5fad:1666:a20c:3e17:26ff:b5bf",
"fd97:50c5:7eed:1f94:2c6a:ddb1:e7fb:c27a",
"fd9e:8cb6:8fc7:8e65:5d2d:37d1:dc88:3430",
"fda5:ff9f:65f1:9697:46f7:7143:36f8:a3c2",
"fda9:3c87:cc5d:2c6d:a3a1:32b3:116e:6349",
"fdab:9ace:9ab8:112d:6046:f2b7:beba:9db9",
"fdab:ab36:33f:f8c6:eda3:1a8e:759c:21ef",
"fdac:bf60:ded7:e502:87ce:6afb:300f:cbd7",
"fdb7:49a3:35ce:fee8:5ae8:240e:73f2:57a8",
"fdba:2ba0:602e:56c8:785a:5a01:bf74:4a26",
"fdbe:6a41:208:bde0:8b9a:eca2:934:5a63",
"fdc0:5a6b:b65:5570:dcba:25bd:ed4a:2e26",
"fdc2:9270:1f52:ab45:4948:27f9:c1e:56da",
"fdc2:e363:a940:c511:f7:6c24:7c51:4b1f",
"fdc7:195e:a470:d449:e4e1:30fa:5e54:b16",
"fdc9:6cf6:3dd2:ad82:63e7:46c1:9214:be05",
"fdca:527f:2cbf:fc92:8e6f:c7bf:47f8:5c7d",
"fdcc:1999:8404:4023:e633:cc93:4954:51a0",
"fdcc:34c3:94c7:256b:cd59:9b7d:a5c8:7abe",
"fdcc:d0c4:33b:2691:7543:a8be:32ea:84b3",
"fdcf:487d:6dcb:8cdd:fb12:6220:37b9:b62f",
"fdd9:4501:7816:7c90:3467:8d8f:7c93:53f3",
"fddb:992d:b733:5802:e317:1cc:c989:436",
"fddb:f983:7f7c:6ecd:d234:751c:3421:215c",
"fdde:5127:3b82:fb85:bcf2:d7ff:284e:c14c",
"fde7:bf31:c82c:a6de:199a:56b9:510f:576d",
"fdf4:df50:805e:22dd:dd0e:6c20:884b:cd2f",
"fdf5:b790:c61d:f4f3:237f:2df1:b697:94ce",
"fdf8:22d1:c7e0:c492:ed9d:1312:9caa:abb1",
"fdf8:5998:df8a:8cd4:3828:81df:6eb1:d6bf",
"fdf8:b689:d5df:bd0c:b678:c6b1:aa6b:2d82",
"fdf8:d89a:f15a:ad6d:beb1:e1b6:18b0:e370",
"fdf9:efc3:9ed7:193c:ccdf:8796:c617:6408",
"fdfc:56f6:4f32:c268:f4a4:8742:1926:6c30",
"fdfc:626b:280d:39a0:a55c:5b62:3603:4e2b",
"fdfe:92e6:2a66:2179:324c:263:3c2a:6e29",
]





NUM_IPV4_DNS = 20
NUM_IPV6_DNS = 20

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