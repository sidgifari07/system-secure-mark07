#!/usr/bin/env python3
"""
ipv6_generator_by_sidgifari.py

Generate Unique Local IPv6 (ULA) addresses (fd00::/8)
and save them in a quoted, comma-ended format like:
"fdxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx",
"""

import ipaddress
import random
import time

def banner():
    print("=" * 60)
    print("IPv6 Generator  —  By Sid Gifari")
    print("=" * 60)
    print("This tool generates Unique Local IPv6 (ULA) addresses (fd00::/8)")
    print("Each address is saved in quoted, comma-ended format.\n")

def generate_unique_local_ipv6():
    """Generate one random Unique Local IPv6 address (fd00::/8)."""
    global_id = random.getrandbits(40)   # 40-bit global ID
    subnet_id = random.getrandbits(16)   # 16-bit subnet
    interface_id = random.getrandbits(64)  # 64-bit interface ID

    ipv6_int = (0xfd << 120) | (global_id << 80) | (subnet_id << 64) | interface_id
    return str(ipaddress.IPv6Address(ipv6_int))

def main():
    banner()

    # Ask user for number of IPv6 addresses
    while True:
        try:
            count = int(input("Enter number of IPv6 addresses to generate: "))
            if count <= 0:
                raise ValueError
            break
        except ValueError:
            print("❌ Please enter a positive integer.")

    # Ask for output file
    output_file = input("Enter output file name (e.g. ipv6_list.txt): ").strip()
    if not output_file:
        output_file = "ipv6_list.txt"

    print(f"\n⏳ Generating {count} IPv6 addresses...")
    start_time = time.time()

    addresses = {generate_unique_local_ipv6() for _ in range(count)}

    # Save to file with quotes and commas
    with open(output_file, "w") as f:
        for addr in sorted(addresses):
            f.write(f"\"{addr}\",\n")

    elapsed = time.time() - start_time
    print(f"\n✅ Done! Saved {len(addresses)} IPv6 addresses to '{output_file}'.")
    print(f"⌛ Completed in {elapsed:.2f} seconds.")
    print("=" * 60)
    print("Thanks for using IPv6 Generator by Sid Gifari!")
    print("=" * 60)

if __name__ == "__main__":
    main()
