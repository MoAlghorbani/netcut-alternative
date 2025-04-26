import sys
import logging
import time # Added for sleep
import msvcrt # Added for non-blocking input on Windows

# Configure logging to suppress Scapy's verbose output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import ARP, Ether, srp, get_if_list, conf
except ImportError:
    print("Scapy library is not installed. Please install it using: pip install scapy")
    sys.exit(1)

def get_local_ip_range():
    """Attempts to determine the local IP range (e.g., 192.168.1.0/24)."""
    # This is a basic attempt; more robust methods might be needed for complex networks
    import socket
    try:
        # Connect to an external host to find the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume a /24 subnet mask, common for home networks
        ip_parts = local_ip.split('.')
        ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        print(f"[*] Determined local IP range: {ip_range}")
        return ip_range
    except Exception as e:
        print(f"[!] Could not automatically determine local IP range: {e}")
        print("[!] Please specify the target IP range manually (e.g., 192.168.1.0/24).")
        return None

def list_interfaces():
    """Lists available network interfaces."""
    print("[*] Available network interfaces:")
    interfaces = get_if_list()
    for i, iface_name in enumerate(interfaces):
        try:
            # Attempt to get details, might fail on some virtual interfaces
            iface_details = conf.ifaces.get(iface_name)
            if iface_details:
                print(f"  {i}: {iface_name} (IP: {iface_details.ip}, MAC: {iface_details.mac})")
            else:
                print(f"  {i}: {iface_name} (Details unavailable)")
        except Exception:
             print(f"  {i}: {iface_name} (Error retrieving details)")
    return interfaces

def select_interface(interfaces):
    """Prompts the user to select an interface."""
    while True:
        try:
            choice = input("[*] Enter the number of the interface to use for scanning: ")
            index = int(choice)
            if 0 <= index < len(interfaces):
                selected_iface = interfaces[index]
                print(f"[*] Using interface: {selected_iface}")
                return selected_iface
            else:
                print("[!] Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("[!] Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\n[!] Scan aborted by user.")
            sys.exit(0)

def arp_scan(ip_range, interface):
    """Performs an ARP scan on the given IP range and returns a list of discovered hosts."""
    print(f"[*] Scanning network: {ip_range}...")
    try:
        # Create an ARP request packet
        arp_request = ARP(pdst=ip_range)
        # Create an Ethernet frame
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine the Ethernet frame and ARP request
        arp_request_broadcast = broadcast / arp_request

        # Send the packet and capture responses
        # timeout=1 means wait 1 second for responses
        # verbose=False suppresses Scapy's output during sending
        # iface=interface specifies the network interface to use
        # timeout=3 increased timeout
        answered_list = srp(arp_request_broadcast, timeout=3, iface=interface, verbose=False)[0]

        clients = []
        for sent, received in answered_list:
            # Extract the IP address (psrc) and MAC address (hwsrc)
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        return clients
    except PermissionError:
        print("[!] Permission denied. Please run this script with administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An error occurred during the scan: {e}")
        return []

def print_results(clients_list):
    """Prints the discovered IP and MAC addresses."""
    if not clients_list:
        print("[!] No active hosts found on the network.")
        return

    print("\n[*] Active hosts found:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in clients_list:
        print(f"{client['ip']}\t\t{client['mac']}")
    print("-----------------------------------------")

if __name__ == "__main__":
    available_interfaces = list_interfaces()
    if not available_interfaces:
        print("[!] No network interfaces found by Scapy. Exiting.")
        sys.exit(1)

    selected_interface_name = select_interface(available_interfaces)
    if not selected_interface_name:
        sys.exit(1) # Exit if no interface selected

    target_range = get_local_ip_range()
    if not target_range:
        # Example of manual input if auto-detection fails
        manual_range = input("[*] Enter the target IP range (e.g., 192.168.1.0/24): ")
        if manual_range:
            target_range = manual_range
        else:
            print("[!] No target range specified. Exiting.")
            sys.exit(1)

    print("\n[*] Initial scan...")
    discovered_hosts = arp_scan(target_range, selected_interface_name)
    print_results(discovered_hosts)

    print("\n[*] Scanner running. Press 'r' to refresh, 'q' to quit.")

    try:
        while True:
            if msvcrt.kbhit(): # Check if a key has been pressed
                key = msvcrt.getch().decode('utf-8').lower()
                if key == 'r':
                    print("\n[*] Refreshing host list...")
                    # Optional: Clear screen (might need os.system('cls') on Windows)
                    # import os
                    # os.system('cls')
                    discovered_hosts = arp_scan(target_range, selected_interface_name)
                    print_results(discovered_hosts)
                    print("\n[*] Scanner running. Press 'r' to refresh, 'q' to quit.")
                elif key == 'q':
                    print("\n[*] Exiting scanner.")
                    break # Exit the loop

            time.sleep(0.1) # Prevent high CPU usage

    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user (Ctrl+C).")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
    finally:
        print("[*] Scanner stopped.")
        sys.exit(0)