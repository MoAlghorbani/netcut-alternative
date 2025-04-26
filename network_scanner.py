import sys
import logging
import time # Added for sleep
import msvcrt # Added for non-blocking input on Windows
from colorama import Fore, Style, init # Added for colors

# Initialize colorama
init(autoreset=True)

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
        print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Determined local IP range: {Fore.CYAN}{ip_range}{Style.RESET_ALL}")
        return ip_range
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Could not automatically determine local IP range: {e}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} Please specify the target IP range manually (e.g., 192.168.1.0/24).")
        return None

def list_interfaces():
    """Lists available network interfaces."""
    print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Available network interfaces:")
    interfaces = get_if_list()
    for i, iface_name in enumerate(interfaces):
        try:
            # Attempt to get details, might fail on some virtual interfaces
            iface_details = conf.ifaces.get(iface_name)
            if iface_details:
                print(f"  {Fore.YELLOW}{i}{Style.RESET_ALL}: {Fore.CYAN}{iface_name}{Style.RESET_ALL} (IP: {iface_details.ip}, MAC: {iface_details.mac})")
            else:
                print(f"  {Fore.YELLOW}{i}{Style.RESET_ALL}: {Fore.CYAN}{iface_name}{Style.RESET_ALL} (Details unavailable)")
        except Exception:
             print(f"  {Fore.YELLOW}{i}{Style.RESET_ALL}: {Fore.CYAN}{iface_name}{Style.RESET_ALL} ({Fore.RED}Error retrieving details{Style.RESET_ALL})")
    return interfaces

def select_interface(interfaces):
    """Prompts the user to select an interface."""
    while True:
        try:
            choice = input(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Enter the number of the interface to use for scanning: ")
            index = int(choice)
            if 0 <= index < len(interfaces):
                selected_iface = interfaces[index]
                print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Using interface: {Fore.CYAN}{selected_iface}{Style.RESET_ALL}")
                return selected_iface
            else:
                print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Invalid choice. Please enter a number from the list.")
        except ValueError:
            print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print(f"\n{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} Scan aborted by user.")
            sys.exit(0)

def arp_scan(ip_range, interface):
    """Performs an ARP scan on the given IP range and returns a list of discovered hosts."""
    print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Scanning network: {Fore.CYAN}{ip_range}{Style.RESET_ALL}...")
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
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Permission denied. Please run this script with administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} An error occurred during the scan: {e}")
        return []

def print_results(clients_list):
    """Prints the discovered IP and MAC addresses."""
    if not clients_list:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} No active hosts found on the network.")
        return

    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Active hosts found:")
    print(f"{Style.BRIGHT}{Fore.WHITE}IP Address\t\tMAC Address{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.WHITE}-----------------------------------------{Style.RESET_ALL}")
    for client in clients_list:
        print(f"{Fore.CYAN}{client['ip']}{Style.RESET_ALL}\t\t{Fore.MAGENTA}{client['mac']}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.WHITE}-----------------------------------------{Style.RESET_ALL}")

if __name__ == "__main__":
    available_interfaces = list_interfaces()
    if not available_interfaces:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} No network interfaces found by Scapy. Exiting.")
        sys.exit(1)

    selected_interface_name = select_interface(available_interfaces)
    if not selected_interface_name:
        sys.exit(1) # Exit if no interface selected

    target_range = get_local_ip_range()
    if not target_range:
        # Example of manual input if auto-detection fails
        manual_range = input(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Enter the target IP range (e.g., 192.168.1.0/24): ")
        if manual_range:
            target_range = manual_range
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} No target range specified. Exiting.")
            sys.exit(1)

    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Initial scan...")
    discovered_hosts = arp_scan(target_range, selected_interface_name)
    print_results(discovered_hosts)

    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Scanner running. Press '{Fore.YELLOW}r{Style.RESET_ALL}' to refresh, '{Fore.YELLOW}q{Style.RESET_ALL}' to quit.")

    try:
        while True:
            if msvcrt.kbhit(): # Check if a key has been pressed
                key = msvcrt.getch().decode('utf-8').lower()
                if key == 'r':
                    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Refreshing host list...")
                    # Optional: Clear screen (might need os.system('cls') on Windows)
                    # import os
                    # os.system('cls')
                    discovered_hosts = arp_scan(target_range, selected_interface_name)
                    print_results(discovered_hosts)
                    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Scanner running. Press '{Fore.YELLOW}r{Style.RESET_ALL}' to refresh, '{Fore.YELLOW}q{Style.RESET_ALL}' to quit.")
                elif key == 'q':
                    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Exiting scanner.")
                    break # Exit the loop

            time.sleep(0.1) # Prevent high CPU usage

    except KeyboardInterrupt:
        print(f"\n{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} Scan aborted by user (Ctrl+C).")
    except Exception as e:
        print(f"\n{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} An unexpected error occurred: {e}")
    finally:
        print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Scanner stopped.")
        sys.exit(0)