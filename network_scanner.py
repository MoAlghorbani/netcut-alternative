import sys
import logging
import time
import msvcrt
import threading # Added for background sniffing
import socket # Moved import here
import os # Added for screen clearing
from collections import defaultdict # Added for tracking usage
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configure logging to suppress Scapy's verbose output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import ARP, Ether, srp, get_if_list, conf, sniff, IP # Added sniff, IP
except ImportError:
    print("Scapy library is not installed. Please install it using: pip install scapy")
    sys.exit(1)

# --- Globals for Bandwidth Monitoring ---
bandwidth_lock = threading.Lock()
# Stores {ip: bytes}
upload_usage = defaultdict(int)
download_usage = defaultdict(int)
# Keep track of known local IPs from the last scan
known_ips = set()
stop_sniffing_event = threading.Event()
# ----------------------------------------

def format_bytes(size):
    """Converts bytes to a human-readable format (KB, MB, GB)."""
    power = 2**10 # 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power and n < len(power_labels) - 1: # Prevent index error if size is huge
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def packet_callback(packet):
    """Callback function for processing sniffed packets."""
    global upload_usage, download_usage, known_ips
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Ensure packet has length attribute (some packets might not)
        packet_size = len(packet) if hasattr(packet, '__len__') else 0
        if packet_size == 0:
            return # Ignore packets with no size

        with bandwidth_lock:
            # Check if source is a known local IP (Sent)
            if src_ip in known_ips:
                upload_usage[src_ip] += packet_size
            # Check if destination is a known local IP (Received)
            # Use 'if' instead of 'elif' to count packets destined for local IPs even if source is also local
            if dst_ip in known_ips:
                download_usage[dst_ip] += packet_size

def start_sniffing(interface):
    """Starts the packet sniffer in a separate thread."""
    print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Starting bandwidth monitor...{Style.RESET_ALL}")
    try:
        # Use stop_filter on the sniff function to allow graceful stopping
        sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda p: stop_sniffing_event.is_set())
    except OSError as e:
         # Handle potential "Network is down" or interface issues gracefully
         print(f"\n{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Error starting sniffer on interface {interface}: {e}")
         print(f"{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Bandwidth monitoring failed to start.")
         # Signal main thread if necessary, or just let the thread exit
         stop_sniffing_event.set() # Ensure main loop knows sniffer isn't running
    except Exception as e:
        print(f"\n{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} An unexpected error occurred in the sniffer thread: {e}")
        stop_sniffing_event.set()
    finally:
        # This print might be confusing if sniffer failed to start
        if not stop_sniffing_event.is_set(): # Only print if stopped normally
             print(f"{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Bandwidth monitor stopped.{Style.RESET_ALL}")


def get_local_ip_range():
    """Attempts to determine the local IP range (e.g., 192.168.1.0/24)."""
    # This is a basic attempt; more robust methods might be needed for complex networks
    # import socket # Moved to top
    try:
        # Connect to an external host to find the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Set a timeout to prevent hanging
        s.settimeout(1)
        try:
            s.connect(("8.8.8.8", 80)) # Google DNS as target
            local_ip = s.getsockname()[0]
        except socket.gaierror: # Handle case where DNS resolution fails
             s.connect(("1.1.1.1", 80)) # Cloudflare DNS as fallback
             local_ip = s.getsockname()[0]
        finally:
            s.close()

        # Assume a /24 subnet mask, common for home networks
        ip_parts = local_ip.split('.')
        if len(ip_parts) == 4:
            ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Determined local IP range: {Fore.CYAN}{ip_range}{Style.RESET_ALL}")
            return ip_range
        else:
             raise ValueError("Failed to parse local IP address.")
    except (socket.error, OSError, ValueError) as e: # Catch socket errors, OS errors (like network unreachable), and ValueErrors
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Could not automatically determine local IP range: {e}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} Please specify the target IP range manually (e.g., 192.168.1.0/24).")
        return None

def list_interfaces():
    """Lists available network interfaces."""
    print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Available network interfaces:")
    interfaces = get_if_list()
    valid_interfaces = []
    for i, iface_name in enumerate(interfaces):
        try:
            # Attempt to get details, might fail on some virtual interfaces
            iface_details = conf.ifaces.get(iface_name)
            # Check if the interface has a usable IP address (basic check)
            if iface_details and hasattr(iface_details, 'ip') and iface_details.ip and iface_details.ip != '0.0.0.0':
                print(f"  {Fore.YELLOW}{i}{Style.RESET_ALL}: {Fore.CYAN}{iface_name}{Style.RESET_ALL} (IP: {iface_details.ip}, MAC: {iface_details.mac})")
                valid_interfaces.append(iface_name) # Add to list of selectable interfaces
            else:
                 # Optionally print interfaces without usable IPs, but don't list them for selection
                 # print(f"  {Fore.LIGHTBLACK_EX}{i}{Style.RESET_ALL}: {Fore.LIGHTBLACK_EX}{iface_name}{Style.RESET_ALL} (No usable IP or details)")
                 pass # Skip interfaces without IP/details for selection
        except Exception as e:
             print(f"  {Fore.YELLOW}{i}{Style.RESET_ALL}: {Fore.CYAN}{iface_name}{Style.RESET_ALL} ({Fore.RED}Error retrieving details: {e}{Style.RESET_ALL})")
    # Return only the interfaces that were printed with details
    # Re-index the valid interfaces for user selection
    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Selectable interfaces:")
    selectable_map = {}
    for idx, name in enumerate(valid_interfaces):
        print(f"  {Fore.YELLOW}{idx}{Style.RESET_ALL}: {Fore.CYAN}{name}{Style.RESET_ALL}")
        selectable_map[idx] = name

    if not selectable_map:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} No suitable network interfaces found for scanning.")
        return None, {} # Return None and empty map

    return valid_interfaces, selectable_map # Return the original list and the map for selection

def select_interface(interfaces, selectable_map):
    """Prompts the user to select an interface from the filtered list."""
    if not interfaces or not selectable_map:
        return None # No interfaces to select

    while True:
        try:
            choice = input(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Enter the number of the interface to use for scanning: ")
            index = int(choice)
            if index in selectable_map:
                selected_iface = selectable_map[index]
                print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Using interface: {Fore.CYAN}{selected_iface}{Style.RESET_ALL}")
                # Find the actual Scapy interface object if needed later, though name is often sufficient
                # selected_iface_obj = conf.ifaces.get(selected_iface)
                return selected_iface # Return the name
            else:
                print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Invalid choice. Please enter a number from the selectable list.")
        except ValueError:
            print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print(f"\n{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} Scan aborted by user.")
            sys.exit(0)

def arp_scan(ip_range, interface):
    """Performs an ARP scan and updates the known IPs set."""
    global known_ips
    print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Scanning network: {Fore.CYAN}{ip_range}{Style.RESET_ALL}...")
    clients = []
    current_scan_ips = set()
    try:
        # Create an ARP request packet
        arp_request = ARP(pdst=ip_range)
        # Create an Ethernet frame
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine the Ethernet frame and ARP request
        arp_request_broadcast = broadcast / arp_request

        # Send the packet and capture responses
        # timeout=3 increased timeout
        # verbose=False suppresses Scapy's output during sending
        # iface=interface specifies the network interface to use
        answered_list, unanswered_list = srp(arp_request_broadcast, timeout=3, iface=interface, verbose=False)

        if not answered_list:
             print(f"{Style.BRIGHT}{Fore.YELLOW}[i]{Style.RESET_ALL} No devices responded to ARP scan.")


        for sent, received in answered_list:
            client_ip = received.psrc
            client_mac = received.hwsrc
            clients.append({'ip': client_ip, 'mac': client_mac})
            current_scan_ips.add(client_ip)

        # Update the global set of known IPs for the sniffer
        with bandwidth_lock:
            known_ips = current_scan_ips
            # Optional: Reset usage for IPs no longer detected?
            # Or keep historical data? For now, keep it.

        return clients
    except PermissionError:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Permission denied. Please run this script with administrator privileges.")
        sys.exit(1)
    except OSError as e:
         # Handle specific OS errors like "Network is down" if srp fails
         print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Network error during scan on interface {interface}: {e}")
         return [] # Return empty list on network error
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} An error occurred during the ARP scan: {e}")
        # Optionally log the full traceback here for debugging
        # import traceback
        # traceback.print_exc()
        return [] # Return empty list on other errors

def print_results(clients_list):
    """Prints the discovered IP, MAC, and bandwidth usage."""
    if not clients_list:
        # Don't print "No active hosts" if the list is just empty after a scan
        # print(f"{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} No active hosts found on the network.")
        return

    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Active hosts found:")
    # Changed to Sent/Received columns - Adjust spacing as needed
    header = f"{'IP Address':<15}\t{'MAC Address':<17}\t{'Sent':>10}\t{'Received':>10}"
    print(f"{Style.BRIGHT}{Fore.WHITE}{header}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.WHITE}{'-' * (len(header) + 5)}{Style.RESET_ALL}") # Adjust separator length

    with bandwidth_lock:
        # Sort by IP address for consistent display
        # Use a try-except block for inet_aton in case of invalid IPs (though unlikely from Scapy)
        def ip_sort_key(client):
            try:
                return socket.inet_aton(client['ip'])
            except socket.error:
                return b'\x00\x00\x00\x00' # Default sort value for invalid IPs

        sorted_clients = sorted(clients_list, key=ip_sort_key)

        for client in sorted_clients:
            ip = client['ip']
            mac = client['mac']
            # Get usage, default to 0 if IP not seen by sniffer yet
            sent_bytes = upload_usage.get(ip, 0)
            received_bytes = download_usage.get(ip, 0)
            sent = format_bytes(sent_bytes)
            received = format_bytes(received_bytes)
            print(f"{Fore.CYAN}{ip:<15}{Style.RESET_ALL}\t{Fore.MAGENTA}{mac:<17}{Style.RESET_ALL}\t{Fore.YELLOW}{sent:>10}{Style.RESET_ALL}\t{Fore.GREEN}{received:>10}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.WHITE}{'-' * (len(header) + 5)}{Style.RESET_ALL}") # Adjust separator length

if __name__ == "__main__":
    # List interfaces returns the list and a map for selection
    all_interfaces, selectable_interface_map = list_interfaces()
    if not selectable_interface_map: # Check if the map is empty
        # Error message already printed in list_interfaces
        sys.exit(1)

    # Pass the map to the selection function
    selected_interface_name = select_interface(all_interfaces, selectable_interface_map)
    if not selected_interface_name:
        sys.exit(1) # Exit if no interface selected

    target_range = get_local_ip_range()
    if not target_range:
        # Example of manual input if auto-detection fails
        while not target_range: # Loop until valid input or Ctrl+C
             try:
                 manual_range = input(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Enter the target IP range (e.g., 192.168.1.0/24): ").strip()
                 # Basic validation (optional but recommended)
                 if '/' in manual_range and '.' in manual_range:
                     target_range = manual_range
                 elif not manual_range: # Allow empty input to exit
                      print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} No target range specified. Exiting.")
                      sys.exit(1)
                 else:
                     print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Invalid format. Please use CIDR notation (e.g., 192.168.1.0/24).")
             except KeyboardInterrupt:
                  print(f"\n{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} Operation cancelled by user.")
                  sys.exit(0)


    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Initial scan...")
    discovered_hosts = arp_scan(target_range, selected_interface_name)

    # --- Add local IP to known_ips --- 
    try:
        local_ip_on_iface = conf.ifaces.get(selected_interface_name).ip
        if local_ip_on_iface and local_ip_on_iface != '0.0.0.0':
            with bandwidth_lock:
                if local_ip_on_iface not in known_ips:
                    print(f"{Style.BRIGHT}{Fore.YELLOW}[i]{Style.RESET_ALL} Adding local IP {Fore.CYAN}{local_ip_on_iface}{Style.RESET_ALL} to monitored set.")
                    known_ips.add(local_ip_on_iface)
                    # Add a dummy entry to discovered_hosts if not found by ARP, so it appears in the list
                    if not any(client['ip'] == local_ip_on_iface for client in discovered_hosts):
                         local_mac = conf.ifaces.get(selected_interface_name).mac
                         discovered_hosts.append({'ip': local_ip_on_iface, 'mac': local_mac if local_mac else '??:??:??:??:??:??'})
        else:
            print(f"{Style.BRIGHT}{Fore.YELLOW}[w]{Style.RESET_ALL} Could not get a valid IP for the selected interface ({selected_interface_name}). Local traffic might not be fully tracked.")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Error getting local IP for interface {selected_interface_name}: {e}")
    # ----------------------------------

    print_results(discovered_hosts) # Initial print (may now include local IP)

    # Start sniffing in a background thread
    # Make it a daemon so it exits when the main thread exits
    sniffer_thread = threading.Thread(target=start_sniffing, args=(selected_interface_name,), daemon=True)
    sniffer_thread.start()

    # Give the sniffer a moment to start up and potentially fail
    time.sleep(1)
    if stop_sniffing_event.is_set(): # Check if sniffer failed immediately
         print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Bandwidth monitor could not be started. Exiting.")
         sys.exit(1)


    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Scanner running. Bandwidth monitoring active.")
    print(f"Press '{Fore.YELLOW}r{Style.RESET_ALL}' to refresh host list & usage, '{Fore.YELLOW}q{Style.RESET_ALL}' to quit.")

    sniffer_alive = True # Assume sniffer is running initially
    last_refresh_time = time.time()
    refresh_interval = 5 # Refresh every 5 seconds
    needs_manual_refresh_display = False # Flag to control display after manual refresh

    try:
        while True:
            current_time = time.time()
            refresh_due = (current_time - last_refresh_time) >= refresh_interval

            # Check if sniffer thread died unexpectedly
            if sniffer_alive and not sniffer_thread.is_alive():
                print(f"\n{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Bandwidth monitor thread stopped unexpectedly.")
                sniffer_alive = False
                # Decide whether to try restarting or just inform the user
                print(f"{Style.BRIGHT}{Fore.YELLOW}[i]{Style.RESET_ALL} Bandwidth usage will not be updated.")
                # Prevent continuous printing of this message
                last_refresh_time = current_time # Reset timer to avoid immediate auto-refresh

            key_pressed = None
            if msvcrt.kbhit(): # Check if a key has been pressed
                try:
                    key_pressed = msvcrt.getch().decode('utf-8').lower()
                except UnicodeDecodeError:
                    key_pressed = '' # Ignore non-decodeable keys

            if key_pressed == 'r':
                print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Refreshing host list and usage...{Style.RESET_ALL}")
                os.system('cls' if os.name == 'nt' else 'clear') # Clear screen
                discovered_hosts = arp_scan(target_range, selected_interface_name)
                print_results(discovered_hosts) # Print updated list with current usage
                last_refresh_time = time.time() # Reset timer after manual refresh
                needs_manual_refresh_display = True # Set flag to reprint instructions

            elif key_pressed == 'q':
                print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Exiting scanner...{Style.RESET_ALL}")
                break # Exit the loop

            elif refresh_due and not key_pressed: # Auto-refresh only if no key was pressed
                os.system('cls' if os.name == 'nt' else 'clear') # Clear screen
                # No need to re-scan hosts, just reprint results with updated usage
                print_results(discovered_hosts)
                last_refresh_time = current_time
                needs_manual_refresh_display = True # Set flag to reprint instructions

            # Reprint instructions if a refresh happened (manual or auto)
            if needs_manual_refresh_display:
                 print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Scanner running. Press '{Fore.YELLOW}r{Style.RESET_ALL}' to refresh, '{Fore.YELLOW}q{Style.RESET_ALL}' to quit.")
                 needs_manual_refresh_display = False

            time.sleep(0.1) # Prevent high CPU usage

    except KeyboardInterrupt:
        print(f"\n{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} Scan aborted by user (Ctrl+C).{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} An unexpected error occurred in the main loop: {e}{Style.RESET_ALL}")
        # import traceback
        # traceback.print_exc() # For debugging
    finally:
        if sniffer_alive and sniffer_thread.is_alive():
             print(f"{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Stopping bandwidth monitor...{Style.RESET_ALL}")
             stop_sniffing_event.set() # Signal the sniffer thread to stop
             # Give the sniffer thread a moment to stop cleanly
             # Note: sniff() might not always exit immediately on stop_filter
             sniffer_thread.join(timeout=2.0) # Wait up to 2 seconds
             if sniffer_thread.is_alive():
                  print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Sniffer thread did not stop cleanly.{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Scanner stopped.{Style.RESET_ALL}")
        sys.exit(0) # Ensure clean exit