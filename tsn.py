import tkinter as tk
from tkinter import ttk
import ipaddress
import socket
import subprocess
import platform

# Utility Functions
def lookup_hostname():
    try:
        ip = ip_address_entry.get()
        hostname = socket.gethostbyaddr(ip)[0]
        result_var.set(f"Hostname: {hostname}")
    except socket.herror:
        result_var.set("Hostname: Not found")
    except Exception as e:
        result_var.set(f"Error: {e}")

def ping_response_time():
    ip = ip_address_entry.get()
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            # For Windows, 'time=' is followed by 'time=XXms'
            # For Unix/Linux, 'time=' is followed by 'time=XX.X ms'
            output = result.stdout
            if 'time=' in output:
                time_str = output.split('time=')[1].split()[0]
                result_var.set(f"Response Time: {time_str}")
            else:
                result_var.set("Unable to parse response time")
        else:
            result_var.set("No response")
    except Exception as e:
        result_var.set(f"Error: {e}")

def copy_details():
    root.clipboard_clear()
    root.clipboard_append(result_var.get())

def calculate_classful():
    ip = ip_address_entry_classful.get()
    num_subnets = num_subnets_entry.get()
    try:
        # Determine the default classful subnet mask
        first_octet = int(ip.split('.')[0])
        if 1 <= first_octet <= 126:
            default_mask = '255.0.0.0'
            default_prefix = 8
        elif 128 <= first_octet <= 191:
            default_mask = '255.255.0.0'
            default_prefix = 16
        elif 192 <= first_octet <= 223:
            default_mask = '255.255.255.0'
            default_prefix = 24
        else:
            result_var_classful.set("Invalid IP address for classful subnetting")
            return

        num_subnets = int(num_subnets)
        if num_subnets <= 0:
            raise ValueError("Number of subnets must be positive")

        # Calculate the number of bits needed for the subnets
        bits_needed = (num_subnets - 1).bit_length()
        new_prefix = default_prefix + bits_needed

        if new_prefix > 30:
            raise ValueError("Number of subnets is too large for the given IP class")

        network = ipaddress.ip_network(f"{ip}/{new_prefix}", strict=False)
        subnet_size = network.num_addresses - 2  # Exclude network and broadcast addresses

        result_var_classful.set(f"Subnet: {network.network_address}\n"
                                f"Mask: {network.netmask}\n"
                                f"Wildcard Mask: {network.hostmask}\n"
                                f"Subnet Size: {subnet_size} usable hosts\n"
                                f"Host Range: {list(network.hosts())[0]} - {list(network.hosts())[-1]}\n"
                                f"Broadcast Address: {network.broadcast_address}")
    except ValueError as e:
        result_var_classful.set(str(e))
    except Exception as e:
        result_var_classful.set(f"Error: {e}")

def calculate_cidr():
    ip_block = address_block_entry.get()
    cidr_mask = cidr_mask_entry.get()
    try:
        cidr_mask = int(cidr_mask)
        if not (0 <= cidr_mask <= 32):
            raise ValueError("CIDR mask must be between 0 and 32")

        network = ipaddress.ip_network(f"{ip_block}/{cidr_mask}", strict=False)
        subnet_size = network.num_addresses - 2  # Exclude network and broadcast addresses

        result_var_cidr.set(f"Network Address: {network.network_address}\n"
                            f"Subnet Mask: {network.netmask}\n"
                            f"Wildcard Mask: {network.hostmask}\n"
                            f"Total Hosts: {network.num_addresses}\n"
                            f"Usable Hosts: {subnet_size}\n"
                            f"Host Range: {list(network.hosts())[0]} - {list(network.hosts())[-1]}\n"
                            f"Broadcast Address: {network.broadcast_address}")
    except ValueError as e:
        result_var_cidr.set(str(e))
    except Exception as e:
        result_var_cidr.set(f"Error: {e}")

def generate_addresses():
    ip = ip_address_entry_subnet.get()
    subnet_mask = subnet_mask_entry_subnet.get()
    try:
        network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
        hosts = [str(host) for host in network.hosts()]
        result_var_subnet.set("Generated Addresses:\n" + '\n'.join(hosts))
    except ValueError as e:
        result_var_subnet.set(str(e))
    except Exception as e:
        result_var_subnet.set(f"Error: {e}")

# Main Application Setup
root = tk.Tk()
root.title("Advanced Subnet Calculator")

tab_control = ttk.Notebook(root)

# Tab 1: Address Details
tab1 = ttk.Frame(tab_control)
tab_control.add(tab1, text="Address Details")
ttk.Label(tab1, text="IP Address:").grid(column=0, row=0, padx=10, pady=10, sticky='w')
ip_address_entry = ttk.Entry(tab1, width=18)
ip_address_entry.grid(column=1, row=0, padx=10, pady=10, sticky='w')
ttk.Button(tab1, text="Lookup Hostname", command=lookup_hostname).grid(column=2, row=0, padx=10)
ttk.Button(tab1, text="Ping", command=ping_response_time).grid(column=3, row=0, padx=10)
ttk.Button(tab1, text="Copy", command=copy_details).grid(column=4, row=0, padx=10)
result_var = tk.StringVar()
result_label = ttk.Label(tab1, textvariable=result_var)
result_label.grid(column=0, row=1, columnspan=5, sticky="w", padx=10)

# Tab 2: Classful Subnet Calculator
tab2 = ttk.Frame(tab_control)
tab_control.add(tab2, text="Classful Subnet Calculator")
ttk.Label(tab2, text="IP Address:").grid(column=0, row=0, padx=10, pady=10, sticky='w')
ip_address_entry_classful = ttk.Entry(tab2, width=18)
ip_address_entry_classful.grid(column=1, row=0, padx=10, pady=10)
ttk.Label(tab2, text="Number of Subnets:").grid(column=2, row=0, padx=10, pady=10, sticky='w')
num_subnets_entry = ttk.Entry(tab2, width=10)
num_subnets_entry.grid(column=3, row=0, padx=10, pady=10)
ttk.Button(tab2, text="Calculate", command=calculate_classful).grid(column=4, row=0, padx=10)
result_var_classful = tk.StringVar()
result_label_classful = ttk.Label(tab2, textvariable=result_var_classful)
result_label_classful.grid(column=0, row=1, columnspan=5, sticky="w", padx=10)

# Tab 3: CIDR Calculator
tab3 = ttk.Frame(tab_control)
tab_control.add(tab3, text="CIDR Calculator")
ttk.Label(tab3, text="Address Block:").grid(column=0, row=0, padx=10, pady=10, sticky='w')
address_block_entry = ttk.Entry(tab3, width=18)
address_block_entry.grid(column=1, row=0, padx=10, pady=10)
ttk.Label(tab3, text="CIDR Mask (/):").grid(column=2, row=0, padx=10, pady=10, sticky='w')
cidr_mask_entry = ttk.Entry(tab3, width=5)
cidr_mask_entry.grid(column=3, row=0, padx=10, pady=10)
ttk.Button(tab3, text="Calculate CIDR", command=calculate_cidr).grid(column=4, row=0, padx=10)
result_var_cidr = tk.StringVar()
result_label_cidr = ttk.Label(tab3, textvariable=result_var_cidr)
result_label_cidr.grid(column=0, row=1, columnspan=5, sticky="w", padx=10)

# Tab 4: Subnet Addresses
tab4 = ttk.Frame(tab_control)
tab_control.add(tab4, text="Subnet Addresses")
ttk.Label(tab4, text="IP Address:").grid(column=0, row=0, padx=10, pady=10, sticky='w')
ip_address_entry_subnet = ttk.Entry(tab4, width=18)
ip_address_entry_subnet.grid(column=1, row=0, padx=10, pady=10)
ttk.Label(tab4, text="Subnet Mask:").grid(column=2, row=0, padx=10, pady=10, sticky='w')
subnet_mask_entry_subnet = ttk.Entry(tab4, width=18)
subnet_mask_entry_subnet.grid(column=3, row=0, padx=10, pady=10)
ttk.Button(tab4, text="Generate Addresses", command=generate_addresses).grid(column=4, row=0, padx=10)
result_var_subnet = tk.StringVar()
result_label_subnet = ttk.Label(tab4, textvariable=result_var_subnet)
result_label_subnet.grid(column=0, row=1, columnspan=5, sticky="w", padx=10)

tab_control.pack(expand=1, fill="both")

root.mainloop()
