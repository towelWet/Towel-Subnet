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

def ping_response_time():
    ip = ip_address_entry.get()
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    result = subprocess.run(command, stdout=subprocess.PIPE, text=True)
    if result.returncode == 0:
        time_str = result.stdout.split('time=')[1].split(' ')[0]
        result_var.set(f"Response Time: {time_str} ms")
    else:
        result_var.set("No response")

def copy_details():
    root.clipboard_clear()
    root.clipboard_append(result_var.get())

def calculate_classful():
    ip = ip_address_entry_classful.get()
    subnet_mask = subnet_mask_entry.get()
    try:
        network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
        num_subnets = int(num_subnets_entry.get())
        result_var_classful.set(f"Subnet: {network.network_address}\n"
                                f"Mask: {network.netmask}\n"
                                f"Inverse Mask: {network.hostmask}\n"
                                f"Subnet Size: {network.num_addresses}\n"
                                f"Host Range: {list(network.hosts())[0]} - {list(network.hosts())[-1]}")
    except ValueError as e:
        result_var_classful.set(str(e))

def calculate_cidr():
    ip_block = address_block_entry.get()
    cidr_mask = cidr_mask_entry.get()
    try:
        network = ipaddress.ip_network(f"{ip_block}/{cidr_mask}", strict=False)
        result_var_cidr.set(f"Subnet: {network.network_address}\n"
                            f"Mask: {network.netmask}\n"
                            f"Inverse Mask: {network.hostmask}\n"
                            f"Subnet Size: {network.num_addresses}\n"
                            f"Host Range: {list(network.hosts())[0]} - {list(network.hosts())[-1]}")
    except ValueError as e:
        result_var_cidr.set(str(e))

def generate_addresses():
    ip = ip_address_entry_subnet.get()
    subnet_mask = subnet_mask_entry_subnet.get()
    try:
        network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
        hosts = '\n'.join([str(host) for host in network.hosts()])
        result_var_subnet.set(f"Generated Addresses:\n{hosts}")
    except ValueError as e:
        result_var_subnet.set(str(e))

# Main Application Setup
root = tk.Tk()
root.title("Advanced Subnet Calculator")

tab_control = ttk.Notebook(root)

# Tab 1: Address Details
tab1 = ttk.Frame(tab_control)
tab_control.add(tab1, text="Address Details")
ip_address_entry = ttk.Entry(tab1, width=18)
ip_address_entry.grid(column=0, row=0, padx=10, pady=10)
ttk.Button(tab1, text="Lookup Hostname", command=lookup_hostname).grid(column=1, row=0, padx=10)
ttk.Button(tab1, text="Ping", command=ping_response_time).grid(column=2, row=0, padx=10)
ttk.Button(tab1, text="Copy", command=copy_details).grid(column=3, row=0, padx=10)
result_var = tk.StringVar()
result_label = ttk.Label(tab1, textvariable=result_var)
result_label.grid(column=0, row=1, columnspan=4, sticky="w")

# Tab 2: Classful Subnet Calculator
tab2 = ttk.Frame(tab_control)
tab_control.add(tab2, text="Classful Subnet Calculator")
ip_address_entry_classful = ttk.Entry(tab2, width=18)
ip_address_entry_classful.grid(column=0, row=0, padx=10, pady=10)
subnet_mask_entry = ttk.Entry(tab2, width=18)
subnet_mask_entry.grid(column=1, row=0, padx=10, pady=10)
num_subnets_entry = ttk.Entry(tab2, width=18)
num_subnets_entry.grid(column=2, row=0, padx=10, pady=10)
ttk.Button(tab2, text="Calculate", command=calculate_classful).grid(column=3, row=0, padx=10)
result_var_classful = tk.StringVar()
result_label_classful = ttk.Label(tab2, textvariable=result_var_classful)
result_label_classful.grid(column=0, row=1, columnspan=4, sticky="w")

# Tab 3: CIDR Calculator
tab3 = ttk.Frame(tab_control)
tab_control.add(tab3, text="CIDR Calculator")
address_block_entry = ttk.Entry(tab3, width=18)
address_block_entry.grid(column=0, row=0, padx=10, pady=10)
cidr_mask_entry = ttk.Entry(tab3, width=3)
cidr_mask_entry.grid(column=1, row=0, padx=10, pady=10)
ttk.Button(tab3, text="Calculate CIDR", command=calculate_cidr).grid(column=2, row=0, padx=10)
result_var_cidr = tk.StringVar()
result_label_cidr = ttk.Label(tab3, textvariable=result_var_cidr)
result_label_cidr.grid(column=0, row=1, columnspan=3, sticky="w")

# Tab 4: Subnet Addresses
tab4 = ttk.Frame(tab_control)
tab_control.add(tab4, text="Subnet Addresses")
ip_address_entry_subnet = ttk.Entry(tab4, width=18)
ip_address_entry_subnet.grid(column=0, row=0, padx=10, pady=10)
subnet_mask_entry_subnet = ttk.Entry(tab4, width=18)
subnet_mask_entry_subnet.grid(column=1, row=0, padx=10, pady=10)
ttk.Button(tab4, text="Generate Addresses", command=generate_addresses).grid(column=2, row=0, padx=10)
result_var_subnet = tk.StringVar()
result_label_subnet = ttk.Label(tab4, textvariable=result_var_subnet)
result_label_subnet.grid(column=0, row=1, columnspan=3, sticky="w")

tab_control.pack(expand=1, fill="both")

root.mainloop()
