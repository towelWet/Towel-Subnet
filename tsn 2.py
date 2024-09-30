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

def update_cidr_fields(*args):
    try:
        ip_block = address_block_entry.get()
        if not ip_block:
            return

        mask_bits = int(cidr_mask_var.get())
        host_bits = 32 - mask_bits
        number_of_subnets = 2 ** (mask_bits) if mask_bits >= 0 else 0
        hosts_per_subnet = (2 ** host_bits) - 2 if host_bits > 0 else 0

        # Update related fields
        subnet_mask = str(ipaddress.IPv4Network(f"0.0.0.0/{mask_bits}").netmask)
        subnet_mask_var.set(subnet_mask)
        host_bits_var.set(host_bits)
        number_of_subnets_var.set(number_of_subnets)
        hosts_per_subnet_var.set(hosts_per_subnet)

        # Update binary mask display
        display_binary_mask_cidr(mask_bits)

    except Exception as e:
        result_var_cidr.set(f"Error: {e}")

def display_binary_mask_cidr(mask_bits):
    # Create the binary representation of the subnet mask
    binary_mask = '1' * mask_bits + '0' * (32 - mask_bits)
    binary_mask_formatted = '.'.join([binary_mask[i:i+8] for i in range(0, 32, 8)])
    binary_mask_label_cidr.config(text=f"Subnet Bit Mask:\n{binary_mask_formatted}", justify='left')

def generate_subnets_cidr():
    try:
        ip_block = address_block_entry.get()
        mask_bits = int(cidr_mask_var.get())
        network = ipaddress.ip_network(f"{ip_block}/{mask_bits}", strict=False)
        subnet_list = list(network.subnets(new_prefix=mask_bits))

        # Clear any existing entries
        tree_cidr.delete(*tree_cidr.get_children())

        for idx, subnet in enumerate(subnet_list):
            # Subnet Details
            subnet_network = subnet.network_address
            subnet_mask = subnet.netmask
            inverse_mask = subnet.hostmask
            subnet_size = subnet.num_addresses - 2 if subnet.prefixlen < 31 else subnet.num_addresses
            host_range = f"{list(subnet.hosts())[0]} - {list(subnet.hosts())[-1]}" if subnet_size > 0 else 'N/A'
            broadcast = subnet.broadcast_address if subnet_size > 0 else 'N/A'

            tree_cidr.insert('', 'end', values=(
                str(subnet_network),
                str(subnet_mask),
                str(inverse_mask),
                str(subnet_size),
                host_range,
                str(broadcast)
            ))
    except ValueError as e:
        result_var_cidr.set(str(e))
    except Exception as e:
        result_var_cidr.set(f"Error: {e}")

def calculate_ipv6():
    try:
        ipv6_address = ipv6_address_entry.get()
        ipv6_network = ipaddress.IPv6Network(ipv6_address, strict=False)
        num_addresses = ipv6_network.num_addresses

        result_var_ipv6.set(f"Network Address: {ipv6_network.network_address}\n"
                            f"Prefix Length: {ipv6_network.prefixlen}\n"
                            f"Total Addresses: {num_addresses}\n"
                            f"First Address: {ipv6_network.network_address}\n"
                            f"Last Address: {ipv6_network.broadcast_address}")
    except ValueError as e:
        result_var_ipv6.set(str(e))
    except Exception as e:
        result_var_ipv6.set(f"Error: {e}")

def generate_subnets_ipv6():
    try:
        ipv6_address = ipv6_address_entry.get()
        new_prefix = int(ipv6_new_prefix_entry.get())
        ipv6_network = ipaddress.IPv6Network(ipv6_address, strict=False)
        subnet_list = list(ipv6_network.subnets(new_prefix=new_prefix))

        # Clear any existing entries
        tree_ipv6.delete(*tree_ipv6.get_children())

        for idx, subnet in enumerate(subnet_list):
            # Subnet Details
            subnet_network = subnet.network_address
            prefix_length = subnet.prefixlen
            num_addresses = subnet.num_addresses

            tree_ipv6.insert('', 'end', values=(
                str(subnet_network),
                f"/{prefix_length}",
                str(num_addresses)
            ))
    except ValueError as e:
        result_var_ipv6.set(str(e))
    except Exception as e:
        result_var_ipv6.set(f"Error: {e}")

# Main Application Setup
root = tk.Tk()
root.title("Advanced Subnet Calculator")

tab_control = ttk.Notebook(root)

# Tab 1: Address Details (unchanged)
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

# Tab 2: Classful Subnet Calculator (unchanged)
# [The code for Tab 2 remains the same as previously provided]

# Tab 3: CIDR Calculator (updated)
tab3 = ttk.Frame(tab_control)
tab_control.add(tab3, text="CIDR Calculator")

# Row 0: Address Block
ttk.Label(tab3, text="Address Block:").grid(column=0, row=0, padx=10, pady=10, sticky='w')
address_block_entry = ttk.Entry(tab3, width=18)
address_block_entry.grid(column=1, row=0, padx=10, pady=10)

# Row 1: CIDR Mask
ttk.Label(tab3, text="CIDR Mask (/):").grid(column=0, row=1, padx=10, pady=10, sticky='w')
cidr_mask_var = tk.StringVar(value='24')
cidr_mask_spinbox = ttk.Spinbox(tab3, from_=0, to=32, textvariable=cidr_mask_var, width=5)
cidr_mask_spinbox.grid(column=1, row=1, padx=10, pady=10, sticky='w')

# Row 2: Subnet Mask and Generate Subnets Button
ttk.Label(tab3, text="Subnet Mask:").grid(column=0, row=2, padx=10, pady=10, sticky='w')
subnet_mask_var = tk.StringVar()
subnet_mask_entry = ttk.Entry(tab3, textvariable=subnet_mask_var, width=18, state='readonly')
subnet_mask_entry.grid(column=1, row=2, padx=10, pady=10)
ttk.Button(tab3, text="Generate Subnets", command=generate_subnets_cidr).grid(column=2, row=2, padx=10)

# Row 3: Mask Bits and Number of Subnets
ttk.Label(tab3, text="Mask Bits:").grid(column=0, row=3, padx=10, pady=10, sticky='w')
mask_bits_entry = ttk.Entry(tab3, textvariable=cidr_mask_var, width=5, state='readonly')
mask_bits_entry.grid(column=1, row=3, padx=10, pady=10, sticky='w')

ttk.Label(tab3, text="Number of Subnets:").grid(column=2, row=3, padx=10, pady=10, sticky='w')
number_of_subnets_var = tk.StringVar()
number_of_subnets_entry = ttk.Entry(tab3, textvariable=number_of_subnets_var, width=10, state='readonly')
number_of_subnets_entry.grid(column=3, row=3, padx=10, pady=10)

# Row 4: Host Bits and Hosts per Subnet
ttk.Label(tab3, text="Host Bits:").grid(column=0, row=4, padx=10, pady=10, sticky='w')
host_bits_var = tk.StringVar()
host_bits_entry = ttk.Entry(tab3, textvariable=host_bits_var, width=5, state='readonly')
host_bits_entry.grid(column=1, row=4, padx=10, pady=10, sticky='w')

ttk.Label(tab3, text="Hosts per Subnet:").grid(column=2, row=4, padx=10, pady=10, sticky='w')
hosts_per_subnet_var = tk.StringVar()
hosts_per_subnet_entry = ttk.Entry(tab3, textvariable=hosts_per_subnet_var, width=10, state='readonly')
hosts_per_subnet_entry.grid(column=3, row=4, padx=10, pady=10)

# Subnet Bit Mask Display
binary_mask_label_cidr = ttk.Label(tab3, text="Subnet Bit Mask:")
binary_mask_label_cidr.grid(column=0, row=5, columnspan=4, padx=10, pady=10, sticky='w')

# Result Display (Treeview for Subnet List)
columns_cidr = ('Subnet', 'Mask', 'Inverse Mask', 'Subnet Size', 'Host Range', 'Broadcast')
tree_cidr = ttk.Treeview(tab3, columns=columns_cidr, show='headings', height=10)
for col in columns_cidr:
    tree_cidr.heading(col, text=col)
    tree_cidr.column(col, width=150)
tree_cidr.grid(column=0, row=6, columnspan=4, padx=10, pady=10)

# Scrollbar for Treeview
scrollbar_cidr = ttk.Scrollbar(tab3, orient='vertical', command=tree_cidr.yview)
tree_cidr.configure(yscroll=scrollbar_cidr.set)
scrollbar_cidr.grid(column=4, row=6, sticky='ns')

# Bind events to update fields in real-time
cidr_mask_var.trace('w', update_cidr_fields)
address_block_entry.bind('<FocusOut>', update_cidr_fields)
address_block_entry.bind('<Return>', update_cidr_fields)

# Initialize the fields
update_cidr_fields()

# Tab 4: Subnet Addresses (unchanged)
# [The code for Tab 4 remains the same as previously provided]

# Tab 5: IPv6 Calculator
tab5 = ttk.Frame(tab_control)
tab_control.add(tab5, text="IPv6 Calculator")

# Row 0: IPv6 Address
ttk.Label(tab5, text="IPv6 Address/Prefix:").grid(column=0, row=0, padx=10, pady=10, sticky='w')
ipv6_address_entry = ttk.Entry(tab5, width=40)
ipv6_address_entry.grid(column=1, row=0, padx=10, pady=10, columnspan=2)

# Row 1: Calculate Button
ttk.Button(tab5, text="Calculate", command=calculate_ipv6).grid(column=3, row=0, padx=10, pady=10)

# Row 2: Result Display
result_var_ipv6 = tk.StringVar()
result_label_ipv6 = ttk.Label(tab5, textvariable=result_var_ipv6)
result_label_ipv6.grid(column=0, row=1, columnspan=4, sticky="w", padx=10)

# Row 3: New Prefix for Subnetting
ttk.Label(tab5, text="New Prefix Length:").grid(column=0, row=2, padx=10, pady=10, sticky='w')
ipv6_new_prefix_entry = ttk.Entry(tab5, width=5)
ipv6_new_prefix_entry.grid(column=1, row=2, padx=10, pady=10, sticky='w')

# Row 4: Generate Subnets Button
ttk.Button(tab5, text="Generate Subnets", command=generate_subnets_ipv6).grid(column=2, row=2, padx=10, pady=10)

# Result Display (Treeview for IPv6 Subnet List)
columns_ipv6 = ('Subnet', 'Prefix Length', 'Total Addresses')
tree_ipv6 = ttk.Treeview(tab5, columns=columns_ipv6, show='headings', height=10)
for col in columns_ipv6:
    tree_ipv6.heading(col, text=col)
    tree_ipv6.column(col, width=200)
tree_ipv6.grid(column=0, row=5, columnspan=4, padx=10, pady=10)

# Scrollbar for IPv6 Treeview
scrollbar_ipv6 = ttk.Scrollbar(tab5, orient='vertical', command=tree_ipv6.yview)
tree_ipv6.configure(yscroll=scrollbar_ipv6.set)
scrollbar_ipv6.grid(column=4, row=5, sticky='ns')

tab_control.pack(expand=1, fill="both")

root.mainloop()
