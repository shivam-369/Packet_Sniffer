import struct
from formatting import *

def ethernet_address_format(addr):
	proper_addr = map('{:02x}'.format, addr)
	proper_mac_addr = ':'.join(proper_addr)
	return proper_mac_addr

def ethernet_frame(data, tab_count):
	destination, source = struct.unpack("! 6s 6s", data[0: 12])
	protocol = struct.unpack("! h", data[12: 14])	
	eth_proto = hex(protocol[0])
	eth_destination = ethernet_address_format(destination)
	eth_source = ethernet_address_format(source)
	print("\nEthernet Frame:")
	print_tabs(tab_count + 1)
	print(f"Destination: {eth_destination}")
	print_tabs(tab_count + 1)
	print(f"Source: {eth_source}")
	print_tabs(tab_count + 1)
	print(f"Protocol: {eth_proto}")
	return eth_proto, data[14: ]
	
