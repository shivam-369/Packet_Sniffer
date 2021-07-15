import struct


def ethernet_address_format(addr):
	proper_addr = map('{:02x}'.format, addr)
	proper_mac_addr = ':'.join(proper_addr)
	return proper_mac_addr

def ethernet_frame(data):
	destination, source = struct.unpack("! 6s 6s", data[0: 12])
	protocol = struct.unpack("! h", data[12: 14])	
	eth_proto = hex(protocol[0])
	eth_destination = ethernet_address_format(destination)
	eth_source = ethernet_address_format(source)
	print("\nEthernet Frame:")
	print(f"\tDestination: {eth_destination}")
	print(f"\tSource: {eth_source}")
	print(f"\tProtocol: {eth_proto}")
	return eth_proto, data[14: ]
	
