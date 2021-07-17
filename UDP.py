import struct
from formatting import *

def UDP_packet(data, total_length, tab_count):
	source_port, destination_port = struct.unpack("! H H", data[:4])
	UDP_Datagram_length, checksum = struct.unpack("! H H", data[4:8])
	
	print("\n")
	print_tabs(tab_count)
	print("UDP Datagram:")
	print_tabs(tab_count + 1)
	print(f"Source port: {source_port}")
	print_tabs(tab_count + 1)
	print(f"Destination port: {destination_port}")
	print_tabs(tab_count + 1)
	print(f"UDP Datagram length: {UDP_Datagram_length}")
	print_tabs(tab_count + 1)
	print(f"Checksum: {hex(checksum)}({checksum})")
	
	return data[8:]
	
	
	
