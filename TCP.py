import struct
from formatting import *


def tcp_flags(flags, tab_count):
	 #print(f"flags: {flags}")
	 CWR = bool(flags & (1 << 7))
	 ECE = bool(flags & (1 << 6))
	 Urgent = bool(flags & (1 << 5))
	 Ack = bool(flags & (1 << 4))
	 Push = bool(flags & (1 << 3))
	 Reset = bool(flags & ( 1 << 2))
	 Syn = bool(flags & (1 << 1))
	 Fin = bool(flags & 1)
	 
	 print_tabs(tab_count)
	 print("TCP Flags:")
	 print_tabs(tab_count + 1)
	 print(f"CWR bit: {CWR}")
	 print_tabs(tab_count + 1)
	 print(f"ECE bit: {ECE}")
	 print_tabs(tab_count + 1)
	 print(f"Urgent bit: {Urgent}")
	 print_tabs(tab_count + 1)
	 print(f"Ack bit: {Ack}")
	 print_tabs(tab_count + 1)
	 print(f"Push bit: {Push}")
	 print_tabs(tab_count + 1)
	 print(f"Reset bit: {Reset}")
	 print_tabs(tab_count + 1)
	 print(f"Syn bit: {Syn}")
	 print_tabs(tab_count + 1)
	 print(f"Fin bit: {Fin}")


def tcp_packet(data, tab_count):
	source_port, destination_port = struct.unpack("! H H", data[:4])
	sequence_number, acknowledgement_number = struct.unpack("! I I", data[4:12])
	offset_and_reserved, TCP_flags, window = struct.unpack("! B B H", data[12: 16])
	data_offset = (offset_and_reserved >> 4) * 4
	reserved_bits = (offset_and_reserved & 15)
	checksum, urgent_pointer = struct.unpack("! H H", data[16:20])
	
	print("\n")
	print_tabs(tab_count)
	print("TCP Segment:")
	print_tabs(tab_count + 1)
	print(f"Source port: {source_port}")
	print_tabs(tab_count + 1)
	print(f"Destination port: {destination_port}")
	print_tabs(tab_count + 1)
	print(f"Sequence number: {sequence_number}")
	print_tabs(tab_count + 1)
	print(f"Acknowledgment number: {acknowledgement_number}")
	print_tabs(tab_count + 1)
	print(f"Data offset(bytes): {data_offset}")
	print_tabs(tab_count + 1)
	print(f"Reserved Bits: {reserved_bits}")
	
	tcp_flags(TCP_flags, tab_count + 1)
	print_tabs(tab_count + 1)
	print(f"Window Size: {window}")
	print_tabs(tab_count + 1)
	print(f"Checksum: {hex(checksum)}({checksum})")
	print_tabs(tab_count + 1)
	print(f"Urgent_pointer: {urgent_pointer}")
	
	return data[data_offset:]
	

def tcp_header_for_ICMP(data, tab_count):

	source_port, destination_port = struct.unpack("! H H", data[:4])
	sequence_number = struct.unpack("! I", data[4: 8])
	
	print("\n")
	print_tabs(tab_count)
	print("TCP Datagram:")
	print_tabs(tab_count + 1)
	print(f"Source port: {source_port}")
	print_tabs(tab_count + 1)
	print(f"Destination port: {destination_port}")
	print_tabs(tab_count + 1)
	print(f"Sequence number: {sequence_number}")
	
