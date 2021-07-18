import struct
from ipv4 import *
from formatting import *
from TCP import *
from UDP import *


'''Types:
	0: Echo Reply			4
		Code:
			0
	3: Destination Unreachable	1
		Codes:
			0:	net unreachable
			1: 	host unreachable
			2:	protocol unreachable
			3:	port unreachable
			4:	freagmentation needed and DF set
			5: 	Source route failed
	4: Source Quench		1
		Code:
			0
	5: Redirect			3
		Codes:
			0:	Redirect Datagrams for the network
			1:	Redirect Datagrams for the host
			2:	Redirect Datagrams for the Type of Service and network
			3:	Redirect Dtagrams for the type of Service and Host
	8: Echo			4
		Code:
			0
	11: Time Exceeded		1
		Codes:
			0: Time to leave excceeded in transit
			1: Fragment reasembly time exceeded
	12: Parameter Problem		2
		Code:
			0: Pointer indicates the error
	13: Timestamp			5
		Code:
			0
	14: Timestamp Reply		5
		Code:
			0
	15: Information Request	6
		Code:
			0
	16: Information Reply		6
		Code:
			0
'''


def Information_packet(data, tab_count):
	
	type_list = {15 : "Information Request message", 16: "Information Reply message"}
	Type, Code, Checksum = struct.unpack("! B B H", data[:4])
	Identifier, Sequence_number = struct.unpack("! H H", data[4: 8])
	
	if Type != 15 and Type != 16:
		return
	else:
		print_tabs(tab_count)
		print(f"Type: {Type}({type_list[Type]})")
		print_tabs(tab_count)
		print(f"Code: {Code}")
		print_tabs(tab_count)
		print(f"Checksum: {hex(Checksum)}({Checksum})")
		print_tabs(tab_count)
		print(f"Identifier: {Identifier}")
		print_tabs(tab_count)
		print(f"Sequence Number: {Sequence_number}")
		
	

def Timestamp_packet(data, tab_count):
	
	type_list = {13: "Timestamp message", 14: "Timestamp Reply message"}
	Type, Code, Checksum = struct.unpack("! B B H", data[:4])
	Identifier, Sequence_number = struct.unpack("! H H", data[4: 8])	
	
	Originate_timestamp = struct.unpack("! I", data[8:12])
	Receive_timestamp = struct.unpack("! I", data[12:16])
	Transmit_timestamp = struct.unpack("! I", data[16: 20])
	
	if Type != 13 and Type != 14:
		return
	else:
		print_tabs(tab_count)
		print(f"Type: {Type}({type_list[Type]})")
		print_tabs(tab_count)
		print(f"Code: {Code}")
		print_tabs(tab_count)
		print(f"Checksum: {hex(Checksum)}({Checksum})")
		print_tabs(tab_count)
		print(f"Identifier: {Identifier}")
		print_tabs(tab_count)
		print(f"Sequence Number: {Sequence_number}")
		print_tabs(tab_count)
		print(f"Originate Timestamp: {Originate_timestamp}")
		print_tabs(tab_count)
		print(f"Receive Timestamp: {Receive_timestamp}")
		print_tabs(tab_count)
		print(f"Transmit Timestamp: {Transmit_timestamp}")
		

def Redirect_packet(data, tab_count):

	Type, Code, Checksum = struct.unpack("! B B H", data[:4])
	Gateway_internet_address = struct.unpack("! 4s", data[4:8])
	Gateway_internet_address = IPv4_address_format(Gateway_internet_address)
	 
	if Type != 5:
		return
	else:
		print_tabs(tab_count)
		print(f"Type: {Type}")
		print_tabs(tab_count)
		print(f"Code: {Code}")
		print_tabs(tab_count)
		print(f"Checksum: {hex(Checksum)}({Checksum})")
		print_tabs(tab_count)
		print(f"Gateway Internet Address: {Gateway_internet_address}")
		#print_tabs(tab_count)
		
		ip_proto, length, remaining_data = ipv4_packet(data[8:], tab_count)
		
		if ip_proto == 6:
			tcp_header_for_ICMP(remaining_data, tab_count)
		elif ip_proto == 17:
			UDP_packet(remaining_data, length, tab_count)	
		

def Source_quench_packet(data, tab_count):
	
	Type, Code, Checksum = struct.unpack("! B B H", data[:4])
	unused_bits = struct.unpack("! 4s", data[4:8])
	
	if Type != 4:
		return
	else:
		print_tabs(tab_count)
		print(f"Type: {Type}")
		print_tabs(tab_count)
		print(f"Code: {Code}")
		print_tabs(tab_count)
		print(f"Checksum: {hex(Checksum)}({Checksum})")
		print_tabs(tab_count)
		print(f"Unused Bits: {unused_bits}")
		
		ip_proto, length, remaining_data = ipv4_packet(data[8:], tab_count)
		
		if ip_proto == 6:
			tcp_header_for_ICMP(remaining_data, tab_count)
		elif ip_proto == 17:
			UDP_packet(remaining_data, length, tab_count)	
	


def Parameter_problem_packet(data, tab_count):
	
	Type, Code, Checksum = struct.unpack("! B B H", data[:4])
	Pointer = struct.unpack("! B", data[4:5])
	unused_bits = struct.unpack("! x 3s", data[5:8])
	
	if Type != 12:
		return
	else:
		print_tabs(tab_count)
		print(f"Type: {Type}")
		print_tabs(tab_count)
		print(f"Code: {Code}")
		print_tabs(tab_count)
		print(f"Checksum: {hex(Checksum)}{{Checksum}}")
		print_tabs(tab_count)
		print(f"Pointer: {Pointer}(Indicates the error)")
		print_tabs(tab_count)
		print(f"Unused Bits: {unused_bits}")
		
		ip_proto, length, remaining_data = ipv4_packet(data[8:], tab_count)
		
		if ip_proto == 6:
			tcp_header_for_ICMP(remaining_data, tab_count)
		elif ip_proto == 17:
			UDP_packet(remaining_data, length, tab_count)	
	
	

def Time_exceeded_packet(data, tab_count):
	
	code_list = {0: "Time to leave exceeded in transit", 1: "Fragment reassembly time exceeded"}
	Type, Code, Checksum = struct.unpack("! B B H", data[:4])
	unused_bits = struct.unpack("! 4s", data[4:8])
	
	if Type != 11:
		return
	else:
		print_tabs(tab_count)
		print(f"Type: {Type}")
		print_tabs(tab_count)
		print(f"Code: {Code}({code_list[Code]})")
		print_tabs(tab_count)
		print(f"Checksum: {hex(Checksum)}({Checksum})")
		print_tabs(tab_count)
		print(f"Unused Bits: {unused_bits}")
		
		ip_proto, length, remaining_data = ipv4_packet(data[8:], tab_count)
		
		if ip_proto == 6:
			tcp_header_for_ICMP(remaining_data, tab_count)
		elif ip_proto == 17:
			UDP_packet(remaining_data, length, tab_count)	
	


def Echo_packet(data, tab_count):
	
	type_list = {0 : "Echo Reply", 8 : "Echo Request"}
	Type, Code, Checksum = struct.unpack("! B B H", data[:4])
	Identifier, Sequence_number = struct.unpack("! H H", data[4: 8])
	
	echo_data_list = map(chr, data[8:])
	echo_data = ''.join(echo_data_list)
	
	if Type != 0 and Type != 8:
		return
	else:
		print_tabs(tab_count)
		print(f"Type: {Type}({type_list[Type]})")
		print_tabs(tab_count)
		print(f"Code: {Code}")
		print_tabs(tab_count)
		print(f"Checksum: {hex(Checksum)}({Checksum})")
		print_tabs(tab_count)
		print(f"Identifier: {Identifier}")
		print_tabs(tab_count)
		print(f"Sequence Number: {Sequence_number}")
		print_tabs(tab_count)
		print(f"Echo data: {echo_data}")


def Unreachable_packet(data, tab_count):

	code_list = {0 : "Net Unreachable", 1 : "Host Unreachable", 2 : "Protocol Unreachable", 3 : "Port Unreachable", 4 : "Fragmentation needed and Don't Fragment set", 5 : "Source route failed"}
	Type, Code, Checksum = struct.unpack("! B B H", data[:4])
	unused_bits = struct.unpack("! 4s", data[4:8])
	
	if Type != 3:
		return
	else:
		
		print_tabs(tab_count)
		print(f"Type: {Type}")
		print_tabs(tab_count)
		print(f"Code: {Code}({code_list[Code]})")
		print_tabs(tab_count)
		print(f"Checksum: {hex(Checksum)}({Checksum})")
		print_tabs(tab_count)
		print(f"Unused Bits: {unused_bits}")
		#print_tabs(tab_count)
		
		ip_proto, length, remaining_data = ipv4_packet(data[8:], tab_count)
		
		if ip_proto == 6:
			tcp_header_for_ICMP(remaining_data, tab_count)
		elif ip_proto == 17:
			UDP_packet(remaining_data, length, tab_count)	


#Classifies ICMP packets based on Type field
def ICMP_classify(data, tab_count):
	print("\n")
	print_tabs(tab_count)
	print("Internet Control Message Protocol(ICMP):")
	Type = struct.unpack("! B", data[0:1])[0]
	#print_tabs(tab_count)
	#print(f"Type: {Type}")
	
	if Type == 0 or Type == 8:
		Echo_packet(data, tab_count + 1)
	elif Type == 3:
		Unreachable_packet(data, tab_count + 1)
	elif Type == 4:
		Source_quench_packet(data, tab_count + 1)
	elif Type == 5:
		Redirect_packet(data, tab_count + 1)
	elif Type == 11:
		Time_exceeded_packet(data, tab_couunt + 1)
	elif Type == 12:
		Parameter_problem_packet(data, tab_count + 1)
	elif Type == 13 or Type == 14: 
		Timestamp_packet(data, tab_count + 1)
	elif Type == 15 or Type == 16:
		Information_packet(data, tab_count + 1)
	
