import struct
from formatting import *

#Prints values of IP flags
def IP_flags(flags, tab_count):
	x_bit = bool(flags >> 2)
	Dont_fragment_bit = bool(flags & (1 << 1))	
	More_Fragments_bit = bool(flags & 1)
	
	print_tabs(tab_count)
	print("IP Flags:")
	print_tabs(tab_count + 1)
	print(f"Reserved Bit: {x_bit}")
	print_tabs(tab_count + 1)
	print(f"Don't Fragment Bit: {Dont_fragment_bit}")
	print_tabs(tab_count + 1)
	print(f"More Fragments Bit: {More_Fragments_bit}")	




#Determines the type of service from IP header
def Type_Of_Service(Type_of_service, tab_count):
	precedence_list = {0: "routine", 1 : "Priority" , 2 : "Immediate", 3 : "Flash", 4 : "Flash Override", 5 : "CRITIC/ECP", 6 : "Internetwork Control", 7 : "Network Control"}
	Delay_list = {0 : "Normal Delay", 1 : "Low Delay"}
	Throughput_list = {0: "Normal Throughput", 1: "High Throughput"}
	Reliability_list = {0:"Normal Reliability" , 1 : "High reliability"}
	
	precedence_bit = (Type_of_service >> 5)
	Delay_bit = (Type_of_service & (1 << 4))
	Throughput_bit = (Type_of_service & (1 << 3))
	Reliability_bit = (Type_of_service & (1 << 2))
	Reserved_bits = (Type_of_service & 3)
	
	print_tabs(tab_count)
	print("Service bits:")
	print_tabs(tab_count + 1)
	print(f"Precedence Bits: {precedence_bit}({precedence_list[precedence_bit]})")
	print_tabs(tab_count + 1)
	print(f"Delay Bit: {Delay_bit}({Delay_list[Delay_bit]})")
	print_tabs(tab_count + 1)
	print(f"Throughput Bit: {Throughput_bit}({Throughput_list[Throughput_bit]})")
	print_tabs(tab_count + 1)
	print(f"Relaibility Bit: {Reliability_bit}({Reliability_list[Reliability_bit]})")
	

	
#prints Differentiated Service field 
def Diff_service_fields(service, tab_count):
	
	''' DSCP - Differentiated service Codepoint
	    ECN  - Explicit Congestion Notification
	'''
	DSCP = (service >> 2)
	ECN = (service & 3)
	
	print_tabs(tab_count)
	print(f"Differentiated Field: {service}")
	print_tabs(tab_count + 1)
	print(f"Differentiated Service Codepoint: {DSCP}({format(DSCP, '#06')})")
	print_tabs(tab_count + 1)
	print(f"Explicit Congestion Notification: {ECN}({format(ECN, '#02')})")
	

# Returns Properly formatted IP address	
def IPv4_address_format(addr):
	return '.'.join(map(str, addr))
	
	
	
#Unpacks IP packet. Same as above function but it returns data and other variables instead of header_length	
def IPv4_packet(data, tab_count):
	
	version_and_Hlength, Type_of_service, total_length = struct.unpack("! B B h", data[:4])
	version = (version_and_Hlength >> 4)
	header_length = (version_and_Hlength & 15) * 4
	
	identification, flags_and_offset = struct.unpack("! H H", data[4: 8])
	flags = (flags_and_offset >> 13)
	fragment_offset = ((flags_and_offset) & (2 ** 13))
	
	TTL, IP_proto, header_checksum = struct.unpack("! B B H", data[8: 12])
	
	source, destination =struct.unpack("! 12x 4s 4s", data[: 20])
	ipv4_source = IPv4_address_format(source)
	ipv4_destination = IPv4_address_format(destination)
	
	print("\n")
	print_tabs(tab_count)
	print("IPv4 packet:")
	print_tabs(tab_count + 1)
	print(f"version: {version}")
	print_tabs(tab_count + 1)
	print(f"Header length: {header_length}")
	
	#print(f"\t\tDifferentiated Service Field: {Type_of_service}")
	Diff_service_fields(Type_of_service, tab_count + 1)
	
	#Type_Of_Service(Type_of_service)
	print_tabs(tab_count + 1)
	print(f"Total Length: {total_length}")
	print_tabs(tab_count + 1)
	print(f"identification: {identification}")
	#print(f"\t\tflags: {flags}")
	IP_flags(flags, tab_count + 1)
	print_tabs(tab_count + 1)
	print(f"fragment offset: {fragment_offset}")
	print_tabs(tab_count + 1)
	print(f"Time to Leave: {TTL}")
	print_tabs(tab_count + 1)
	print(f"protocol: {IP_proto}")
	print_tabs(tab_count + 1)
	print(f"header checksum: {hex(header_checksum)}({header_checksum})")	
	print_tabs(tab_count + 1)
	print(f"Source: {ipv4_source}")
	print_tabs(tab_count + 1)
	print(f"Destination: {ipv4_destination}")
	
	return IP_proto, total_length - header_length, data[header_length:]	 

