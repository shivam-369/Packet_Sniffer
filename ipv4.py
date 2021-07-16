import struct


#Prints values of IP flags
def IP_flags(flags):
	x_bit = bool(flags >> 2)
	Dont_fragment_bit = bool(flags & (1 << 1))	
	More_Fragments_bit = bool(flags & 1)
	
	print("\t\tIP Flags:")
	print(f"\t\t\tReserved Bit: {x_bit}")
	print(f"\t\t\tDon't Fragment Bit: {Dont_fragment_bit}")
	print(f"\t\t\tMore Fragments Bit: {More_Fragments_bit}")	

#Determines the type of service from IP header
def Type_Of_Service(Type_of_service):
	precedence_list = {0: "routine", 1 : "Priority" , 2 : "Immediate", 3 : "Flash", 4 : "Flash Override", 5 : "CRITIC/ECP", 6 : "Internetwork Control", 7 : "Network Control"}
	Delay_list = {0 : "Normal Delay", 1 : "Low Delay"}
	Throughput_list = {0: "Normal Throughput", 1: "High Throughput"}
	Reliability_list = {0:"Normal Reliability" , 1 : "High reliability"}
	
	precedence_bit = (Type_of_service >> 5)
	Delay_bit = (Type_of_service & (1 << 4))
	Throughput_bit = (Type_of_service & (1 << 3))
	Reliability_bit = (Type_of_service & (1 << 2))
	Reserved_bits = (Type_of_service & 3)
	
	print("\t\tService bits:")
	print(f"\t\t\tPrecedence Bits: {precedence_bit}({precedence_list[precedence_bit]})")
	print(f"\t\t\tDelay Bit: {Delay_bit}({Delay_list[Delay_bit]})")
	print(f"\t\t\tThroughput Bit: {Throughput_bit}({Throughput_list[Throughput_bit]})")
	print(f"\t\t\tRelaibility Bit: {Reliability_bit}({Reliability_list[Reliability_bit]})")
	
	
#prints Differentiated Service field 
def Diff_service_fields(service):
	
	''' DSCP - Differentiated service Codepoint
	    ECN  - Explicit Congestion Notification
	'''
	DSCP = (service >> 2)
	ECN = (service & 3)
	
	print(f"\t\tDifferentiated Field: {service}")
	print(f"\t\t\tDifferentiated Service Codepoint: {DSCP}({format(DSCP, '#06')})")
	print(f"\t\t\tExplicit Congestion Notification: {ECN}({format(ECN, '#02')})")
	


# Returns Properly formatted IP address	
def IPv4_address_format(addr):
	return '.'.join(map(str, addr))
	
	
#Unpacks IP packet	
def IPv4_packet(data):
	version_and_Hlength, Type_of_service, total_length = struct.unpack("! B B h", data[:4])
	version = (version_and_Hlength >> 4)
	header_length = (version_and_Hlength & 15) * 4
	identification, flags_and_offset = struct.unpack("! h h", data[4: 8])
	flags = (flags_and_offset >> 13)
	fragment_offset = ((flags_and_offset) & (2 ** 13))
	TTL, IP_proto, header_checksum = struct.unpack("! B B h", data[8: 12])
	source, destination =struct.unpack("! 12x 4s 4s", data[: 20])
	ipv4_source = IPv4_address_format(source)
	ipv4_destination = IPv4_address_format(destination)
	
	print("\n\tIPv4 packet:")
	print(f"\t\tversion: {version}")
	print(f"\t\tHeader length: {header_length}")
	
	#print(f"\t\tDifferentiated Service Field: {Type_of_service}")
	Diff_service_fields(Type_of_service)
	
	#Type_Of_Service(Type_of_service)
	
	print(f"\t\tTotal Length: {total_length}")
	print(f"\t\tidentification: {identification}")
	#print(f"\t\tflags: {flags}")
	IP_flags(flags)
	print(f"\t\tfragment offset: {fragment_offset}")
	print(f"\t\tTime to Leave: {TTL}")
	print(f"\t\tprotocol: {IP_proto}")
	print(f"\t\theader checksum: {header_checksum}")	
	print(f"\t\tSource: {ipv4_source}")
	print(f"\t\tDestination: {ipv4_destination}")
	
	return IP_proto, total_length - header_length, data[header_length:]	 

