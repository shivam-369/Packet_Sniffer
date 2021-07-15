import struct

def UDP_packet(data, total_length):
	source_port, destination_port = struct.unpack("! H H", data[:4])
	UDP_Datagram_length, checksum = struct.unpack("! H h", data[4:8])
	
	print("\n\t\tUDP Datagram:")
	print(f"\t\t\tSource port: {source_port}")
	print(f"\t\t\tDestination port: {destination_port}")
	print(f"\t\t\tUDP Datagram length: {UDP_Datagram_length}")
	print(f"\t\t\tChecksum: {checksum}")
	
	return data[8:]
	
	
