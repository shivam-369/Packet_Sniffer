import socket
import sys
from ethernet_frame import ethernet_address_format, ethernet_frame
from ipv4 import IPv4_address_format, IPv4_packet, Type_Of_Service, IP_flags
from TCP import tcp_flags, tcp_packet
from UDP import UDP_packet



		
def main():
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	while True:
		raw_data, addr = s.recvfrom(65536)
		eth_proto, eth_data = ethernet_frame(raw_data)
		if eth_proto == hex(2048):
			ipv4_proto, total_length, ipv4_data = IPv4_packet(eth_data)
			if ipv4_proto == 6:
				tcp_data = tcp_packet(ipv4_data)
			elif ipv4_proto == 17:
				udp_data = UDP_packet(ipv4_data, total_length)
		
		
		
	
main()
#print(sys.byteorder)

