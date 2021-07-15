import struct

def tcp_flags(flags):
	 #print(f"flags: {flags}")
	 CWR = bool(flags & (1 << 7))
	 ECE = bool(flags & (1 << 6))
	 Urgent = bool(flags & (1 << 5))
	 Ack = bool(flags & (1 << 4))
	 Push = bool(flags & (1 << 3))
	 Reset = bool(flags & ( 1 << 2))
	 Syn = bool(flags & (1 << 1))
	 Fin = bool(flags & 1)
	 print("\t\t\tTCP Flags:")
	 print(f"\t\t\t\tCWR bit: {CWR}")
	 print(f"\t\t\t\tECE bit: {ECE}")
	 print(f"\t\t\t\tUrgent bit: {Urgent}")
	 print(f"\t\t\t\tAck bit: {Ack}")
	 print(f"\t\t\t\tPush bit: {Push}")
	 print(f"\t\t\t\tReset bit: {Reset}")
	 print(f"\t\t\t\tSyn bit: {Syn}")
	 print(f"\t\t\t\tFin bit: {Fin}")


def tcp_packet(data):
	source_port, destination_port = struct.unpack("! H H", data[:4])
	sequence_number, acknowledgement_number = struct.unpack("! i i", data[4:12])
	offset_and_reserved, TCP_flags, window = struct.unpack("! B B H", data[12: 16])
	data_offset = (offset_and_reserved >> 4) * 4
	reserved_bits = (offset_and_reserved & 15)
	checksum, urgent_pointer = struct.unpack("! h h", data[16:20])
	
	print("\n\t\tTCP Segment:")
	print(f"\t\t\tSource port: {source_port}")
	print(f"\t\t\tDestination port: {destination_port}")
	print(f"\t\t\tSequence number: {sequence_number}")
	print(f"\t\t\tAcknowledgment number: {acknowledgement_number}")
	print(f"\t\t\tData offset(bytes): {data_offset}")
	print(f"\t\t\tReserved Bits: {reserved_bits}")
	tcp_flags(TCP_flags)
	print(f"\t\t\tWindow Size: {window}")
	print(f"\t\t\tChecksum: {checksum}")
	print(f"\t\t\tUrgent_pointer: {urgent_pointer}")
	
	return data[data_offset:]
