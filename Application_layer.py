import struct
from formatting import *

def application_data(data, tab_count):
	
	app_data = map(chr, data)
	
	app_layer_data = ''.join(app_data)
	
	print("\n")
	print_tabs(tab_count)
	print(f"Application Layer Data:")
	print_tabs(tab_count + 1)
	print(f"{app_layer_data}")
