import sys
import ipaddress
import argparse
import sys
import requests
import AppleWLoc_pb2
import os



def expand_ipv6_address(ipv6):
    try:
        return str(ipaddress.IPv6Address(ipv6))
    except ipaddress.AddressValueError:
        return None

def extract_eui64_from_ipv6(ipv6):
    """
    Extracts and converts the EUI-64 portion of an IPv6 address to a MAC address.
    Returns the MAC address as a string if valid, otherwise returns None.
    """
    try:
        # Normalize and expand the IPv6 address
        ipv6_obj = ipaddress.IPv6Address(ipv6)
        expanded_ipv6 = ipv6_obj.exploded
    except ipaddress.AddressValueError:
        print("Ungültige IPv6-Adresse.")
        return None

    # Split the expanded IPv6 address into its 8 hextets
    ipv6_parts = expanded_ipv6.split(':')
    
    # Extract the lower 64 bits (last 4 hextets) for the interface identifier
    interface_identifier = ''.join(ipv6_parts[4:])
    if len(interface_identifier) != 16:
        print("Ungültige Länge des Interface-Identifiers.")
        return None

    # Handle conversion to MAC address by removing "fffe" if present
    if 'fffe' in interface_identifier:
        interface_identifier = interface_identifier.replace('fffe', '')

    # Convert the identifier into a MAC address format
    mac_parts = [
        interface_identifier[0:2],  # Erstes Byte
        interface_identifier[2:4],  # Zweites Byte
        interface_identifier[4:6],  # Drittes Byte
        interface_identifier[6:8],  # Viertes Byte
        interface_identifier[8:10], # Fünftes Byte
        interface_identifier[10:12] # Sechstes Byte
    ]

    # Invert the seventh bit of the first octet (U/L bit)
    mac_parts[0] = hex(int(mac_parts[0], 16) ^ 0b00000010)[2:].zfill(2).upper()

    # Join the parts into a MAC address format
    mac_address = ':'.join(mac_parts).upper()
    return mac_address


def calculate_bssid_from_wan_mac(wan_mac, offsets):
    # Konvertiere die MAC-Adresse in eine Liste von Bytewerten
    mac_bytes = [int(x, 16) for x in wan_mac.split(':')]

    # Liste zur Speicherung der berechneten BSSIDs
    calculated_bssids = []

    # Wende jeden Offset an
    for offset in offsets:
        modified_mac = mac_bytes.copy()
        modified_mac[-1] += offset

        # Überlauf- und Unterlaufkorrektur
        for i in reversed(range(6)):
            if modified_mac[i] > 255:
                modified_mac[i] -= 256
                if i > 0:
                    modified_mac[i - 1] += 1
            elif modified_mac[i] < 0:
                modified_mac[i] += 256
                if i > 0:
                    modified_mac[i - 1] -= 1

        # Konvertiere zurück zu einer MAC-Adresszeichenkette
        bssid = ':'.join(f'{x:02x}' for x in modified_mac)
        calculated_bssids.append((offset, bssid))

    return calculated_bssids



def get_argument_parser():
	parser = argparse.ArgumentParser()
	parser.add_argument("bssid", type=str, help="display the location of the bssid")
	parser.add_argument("-m", "--map", help="shows the location on google maps", action='store_true')
	return parser
	
def parse_arguments():
	parser = get_argument_parser()
	args = parser.parse_args()
	return args
	
def format_bssid(bssid):
	result = ''
	for e in bssid.split(':'):
		if len(e) == 1:
			e='0%s'%e
		result += e+':'
	return result.strip(':')

def process_result(apple_wloc):
	device_locations = {}
	for wifi_device in apple_wloc.wifi_devices:
		if wifi_device.HasField('location'):
			lat = wifi_device.location.latitude * pow(10,-8)
			lon = wifi_device.location.longitude * pow(10,-8)
			mac = format_bssid(wifi_device.bssid)
			device_locations[mac] = (lat,lon)
	return device_locations

def query_bssid(bssid):
    apple_wloc = AppleWLoc_pb2.AppleWLoc()
    wifi_device = apple_wloc.wifi_devices.add()
    wifi_device.bssid = bssid
    apple_wloc.unknown_value1 = 0
    apple_wloc.return_single_result = 1
    serialized_apple_wloc = apple_wloc.SerializeToString()
    length_serialized_apple_wloc = len(serialized_apple_wloc)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
        "Accept-Charset": "utf-8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-us",
        'User-Agent': 'locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0'
    }
    data = "\x00\x01\x00\x05" + "en_US" + "\x00\x13" + "com.apple.locationd" + "\x00\x0a" + "8.1.12B411" + "\x00\x00\x00\x01\x00\x00\x00" + chr(length_serialized_apple_wloc) + serialized_apple_wloc.decode()

    cert_path = 'appleapi.crt'
    r = requests.post('https://gs-loc.apple.com/clls/wloc', headers=headers, data=data, verify=cert_path)
    
    apple_wloc = AppleWLoc_pb2.AppleWLoc() 
    apple_wloc.ParseFromString(r.content[10:])
    return process_result(apple_wloc)


def bssidlocator(bssid_address):
    #print("Searching for location of bssid: %s" % bssid_address)
    results = query_bssid(bssid_address)
    lat = "-180.0"
    lon = "-180.0"
     
    if len(results) > 0:
            if results[bssid_address] != (-180.0, -180.0):
                print(results[bssid_address])
    else:
        print("The bssid was not found.")




if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python ipv6_to_mac.py <IPv6-Adresse>")
        sys.exit(1)

    ipv6_address = sys.argv[1]
    wan_mac_address = extract_eui64_from_ipv6(ipv6_address)
    
    print(f"Die rekonstruierte MAC-Adresse aus der IPv6-Adresse {ipv6_address} ist: {wan_mac_address}")

    if len(wan_mac_address) > 2:
        # Use predefined offsets if the MAC address is valid
        offsets = [-2, -1, 0, 1, 2, 3, 10, 16, -10, -16]
    else:
        print("Ungültige MAC-Adresse generiert. Keine Offsets verwendet.")
        sys.exit(1)

    bssid_list = calculate_bssid_from_wan_mac(wan_mac_address, offsets)

    print("Offsets für BSSIDs werden getestet...")

    for offset, bssid in bssid_list:
        #print(f"Berechnete BSSID mit Offset {offset}: {bssid}")
        try:
            bssidlocator(bssid)  # Pass only the bssid string, not the tuple
        except Exception as e:
            print(f"Error querying BSSID {bssid}: {e}")
    print("Alle Offsets getestet.")