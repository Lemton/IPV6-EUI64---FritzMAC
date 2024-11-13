import sys

def ipv6_to_mac(ipv6):
    
    ipv6_parts = ipv6.split(':')
    if len(ipv6_parts) != 8:
        return "Ungültige IPv6-Adresse"

    
    interface_identifier = ipv6_parts[4:]  
    interface_identifier = ''.join(interface_identifier)  

    
    mac_parts = [
        interface_identifier[0:2],
        interface_identifier[2:4],
        interface_identifier[5:7],
        interface_identifier[7:9],
        interface_identifier[10:12],
        interface_identifier[12:14]
    ]

    
    mac_parts[0] = hex(int(mac_parts[0], 16) ^ 0b00000010)[2:].zfill(2)  # U/L-Bit umkehren (zweites Bit)

    
    mac_address = ':'.join(mac_parts)
    return mac_address


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python ipv6_to_mac.py <IPv6-Adresse>")
        sys.exit(1)

    ipv6_address = sys.argv[1]
    mac_address = ipv6_to_mac(ipv6_address)
    print(f"Die rekonstruierte MAC-Adresse aus der IPv6-Adresse {ipv6_address} ist: {mac_address}")
