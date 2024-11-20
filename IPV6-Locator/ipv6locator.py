import sys
import ipaddress
from appleapi import bssidlocator

def expand_ipv6_address(ipv6):
    try:
        return str(ipaddress.IPv6Address(ipv6))
    except ipaddress.AddressValueError:
        return None

def extract_eui64_from_ipv6(ipv6):
    """
    Extrahiert und konvertiert den EUI-64-Teil einer IPv6-Adresse in eine MAC-Adresse.
    Gibt die MAC-Adresse als Zeichenkette zurück, falls gültig, andernfalls None.
    """
    try:
        # Normalisierung und Expansion der IPv6-Adresse
        ipv6_obj = ipaddress.IPv6Address(ipv6)
        expanded_ipv6 = ipv6_obj.exploded
    except ipaddress.AddressValueError:
        print("Ungültige IPv6-Adresse.")
        return None

    # Aufteilen der expandierten IPv6-Adresse in 8 Hextets
    ipv6_parts = expanded_ipv6.split(':')
    
    # Extraktion der unteren 64 Bits (letzte 4 Hextets) für den Interface-Identifier
    interface_identifier = ''.join(ipv6_parts[4:])
    if len(interface_identifier) != 16:
        print("Ungültige Länge des Interface-Identifiers.")
        return None

    # Entfernen von "fffe", falls vorhanden, zur Konvertierung in die MAC-Adresse
    if 'fffe' in interface_identifier:
        interface_identifier = interface_identifier.replace('fffe', '')

    # Umwandlung in ein MAC-Adressformat
    mac_parts = [
        interface_identifier[0:2],
        interface_identifier[2:4],
        interface_identifier[4:6],
        interface_identifier[6:8],
        interface_identifier[8:10],
        interface_identifier[10:12]
    ]

    # Invertierung des siebten Bits des ersten Oktetts (U/L-Bit)
    mac_parts[0] = hex(int(mac_parts[0], 16) ^ 0b00000010)[2:].zfill(2).upper()

    # Zusammenfügen der Teile zur MAC-Adresse
    mac_address = ':'.join(mac_parts).upper()
    return mac_address

def calculate_bssid_from_wan_mac(wan_mac, offsets):
    # Konvertierung der MAC-Adresse in eine Liste von Bytewerten
    mac_bytes = [int(x, 16) for x in wan_mac.split(':')]

    calculated_bssids = []

    # Anwenden der Offsets
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

        # Konvertierung zurück in eine MAC-Adresszeichenkette
        bssid = ':'.join(f'{x:02x}' for x in modified_mac)
        calculated_bssids.append((offset, bssid))

    return calculated_bssids


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Verwendung: python ipv6_to_mac.py <IPv6-Adresse>")
        sys.exit(1)

    ipv6_address = sys.argv[1]
    wan_mac_address = extract_eui64_from_ipv6(ipv6_address)
    
    print(f"Die rekonstruierte MAC-Adresse aus der IPv6-Adresse {ipv6_address} ist: {wan_mac_address}")

    if len(wan_mac_address) > 2:
        offsets = [-2, -1, 0, 1, 2, 3, 10]
    else:
        print("Ungültige MAC-Adresse generiert. Keine Offsets verwendet.")
        sys.exit(1)

    bssid_list = calculate_bssid_from_wan_mac(wan_mac_address, offsets)

    print("Offsets für BSSIDs werden getestet...")

    for offset, bssid in bssid_list:
        try:
            print(f"Offset {offset}:")
            l = bssidlocator(bssid) 
        except Exception as e:
            print(f"Error querying BSSID {bssid}: {e}")
    print("Alle Offsets getestet.")
