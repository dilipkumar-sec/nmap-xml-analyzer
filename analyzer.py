print("==============================")
print("       NMAP XML ANALYZER")
print("==============================")

print("My first cybersecurity project!")

import xml.etree.ElementTree as ET


def analyze_scan(filename):
    try:
        tree = ET.parse(filename)
        root = tree.getroot()

    except (ET.ParseError, OSError) as error:
        print(f"Error reading scan file: {error}")
        return

    hosts_found = 0
    open_ports_found = 0

    for host in root.findall("host"):
        status = host.find("status")

        if status is not None and status.get("state") != "up":
            continue

        address = host.find("address")
        ip_address = address.get("addr") if address is not None else "Unknown"

        print(f"\nHost: {ip_address}")
        hosts_found += 1

        ports = host.find("ports")

        if ports is None:
            print("No port information found.")
            continue

        for port in ports.findall("port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            port_number = port.get("portid")
            protocol = port.get("protocol")
            service = port.find("service")

            service_name = service.get("name", "Unknown") if service is not None else "Unknown"
            service_version = service.get("version", "") if service is not None else ""

            print(f"  {port_number}/{protocol} - {service_name}", end="")

            if service_version:
                print(f" ({service_version})")
            else:
                print()

            open_ports_found += 1

    print("\n" + "=" * 40)
    print(f"Hosts found: {hosts_found}")
    print(f"Open ports found: {open_ports_found}")
    print("=" * 40)


if __name__ == "__main__":
    analyze_scan("sample-scan.xml")
