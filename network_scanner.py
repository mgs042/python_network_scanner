from scapy.all import ARP, Ether, srp
import ipaddress
import socket
import requests
import concurrent.futures
import time
import argparse
import csv 

def get_device_name(ip, mac):
	try:
		# Try reverse DNS lookup first
		host = socket.gethostbyaddr(ip)
		return host[0]  # Return the hostname if available
	except socket.herror:
		pass  # If no reverse DNS entry, proceed to MAC lookup

	# Try querying the macvendors API using the MAC address
	try:
		url = f"https://www.macvendorlookup.com/api/v2/{mac}"
		response = requests.get(url)

		if response.status_code == 200:
			vendor_info = response.json()
			return vendor_info[0].get('company', "Unknown Manufacturer")  # Return the manufacturer name from the API
		elif response.status_code == 429:
			print(f"Rate limit reached for MAC {mac}, retrying in 10 seconds...")
			time.sleep(10)  # Wait before retrying
			return get_device_name(ip, mac)
		else:
			print(f"API error for MAC {mac}: Status code {response.status_code}")
			return "Unknown Manufacturer"  # In case of any error from the API
	except requests.RequestException:
		return "Unknown"  # If the API request fails, return "Unknown"

def scan_ip(ip):
	arp_request = ARP(pdst=str(ip))
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast / arp_request

	# Send the packet and capture the response
	answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	devices = []
	for element in answered_list:
	    device_ip = element[1].psrc
	    device_mac = element[1].hwsrc
	    device_name = get_device_name(device_ip, device_mac)  # Get the device name using reverse DNS
	    device = {
		'name': device_name if device_name else "Unknown",
		'ip': device_ip,
		'mac': device_mac
	    }
	    print(device)
	    devices.append(device)  # Append device to list
    
	return devices
def scan_network(network):
	devices = []

	# Generate individual IPs in the subnet
	ips = list(ipaddress.IPv4Network(network).hosts())

	# Use ThreadPoolExecutor to run multiple scans concurrently
	with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
		results = executor.map(scan_ip, ips)

		for result in results:
			devices.extend(result)

	return devices

def scan_ips_from_csv(csv_file):
	ips = []
	# Read IPs from the provided CSV file
	with open(csv_file, mode='r') as file:
		csv_reader = csv.reader(file)
		for row in csv_reader:
			if row:  # Avoid empty rows
				ips.append(row[0])  # Assuming IP addresses are in the first column
	return ips

def write_to_csv(devices, output_file):
	# Write the scanned device information to a CSV file
	with open(output_file, mode='w', newline='') as file:
		writer = csv.writer(file)
		# Write the header
		writer.writerow(["IP Address", "MAC Address", "Hostname"])

		# Write the device data
		for device in devices:
	    		writer.writerow([device['ip'], device['mac'], device['name']])

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument('-ip', '--ip', type=str, help="Single IP to scan", default=None)
    parser.add_argument('-range', '--range', type=str, help="IP range to scan (e.g., 192.168.1.0/24)", default=None)
    parser.add_argument('-csv', '--csv', type=str, help="CSV file containing list of IPs to scan", default=None)
    parser.add_argument('-out', '--output', type=str, help="Output CSV file to write the results", default="scan_results.csv")

    # Parse the arguments
    args = parser.parse_args()

    devices = []

    if args.ip:
        # Scan a single IP address
        print(f"Scanning IP: {args.ip}")
        devices = scan_ip(args.ip)

    elif args.range:
        # Scan an IP range
        print(f"Scanning Network Range: {args.range}")
        devices = scan_network(args.range)

    elif args.csv:
        # Scan IPs from a CSV file
        print(f"Scanning IPs from CSV: {args.csv}")
        ips = scan_ips_from_csv(args.csv)
        print("Scanning the IPs...")
        for ip in ips:
            devices.extend(scan_ip(ip))

    else:
        print("Please provide either a single IP, an IP range, or a CSV file to scan.")

    # Print results
    if devices:
        print("Available Devices in the Network:")
        print("IP Address\t\tMAC Address\t\tHostname")
        print("-----------------------------------------------")
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}\t\t{device['name']}")

        # Write the results to the output CSV file
        write_to_csv(devices, args.output)
        print(f"Results have been written to {args.output}")

if __name__ == "__main__":
    main()
