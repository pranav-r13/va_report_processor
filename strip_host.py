import re

def process_input(data):
    # Split entries like "192.168.4.232/CVE-2020-11655"
    entries = data.split()

    # Extract IPs and CVEs
    ips = set()
    cves = set()

    for entry in entries:
        if "/" in entry:
            ip, cve = entry.split('/')
            ips.add(ip.strip())
            cves.add(cve.strip())

    # Sort CVEs by year and number
    def cve_sort_key(cve):
        match = re.match(r"CVE-(\d+)-(\d+)", cve)
        if match:
            year, num = match.groups()
            return int(year), int(num)
        return (0, 0)

    sorted_cves = sorted(cves, key=cve_sort_key, reverse=True)

    # Get only the two latest CVEs
    latest_cves = sorted_cves[:2]

    # Return result in one line
    return " ".join(sorted(ips)) + " " + " ".join(latest_cves)


# Run continuously
while True:
    data = input("\nEnter the IP/CVE list (or type 'exit' to quit): ")
    if data.lower() == "exit":
        print("Exiting...")
        break
    result = process_input(data)
    print("\n\n",result)
