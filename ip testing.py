verwerkt_ip = []

ip_addressen = [100, 200, 300, 400, 500, 100, 200, 800, 300, 200, 100, 150, 205]
ips = {}

def process_ips():
    global ips
    for ip in ip_addressen:
        if not ip in ips:
            ips[ip] = 1
        else:
            ips[ip] += 1

process_ips()

print(ips)
print(verwerkt_ip)