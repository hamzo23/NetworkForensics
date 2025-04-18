import pandas as pd
import random
from datetime import datetime, timedelta

# Settings
rows = 1000
start_time = datetime(2025, 4, 17, 0, 0, 0)

protocols = ["HTTP", "HTTPS", "DNS", "FTP", "ICMP", "SMB", "SSH"]
benign_keywords = ["connect", "ack", "handshake", "query", "response"]
malicious_keywords = ["C2", "Upload", "delete", "cleanup", "phishing"]
all_keywords = benign_keywords + malicious_keywords

ports = list(range(20, 1025)) + [4444, 5555]
malicious_ips = ["198.51.100.25", "203.0.113.45", "172.217.5.110"]
benign_ips = ["192.168.1." + str(i) for i in range(10, 100)]

data = []

for i in range(rows):
    time = start_time + timedelta(seconds=i * random.randint(1, 3))
    protocol = random.choice(protocols)
    port = random.choice(ports)
    pkt_size = random.randint(100, 1500)

    # 20% chance of attack
    is_attack = random.random() < 0.2

    dest_ip = random.choice(malicious_ips if is_attack else benign_ips)
    keyword = random.choice(malicious_keywords if is_attack else benign_keywords)

    row = {
        "Timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "Source IP": random.choice(benign_ips),
        "Destination IP": dest_ip,
        "Protocol": protocol,
        "Port": port,
        "Packet Size": pkt_size,
        "Info": f"{keyword} initiated"
    }
    data.append(row)

df = pd.DataFrame(data)
df.to_csv("traffic.csv", index=False)
print("Generated synthetic dataset as traffic.csv")
