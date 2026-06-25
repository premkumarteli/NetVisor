import os
import time
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

def create_pcaps():
    os.makedirs("tests/fixtures/pcaps", exist_ok=True)
    
    # 1. Standard PCAP
    pkts = [
        Ether()/IP(src="192.168.1.50", dst="192.168.1.1")/UDP(sport=53535, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")),
        Ether()/IP(src="192.168.1.50", dst="192.168.1.100")/TCP(sport=54321, dport=80, flags="S"),
        Ether()/IP(src="192.168.1.100", dst="192.168.1.50")/TCP(sport=80, dport=54321, flags="SA"),
        Ether()/IP(src="192.168.1.50", dst="192.168.1.100")/TCP(sport=54321, dport=80, flags="A")
    ]
    wrpcap("tests/fixtures/pcaps/standard.pcap", pkts)
    
    # 2. Port Scan PCAP
    pkts = []
    for port in range(8000, 8015):
        pkts.append(Ether()/IP(src="192.168.1.50", dst="10.0.0.99")/TCP(sport=54321, dport=port, flags="S"))
    wrpcap("tests/fixtures/pcaps/scan.pcap", pkts)
    
    # 3. DNS Tunneling PCAP
    pkts = []
    for i in range(55):
        sub = f"sub{i}.tunnel.example.com"
        # Use different source ports so each query maps to a separate flow
        pkts.append(Ether()/IP(src="192.168.1.50", dst="8.8.8.8")/UDP(sport=53535 + i, dport=53)/DNS(rd=1, qd=DNSQR(qname=sub)))
    wrpcap("tests/fixtures/pcaps/tunnel.pcap", pkts)
    
    # 4. Beaconing PCAP
    pkts = []
    start_time = time.time()
    for i in range(6):
        # Use different source ports so they are treated as separate beacon connections
        p = Ether()/IP(src="192.168.1.50", dst="10.0.0.99")/TCP(sport=54321 + i, dport=443, flags="A")
        p.time = start_time + i * 10
        pkts.append(p)
    wrpcap("tests/fixtures/pcaps/beacon.pcap", pkts)
    
    # 5. Tor PCAP
    # The Tor exit IP must be the destination to trigger outbound VPN/Tor checks
    pkts = [
        Ether()/IP(src="192.168.1.50", dst="185.220.101.1")/TCP(sport=54321, dport=443, flags="S")
    ]
    wrpcap("tests/fixtures/pcaps/tor.pcap", pkts)
    
    # 6. Mixed Attack PCAP: Port Scan + DNS Tunnel + Large Upload
    pkts = []
    # Port scan (12 ports)
    for port in range(9000, 9012):
        pkts.append(Ether()/IP(src="192.168.1.50", dst="10.0.0.99")/TCP(sport=54321, dport=port, flags="S"))
    # DNS Tunnel (52 subdomains)
    for i in range(52):
        sub = f"sub{i}.mixedtunnel.example.com"
        pkts.append(Ether()/IP(src="192.168.1.50", dst="8.8.8.8")/UDP(sport=53535 + i, dport=53)/DNS(rd=1, qd=DNSQR(qname=sub)))
    # Large upload (TCP payload > 5,000,000 bytes, split into 100 packets of 60,000 bytes)
    large_chunk = b"A" * 60000
    for _ in range(100):
        pkts.append(Ether()/IP(src="192.168.1.50", dst="10.0.0.99")/TCP(sport=54321, dport=443)/large_chunk)
    wrpcap("tests/fixtures/pcaps/mixed.pcap", pkts)

    # 7. WireGuard PCAP (bidirectional handshake + keepalive)
    pkts = [
        Ether()/IP(src="192.168.1.50", dst="10.0.0.99")/UDP(sport=51820, dport=51820)/Raw(load=bytes([1]) + b"A"*147),
        Ether()/IP(src="10.0.0.99", dst="192.168.1.50")/UDP(sport=51820, dport=51820)/Raw(load=bytes([2]) + b"B"*91),
        Ether()/IP(src="192.168.1.50", dst="10.0.0.99")/UDP(sport=51820, dport=51820)/Raw(load=bytes([4]) + b"C"*31)
    ]
    wrpcap("tests/fixtures/pcaps/wireguard.pcap", pkts)

    # 8. OpenVPN PCAP (UDP reset handshakes starting with OpenVPN opcodes)
    pkts = [
        Ether()/IP(src="192.168.1.50", dst="10.0.0.99")/UDP(sport=1194, dport=1194)/Raw(load=bytes([56]) + b"OpenVPN reset")
    ]
    wrpcap("tests/fixtures/pcaps/openvpn.pcap", pkts)

    # 9. Normal UDP Stream PCAP (VoIP / gaming negative test)
    pkts = [
        Ether()/IP(src="192.168.1.50", dst="10.0.0.99")/UDP(sport=12345, dport=3478)/Raw(load=bytes([0]) + b"A"*199),
        Ether()/IP(src="10.0.0.99", dst="192.168.1.50")/UDP(sport=3478, dport=12345)/Raw(load=bytes([0]) + b"B"*299)
    ]
    wrpcap("tests/fixtures/pcaps/normal_udp_stream.pcap", pkts)

if __name__ == "__main__":
    create_pcaps()
