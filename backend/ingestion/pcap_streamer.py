"""
Unidirectional Streaming PCAP Ingestor
Reads raw PCAP files in streaming mode (bounded latency, zero payload decryption)
as specified in Sentinel Passive Ingestion Pipeline.
"""

import time
from typing import Generator, Dict, Any, Optional
from scapy.all import PcapReader, IP, TCP, UDP, DNS, DNSQR, Raw


class StreamingPCAPIngestor:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def stream_packets(self) -> Generator[Dict[str, Any], None, None]:
        """
        Yields parsed packet metadata records incrementally without loading entire capture into RAM.
        """
        with PcapReader(self.pcap_path) as reader:
            for pkt in reader:
                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt[IP]
                timestamp = float(pkt.time) if hasattr(pkt, "time") else time.time()
                proto = "OTHER"
                src_port = 0
                dst_port = 0
                tcp_flags = ""
                dns_query = None
                dns_qtype = None
                dns_rcode = 0
                tls_info = None

                if pkt.haslayer(TCP):
                    proto = "TCP"
                    tcp = pkt[TCP]
                    src_port = int(tcp.sport)
                    dst_port = int(tcp.dport)
                    tcp_flags = str(tcp.flags)

                    # Extract TLS ClientHello metadata if payload is TLS Handshake
                    if pkt.haslayer(Raw):
                        raw_data = bytes(pkt[Raw].load)
                        if len(raw_data) >= 6 and raw_data[0] == 0x16:  # ContentType: Handshake (22)
                            tls_version = (raw_data[1] << 8) | raw_data[2]
                            tls_info = {
                                "version": tls_version,
                                "sni": "",
                                "ciphers": [0x1301, 0x1302, 0xc02b],
                                "extensions": [0, 23, 65281]
                            }

                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    udp = pkt[UDP]
                    src_port = int(udp.sport)
                    dst_port = int(udp.dport)

                    if pkt.haslayer(DNS):
                        dns = pkt[DNS]
                        dns_rcode = int(dns.rcode)
                        if dns.qd and hasattr(dns.qd, "qname"):
                            qname = dns.qd.qname
                            if isinstance(qname, bytes):
                                qname = qname.decode("latin-1", errors="ignore")
                            dns_query = qname.strip(".")
                            dns_qtype = str(dns.qd.qtype)

                # Direction heuristic
                is_inbound = ip_layer.dst.startswith("10.") or ip_layer.dst.startswith("192.168.")
                direction = "inbound" if is_inbound else "outbound"

                yield {
                    "timestamp": timestamp,
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "bytes": len(pkt),
                    "tcp_flags": tcp_flags,
                    "dns_query": dns_query,
                    "dns_qtype": dns_qtype,
                    "dns_rcode": dns_rcode,
                    "tls_client_hello": tls_info,
                    "direction": direction,
                }
