"""
DNS request responder
We borrow the solution from https://thepacketgeek.com/scapy-p-09-scapy-and-dns/
with small modification

Team-9
"""
from scapy.all import *

DNSServerIP = "100.0.0.21"
filter = "udp port 53 and ip dst " + DNSServerIP + " and not ip src " + DNSServerIP
RespIP = "100.0.0.45"

def DNS_Responder(localIP):
        def getResponse(pkt):
                if (DNS in pkt and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 and pkt[IP].src != RespIP):
                        if "sdncourse.se" in pkt['DNS Question Record'].qname:
				spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst)\
					/UDP(dport=pkt[UDP].sport, sport=53)\
					/DNS(id=pkt[DNS].id, \
					qr=1L,\
					qd=DNSQR(qname=pkt[DNSQR].qname), \
					an=DNSRR(rrname="sdncourse.se",rdata=RespIP))
                                #spfResp = IP(dst=pkt[IP].src)\
                                #        /UDP(dport=pkt[UDP].sport, sport=53)\
                                #        /DNS(id=pkt[DNS].id,ancount=1,rd=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=RespIP)\
                                #        /DNSRR(rrname="sdncourse.se",rdata=RespIP))
                                send(spfResp,verbose=0)
                                return "Spoofed DNS Response Sent"
                        else :
                                # do nothing, since we do not forward dns here
                                return False
                else :
                        return False
        return getResponse

sniff(filter=filter,prn=DNS_Responder(DNSServerIP))

