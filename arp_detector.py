import scapy.all as scarpy
import scapy.layers.l2 as scapy

def sniff(interface):
    scarpy.sniff(iface=interface, store=False, prn=process_packet_sniff)

def process_packet_sniff(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op==2:
        #print(packet.show())
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac==response_mac:
                print("[+] you are under apr spoofing attack ")
        except IndexError:
            pass

def get_mac(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # broadcast mac add is 6ff
    arp_request_broadcast = broadcast / arp_request
    # print(arp_request_broadcast.show())
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # 0 gives the answered and 1 gives the unanswered
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print("\n[-] NO response from the " + str(target_ip))
        exit()

sniff("wlan0")
