
import scapy.layers.l2 as scapy
import optparse
def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target", dest="target", help="enter the ip address or the range of ip address")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Enter the the ip address  --help for more information")
    else:
        return options
def scanner(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")  #broadcast mac add is 6ff
    arp_request_broadcast = broadcast/arp_request
    #print(arp_request_broadcast.show())
    answered_list = scapy.srp(arp_request_broadcast,timeout =1,verbose=False)[0]  #0 gives the answered and 1 gives the unanswered
    client_list=[]
    for element in answered_list:
        client_det ={"ip":element[1].psrc,"mac":element[1].hwsrc}
        client_list.append(client_det)
    return client_list


def print_result(scan_result):
    print("\tip\t\tMac\n---------------------------------------------------")
    for client in scan_result:
        print(client["ip"]+"\t|\t"+client["mac"])
options = get_argument()
scan_result=scanner(options.target)
print_result(scan_result)

