import subprocess
import optparse
import re
def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface", dest="interface", help="enter the valid interface to change mac address")
    parser.add_option("-m","--mac", dest="new_mac", help="enter the valid new mac to change mac address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Enter the the interface  --help for more information")
    elif not options.new_mac:
        parser.error("[-] Enter the  mac address --help for more information")
    else:
        return options
def mac_change(interface, new_mac):
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])
def get_current_mac(interface):
    mac_result = subprocess.check_output(["ifconfig",interface])
    current_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",str(mac_result))
    if current_mac:
        return str(current_mac.group(0))
    else:
        print("[-] The mac address isn't present in this "+interface)
options = get_argument()
current_mac =get_current_mac(options.interface)
print("[+] The current mac address of "+options.interface+" is "+current_mac)
mac_change(options.interface, options.new_mac)
current_mac=get_current_mac(options.interface)
if (current_mac == options.new_mac):
    print("[+] The mac address of "+options.interface+" is successfully changed to "+current_mac)
else:
    print("[-] The mac address wasn't changed successfully")