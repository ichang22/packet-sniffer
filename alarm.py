#!/usr/bin/python3

from scapy.all import *
import argparse
import base64


# Alert 1 = NULL scan (packets without flags detected)
# Alert 2 = FIN scan (packets with only FIN (but no ACK) flags detected)
# Alert 3 = XMAS scan (packets with FIN, PSH, URG detected)
# Alert 4 = plaintext passwords detected (passwords sent under http detected)
# Alert 5 = nikto scan (packets contain word "Nikto")
# Alert 6 = Someone scanning SMB (packets sent to ports 445 or 139)

def packetcallback(packet):
  try:

    #NULL scan
    if packet[TCP].flags == '':
      print("Alert 1! NULL scan detected from " + packet[IP].src + " (TCP)")
    
    # FIN scan
    if ('F' in packet[TCP].flags) and 'A' not in packet[TCP].flags and 'U' not in packet[TCP].flags and 'P' not in packet[TCP].flags and 'R' not in packet[TCP].flags and 'S' not in packet[TCP].flags:
      print("Alert 2! FIN scan detected from " + packet[IP].src + " (TCP)")
    
    # XMAS scan
    if 'F' in packet[TCP].flags and 'P' in packet[TCP].flags and 'U' in packet[TCP].flags and 'A' not in packet[TCP].flags and 'R' not in packet[TCP].flags and 'S' not in packet[TCP].flags:
      print("Alert 3! XMAS scan detected from " + packet[IP].src + " (TCP)")

    # passwords
    s = str(packet[TCP].load)
    if "Authorization:" in s:
      start = "Authorization: Basic"
      end = "\\r\\n"
      encoded = ((s.split(start))[1]).split(end)[0]
      userpass = base64.b64decode(encoded).decode('utf-8')
      print("Alert 4! Usernames and passwords sent in the clear! (" + str(packet[TCP].dport) + ") " "(" + userpass + ")")

    #nikto
    if "Nikto" in s:
      print("Alert 5! Nikto scan detected from " + packet[IP].src + " (" + str(packet[TCP].sport) + ")")

    # SMB
    if packet[TCP].dport == 139 or packet[TCP].dport == 445:
      print("Alert 6! SMB protocol being scanned from " + packet[IP].src + " (" + str(packet[TCP].sport) + ")")


  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()

if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
