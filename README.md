# packet-sniffer

reads a PCAP file and raises an alert if any of the following activity is found:
  • NULL scan 
  • FIN scan
  • XMAS scan
  • plaintext passwords detected
  • nikto scan
  • Someone scanning SMB
