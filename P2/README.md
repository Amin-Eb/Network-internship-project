Second part: Web protocols

# Transactional protocols
Many of the communications over the web are based on protocols, which use transactions (the request and its responses or responses)

The transaction success rate is a really important metric, some of which means communication quality

## DNS Protocol
For example, in DNS servers
We will help the server owners find their failures to fix them
First, learn about the DNS protocol, and then we will continue with how to detect the transaction success rate

### A pragmatic approach to learning about DNS

1. Install Wireshark 
2. Clear DNS cache
3. Start Wireshark capture
4. Open any browser and check some different addresses
5. Write some addresses which no IP would bind them
6. Stop Wireshark capturing
7. Save captured traffic as a PCAP file
8. Open the pcap file and filter DNS

There are requests and their responses
Usually, successful transactions happen
Most of the transactions are about telling you IP for your address
Some of them introduce aliases for addresses

### Official documents about DNS


### Cpp Libraries understanding DNS

