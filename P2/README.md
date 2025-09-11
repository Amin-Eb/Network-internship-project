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

It is recommended to read below RFCs (request for comments).

1. [DNS Terminology](https://datatracker.ietf.org/doc/html/rfc9499) can be used as a dictionary for DNS related terms. 
2. [Domain names - concepts and facilities](https://datatracker.ietf.org/doc/html/rfc1034) can explains how DNS works
3. [Domain names - implementation and specification](https://datatracker.ietf.org/doc/html/rfc1035) is a guideline for DNS servers  implementation


### Cpp Libraries understanding DNS
TODO: please fill this part by your search results.

### DNS transaction reporter

Final goal is have an executable file which can report success rate of DNS transactions.

It may do it either reading a pcap file or read packet from network interface (as Wireshark did).

#### DNS transaction success detector

At this point we may assume an stream of DnsTransaction are available so we can report them.

class is not responsible to handle receiving stream but some one should be able use it that way.

Write an example and may simulate stream by 10 DnsTransaction content.

```
structure Binary
{
    uint8_t* data;
    uint16_t length;
};

structure DnsTransaction
{
    Binary request;
    Binary response;
};
```

First write a class that may receive DnsTransactions and report success rate.

It should have unit tests which cover class functionality.

#### DNS transaction detector

Here we will implement a class which can relate responses to their own requests.

Here you may need some metadata of packet more than just Binary for request and response.

Look for pcap you captured and gather needed information as an structure contains Binary (lets call it Packet).

The transaction detector should be used for relate response to request and provide DnsTransaction to success rate reporter.

It should capable of receive stream of Packets and deliver stream of DnsTransactions.

Again unit tests should cover this class functionality again.

Again class is not responsible to handle receiving stream but some one should be able use it that way.

Write an example and may simulate stream by 20 Packets content.

#### Design your own approach

You can create other flow to receive stream of data and some how report success rate

Here you should design classes with different functionality.

Again unit test, and example of 20 content representing a packet is necessary.
