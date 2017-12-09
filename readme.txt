spoofing and inject:
	modifying rdata field of packet in spoofed packet
	all other fields are the same
	race condition: between spoofed packet and actual packet
	ideally to prevent race condition: we must use scapy + nfqueue for packet blocking, modification, and forwarding 
		-> set up IP tables packet queue for all packets with dst port 53, modify packet and send spoofed packet, drop original packet 
		-> however this method would prevent us from detecting spoofed packets in our dnsdetect, hence the simple method is used

detect:
	check if all fields match, including TXID to avoid false positives, like with legitimate consecutive responses with different IP addresses for same hostname
	cases where this may not work:
		two dns packets all have same fields, including TXID, yet are not spoofed and are both not poisonous
		occurs when in a NAT and due to various other reasons mentioned by Prof. in piazza

	limitation: bpf filtering doesn't work in offline mode for scapy. mentioned in piazza.

for dns packets:
	packets with dst port 53 as dns can be on both udp and tcp

invalid bpf filter:
- you get an exception
- depending on whether your system has Global name Scapy_Exception

-i:
not mentioned:
	default eth0 used
mentioned: 
	valid interface used
	invalid interface: error messaeg displayed

-h:
not mentioned:
	all requests forged with local machine IP in rdata as answer
mentioned:
	qname in hostnames.txt file, only those are forged

expression:
	augmented to "dst port 53" filter expression and given as bpf filter to sniff()
	if invalid expression, Exception occurs and is shown on terminal

dns packet types:
	only dns A requests are forged and injected

testing:
dnsinject:
	all possible combinations for cmdline args
	python dnsinject.py 
	python dnsinject.py -i eth0 -h hostnames.txt "udp"
	python dnsinject.py -i eth0
	python dnsinject.py -h hostnames.txt
	python dnsinject.py "udp"
	python dnsinject.py -h hostnames.txt "udp"
	python dnsinject.py -i eth0 "udp"
	python dnsinject.py -i eth0 -h hostnames.txt
dnsdetect:
	all possible combinations for cmdline args
	python dnsdetect.py
	python dnsdetect.py -i eth0
	python dnsdetect.py -r tracefile.pcap
	python dnsdetect.py -i eth0 "udp"
	python dnsdetect.py -r tracefile.pcap "udp"
	python dnsdetect.py "udp"

final test:
	victim guest VM
	another guest VM runs dnsinject and dnsdetect and observes victim's traffic
	
references:
- http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html
- http://www.secdev.org/conf/scapy_lsm2003.pdf
- http://scapy.readthedocs.io/en/latest/functions.html
- https://pypi.python.org/pypi/netifaces
- https://stackoverflow.com/questions/3277503/how-do-i-read-a-file-line-by-line-into-a-list
- http://securitynik.blogspot.com/2014/05/building-your-own-tools-with-scapy.html
- https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
- https://stackoverflow.com/questions/19124304/what-does-metavar-and-action-mean-in-argparse-in-python
