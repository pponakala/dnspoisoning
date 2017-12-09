import argparse
from scapy.all import *
import collections

def print_poisoning_details(prev_packet, pkt):
	print ""
	print "DNS poisoning attempt"
	print "TXID %s Request %s" % (pkt[DNS].id, pkt[DNS].qd.qname[:-1])
	print "Answer1 %s" % prev_packet[DNSRR].rdata
	print "Answer2 %s" % pkt[DNSRR].rdata

def check_duplicate_responses(pkt):
	#print "checking duplicate packets"
	for prev_packet in prev_packets:
		if prev_packet[IP].dst != pkt[IP].dst or\
		prev_packet[IP].sport != pkt[IP].sport or\
		prev_packet[IP].dport != pkt[IP].dport:
			continue
		if prev_packet[DNS].id == pkt[DNS].id and\
		prev_packet[DNS].qd.qname == pkt[DNS].qd.qname and\
		prev_packet[DNSRR].rdata != pkt[DNSRR].rdata:
			print_poisoning_details(prev_packet, pkt)
	return

def arg_parser():
	parser = argparse.ArgumentParser(add_help=False)
	parser.add_argument("-i", help ="interface")
	parser.add_argument("-r", help="tracefile in tcpdump format")
	parser.add_argument("expression", type=str, help="expression is BPF filter", default="", nargs="?")
	return parser.parse_args()

def callback(pkt):
	if not pkt.haslayer(DNS) or not pkt.haslayer(DNSRR):
		#print "no dns,dns rr layer"
		return
	elif len(prev_packets) < 0:
		#not received any packets yet to compare
		#print "prev packets queue empty"
		return

	#parse packet and check with prev unsent packets that were stored
	check_duplicate_responses(pkt)
	prev_packets.append(pkt)
	return

if __name__ == '__main__':
	args = arg_parser()
	interface = args.i
	tracefile = args.r
	space = " "
	dst_port_filter = "dst port 53" #use for both udp and tcp
	expression = args.expression
	bpf_filter = expression + space + dst_port_filter
	length = 100 #arbitrary
	prev_packets = deque(maxlen = length)

	print interface
	print tracefile
	print expression

	if interface is not None and tracefile is not None:
		print "Expected: either interface or tracefile. Got: both arguments"
	elif interface is not None:
		sniff(filter=bpf_filter, prn=callback, iface=interface, store=0)
	elif tracefile is not None:
		sniff(filter=bpf_filter, prn=callback, offline=tracefile, store=0)
	elif interface is None and tracefile is None:
		interface = 'eth0'
		sniff(filter=expression, prn=callback, store=0)
