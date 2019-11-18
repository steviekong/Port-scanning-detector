from scapy.all import *
import sys

def main():
	if(len(sys.argv) != 2):
		print("Invalid arguments, should be \"python detector.py filename\"")

	reader = PcapReader(sys.argv[1])
	syn_dict = {}
	syn_ack_dict = {}
	ip_list = []
	for p in reader:
		if TCP in p and IP in p:
			f = p['TCP'].flags
			if f & 0x02:
				if p[IP].src not in ip_list:
					ip_list.append(p[IP].src)
					print(ip_list)
				if p[IP].src in syn_dict:
					syn_dict[p[IP].src] += 1
				else:
					syn_dict[p[IP].src] = 1
			if f & 0x012:
				if p[IP].src not in ip_list:
					ip_list.append(p[IP].src)
				if p[IP].src in syn_ack_dict:
					syn_ack_dict[p[IP].src] += 1
				else:
					syn_ack_dict[p[IP].src] = 1
	filtered_ip_list = []
	for i in ip_list:
		if i in syn_dict and i in syn_ack_dict:
			if syn_dict[i]/syn_ack_dict[i] > 3:
				filtered_ip_list.append(i)
		if i in syn_dict and i not in syn_ack_dict:
			filtered_ip_list.append(i)
	print(filtered_ip_list)

if __name__ == '__main__':
	main()