from scapy.all import *
import sys

'''
Simple port scanner detector. 

This was created with Python3, Python2 may or may not work. 
You need to have scapy installed, you can do that with the command "pip install scapy"

Run the program on any pcap file with the command "python detector.py filename.pcap".

'''

def main():
	if(len(sys.argv) != 2):
		print("Invalid arguments, should be \"python detector.py filename\"")

	reader = PcapReader(sys.argv[1])
	syn_dict = {}
	syn_ack_dict = {}
	ip_list = set()
	for p in reader:
		if TCP in p and IP in p:
			f = p['TCP'].flags
			if f == 'S':
				ip_list.add(p[IP].src)
				if p[IP].src in syn_dict:
					syn_dict[p[IP].src] += 1
				else:
					syn_dict[p[IP].src] = 1
			if f == 'SA':
				ip_list.add(p[IP].dst)
				if p[IP].dst in syn_ack_dict:
					syn_ack_dict[p[IP].dst] += 1
				else:
					syn_ack_dict[p[IP].dst] = 1
	filtered_ip_list = []
	for i in ip_list:
		if i in syn_dict and i in syn_ack_dict:
			if syn_dict[i]/syn_ack_dict[i] >= 3:
				filtered_ip_list.append(i)
		if i in syn_dict and i not in syn_ack_dict:
			filtered_ip_list.append(i)
	
	if len(filtered_ip_list) == 0:
		print("No port scanners found in the given file")
	else:
		print("The following IP's were found to have using port scanners")
		for i in filtered_ip_list:
			print(i)

if __name__ == '__main__':
	main()