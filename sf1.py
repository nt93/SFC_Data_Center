# This code is to be run on Service Function 1

import socket, os, sys
from struct import *
from PIL import Image
import io
import time
from PIL import ImageFile
from thread import *
def makeip_header(source_ip, dest_ip):
	ip_ihl = 5
	ip_ver = 4
	ip_tos = 0
	ip_tot_len = 0  # kernel will fill the correct total length
	ip_id = 54321   #Id of this packet
	ip_frag_off = 0
	ip_ttl = 255
	ip_proto = socket.IPPROTO_UDP
	ip_check = 0    # kernel will fill the correct checksum
	ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
	ip_daddr = socket.inet_aton ( dest_ip )

	ip_ihl_ver = (ip_ver << 4) + ip_ihl

	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
	return ip_header

def makeudp_header(src_port,dest_port,length):
	udp_dest = 1234   # source port
	udp_source = 5678   # destination port
	udp_check = 0
	udp_len = 8 + length
	udp_header = pack('!HHHH' , udp_source, udp_dest, udp_len, udp_check)
	return udp_header


def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]

while True:
    packet = s.recvfrom(65565)
    packet = packet[0]

    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    if eth_addr(packet[0:6]) == "fa:16:3e:00:16:83":
	    print "Received Some packet"
	    if eth_protocol == 8 :
       		ip_header = packet[eth_length:20+eth_length]

        	iph = unpack('!BBHHHBBH4s4s' , ip_header)

        	version_ihl = iph[0]
        	version = version_ihl >> 4
        	ihl = version_ihl & 0xF

        	iph_length = ihl * 4

        	ttl = iph[5]
        	protocol = iph[6]
        	s_addr = socket.inet_ntoa(iph[8]);
        	d_addr = socket.inet_ntoa(iph[9]);

        	print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

            	if protocol == 17 :
            		u = iph_length + eth_length
            		udph_length = 8
            		udp_header = packet[u:u+8]

            		udph = unpack('!HHHH' , udp_header)

            		source_port = udph[0]
            		dest_port = udph[1]
            		length = udph[2]
            		checksum = udph[3]

            		print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

            		h_size = eth_length + iph_length + udph_length
            		data_size = len(packet) - h_size

            		data = packet[h_size:]
			data_str = str(data)
			if (data_str.find("SIGSFC") != -1) or (data_str.find("PROBE") != -1):
				print "Signal Received"
				try:
    					newSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
				except socket.error , msg:
    					print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
				ip_header = makeip_header(s_addr,d_addr)
				user_data = data
				udp_header=makeudp_header(dest_port,source_port,len(user_data))
				packet = ip_header + udp_header + user_data
				newSock.sendto(packet, (d_addr , 0 ))    # put this in a loop if you want to flood the target
				newSock.close()
				data = 0
				print "Signal Sent"
			else:
				print "Image Received"
				img_file=open('image_client','wb')
     				img_file.write(data)
     				img_file.close()
    				img_modi=Image.open('image_client').convert('L')                #Converting to Gray Scale
    				img_modi.save('Server_img_modified.jpg')
				try:
    					newSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
				except socket.error , msg:
    					print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
				ip_header = makeip_header(s_addr,d_addr)
				user_data = ""
    				img_modifile=open('Server_img_modified.jpg','rb')
    				user_data=user_data+img_modifile.read(1400)
				udp_header=makeudp_header(dest_port,source_port,len(user_data))
				packet = ip_header + udp_header + user_data
				newSock.sendto(packet, (d_addr , 0 ))    # put this in a loop if you want to flood the target
				newSock.close()
				print "Image Sent"
		elif protocol == 1 :
            		u = iph_length + eth_length
            		icmph_length = 4
            		icmp_header = packet[u:u+4]
 
            		icmph = unpack('!BBH' , icmp_header)
             
            		icmp_type = icmph[0]
            		code = icmph[1]
            		checksum = icmph[2]
             
            		print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
             
            		h_size = eth_length + iph_length + icmph_length
            		data_size = len(packet) - h_size
             
            		data = packet[h_size:]
             
            		print 'Data : ' + data
    
			try:
    				s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
			except socket.error , msg:
    				print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    			packet = ip_header + icmp_header + data
			print "Sending packet"
			try:
				s.sendto(packet, (d_addr , 0 ))    # put this in a loop if you want to flood the target
			except sendto.error , msg:
				print "Did not send"
			print "Packet sent"
            	else :
            		print 'Protocol other than TCP/UDP/ICMP'
		print "Signal Sent. Go to while loop"

