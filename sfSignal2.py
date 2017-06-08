# This code is to be run on Client to first send a signaling message for Tenant 2, followed by the payload (colored image)

import socket, sys
from struct import *
import time 

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
packet = '';
 
source_ip = '1.1.1.2'
dest_ip = '192.168.0.1' # or socket.gethostbyname('www.google.com')

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
 
user_data = "\"SIGSFC,SF2,TS2"

udp_source = 1234   # source port
udp_dest = 5678   # destination port
udp_check = 0
udp_len = 8 + len(user_data)
udp_header = pack('!HHHH' , udp_source, udp_dest, udp_len, udp_check)
 
source_address = socket.inet_aton( source_ip )
dest_address = socket.inet_aton(dest_ip)
protocol = socket.IPPROTO_UDP
packet = ip_header + udp_header + user_data
 
s.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target

time.sleep(5)

user_data = ""
with open("facebook.jpg","rb") as f:
     print 'file opened'
     user_data=user_data+f.read(1400)

udp_source = 1234   # source port
udp_dest = 5678   # destination port
udp_check = 0
udp_len = 8 + len(user_data)
udp_header = pack('!HHHH' , udp_source, udp_dest, udp_len, udp_check)
 
source_address = socket.inet_aton( source_ip )
dest_address = socket.inet_aton(dest_ip)
protocol = socket.IPPROTO_UDP
 
packet = ip_header + udp_header + user_data
 
s.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target
