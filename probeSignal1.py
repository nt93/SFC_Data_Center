# This code is to be run on Client to send a probe packet on behalf of tenant 1

import socket, sys
from struct import *
import time 
def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
    s = ~s & 0xffff
    return s
 
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
packet = '';
 
source_ip = '1.1.1.1'
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
 
user_data = "PROBE,1.1.1.1"

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

