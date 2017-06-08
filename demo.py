# This code is to be run on controller

import ryu
import os
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp, udp
from ryu.lib.packet import ether_types
from ryu.ofproto.ofproto_v1_4_parser import OFPActionSetField
import sqlite3
import subprocess
import sys
from collections import OrderedDict

def print_db(self):
    sql="SELECT * from %s"%self.mac_to_port
    for row in self.cur.execute(sql):
          VTEP_num, MAC_addr, SF_name, port_num, VTEP_IP, VNI_num = row
          print "        VTEP_num : %d, MAC_addr : %s, SF_name: %s, port_num: %d, VTEP_IP: %s, VNI_num %d" %(VTEP_num, MAC_addr, SF_name, port_num, VTEP_IP, VNI_num)


def createTable(self):
    self.cur.execute("CREATE TABLE IF NOT EXISTS %s (VTEP_num INT, MAC_addr TEXT, SF_name TEXT, port_num INT, VTEP_IP TEXT, VNI_num INT)" %self.mac_to_port)


class v3(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(v3, self).__init__(*args, **kwargs)

        self.database_created = 0
        self.database='macTable.db'
        if os.path.exists('macTable.db'):
            os.remove('macTable.db')
            self.database_created = 0
            self.database='macTable.db'

        # our table name = "mac_to_port"
        self.mac_to_port='macToPort_table'

        conn = sqlite3.connect(self.database)
        self.cur =conn.cursor()

        self.route_path = {}
        self.hashmap = OrderedDict()        


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(self.datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=self.datapath, priority=priority,
                                match=match, instructions=inst)
        self.datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        self.datapath = msg.datapath
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = self.datapath.id
        org_dst = eth.dst
        org_src = eth.src


        # Generating the correct hashmap using Signalling message begins here
        print "\n*** **** *** Incoming packet *** **** ***"
        print "\n", pkt
        pkt_string = str(pkt)
        udp_index = pkt_string.find("SIGSFC")
        
        if dpid == 1 and udp_index != -1 and self.database_created == 0:
            sf_start_index =  udp_index + 7 
            recv_route = pkt_string[sf_start_index : -1]
        
            # ssh to the needed services to fetch the MAC address
            self.route_path = recv_route.split(',')    # e.g. {"SF2", "SF1"}
            print "\n        Route for services is: ", self.route_path
            fetched_mac = []
            for sf_ip in self.route_path:
                if sf_ip == "SF1":
                    ip_addr = "10.103.0.75"
                elif sf_ip == "SF2":
                    ip_addr = "10.103.0.78"
                elif sf_ip == "TS1":
                    ip_addr = "10.103.0.76"
                elif sf_ip == "TS2":
                    ip_addr = "10.103.0.51"
                ssh = subprocess.Popen(["ssh", "%s" %ip_addr, "cat /sys/class/net/eth1/address"],
                                        shell=False, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                fetched_mac.append(ssh.stdout.readlines())   
                if fetched_mac == []:
                    error = ssh.stderr.readlines()
                    
            createTable(self)

            c = 0
            for service in self.route_path:
                mac_of_service = fetched_mac[c][0].split('\n')[0]
                if service == "SF1":
                    v_no = 2 
                    v_ip = "192.168.12.2"
                    port =  1
                    vni = 100
                elif service == "SF2":
                    v_no = 3 
                    v_ip = "192.168.11.2"
                    port = 2
                    vni = 200
                elif service == "TS2":
                    v_no = 3
                    v_ip = "192.168.11.2"
                    port = 3
                    vni = 300
                elif service == "TS1":
                    v_no = 2
                    v_ip = "192.168.12.2"
                    port = 2
                    vni = 400
                self.cur.execute("INSERT INTO %s (VTEP_num, MAC_addr, SF_name, port_num, VTEP_IP, VNI_num) VALUES (?, ?, ?, ?, ?, ?)" %self.mac_to_port, (v_no, mac_of_service, service, port, v_ip, vni))
                c += 1

            print_db (self)
            tenant_list = ["1.1.1.1", "1.1.1.2"]


            if dpid == 1:

                ip4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
                src_ip  = ip4_pkt.src            
                
                tenant_source = 0
                if src_ip in tenant_list:
                    tenant_source = src_ip
                '''    
                else:
                    sys.exit("Sorry, this tenant is not subscribed to our Datacenter !")
                    return
                '''
                self.hashmap[tenant_source] = [1]
                self.hashmap[tenant_source].extend(self.route_path)
                self.index = list(self.hashmap.get(tenant_source))[0]

            # Generating the correct hashmap ends here


        if org_dst == "ff:ff:ff:ff:ff:ff":
            
            arp_pkt = pkt.get_protocols(arp.arp)[0]
            self.logger.info("\n         --- New ARP packet received on VTEP %s looks like: %s ---", dpid, arp_pkt)
            destination = arp_pkt.dst_ip
            source = arp_pkt.src_ip
            tenant_src_ip = source

            e = ethernet.ethernet(dst=org_src, src="00:00:00:aa:aa:aa",
                                  ethertype=ether.ETH_TYPE_ARP)
            a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                            src_mac="00:00:00:aa:aa:aa", src_ip=arp_pkt.dst_ip,
                            dst_mac=org_src, dst_ip=arp_pkt.src_ip)
            p = packet.Packet()
            p.add_protocol(e)
            p.add_protocol(a)
            p.serialize()
            self.logger.info("\n        Our new packet looks like: %s", p)

            # Since it is and ARP packet, we'd like to return it from the same incoming i/f
            out_port = in_port
            actions = [parser.OFPActionOutput(out_port)]

            # packet's input port is OFPP_CONTROLLER
            out = parser.OFPPacketOut(datapath=self.datapath, buffer_id=0xffffffff,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=p.data)
            self.datapath.send_msg(out)
            # self.logger.info("\n        A signalling message, from tenant with source IP %s received!", tenant_src_ip)

        # else it is an IPv4 packet
        else:
            ip4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
            src_ip  = ip4_pkt.src
            dst_ip  = ip4_pkt.dst

            eth = pkt.get_protocols(ethernet.ethernet)[0]
            dst = eth.dst
            src = eth.src

            self.logger.info("\n        ------ New ICMP packet received on port %s, on VTEP %s with dst mac %s------", in_port, dpid, dst)
            self.logger.info("\n        ------ ICMP packet on looks like ------")            
            print "        ", ip4_pkt
            self.logger.info("\n        Hashmap for this source IP %s looks like %s; Index is currently at %s", src_ip, self.hashmap, self.index)

            if src_ip not in tenant_list:
                actions = []
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, eth_type=0x800, ipv4_src=src_ip)
                self.add_flow(self.datapath, 1, match, actions)

                self.logger.info("\n --------- DROPPING PACKET, since this tenant is not subscribed -------")

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=self.datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                self.datapath.send_msg(out)                

            else:
                out_port = 0 
                if dpid == 1:
                    if src_ip == "1.1.1.1":
                        self.logger.info("        SYSLOG PASS: #################Tenant 1 (1.1.1.1) Traffic Received##################")            
                    elif src_ip == "1.1.1.2":
                        self.logger.info("        SYSLOG PASS: #################Tenant 2 (1.1.1.2) Traffic Received##################")            
                    else:
                        self.logger.info("        SYSLOG PASS: #################Unknown Tenant %s Traffic Received###################", src_ip)
             
                # If this was first UDP packet received on first VTEP
                if dst == "00:00:00:aa:aa:aa":
                    # print list(self.hashmap.get(src_ip))

                    self.logger.info("\n        Hashmap for this source IP %s looks like %s; Index is currently at %s", src_ip, self.hashmap, self.index)                
                    service_name = list(self.hashmap.get(src_ip))[self.index]
                    mac_query = "SELECT MAC_addr from %s where SF_name = ?"%(self.mac_to_port)
                    self.cur.execute(mac_query, [(service_name)])
                    mac_of_sf = self.cur.fetchone()[0]
                    self.hashmap[src_ip] = [self.index + 1]
                    self.index += 1
                    self.hashmap[src_ip].extend(self.route_path)
                    
                    # self.logger.info("\n        After update, hashmap for this source IP %s looks like %s; Index is currently at %s", src_ip, self.hashmap, self.index)
                    self.logger.info("\n        MAC address to be serviced is: %s", mac_of_sf)

                    vtep_query = "SELECT VTEP_num from %s where MAC_addr = ?"%(self.mac_to_port)
                    self.cur.execute(vtep_query, [(mac_of_sf)])
                    closest_vtep_of_sf = self.cur.fetchone()[0]               
                    self.logger.info("        closest_vtep_of_sf calculated is %s", closest_vtep_of_sf)

                    if dpid == closest_vtep_of_sf:
                        self.logger.info("        Destination found on the same VTEP %s", dpid)
        	        port_query = "SELECT port_num from %s where MAC_addr = ?"%(self.mac_to_port)
                        self.cur.execute(port_query, [(mac_of_sf)])
                        out_port = self.cur.fetchone()[0]
                        self.logger.info("\n        Forwarding the ICMP packet to port %d of VTEP %d", out_port, dpid)
                        actions =[parser.OFPActionSetField(eth_dst=mac_of_sf), parser.OFPActionOutput(out_port)]

                    else:
                        # Forward the packet out from port 10
                        out_port = 10
                        self.logger.info("        I am here to assign port 10 on VTEP %s", dpid)
                        vtep_ip_query = "SELECT VTEP_ip from %s where MAC_addr = ?"%(self.mac_to_port)
                        self.cur.execute(vtep_ip_query, [(mac_of_sf)])
                        closest_vtep_ip = self.cur.fetchone()[0]
                        print "        Forwarding the packet to closest VTEP: ", closest_vtep_ip

                        # Make the 'dst' to correct 'mac_of_sf' fetched from table above & increase the index value
                        actions =[parser.OFPActionSetField(eth_dst=mac_of_sf), parser.OFPActionSetField(tun_ipv4_dst=closest_vtep_ip), parser.OFPActionOutput(out_port)]

                else:
                    port_query = "SELECT port_num from %s where MAC_addr = ?"%(self.mac_to_port)
                    self.cur.execute(port_query, [(dst)])
                    out_port = self.cur.fetchone()[0]
                    self.logger.info("\nForwarding the ICMP packet to port %d of VTEP %d", out_port, dpid)
                    actions =[parser.OFPActionOutput(out_port)]
                    

                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, eth_type=0x800, ipv4_src=src_ip)
                    # match = parser.OFPMatch()
                    self.add_flow(self.datapath, 1, match, actions)

                self.logger.info("\n        Flow added above, I should be now sending packet out from port %s of VTEP %s", out_port, dpid)

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=self.datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                self.datapath.send_msg(out)



