#!/usr/bin/python

# Copyright (C) 2017 Jibran Ahmed
#
# Makes use of RYU Controller and used partial code from
# Nippon Telegraph and Telephone Corporation.
# Licensed under the Apache License, Version 2.0 (the "License");

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import pcaplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

from libclient import crt_sock #Jibran's lib for API support
from ryu.lib.lib2client import crt_tcp_sock, crt_udp_sock, snd_tcp_msg
import subprocess

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.tcp_conn = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Install ARP flow to controller
        match_arp1 = parser.OFPMatch(eth_type=0x0806, arp_op=1)
        match_arp2 = parser.OFPMatch(eth_type=0x0806, arp_op=2)
        action_bk_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 10, match_arp1, actions)
        self.add_flow(datapath, 10, match_arp2, actions)

        # Backup path to flood ARP
        self.add_flow(datapath, 2, match_arp1, action_bk_arp)
        self.add_flow(datapath, 2, match_arp2, action_bk_arp)

        # install flow for TCP Port 80 at the start
        match_tcp1 = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=80)
        self.add_flow(datapath, 10, match_tcp1, actions)

        match_tcp2 = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=90)
        self.add_flow(datapath, 10, match_tcp2, actions)

        match_tcp3 = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=22)
        self.add_flow(datapath, 10, match_tcp3, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        # Bali delivering IP L3 Switch learning from ARP
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self.logger.info("Inside ARP, adding IP flow")
            src_ip = pkt_arp.src_ip
            src_mac = pkt_arp.src_mac
            actions = [parser.OFPActionOutput(in_port)]
            match = parser.OFPMatch(eth_type=0x800,ipv4_dst=src_ip)
            self.add_flow(datapath, 5, match, actions)                            

        self.logger.info("Ethernet type in decimal: %s ", str(eth.ethertype))

        # Setting flag to make decisions
        # Deliver part of Goa release
        flag = 0
        rcvMsg = ''
        """
            Customizable parameters introduced in BV Goa ##
            Modify the parameters accordingly
            set bypass = 1 if response from upper application is to be ignored

            Flavor of connection: TCP or UDP
            set typec = 'tcp' for TCP Connection
            set typec = 'udp' for UDP Connection

        """
        bypass = 0
        typec = 'tcp'
        if eth.ethertype == ether.ETH_TYPE_IP:
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if pkt_ipv4.proto == inet.IPPROTO_UDP:
                self.logger.info("UDP Packet")
            if pkt_ipv4.proto == inet.IPPROTO_TCP:
                self.logger.info("TCP Packet")
                pkt_tcp = pkt.get_protocol(tcp.tcp)
                dst_port = pkt_tcp.dst_port
                self.logger.info("TCP destination port: %s", dst_port)
                #self.pcaplib.Writer(pcapin)
                #self.pcapin = {}
                #self.pcap_writer = pcaplib.Writer(pcapin)
                #out_msg = pcap_writer.write_pkt(msg)
                if dst_port == 80:
                    if typec == 'tcp':
                        netst = subprocess.check_output('netstat -an | grep 8888 | wc -l', shell=True)
                        self.logger.info("netst: %s",netst)
                        if '0' in netst:
                            self.logger.info("inside finally")
                            try:
                                conn = crt_tcp_sock('192.168.0.2',8888)
                                rcvMsg = snd_tcp_msg(conn,str(msg))
                                self.tcp_conn[1] = conn
                            except Exception:
                                self.logger.info("Connection TCP Failed, moving on..")
                                pass
                        else:
                            conn = self.tcp_conn[1]
                            rcvMsg = snd_tcp_msg(conn,str(msg))

                    elif typec == 'udp':
                        rcvMsg = crt_udp_sock('192.168.0.2',8888,str(msg))

                    else:
                        #falling back to bali
                        crt_sock(str(msg))
                        rcvMsg = 'received'

                    self.logger.info("Checking recieved message")
                    if rcvMsg == 'received' or bypass == 1 :
                        flag = 0
                    else:
                        flag = 1
                self.logger.info("Flag is set to: %i", flag)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s ;; %s ;; %s ;; %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid] and flag == 0:
            out_port = self.mac_to_port[dpid][dst]
        elif flag == 1:
            out_port = ofproto.OFPP_ANY
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and flag != 1:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


