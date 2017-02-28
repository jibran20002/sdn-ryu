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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

from libclient import crt_sock #Jibran's lib for API support

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

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
        match_tcp = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=80)
        self.add_flow(datapath, 10, match_tcp, actions)

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
        if eth.ethertype == ether.ETH_TYPE_IP:
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if pkt_ipv4.proto == inet.IPPROTO_UDP:
                self.logger.info("UDP Packet")
            if pkt_ipv4.proto == inet.IPPROTO_TCP:
                self.logger.info("TCP Packet")
                pkt_tcp = pkt.get_protocol(tcp.tcp)
                dst_port = pkt_tcp.dst_port
                self.logger.info("TCP destination port: %s", dst_port)
                crt_sock(str(msg))

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s ;; %s ;; %s ;; %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
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


