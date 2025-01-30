# -*- coding: utf-8 -*-

"""
Ryu Tutorial Controller

This controller allows OpenFlow datapaths to act as Ethernet Hubs. Using the
tutorial you should convert this to a layer 2 learning switch.

See the README for more...
"""

from os_ken.base.app_manager import OSKenApp
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.dpid import dpid_to_str
from os_ken.lib.packet import ethernet

class Controller(OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.macAddrToPort = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        '''
        Handshake: Features Request Response Handler

        Installs a low level (0) flow table modification that pushes packets to
        the controller. This acts as a rule for flow-table misses.
        '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.logger.info("Handshake taken place with {}".format(dpid_to_str(datapath.id)))
        self.__add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Packet In Event Handler

        Takes packets provided by the OpenFlow packet in event structure and
        floods them to all ports. This is the core functionality of the Ethernet
        Hub.
        '''

        msg = ev.msg                        # get message
        datapath = msg.datapath             # get datapath object (switch)
        ofproto = msg.datapath.ofproto      # get protocol constants for switch
        parser = msg.datapath.ofproto_parser # get parser for message creation
        dpid = msg.datapath.id              # get data path id

        print("Here")
        # Parses the raw packet data into a structured format.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)  # Extract Ethernet header


        if eth is None:
            return  # Ignore non-Ethernet packets

        src_mac = eth.src  # Source MAC address
        dst_mac = eth.dst  # Destination MAC address
        in_port = msg.match['in_port']  # Input port where packet arrived
        dpid = datapath.id  # Unique switch identifier

        self.logger.info("Received packet: dpid={} in_port={} src={} dst={}".format(dpid, in_port, src_mac, dst_mac))

        if dpid not in self.macAddrToPort:
            self.macAddrToPort[dpid] = {}
        # Initialize MAC table for this switch if not present
        self.macAddrToPort[dpid][src_mac] = in_port

        # Learn the source MAC only if it's not already known
        if src_mac not in self.macAddrToPort[dpid]:

            # Learn the source MAC address
            self.macAddrToPort[dpid][src_mac] = in_port
            self.logger.info("Learned MAC {} - Port {} on Switch {}".format(src_mac, in_port, dpid))

        # Determine output port based on destination MAC
        out_port = self.macAddrToPort[dpid].get(dst_mac, ofproto.OFPP_FLOOD)

        # Define action to send the packet
        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow rule if the destination MAC is known
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst_mac)
            self.__add_flow(datapath, priority=1, match=match, actions=actions)
            self.logger.info("Flow added: MAC {} → Port {} on Switch {}".format(dst_mac, out_port, dpid))
        print("Here2")
        # If the switch does NOT buffer the packet (`OFP_NO_BUFFER`), include the full packet data.
        # Otherwise, set `data` to `None` to avoid sending redundant packet data (switch already has it).
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        # packet out message
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        self.logger.info("Sending packet out")              # logger to print messages to terminal
        datapath.send_msg(out)                              # send message along chosen path

        return

    def __add_flow(self, datapath, priority, match, actions):
        '''
        Install Flow Table Modification

        Takes a set of OpenFlow Actions and a OpenFlow Packet Match and creates
        the corresponding Flow-Mod. This is then installed to a given datapath
        at a given priority.
        '''

        ofproto = datapath.ofproto                      # Get OpenFlow protocol versio
        parser = datapath.ofproto_parser                # Get OpenFlow parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)

        # logger to print messages to terminal
        self.logger.info("Flow-Mod written to {}".format(dpid_to_str(datapath.id)))

        # send message along chosen path
        datapath.send_msg(mod)