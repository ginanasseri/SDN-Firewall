'''
Firewall University 
'''
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
import os



log = core.getLogger()
#FIREWALL_COOKIE = 0x00F1REWALL

ADMIN_LANS = {0x4: ("00:00:00:00:00:01", "00:00:00:00:00:02")}

STUDENT_LANS = {
    0x5: ("00:00:00:00:00:03", "00:00:00:00:00:04"),
    0x6: ("00:00:00:00:00:05", "00:00:00:00:00:06"),
    0x7: ("00:00:00:00:00:07", "00:00:00:00:00:08"),
}


#class Policy(object):

class Firewall(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        self.connections = {}
        log.debug("Starting Firewall")


    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % event.connection)
        self.connections[event.dpid] = event.connection


    def _handle_PacketIn(self, event):
        """
        Cases: 

        1. Signal Firewall to install rules

        2. Delete all Fireawll rules 

        TODO: change to TCP signals 
        """
        packet = event.parsed

        # TCP packet to port 9999 triggers Firewall ON rules. 
        if event.dpid in ADMIN_LANS:
            tcp_pkt = packet.find('tcp')
            if tcp_pkt and tcp_pkt.dstport == 9999:
#                log.debug("Firewall trigger packet received (TCP dstport 9999)")
                self._install_Firewall_Rules()

   
    def _install_Student_Rules(self, dpid, conn):
        """
        Student Firewall Rules: Isolates each student LAN allowing local traffic only with ADMIN permission to 
                                communicate IN port 1. 
        """
        # Allow communication between hosts on LAN
        mac0, mac1 = STUDENT_LANS[dpid]
#        log.info("Firewall installing rules on %s", dpid_to_str(dpid))
        for src_mac, src_port, dst_port, dst_mac in [(mac0, 2, 3, mac1), (mac1, 3, 2, mac0)]:
            match = of.ofp_match(in_port=src_port)
#            match.in_port = src_port
            match.dl_src = EthAddr(src_mac)
            match.dl_dst = EthAddr(dst_mac)
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match = match
            msg.actions.append(of.ofp_action_output(port=dst_port))
            conn.send(msg)
#            log.info("installing: allow %s.%s -> %s.%s", src_mac, src_port, dst_mac, dst_port)
        log.info("installing: allow %s.2 <-> %s.3", mac0, mac1)


        for (p_in, p_out) in [(2,3),(3,2)]:
            msg = of.ofp_flow_mod(priority=110)            # above your 100 unicast rule
            msg.match = of.ofp_match(in_port=p_in, dl_type=0x0806)  # ARP
            msg.actions.append(of.ofp_action_output(port=p_out))
            conn.send(msg)

        # Block external communication from hosts 
        for p in (2, 3):
            match = of.ofp_match(in_port=p)
            msg = of.ofp_flow_mod(priority=10)
            msg.match = match
            # No action = drop
            conn.send(msg)
        log.info("installing: disable external traffic from %s", dpid_to_str(dpid))
#        log.info("---- disabling external traffic from %s ----", dpid_to_str(dpid))


    def _install_Firewall_Rules(self):
#        log.debug("--------  Installing firewall rules on STUDENT LANS   --------")
        for dpid, conn in self.connections.items():
            if dpid in (0x5, 0x6, 0x7):
                # Allow rules
                self._install_Student_Rules(dpid, conn)
            
def launch():
    core.registerNew(Firewall)
