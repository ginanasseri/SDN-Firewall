from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.host_tracker.host_tracker import HostEvent
from pox.lib.packet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from collections import defaultdict

log = core.getLogger()

class SwitchState:
    def __init__(self, dpid):
        self.dpid = dpid
        self.mac_at_port = {} # port -> mac
        self.port_to_mac = {} # mac  -> port

class Connections:
    def __init__(self):
        core.openflow.addListeners(self)
        core.host_tracker.addListenerByName("HostEvent", self._on_host_event)
        self.switch_states = {}
        self.ip_to_mac = {}  # IP string -> MAC string
        log.debug("Starting Learning Connetions...")


    def _update_switch_states(self,dpid):
        if dpid not in self.switch_states:
            self.switch_states[dpid] = SwitchState(dpid)

    def _handle_ConnectionUp(self, event):
        self._update_switch_states(event.dpid)

        # add table-miss entry to forward to controller 
        miss = of.ofp_flow_mod(priority=0)
        miss.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(miss)
        log.info("Connected to %s", dpid_to_str(event.dpid))

    def _on_host_event(self, event: HostEvent):
        """
        Triggered when host sends frame to switch. Saves host's MAC addr, in port, and
        DPID of the switch, install entry for host MAC and port at switch if first time
        seen. 
        """
        dpid = event.entry.dpid # switch
        port = event.entry.port # inport
        mac = str(event.entry.macaddr)  # (00:...:01, 00:...:02, ...)
        ip = getattr(event, "ipv4", None) or getattr(event.entry, "ipaddr", None)
        if ip:
            self.ip_to_mac[str(ip)] = mac

        self._update_switch_states(dpid)
        state = self.switch_states[dpid]
        
        # host seen for first time or on diff port of switch
        if event.join or event.move:  
            state.mac_at_port[port] = mac
            state.port_to_mac[mac]  = port

        # if host disappeared (good book keeping)
        if event.leave:  
            state.mac_at_port.pop(port, None)
            # only delete if still mapped to this port
            if state.port_to_mac.get(mac) == port:
                state.port_to_mac.pop(mac, None)


    def _proxy_arp(self, frame, event, in_port):
        """
        Acts like an ARP proxy. Answers IP resolution queries if known.

        Learn sender's IP and MAC. If the controller already has an entry for sender,
        then creates a unicast ARP reply. I.e., only reply with requested MAC.  
        """
        a = frame.find('arp')
        if not a:
            return False

        # Learn sender mapping
        self.ip_to_mac[str(a.protosrc)] = str(frame.src)

        if a.opcode != arp.REQUEST:
            return False

        target_ip  = str(a.protodst)
        target_mac = self.ip_to_mac.get(target_ip)
        if not target_mac:
            return False

        # Build reply
        reply = arp()
        reply.hwtype   = a.hwtype
        reply.prototype= a.prototype
        reply.hwlen    = a.hwlen
        reply.protolen = a.protolen
        reply.opcode   = arp.REPLY
        reply.hwdst    = frame.src
        reply.hwsrc    = EthAddr(target_mac)
        reply.protodst = a.protosrc
        reply.protosrc = IPAddr(target_ip)

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src  = EthAddr(target_mac)
        eth.dst  = frame.src
        eth.payload = reply

        po = of.ofp_packet_out(in_port=of.OFPP_NONE, data=eth.pack())
        po.actions.append(of.ofp_action_output(port=in_port))
        event.connection.send(po)
        log.info("[arp] Sending ARP reply from %s to %s", target_ip, str(a.protosrc))
        return True


    def _handle_PacketIn(self, event):

        frame = event.parsed
        if not frame:
            return 

        if frame.type == 0x88cc:  # LLDP (OpenFlow Discovery)
            return  

        dpid, in_port = event.dpid, event.port
        state = self.switch_states.get(dpid)

        # packetIn/Connection race condition safeguard:
        if not state:
            self._update_switch_states(event.dpid)
            state = self.switch_states(event.dpid)

        # ------- Learns host MAC's from port 1 ---- 
        src = str(frame.src)
        if not (src.startswith('ff:') or src.startswith('33:33:')):
            state.port_to_mac[src] = in_port
            state.mac_at_port[in_port] = src

        # ---------- ARP suppression ----------
        if frame.type == ethernet.ARP_TYPE:
            if self._proxy_arp(frame, event, in_port):
                return

        # ---------- forwarding rules ---------------
        dst_mac = str(frame.dst)
        out_port = state.port_to_mac.get(dst_mac)

        # check if packet in buffer 
        buf = event.ofp.buffer_id
        has_buf = (buf is not None) and (buf != -1) 

        if out_port and out_port != in_port:

            fm = of.ofp_flow_mod() # flow mod message
            fm.priority = 50
            fm.idle_timeout = 0
            fm.hard_timeout = 0
            fm.match = of.ofp_match(dl_dst=frame.dst)
            fm.actions.append(of.ofp_action_output(port=out_port))

            if has_buf:
                fm.buffer_id = buf         
                event.connection.send(fm)
                log.info("[flow] Installing flow for %s.%d -> %s", dpid_to_str(dpid), out_port, frame.dst)
            else:
                event.connection.send(fm)  # install first
                log.info("[flow] Installing flow for %s.%d -> %s", dpid_to_str(dpid), out_port, frame.dst)
                po = of.ofp_packet_out(in_port=in_port, data=event.ofp.data)
                po.actions.append(of.ofp_action_output(port=out_port))
                event.connection.send(po)               
        else:
            # Unknown destination → FLOOD
            if has_buf:
                po = of.ofp_packet_out(buffer_id=buf, in_port=in_port) # packet out message
            else:
                po = of.ofp_packet_out(in_port=in_port, data=event.ofp.data)
            po.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(po)


def launch():
    Connections()
