"""Dynamic firewall controller (OS-Ken, OpenFlow 1.3).

Run in the VM with:  osken-manager --verbose controller/firewall.py

Decisions are made per connection:
  - IPv4 that matches a deny rule in policy.json -> drop rule (priority 50)
  - other allowed IPv4 -> forwarding rule for that connection (priority 1)
  - ARP and non-IP frames are only forwarded with packet-out, no rule
Every ALLOW / DENY decision is queued and sent to the logger over TCP.
"""
import json
import os
import select
import socket
import time
from collections import deque

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.lib import hub
from os_ken.lib.packet import ether_types, ethernet, in_proto, ipv4, packet, tcp
from os_ken.ofproto import ofproto_v1_3

LOGGER_HOST = "10.0.0.6"
LOGGER_PORT = 6000
CONTROLLER_IP = "10.0.0.254"   # root namespace address (see docs/architecture.md)
POLICY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.json")

PRIO_MISS = 0
PRIO_FORWARD = 1
PRIO_DENY = 50

FORWARD_IDLE = 10    # seconds without traffic before a connection rule expires
DENY_IDLE = 60       # same for drop rules
RETRY_SECS = 2       # wait between attempts to reach the logger

PROTOS = {"tcp": in_proto.IPPROTO_TCP, "icmp": in_proto.IPPROTO_ICMP,
          "udp": in_proto.IPPROTO_UDP}


def load_policy(path):
    """Read the deny rules from the JSON policy file."""
    with open(path) as f:
        rules = json.load(f).get("deny", [])
    for rule in rules:
        if "dst_port" in rule:
            rule.setdefault("proto", "tcp")   # a port rule needs a protocol
        if "proto" in rule:
            rule["ip_proto"] = PROTOS[rule["proto"]]
    return rules


def rule_matches(rule, src, dst, proto, dport):
    """True if the packet fields match every field given in the rule."""
    if "src" in rule and rule["src"] != src:
        return False
    if "dst" in rule and rule["dst"] != dst:
        return False
    if "ip_proto" in rule and rule["ip_proto"] != proto:
        return False
    if "dst_port" in rule and rule["dst_port"] != dport:
        return False
    return True


def peer_closed(sock):
    """True if the logger closed its end (it never sends data, so any
    readable event with no data means a FIN)."""
    try:
        readable, _, _ = select.select([sock], [], [], 0)
        return bool(readable) and sock.recv(1) == b""
    except OSError:
        return True


class Firewall(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.deny_rules = load_policy(POLICY_FILE)
        # Events waiting to be sent to the logger (kept if the logger is down)
        self.events = deque(maxlen=10000)
        hub.spawn(self._logger_sender)
        self.logger.info("firewall started, %d deny rules loaded",
                         len(self.deny_rules))

    # ---------- flow helpers ----------

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # An empty instruction list means "drop"
        instructions = []
        if actions:
            instructions = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=instructions, idle_timeout=idle_timeout))

    def packet_out(self, msg, in_port, out_port):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=[parser.OFPActionOutput(out_port)], data=data))

    # ---------- switch connect ----------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Remove rules left over from an earlier run
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()))

        # Table-miss: anything without a rule goes to the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, PRIO_MISS, parser.OFPMatch(), actions)
        self.logger.info("switch connected, dpid=%s", datapath.id)

    # ---------- packet-in ----------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Learn which port the source MAC is on (used only to pick out_port)
        table = self.mac_to_port.setdefault(datapath.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofproto.OFPP_FLOOD)

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            # ARP and other non-IP frames: forward the packet, no flow rule
            self.packet_out(msg, in_port, out_port)
            return

        segment = pkt.get_protocol(tcp.tcp)
        sport = segment.src_port if segment else None
        dport = segment.dst_port if segment else None

        # 1. Static deny rules
        for rule in self.deny_rules:
            if rule_matches(rule, ip.src, ip.dst, ip.proto, dport):
                self.deny(datapath, rule, ip, segment)
                return   # packet is dropped (no packet-out)

        # 2. Allowed: one rule per connection (or per IP flow for non-TCP)
        parser = datapath.ofproto_parser
        fields = dict(eth_type=ether_types.ETH_TYPE_IP, ip_proto=ip.proto,
                      ipv4_src=ip.src, ipv4_dst=ip.dst)
        if segment:
            fields.update(tcp_src=sport, tcp_dst=dport)
        # Do not install a rule that floods; the destination is not known yet
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, PRIO_FORWARD, parser.OFPMatch(**fields),
                          [parser.OFPActionOutput(out_port)], FORWARD_IDLE)
        self.packet_out(msg, in_port, out_port)

        # Log ALLOW once per connection: only for the first SYN
        if segment and segment.bits & tcp.TCP_SYN and \
                not segment.bits & tcp.TCP_ACK:
            what = "tcp %s:%d -> %s:%d" % (ip.src, sport, ip.dst, dport)
            self.logger.info("ALLOW %s", what)
            if ip.src != CONTROLLER_IP:   # skip our own logger connection
                self.emit("ALLOW", ip.src, "no deny rule matched", what)

    def deny(self, datapath, rule, ip, segment):
        """Install a drop rule built from the policy rule and log DENY."""
        parser = datapath.ofproto_parser
        fields = {"eth_type": ether_types.ETH_TYPE_IP}
        if "src" in rule:
            fields["ipv4_src"] = rule["src"]
        if "dst" in rule:
            fields["ipv4_dst"] = rule["dst"]
        if "ip_proto" in rule:
            fields["ip_proto"] = rule["ip_proto"]
        if "dst_port" in rule:
            fields["tcp_dst"] = rule["dst_port"]
        self.add_flow(datapath, PRIO_DENY, parser.OFPMatch(**fields), None,
                      DENY_IDLE)

        what = "%s -> %s" % (ip.src, ip.dst)
        if segment:
            what = "tcp %s:%d -> %s:%d" % (ip.src, segment.src_port,
                                           ip.dst, segment.dst_port)
        self.logger.info("DENY %s (%s)", what, rule.get("reason", ""))
        self.emit("DENY", ip.src, rule.get("reason", "policy"), what)

    # ---------- event logging (never blocks packet-in) ----------

    def emit(self, event, src_ip, reason, detail):
        """Queue one event; the sender thread delivers it later."""
        line = json.dumps({"ts": time.time(), "source": "controller",
                           "event": event, "src_ip": src_ip,
                           "reason": reason, "detail": detail}) + "\n"
        self.events.append(line.encode("utf-8"))

    def _logger_sender(self):
        """Background green thread: send queued events to the logger."""
        sock = None
        while True:
            if not self.events:
                hub.sleep(0.2)
                continue
            if sock is not None and peer_closed(sock):
                sock.close()
                sock = None
            if sock is None:
                try:
                    sock = socket.create_connection(
                        (LOGGER_HOST, LOGGER_PORT), timeout=2)
                    self.logger.info("connected to logger %s:%d",
                                     LOGGER_HOST, LOGGER_PORT)
                except OSError as e:
                    self.logger.warning(
                        "logger unreachable (%s), %d events queued",
                        e, len(self.events))
                    hub.sleep(RETRY_SECS)
                    continue
            try:
                item = self.events[0]
                sock.sendall(item)
                # drop it from the queue only after it was sent
                if self.events and self.events[0] is item:
                    self.events.popleft()
            except OSError:
                sock.close()
                sock = None
                hub.sleep(RETRY_SECS)
