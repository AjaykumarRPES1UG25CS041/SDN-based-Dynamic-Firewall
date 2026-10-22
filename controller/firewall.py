"""Dynamic firewall controller (OS-Ken, OpenFlow 1.3).

Run in the VM with:  osken-manager --verbose controller/firewall.py
Static policy only (no flood or AUTH_FAIL blocking, used as a baseline in
the experiments):  FW_DYNAMIC=0 osken-manager controller/firewall.py

Decisions are made per connection:
  - IPv4 that matches a deny rule in policy.json -> drop rule (priority 50)
  - other allowed IPv4 -> forwarding rule for that connection (priority 1)
  - ARP and non-IP frames are only forwarded with packet-out, no rule
A source is blocked (drop rule, priority 100, expires by itself) when it
opens too many new connections, or when the app server reports repeated
failed logins on port 7000. When the rule expires the switch tells us and
we log UNBLOCK.
Every decision is queued and sent to the logger over TCP.
"""
import ipaddress
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
PRIO_BLOCK = 100

FORWARD_IDLE = 10    # seconds without traffic before a connection rule expires
DENY_IDLE = 60       # same for drop rules
RETRY_SECS = 2       # wait between attempts to reach the logger

# Dynamic blocking (set FW_DYNAMIC=0 in the environment to turn it off)
DYNAMIC = os.environ.get("FW_DYNAMIC", "1") != "0"
FLOOD_LIMIT = 20     # block a source with more than this many new connections...
FLOOD_WINDOW = 5     # ...within this many seconds
BLOCK_SECS = 30      # hard_timeout of a block rule
REPORT_PORT = 7000   # app server sends AUTH_FAIL reports here
# Only these addresses may send reports (the app server; loopback/root for tests)
REPORTERS = {"10.0.0.5", "10.0.0.254", "127.0.0.1"}
# Never block the controller side or the logger
NEVER_BLOCK = {CONTROLLER_IP, LOGGER_HOST}

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
        # Events waiting for the logger (kept if it is down). Not "events":
        # the base class already uses self.events internally.
        self.event_queue = deque(maxlen=10000)
        self.datapaths = {}     # dpid -> datapath, needed to block from reports
        self.blocked = set()    # IPs that currently have a block rule
        self.syn_times = {}     # src IP -> recent new-connection timestamps
        hub.spawn(self._logger_sender)
        hub.spawn(self._report_server)
        self.logger.info("firewall started, %d deny rules loaded, mode: %s",
                         len(self.deny_rules),
                         "dynamic (static policy + blocking)" if DYNAMIC
                         else "static policy only")

    # ---------- flow helpers ----------

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0, flags=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # An empty instruction list means "drop"
        instructions = []
        if actions:
            instructions = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=instructions, idle_timeout=idle_timeout,
            hard_timeout=hard_timeout, flags=flags))

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
        self.datapaths[datapath.id] = datapath
        # The switch starts with an empty table, so forget old state
        self.mac_to_port.pop(datapath.id, None)
        self.blocked.clear()
        self.syn_times.clear()

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

        # A blocked source may still get a packet in before the rule is active
        if ip.src in self.blocked:
            return

        segment = pkt.get_protocol(tcp.tcp)
        sport = segment.src_port if segment else None
        dport = segment.dst_port if segment else None
        new_conn = bool(segment and segment.bits & tcp.TCP_SYN
                        and not segment.bits & tcp.TCP_ACK)

        # 0. Flood detection: count new connections per source
        if new_conn and DYNAMIC:
            self.count_new_connection(ip.src)
            if ip.src in self.blocked:
                return   # this connection pushed it over the limit

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
        if new_conn:
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

    # ---------- dynamic blocking ----------

    def count_new_connection(self, src):
        """Remember this SYN; block the source if it opens too many."""
        now = time.time()
        times = self.syn_times.setdefault(src, deque())
        times.append(now)
        while times and times[0] < now - FLOOD_WINDOW:
            times.popleft()
        if len(times) > FLOOD_LIMIT:
            self.block(src, "connection_flood",
                       "%d conns in %ds" % (len(times), FLOOD_WINDOW))

    def block(self, src, reason, detail):
        """Install a drop rule for a source IP that expires on its own."""
        if src in NEVER_BLOCK or src in self.blocked:
            return
        self.blocked.add(src)
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=src)
            # SEND_FLOW_REM: the switch tells us when the rule is removed
            self.add_flow(datapath, PRIO_BLOCK, match, None,
                          hard_timeout=BLOCK_SECS,
                          flags=datapath.ofproto.OFPFF_SEND_FLOW_REM)
        self.logger.info("BLOCK %s for %ds (%s: %s)", src, BLOCK_SECS,
                         reason, detail)
        self.emit("BLOCK", src, reason, detail)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """A block rule expired: allow the source again."""
        msg = ev.msg
        if msg.priority != PRIO_BLOCK:
            return
        src = msg.match.get("ipv4_src")
        if src is None:
            return
        self.blocked.discard(src)
        self.syn_times.pop(src, None)   # start counting from zero
        self.logger.info("UNBLOCK %s", src)
        self.emit("UNBLOCK", src, "block_expired",
                  "block rule removed after %ds" % msg.duration_sec)

    # ---------- report listener (app server -> controller) ----------

    def _report_server(self):
        """Background green thread: accept AUTH_FAIL reports on REPORT_PORT."""
        try:
            server = hub.StreamServer(("0.0.0.0", REPORT_PORT),
                                      self._handle_reporter)
        except OSError as e:
            self.logger.error("cannot listen on port %d: %s", REPORT_PORT, e)
            return
        self.logger.info("listening for reports on port %d", REPORT_PORT)
        server.serve_forever()

    def _handle_reporter(self, sock, addr):
        """Read newline-delimited JSON reports from one connection."""
        if addr[0] not in REPORTERS:
            self.logger.warning("ignoring report connection from %s", addr[0])
            sock.close()
            return
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break   # reporter disconnected
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._handle_report(line)
                if len(buf) > 65536:
                    self.logger.warning("report line too long, closing")
                    break
        except OSError as e:
            self.logger.warning("report connection error: %s", e)
        finally:
            sock.close()

    def _handle_report(self, line):
        line = line.strip()
        if not line:
            return
        try:
            report = json.loads(line.decode("utf-8", "replace"))
            src = str(ipaddress.ip_address(report["src_ip"]))
            kind = report["event"]
        except (ValueError, KeyError, TypeError):
            self.logger.warning("ignoring malformed report: %r", line[:80])
            return
        if kind != "AUTH_FAIL":
            self.logger.warning("ignoring report with event %r", kind)
            return
        count = report.get("count", "?")
        self.logger.info("report: AUTH_FAIL from %s (count=%s)", src, count)
        self.emit("AUTH_FAIL", src, "failed_logins",
                  "%s failed logins reported by app server" % count)
        if DYNAMIC:
            self.block(src, "brute_force", "%s failed logins" % count)

    # ---------- event logging (never blocks packet-in) ----------

    def emit(self, event, src_ip, reason, detail):
        """Queue one event; the sender thread delivers it later."""
        line = json.dumps({"ts": time.time(), "source": "controller",
                           "event": event, "src_ip": src_ip,
                           "reason": reason, "detail": detail}) + "\n"
        self.event_queue.append(line.encode("utf-8"))

    def _logger_sender(self):
        """Background green thread: send queued events to the logger."""
        sock = None
        while True:
            if not self.event_queue:
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
                        e, len(self.event_queue))
                    hub.sleep(RETRY_SECS)
                    continue
            try:
                item = self.event_queue[0]
                sock.sendall(item)
                # drop it from the queue only after it was sent
                if self.event_queue and self.event_queue[0] is item:
                    self.event_queue.popleft()
            except OSError:
                sock.close()
                sock = None
                hub.sleep(RETRY_SECS)
