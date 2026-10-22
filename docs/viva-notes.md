# Viva Notes

For someone who did not build the project. Read sections 1 to 3 first, then
the walkthroughs (section 4), then practise the questions in section 8.
Design details and message formats are in `architecture.md`; test results are
in `../tests/README.md`.

## 1. SDN basics in plain language

**Control plane and data plane.** A normal switch or router does two jobs:
it *decides* where traffic should go (control plane) and it *moves* the
packets (data plane). In Software-Defined Networking these are separated. The
switch only moves packets, following a table of rules. A separate program, the
**controller**, makes the decisions and writes the rules into the switch. In
this project the switch is Open vSwitch (`s1`) and the controller is our
OS-Ken program `controller/firewall.py`.

**OpenFlow.** The protocol the controller and the switch speak (we use
version 1.3). It runs over a TCP connection on port 6653. Through it the
controller installs rules, receives packets the switch does not know what to
do with, and gets notifications.

**Flow table and flow entries.** The switch's rule table. Each entry has:

- a **match**: which packets it applies to (for example "TCP, from 10.0.0.1 to
  10.0.0.5, port 5000"),
- a **priority**: when several entries match a packet, the highest priority
  wins,
- **actions**: what to do (forward out a port, or nothing, which means drop),
- **timeouts**: an *idle timeout* (remove the entry after this many seconds
  without matching traffic) and a *hard timeout* (remove it after this many
  seconds no matter what).

**Table-miss entry.** A priority 0 entry that matches everything and sends the
packet to the controller. It catches every packet that no other entry handles.

**Packet-In.** The OpenFlow message the switch sends to the controller with a
copy of a packet (the table-miss entry causes this). The controller examines
it and decides.

**Packet-Out.** The controller tells the switch to send a specific packet out
of a port. After a Packet-In the first packet has already left the switch's
hands, so the controller forwards it with a Packet-Out.

**FlowMod.** The message that adds, changes or deletes a flow entry. This is
how every firewall decision becomes a rule in the switch.

**FlowRemoved.** A message the switch sends when an entry disappears (timeout
or delete), if the entry was installed with the "send flow removed" flag. We
use it to learn that a block has expired.

Key idea: the controller is only involved for the *first packet* of something
new. After it installs a rule, the switch handles the rest of the traffic by
itself at full speed.

## 2. The project in one paragraph

A TCP application (client and app server) runs on a Mininet network of six
hosts and one Open vSwitch. The switch has no built-in knowledge; the
controller decides everything. For each new TCP connection the controller
checks a static policy (deny telnet, deny h3 to the logger), and installs
either a drop rule (denied) or a forwarding rule for that connection
(allowed). It also counts new connections per source: if one source opens more
than 20 in 5 seconds, it is blocked for 30 seconds. The app server counts
failed logins and reports to the controller, which blocks a source after more
than 3 failures. When the 30 seconds end, the switch removes the rule and the
controller notes the recovery. Every decision (ALLOW, DENY, BLOCK, UNBLOCK,
AUTH_FAIL) is sent to a logger on h6, which keeps a log file. We measured how
well this works against a connection flood.

## 3. The files, in plain language

### `controller/firewall.py` (the firewall)

The OS-Ken application. Key parts:

- **Constants at the top:** priorities (0, 1, 50, 100), timeouts (forwarding
  rules 10 s idle, deny rules 60 s idle, blocks 30 s hard), flood limit (20
  connections in 5 s), ports, addresses that must never be blocked.
- `load_policy`, `rule_matches`: read `policy.json` and test a packet against
  its deny rules.
- `switch_features_handler`: runs when the switch connects. Forgets old state
  (blocked sources, counters, learned MACs), deletes any old rules, and
  installs the table-miss rule.
- `packet_in_handler`: the heart of the program. For every packet the switch
  sends up: learn the sender's MAC and port; if it is not IP (ARP, for
  example), just forward it; if the source is blocked, ignore it; if it is a
  new TCP connection (SYN), count it for flood detection; check the deny
  rules; otherwise install a forwarding rule for the connection and forward
  the packet.
- `deny`: installs a priority 50 drop rule built from the policy rule and
  queues a DENY event.
- `count_new_connection`, `block`: keep a list of recent SYN times per source
  and, when the limit is exceeded, install the priority 100 drop rule with a
  30 s hard timeout and the flow-removed flag.
- `flow_removed_handler`: when a priority 100 rule is removed, forget the
  block and queue an UNBLOCK event.
- `_report_server`, `_handle_reporter`, `_handle_report`: a TCP server on port
  7000 that reads JSON reports from the app server; an `AUTH_FAIL` report
  queues an AUTH_FAIL event and blocks the source.
- `emit`, `_logger_sender`: events go into an in-memory queue; a background
  task connects to the logger and sends them, retrying every 2 seconds if the
  logger is down.
- `FW_DYNAMIC=0` environment variable: turns off flood and login blocking, so
  the same code also serves as the "static policy" baseline.

Why this design: one rule per connection gives the controller the visibility
it needs for counting and policy; priorities make deny and block override
forwarding; short timeouts keep the table small and make recovery automatic.

### `controller/policy.json`

The static deny rules: any TCP port 23, and all traffic from 10.0.0.3 to
10.0.0.6. Easy to edit without changing code.

### `controller/learning_switch.py`

A plain learning switch with MAC-based rules and no policy. It is the "no
firewall" baseline in the experiments.

### `app/app_server.py`

The TCP server on h5 (port 5000), one thread per client. It understands
`AUTH <user> <pass>`, `MSG <text>` (echoed back only after a successful AUTH)
and `QUIT`. It counts failed logins per client IP; when an IP has more than 3
failures it sends a JSON `AUTH_FAIL` report to the controller on
10.0.0.254:7000 and starts counting that IP from zero again. If the controller
cannot be reached it prints a warning and carries on.

### `app/client.py`

The client with three modes: normal (log in, send messages, print round-trip
times), `--bad-auth` (wrong passwords, simulating brute force) and `--attack`
(many short connections, simulating a flood). Connect and read timeouts give
clear error messages when packets are dropped.

### `logger/logger_server.py`

The central logger on h6 (port 6000), one thread per sender. It reads one JSON
event per line, ignores malformed lines, adds a `recv_ts` receive time, prints
a readable line and appends the event to the log file.

### `topology/topology.py`

Builds the network: switch `s1`, hosts h1 to h6 (fixed IPs and MACs, 10.0.0.x
/24), a remote controller at 127.0.0.1:6653, and a `root` node linking s1 to
the VM's root namespace as 10.0.0.254/24. It starts the logger on h6 and the
app server on h5 and then opens the Mininet CLI. `--bw` and `--delay` shape
every link. It is also imported by the experiment script.

### `topology/ns_test.py`

The small first topology used to prove that hosts can reach the root
namespace (test T0).

### `experiments/run_experiment.py`, `plot_results.py`

Run one measurement (h1 RTT and throughput without and with an attack,
attack connections that got through, block response time) and append a row to
`results/results.csv`; the plot script draws two charts from that file.

### `demo.sh`

Starts the controller in the background, waits until it listens, runs the
topology, and cleans up afterwards. It prints the demo commands first.

## 4. End-to-end walkthroughs

### Normal connection (h1 to h5)

1. h1 first needs h5's MAC address, so it sends an ARP request. The switch has
   no rule for it, so it goes to the controller (Packet-In). The controller
   learns h1's MAC and port, sees it is not IP, and floods it with a
   Packet-Out. h5 answers; the controller learns h5's MAC and forwards the
   reply to the port where h1 was seen. No rule is installed for ARP.
2. h1 sends a TCP SYN to port 5000. No rule matches, so it goes to the
   controller. It is IP and a new connection; the controller counts it, finds
   no deny rule, installs a priority 1 rule for exactly this connection
   (source and destination IP and port) with a 10 s idle timeout, forwards
   the SYN with a Packet-Out, and queues an ALLOW event.
3. h5's SYN-ACK travels the other way. It also has no rule, so it also goes up
   once; the controller installs the matching reverse rule (no event, because
   it is not a new-connection SYN).
4. All remaining packets match these two rules and never reach the
   controller. The rules disappear 10 s after the traffic stops.

### Static deny (telnet)

h1 sends a SYN to port 23. The controller finds the policy rule "TCP port 23"
and installs a priority 50 rule that matches *any* TCP traffic to port 23 and
has no actions, so matching packets are dropped. It queues a DENY event and
does not forward the packet. The client keeps waiting and times out. (If the
port were simply closed, it would be refused immediately; a timeout means the
packet was dropped.) The rule expires after 60 s idle.

### Flood, block and recovery

1. h4 opens connection after connection to h5. Each new SYN reaches the
   controller, which adds the time to h4's list and removes entries older than
   5 seconds.
2. On the 21st SYN within 5 s the list is longer than 20. The controller adds
   h4 to its blocked set, installs a priority 100 rule (match: IPv4 from
   10.0.0.4; no actions; hard timeout 30 s; "send flow removed" flag), queues
   a BLOCK event and drops that SYN.
3. From then on h4's packets match the rule in the switch and are dropped.
   Other hosts are unaffected. Priority 100 beats the priority 1 and 50 rules.
4. 30 seconds after installation the switch removes the rule by itself and
   sends FlowRemoved. The controller removes h4 from the blocked set, clears
   its counters and queues an UNBLOCK event. h4 can connect again.

### Brute-force login and block through the app-server report

1. h2 sends `AUTH` with wrong passwords. The controller cannot see this: it
   only sees the first packet of a connection, not what is inside the TCP
   data. The app server can see it.
2. After the 4th failure from 10.0.0.2 the app server sends a JSON line
   `{"event": "AUTH_FAIL", "src_ip": "10.0.0.2", "count": 4, ...}` to
   10.0.0.254:7000, and resets its count for that IP.
3. The controller's listener accepts it (only from the app server or the
   local machine), queues an AUTH_FAIL event, and calls the same `block`
   function as the flood detector. The rest is as above: priority 100 rule,
   BLOCK event, expiry after 30 s, UNBLOCK event.

### Logger crash and recovery

1. The logger on h6 is stopped. The firewall keeps working, because decisions
   do not depend on the logger.
2. New events go into the controller's queue. The sender task cannot connect
   and retries every 2 seconds, printing a warning.
3. The logger is started again. At the next retry the controller connects and
   sends the waiting events in order. In the log the event's `ts` (when it
   happened) differs from `recv_ts` (when it arrived) by the downtime.

## 5. Key design decisions and why

- **Per-connection rules instead of MAC rules.** A MAC rule covers all traffic
  between two hosts, so after the first packet nothing more reaches the
  controller and the firewall could not tell an allowed connection from a
  denied one or count connections. Matching on IPs and ports means each new
  connection is seen once and judged on its own. The cost: every new
  connection goes to the controller.
- **Priorities 0 / 1 / 50 / 100.** 0 is the table-miss, 1 is ordinary
  forwarding, 50 is static deny, 100 is dynamic block. The switch applies the
  highest matching priority, so a block overrides a deny, which overrides
  forwarding, without any extra code.
- **Root-namespace link at 10.0.0.254/24.** The controller runs on the VM, not
  inside a Mininet host, so hosts cannot normally reach it. An extra link from
  s1 to the root namespace gives it an address in the host subnet, so the app
  server can send reports to port 7000 and the controller can reach the logger
  on h6. /24 (not /8) avoids overlapping the VM's NAT network 10.0.2.0/24. The
  OpenFlow channel stays separate on 127.0.0.1:6653.
- **Non-blocking event queue.** The controller handles everything in
  cooperative tasks on one thread. If the packet-in handler waited for a slow
  or dead logger, all packet handling would freeze. So handlers only append to
  a queue; a background task does the network work and keeps events if the
  logger is down.
- **`hard_timeout` plus FlowRemoved for recovery.** A hard timeout removes the
  block after exactly 30 s even if the attacker keeps sending (an idle timeout
  would never fire). The flow-removed message tells the controller, so it keeps
  no timers and can log UNBLOCK.
- **Reset state on switch reconnect.** The switch starts with an empty table
  when it reconnects, so the controller forgets its blocked set, counters and
  learned MACs; otherwise a host could look blocked with no rule in the switch.
  This matters for repeated experiment runs.
- **`FW_DYNAMIC` flag.** The same program runs with blocking turned off, which
  gives a "static only" baseline with identical rules, so the comparison
  isolates the effect of dynamic blocking.
- **Login failures are counted by the app server, not the controller.** Only
  the application sees what is inside the connection. The controller only
  enforces the block.
- **Newline-delimited messages.** TCP is a byte stream with no message
  boundaries, so every message ends with `\n` and receivers read until a
  newline.

## 6. Results summary

(Full table and charts: section 9 of `architecture.md`. Single runs.)

| Setup | Attack connections that succeeded (of 300) | Block response |
|-------|--------------------------------------------|----------------|
| No firewall | 298 (0 ms), 300 (20 ms) | n/a |
| Static policy | 300, 300 | n/a |
| Dynamic firewall | 60, 60 | 953.7 ms (0 ms), 2502.7 ms (20 ms) |

- About 80% of the flood was stopped. 60 and not 20 because the attack lasted
  75 to 79 s and each block lasts 30 s: about three block and recover cycles
  of roughly 20 connections each, which shows automatic recovery working.
- The block response time is mostly the time the attacker needs to reach 21
  connections; link delay slows the attacker (about 22 connections per second
  at 0 ms, 8 to 9 at 20 ms), so the threshold is reached later.
- h1's RTT and throughput showed no clear difference between setups; the
  differences are within VM noise (even the no-attack throughput differed
  between setups). Established connections have their own rules and do not
  pass through the controller again.
- Trade-off: the firewall's per-connection rules send every new connection to
  the controller, which the MAC-based baseline avoids. That cost buys the
  ability to apply policy and block floods.

## 7. Known limitations and issues found during testing

Issues found and fixed:

- **A name clash in the controller.** The first version stored its event queue
  in `self.events`, a name the OS-Ken base class already uses internally. The
  switch connected but no events were delivered and the controller printed
  errors repeatedly. Renaming the queue to `event_queue` fixed it. (It showed
  up only in the VM.)
- **Re-block after unblock.** The app server never reset its failed-login
  counter, so a single delayed retransmission after the unblock counted as
  failure number 6 and blocked the host again. Now the counter restarts from
  zero after each report.

Behaviour to be aware of:

- **Attempts slip through before the rule is installed.** In the brute-force
  test, attempts 5 and 6 still got replies, because they were already in
  flight during the few milliseconds the controller needed to install the
  rule. Traffic after that was dropped.
- **Wildcard telnet rule logs only the first denied packet.** The deny rule
  matches any source, so once it is installed other hosts' telnet attempts are
  dropped in the switch without reaching the controller and are not logged,
  until the rule has been idle for 60 s.
- **Only new TCP connections are logged as ALLOW.** ICMP and UDP get rules but
  no ALLOW event. The controller's own connection to the logger is allowed but
  not logged.
- **Single runs.** Each experiment row is one run in one VM, so results are
  indicative, not statistically established.

Limitations of the design:

- Blocking is by source IP; a source could spoof its address.
- Reports from the app server are not authenticated; the controller only
  accepts them from the app server's address (and the local machine).
- Passwords are hardcoded and sent in plain text; the logger has no
  authentication.
- Everything is in memory: blocked set, counters and queued events are lost if
  the controller restarts. The event queue is capped at 10000 events.
- One switch only; the controller does not track switches disconnecting.
- The flood threshold (20 in 5 s) is fixed, not adaptive.

## 8. Likely viva questions

**1. What is SDN?**
A network design where the decision-making (control plane) is moved out of
the switches into a software controller, and the switches only forward packets
according to rules the controller installs.

**2. What is the difference between control plane and data plane?**
The control plane decides where traffic goes; the data plane actually moves
packets. Here the OS-Ken controller is the control plane and Open vSwitch is
the data plane.

**3. What is OpenFlow?**
The standard protocol between the controller and the switch (we use 1.3, on
port 6653) for installing rules, receiving packets and getting notifications.

**4. What is a flow table entry?**
A rule with a match (which packets), a priority, actions (what to do) and
timeouts.

**5. What is a table-miss entry and why do you need it?**
A priority 0 entry that matches everything and sends the packet to the
controller. Without it, packets with no rule would be dropped and the
controller would never learn about new traffic.

**6. What are Packet-In, Packet-Out and FlowMod?**
Packet-In: the switch sends a packet to the controller. Packet-Out: the
controller tells the switch to send a packet. FlowMod: the controller adds or
removes a flow entry.

**7. What does FlowRemoved do in your project?**
It tells the controller when a block rule expired, so the controller can
forget the block and log UNBLOCK without running its own timers.

**8. Why do priorities matter?**
When several rules match, the switch uses the highest priority. 100 (block)
beats 50 (static deny), which beats 1 (forwarding), so the most restrictive
decision wins.

**9. Idle timeout or hard timeout?**
Idle: removed after no matching traffic for N seconds (used for forwarding and
deny rules, to keep the table clean). Hard: removed after N seconds regardless
(used for blocks, so an attacker that keeps sending cannot keep the block
alive, and recovery is guaranteed).

**10. Why per-connection rules instead of MAC rules?**
A MAC rule hides which connection a packet belongs to, so nothing more reaches
the controller after the first packet and it cannot apply a policy by port or
count connections. Per-connection rules let the controller judge every new
connection.

**11. How do you detect a flood?**
For each source IP the controller keeps the times of its recent new-connection
SYN packets. If more than 20 fall within the last 5 seconds, it blocks the
source.

**12. Why can the controller count SYNs?**
Each new connection has no rule yet, so its first packet goes to the
controller. Packets of established connections match a rule and do not.

**13. How is brute force detected, and why not in the controller?**
The app server counts failed logins per client IP. Passwords are inside the
TCP data, which the controller never sees, so the app server reports to the
controller (over port 7000) after more than 3 failures, and the controller
blocks the source.

**14. What exactly is a block?**
A priority 100 flow entry that matches IPv4 traffic from the source IP, has no
actions (drop), a 30 s hard timeout and the flow-removed flag.

**15. How does the system recover automatically?**
After 30 s the hard timeout makes the switch delete the rule and send
FlowRemoved; the controller clears its state and logs UNBLOCK.

**16. Why is there a root-namespace link at 10.0.0.254?**
The controller runs in the VM's root namespace, which Mininet hosts cannot
reach. The extra link gives it an address in the host subnet so the app server
can send reports and the controller can reach the logger.

**17. Why /24 and not /8?**
A /8 would overlap the VM's NAT network 10.0.2.0/24 and could break the VM's
own routes (internet access). /24 keeps the route to 10.0.0.0/24 only.

**18. Why must the logger sender be non-blocking?**
The controller's tasks share one thread. A blocking send to a slow or dead
logger would freeze packet handling. The handler only appends to a queue and a
background task sends.

**19. What happens when the logger is down?**
The firewall keeps working. Events stay in the controller's queue, and the
sender retries every 2 seconds and delivers them when the logger returns. The
log shows their original `ts` and the later `recv_ts`.

**20. What happens if the controller is down?**
The switch is in "secure" mode: existing rules keep working until they expire,
but new connections cannot be set up because nothing answers the Packet-Ins.
When the controller comes back, the switch reconnects and the controller starts
fresh.

**21. Why does a denied telnet attempt time out instead of being refused?**
The SYN is dropped by the switch, so nothing replies. A refusal needs a reply
(a TCP reset) from the destination.

**22. Why do you ignore ARP in the rules?**
ARP is not IP, has no connection to match, and is needed for hosts to find
each other. The controller just forwards it (flood if the MAC is unknown) and
installs no rule.

**23. How does the controller learn MAC addresses?**
From the source MAC of each Packet-In: it remembers which switch port that MAC
was seen on, and uses it to choose the output port for later packets.

**24. Why one thread per client in the app server and logger?**
Reading from a socket blocks until data arrives. With one thread per
connection, a slow client does not stop the others. The main thread keeps
accepting new connections.

**25. Why are messages newline-delimited?**
TCP is a byte stream; it does not keep message boundaries. A newline at the
end of each message lets the receiver know where one ends and the next begins.

**26. Why SO_REUSEADDR?**
It lets a server restart immediately on the same port instead of waiting for
old connections in TIME_WAIT.

**27. Why OS-Ken and not Ryu?**
Ryu's dependencies did not work in this environment; OS-Ken is a maintained
fork with the same programming model (imports from `os_ken.*`).

**28. What is the difference between your static and dynamic setups?**
Same controller code. Static (`FW_DYNAMIC=0`) applies only the deny rules from
`policy.json`; dynamic also blocks on flooding and failed logins.

**29. What did the experiments show?**
The dynamic firewall stopped about 80% of the flood (60 of 300 connections
got through, against 298 to 300), with a block response of 953.7 ms at 0 ms
delay and 2502.7 ms at 20 ms. h1's RTT and throughput did not change
noticeably; differences were within VM noise.

**30. What are the limitations, and what would you improve?**
Source-IP based blocking can be defeated by spoofing; reports and the logger
are unauthenticated; state is lost on restart; thresholds are fixed; only one
switch. Improvements: authenticate reports, persist state, adaptive
thresholds, rate limiting instead of full blocking, and repeated experiment
runs to get averages.
