# Tests

Manual test cases for the project. Each test lists its purpose, the exact
commands, the expected result, and the result actually observed in the VM.

Test environment: Ubuntu 22.04, Mininet 2.3.0, Open vSwitch 2.17.12
(OpenFlow 1.3), OS-Ken 3.1.1.

| ID | Name                         | Status |
|----|------------------------------|--------|
| T0 | Namespace connectivity test  | Passed |
| T1 | Static firewall (allow/deny) | Passed |
| T2 | Dynamic blocking             | Passed |
| T3 | Logger crash and reconnect   | Passed |

---

## T0 – Namespace connectivity test

Topology script: `topology/ns_test.py` (one switch `s1`, hosts `h1` and `h2`,
plus a `root` node placed in the VM's root namespace).

### Purpose

Prove that the root network namespace, where the OS-Ken controller will run,
can exchange TCP traffic with the Mininet hosts. The connection goes through
an extra link from `s1` to the root namespace. The root side of that link is
`10.0.0.254/24` and the switch side is port `s1-eth3`.

### Why the root link is needed

Mininet hosts each live in their own network namespace, so they cannot reach
programs running in the VM's root namespace. The controller (and later the
report listener on port 7000) runs in the root namespace. The `root` node is
attached to `s1` with a real link, so it becomes one more port on the switch
with an address in the host subnet. Hosts can then send packets to
`10.0.0.254`, for example the app server's reports to the controller. The
OpenFlow control channel is separate and stays on `127.0.0.1:6653`.

### Why /24 and not /8

Mininet hosts default to `10.0.0.x/8`. A /8 covers `10.0.0.0` to
`10.255.255.255`, which overlaps the VM's NAT network `10.0.2.0/24`. The root
namespace would then have two routes covering the same addresses and could
lose its connection to the outside (for example `apt` or `git`). Using
`10.0.0.254/24` limits the root side to `10.0.0.0/24` and leaves `10.0.2.0/24`
untouched.

### Setup

Terminal 1 (controller):

```bash
osken-manager --verbose controller/learning_switch.py
```

Terminal 2 (topology, leaves the Mininet CLI open):

```bash
sudo python3 topology/ns_test.py
```

Terminal 3 is a plain shell in the VM. It is in the root namespace, so it is
the "root shell" in the tests below.

Check the root interface first:

```bash
ip addr show root-eth0
```

Expected: `10.0.0.254/24` on `root-eth0`.

### Test A – Root to hosts (ICMP)

Root shell:

```bash
ping -c 3 10.0.0.1
ping -c 3 10.0.0.2
```

Expected: 0% packet loss for both.

### Test B – Root to host (TCP)

Mininet CLI, start a listener on h1:

```
mininet> h1 nc -l 6000 &
```

Root shell, send a message:

```bash
echo "hello from root" | nc -q 1 10.0.0.1 6000
```

Expected: `hello from root` appears in the Mininet CLI output from h1's
listener, and the root shell's `nc` exits after one second.

### Test C – Host to root (TCP)

Root shell, start a listener (leave it running):

```bash
nc -l 7000
```

Mininet CLI, send from h2:

```
mininet> h2 sh -c 'echo "hello from h2" | nc -q 1 10.0.0.254 7000'
```

Expected: `hello from h2` appears in the root shell where `nc -l 7000` is
running.

### Test D – Host to root (ICMP) and full reachability

Mininet CLI:

```
mininet> h1 ping -c 3 10.0.0.254
mininet> h2 ping -c 3 10.0.0.254
mininet> pingall
```

Expected: 0% packet loss. `pingall` covers `h1`, `h2` and `root`.

### Result

All four tests (A–D) passed on Ubuntu 22.04 / Mininet 2.3.0 /
Open vSwitch 2.17.12 / OS-Ken 3.1.1.

---

## Setup for T1 to T3

Topology: `topology/topology.py` (s1, h1-h6, root link at 10.0.0.254/24).
It starts the logger on h6 and the app server on h5 automatically.

Terminal 1 (controller):

```bash
source /home/vboxuser/osken/venv/bin/activate
cd ~/sdn-dynamic-firewall
osken-manager --verbose controller/firewall.py
```

Terminal 2 (topology, leaves the Mininet CLI open):

```bash
cd ~/sdn-dynamic-firewall
sudo mn -c
sudo rm -f /tmp/security_events.log /tmp/logger.out /tmp/app_server.out
sudo python3 topology/topology.py
```

Check first: the controller prints `switch connected, dpid=1`, and in the
Mininet CLI `sh ovs-vsctl show` shows `is_connected: true`.

Events are written by the logger to `/tmp/security_events.log` (JSON lines).

---

## T1 – Static firewall (allow and deny)

### Purpose

Show that the controller denies traffic listed in `controller/policy.json`
with priority 50 drop rules, allows other traffic with one priority 1 rule
per connection, and sends an event to the logger for each decision.

Policy under test: drop any TCP port 23; drop all traffic from 10.0.0.3 to
10.0.0.6.

### Commands (Mininet CLI, in this order)

```
h1 python3 app/client.py --host 10.0.0.5 --port 23
h3 ping -c 3 -W 1 10.0.0.6
h1 python3 app/client.py --host 10.0.0.5
sh ovs-ofctl -O OpenFlow13 dump-flows s1
sh cat /tmp/security_events.log
```

Run `dump-flows` right after the client session: priority 1 rules expire
after 10 s without traffic, priority 50 rules after 60 s.

### Expected result

- Port 23: no response (the SYN is dropped, so the client times out rather
  than getting "connection refused"). A DENY event with reason
  "telnet is not allowed".
- h3 to h6: 100% packet loss. A DENY event for 10.0.0.3.
- Normal session: `AUTH -> OK`, five echoes with round-trip times. An ALLOW
  event for 10.0.0.1 to 10.0.0.5:5000.
- `dump-flows`: two priority 50 drop rules, priority 1 rules for the h1/h5
  connection (one per direction, exact ports), and the priority 0 rule that
  sends to the controller.

### Actual result

Passed.

- Port 23: `error: no response from 10.0.0.5:23 within 3.0 s`.
- h3 ping h6: 3 sent, 0 received, 100% loss.
- Normal session: `AUTH -> OK`, 5 echoes, average RTT 5.758 ms.
- Flow table contained:
  - `priority=50,tcp,tp_dst=23 actions=drop` (idle_timeout=60)
  - `priority=50,ip,nw_src=10.0.0.3,nw_dst=10.0.0.6 actions=drop`
    (idle_timeout=60)
  - `priority=1,tcp,nw_src=10.0.0.1,nw_dst=10.0.0.5,tp_src=45406,tp_dst=5000
    actions=output:"s1-eth5"` and the reverse rule to `s1-eth1`
    (idle_timeout=10)
  - priority 1 rules for the controller's own connection to the logger
    (10.0.0.254 <-> 10.0.0.6:6000)
  - `priority=0 actions=CONTROLLER:65535`

### Notes

- The telnet drop rule matches any source, so only the first denied packet
  produces a DENY event until the rule has been idle for 60 s.
- ALLOW is logged once per connection (first SYN only). The controller's
  own connection to the logger is allowed but not logged.

---

## T2 – Dynamic blocking

### Purpose

Show that a source is blocked automatically for 30 s when it floods the
network with new connections, or when the app server reports repeated failed
logins, and that it is unblocked automatically when the rule expires.

Limits: more than 20 new TCP connections in 5 s (flood), or more than 3 failed
logins (brute force). Block rule: priority 100, matching IPv4 source,
`hard_timeout` 30 s, with flow-removed notification.

### T2a – Connection flood

Commands (paste together so they run within a few seconds):

```
h4 python3 app/client.py --host 10.0.0.5 --attack --count 25 --timeout 0.2
h4 ping -c 2 -W 1 10.0.0.5
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100
h1 python3 app/client.py --host 10.0.0.5
```

After about 35 s:

```
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100
sh grep BLOCK /tmp/security_events.log
h4 ping -c 2 10.0.0.5
```

Expected:

- 20 connections succeed, the rest fail (the 21st is the one over the limit).
- h4 ping fails (100% loss) while blocked.
- A priority 100 drop rule for 10.0.0.4 with a non-zero packet count.
- h1 is not affected: its normal session works while h4 is blocked.
- After about 30 s the rule is gone, the log has BLOCK (`connection_flood`)
  followed by UNBLOCK (`block_expired`), and h4 can ping h5 again.

Actual result: passed.

- `connections: 20 succeeded, 5 failed in 1.969 s`.
- h4 ping: 2 sent, 0 received, 100% loss.
- Flow table:
  `hard_timeout=30, send_flow_rem priority=100,ip,nw_src=10.0.0.4
  actions=drop` with `n_packets=7`.
- h1: `AUTH -> OK`, 5 echoes, average RTT 7.313 ms.
- Log: BLOCK (`connection_flood`, detail `21 conns in 5s`) and an UNBLOCK 30.5 s
  later (`block_expired`). After the rule expired h4 pinged h5 with 0% loss.

### T2b – Brute-force login

Commands:

```
h2 python3 app/client.py --host 10.0.0.5 --bad-auth --count 6
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100
```

After about 40 s:

```
sh grep -E "AUTH_FAIL|BLOCK" /tmp/security_events.log
sh grep -E "failed|reported" /tmp/app_server.out
```

Expected: after the 4th failed login the app server reports to the
controller (10.0.0.254:7000); the controller logs AUTH_FAIL, installs a
priority 100 rule for 10.0.0.2 and logs BLOCK (`brute_force`); 30 s later it
logs UNBLOCK. The app server restarts its count for that IP after reporting,
so no second block follows.

Actual result: passed.

- Rule: `hard_timeout=30, send_flow_rem priority=100,ip,nw_src=10.0.0.2
  actions=drop`, `n_packets=4`.
- Log: one AUTH_FAIL (`4 failed logins reported by app server`), one BLOCK
  (`brute_force`) and one UNBLOCK 30.04 s later. No second BLOCK.
- App server: `reported AUTH_FAIL for 10.0.0.2 (count=4) to controller` once;
  later failures were counted from 1 again.

### Notes

- Attempts 5 and 6 of the brute-force run still received replies: they were
  already in flight before the controller had installed the rule (a few
  milliseconds). Traffic sent after the rule was active was dropped.
- Before the failed-login counter was reset after each report, a delayed
  retransmission arriving just after the unblock was counted as failure number
  6, which caused an immediate second block.

---

## T3 – Logger crash and reconnect

### Purpose

Show that the firewall keeps working while the logger is down, and that events
made in the meantime are delivered when the logger comes back.

### Commands (Mininet CLI)

```
sh pkill -f logger_server.py
h1 python3 app/client.py --host 10.0.0.5
```

The controller console prints `logger unreachable ... events queued` every 2 s.
Then restart the logger and read the log:

```
h6 python3 -u logger/logger_server.py --logfile /tmp/security_events.log > /tmp/logger.out 2>&1 &
sh cat /tmp/security_events.log
```

### Expected result

- The h1 session works normally while the logger is down.
- After the restart the controller reconnects (`connected to logger
  10.0.0.6:6000`) and the queued ALLOW event appears in the log.
- The event's `recv_ts` is later than its `ts` by about the time the logger
  was down.

### Actual result

Passed. The h1 session worked (`AUTH -> OK`, 5 echoes, average RTT 3.698 ms)
with the logger stopped. After the restart the log contained the ALLOW event
for `tcp 10.0.0.1:52982 -> 10.0.0.5:5000` with `ts` 1791951194.4 and `recv_ts`
1791951244.9, so it was delivered about 50 s after it was created.

---

<!-- Add later test cases below as T4, T5, ... using the same layout:
     purpose, setup, commands, expected result, actual result. -->
