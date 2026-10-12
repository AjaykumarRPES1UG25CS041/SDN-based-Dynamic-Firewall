# Architecture

## 1. Objective

An SDN-based dynamic firewall. An OS-Ken controller watches the traffic of a
TCP socket application, installs allow, deny and block flow rules on an Open
vSwitch at runtime, and sends every security event to a central TCP logger.

## 2. Topology

```
                     VM root namespace
              +--------------------------------+
              |  OS-Ken controller             |
              |  (firewall)                    |
              |  10.0.0.254/24  (root-eth0)    |
              +---------------+----------------+
                              | extra link (s1-eth3 side shown on s1)
                              |
   h1 10.0.0.1 --+            |
   h2 10.0.0.2 --+            |
   h3 10.0.0.3 --+--------- [ s1 ] OVS, OpenFlow 1.3
   h4 10.0.0.4 --+  attacker   |
   h5 10.0.0.5 --+  app server |
   h6 10.0.0.6 --+  logger     |

   OpenFlow control channel: s1 <-> controller, 127.0.0.1:6653
```

- h1-h3 are normal clients, h4 is the attacker, h5 runs the app server, h6
  runs the logger.
- The controller runs in the VM's root namespace, which Mininet hosts cannot
  reach by default. The extra link from the root namespace to s1 gives it the
  address 10.0.0.254/24 inside the host subnet. This was verified (test T0 in
  `tests/README.md`).
- /24 is used instead of /8 so the route does not overlap the VM's NAT
  network 10.0.2.0/24.

## 3. Components

| Component       | File (planned)                  | Role |
|-----------------|---------------------------------|------|
| App server      | `app/server.py` (h5)            | TCP server on port 5000. Authenticates users, echoes messages, reports failed logins to the controller. |
| Client          | `app/client.py` (h1-h4)         | Normal mode: logs in and sends messages. Attack mode: connection flood or repeated bad logins. |
| Logger server   | `logger/logger_server.py` (h6)  | TCP server on port 6000. Receives JSON events and appends them to a log file. |
| Firewall controller | `controller/firewall.py`    | OS-Ken app. Learns forwarding, applies static policy, detects attacks, installs and expires block rules, sends events to the logger. |
| Topology script | `topology/topology.py`          | Builds s1, h1-h6 and the root link. Run with `sudo python3`. |

Static policy is read from `controller/policy.json`.

## 4. Communication

| From -> To                  | Protocol / port | Purpose |
|-----------------------------|-----------------|---------|
| client <-> app server       | TCP 5000        | Application traffic |
| controller -> logger        | TCP 6000        | Security events |
| app server -> controller    | TCP 7000        | Failed-login reports |
| switch <-> controller       | OpenFlow 1.3, 6653 | Flow rules, packet-in, flow-removed |

The controller connects to the logger at 10.0.0.6 and listens for the app
server's reports on 10.0.0.254:7000, both over the root link.

## 5. Message formats

All messages are one line terminated by `\n`.

**Application protocol (port 5000)**

| Client sends        | Server replies                  |
|---------------------|---------------------------------|
| `AUTH <user> <pass>`| `OK` or `ERR bad_credentials`   |
| `MSG <text>`        | `ECHO <text>` (only after AUTH) |
| `QUIT`              | connection closed               |

A `MSG` before a successful `AUTH` is rejected with an `ERR` line.

**Events and reports (ports 6000 and 7000)**: one JSON object per line:

```
{"ts": 1730000000.5, "source": "controller", "event": "BLOCK",
 "src_ip": "10.0.0.4", "reason": "flood", "detail": "27 new connections in 5 s"}
```

Fields: `ts`, `source`, `event`, `src_ip`, `reason`, `detail`.
Event types: `ALLOW`, `DENY`, `BLOCK`, `UNBLOCK`, `AUTH_FAIL`.

## 6. Firewall logic

- **Allow**: traffic that matches no deny or block rule is forwarded normally
  (learning-switch behaviour).
- **Deny (static)**: rules loaded from `controller/policy.json` when the
  controller starts, for example drop TCP port 23, drop traffic from 10.0.0.3
  to 10.0.0.6.
- **Block (dynamic)**: a source IP is blocked when either
  - it opens more than 20 new connections in 5 seconds (counted from
    packet-in of TCP SYN packets), or
  - the app server reports more than 3 failed `AUTH` attempts from it.

  The controller installs a drop rule matching that source IP with
  `hard_timeout` = 30 s. When the rule expires the switch sends a
  flow-removed message and the controller logs `UNBLOCK`.

Every decision (`ALLOW`, `DENY`, `BLOCK`, `UNBLOCK`) and every reported
failed login (`AUTH_FAIL`) is sent to the logger.

## 7. Flow rule priorities

| Priority | Rule |
|----------|------|
| 0        | Table-miss: send to controller |
| 1        | Learned forwarding (per src/dst MAC and port) |
| 50       | Static deny rules |
| 100      | Dynamic block rules |

The higher priority wins, so a block overrides a deny, which overrides normal
forwarding.

## 8. Demo scenarios

1. **Normal traffic**: h1-h3 log in and exchange messages with h5; events are
   logged as `ALLOW`.
2. **Denied port**: a client tries TCP port 23; the static rule drops it and
   `DENY` is logged.
3. **Flood attack**: h4 opens many connections quickly; the controller blocks
   10.0.0.4 for 30 s, then `UNBLOCK` is logged.
4. **Brute-force login**: h4 sends repeated wrong passwords; the app server
   reports `AUTH_FAIL` events and the controller blocks h4.
5. **Logger crash and reconnect**: stop the logger on h6 during traffic; the
   controller keeps enforcing rules, buffers events, reconnects and delivers
   them when the logger returns.
