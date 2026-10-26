# SDN-based Dynamic Firewall with a Security Event Logger

A Computer Networks mini project. An OS-Ken (OpenFlow 1.3) controller watches
the traffic of a small TCP application running in Mininet and decides, per
connection, whether to allow or deny it. It blocks a source automatically
when it floods the network with connections or keeps failing to log in, and
lifts the block by itself 30 seconds later. Every decision is sent to a
central TCP logger.

## Topology

```
                      VM root namespace
              +--------------------------------+
              |  OS-Ken controller (firewall)  |
              |  10.0.0.254/24                 |
              +---------------+----------------+
                              | extra link
   h1 10.0.0.1 client --+     |
   h2 10.0.0.2 client --+     |
   h3 10.0.0.3 client --+--- [ s1 ] Open vSwitch, OpenFlow 1.3
   h4 10.0.0.4 attacker +
   h5 10.0.0.5 app server (TCP 5000)
   h6 10.0.0.6 logger     (TCP 6000)

   Ports: 5000 app, 6000 logger, 7000 app server -> controller reports,
          6653 OpenFlow (switch <-> controller)
```

## Components

| File | What it does |
|------|--------------|
| `controller/firewall.py` | The firewall: static policy, per-connection rules, flood and brute-force blocking, event queue to the logger |
| `controller/policy.json` | Static deny rules (any TCP port 23; 10.0.0.3 to 10.0.0.6) |
| `controller/learning_switch.py` | Plain learning switch, used as the "no firewall" baseline |
| `controller/requirements.txt` | Python packages for the controller's virtual environment (OS-Ken 3.1.1) |
| `app/app_server.py` | TCP app server (AUTH / MSG / QUIT); counts failed logins and reports them to the controller |
| `app/client.py` | Client: normal session, `--bad-auth` (brute force), `--attack` (connection flood) |
| `logger/logger_server.py` | Receives JSON events over TCP, prints them and appends them to a file |
| `topology/topology.py` | Mininet topology (s1, h1-h6, root link); starts the logger and app server |
| `topology/ns_test.py` | Small topology used to test the root-namespace link |
| `experiments/run_experiment.py` | Runs one performance experiment and appends a row to `results/results.csv` |
| `experiments/plot_results.py` | Draws the result charts from the CSV |
| `demo.sh` | Starts the controller and the topology for the demo |
| `docs/architecture.md` | Design, message formats, rule priorities, performance evaluation |
| `docs/viva-notes.md` | Plain-language explanation of everything, for the viva |
| `tests/README.md` | Test cases with the commands and observed results |

## Repo layout

```
demo.sh                 start the controller and topology
app/                    app server and client
controller/             firewall, policy, baseline switch, requirements
logger/                 security event logger
topology/               Mininet topology scripts
experiments/            experiment runner, plot script, instructions
results/                results.csv and the charts
tests/                  test cases (README.md)
docs/                   architecture and viva notes
```

## Setup on a fresh Ubuntu 22.04 VM

The project was developed and tested on Ubuntu 22.04.5, Python 3.10.12,
Mininet 2.3.0, Open vSwitch 2.17.12 and OS-Ken 3.1.1 (OpenFlow 1.3).
A fresh VM also worked with Open vSwitch 3.7.1.

No VM yet? See [docs/vm-setup.md](docs/vm-setup.md) for creating the Ubuntu VM
in VirtualBox and connecting to it from Windows with SSH and VS Code. Then
continue here.

1. Install the system packages:

```bash
sudo apt update
sudo apt install -y git mininet openvswitch-switch python3-venv python3-pip iperf
sudo service openvswitch-switch start
sudo systemctl enable openvswitch-switch
```

If installing the Python packages in step 3 fails while building a package,
also run
`sudo apt install -y build-essential libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev`.

2. Clone the repository:

```bash
git clone https://github.com/abhiramagaram-180/SDN-based-Dynamic-Firewall.git ~/sdn-dynamic-firewall
cd ~/sdn-dynamic-firewall
```

3. Create the OS-Ken virtual environment and install the controller
   requirements:

```bash
python3 -m venv ~/osken/venv
source ~/osken/venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r controller/requirements.txt
deactivate
```

4. Check the installation:

```bash
python3 --version
mn --version
ovs-vsctl --version
~/osken/venv/bin/osken-manager --help
```

The Mininet and topology scripts run with the system Python (`sudo python3`)
and never import OS-Ken. Only the controller runs inside the virtual
environment.

## Quick start

```bash
cd ~/sdn-dynamic-firewall
chmod +x demo.sh
./demo.sh
```

`demo.sh` cleans up old Mininet state, starts the controller in the
background (output in `/tmp/controller.out`), waits until it is listening, and
opens the Mininet CLI. A list of demo commands is printed first. When you type
`exit`, it stops the controller and cleans up again. If your virtual
environment is somewhere else: `OSKEN_VENV=/path/to/venv ./demo.sh`.

Logs: `/tmp/controller.out` (controller), `/tmp/logger.out` and
`/tmp/security_events.log` (logger), `/tmp/app_server.out` (app server).

### Demo walkthrough

Type these at the `mininet>` prompt, **one line at a time**.

**0. Check that the switch has connected**

```
sh ovs-vsctl show
```
Expect `is_connected: true` under the controller entry.

**1. Normal session (allowed)**

```
h1 python3 app/client.py --host 10.0.0.5
```
Expect `AUTH -> OK`, five `ECHO` replies with round-trip times and an
average. The log gets an `ALLOW` event for 10.0.0.1 to 10.0.0.5:5000.

**2. Telnet denied (static rule)**

```
h1 python3 app/client.py --host 10.0.0.5 --port 23
```
Expect `error: no response from 10.0.0.5:23 within 3.0 s`. The packet is
dropped, so the client times out instead of being refused. The log gets a
`DENY` event ("telnet is not allowed").

**3. h3 to h6 denied (static rule)**

```
h3 ping -c 3 -W 1 10.0.0.6
```
Expect 100% packet loss and a `DENY` event for 10.0.0.3.

**4. Connection flood from h4 (dynamic block and recovery)**

Run these four lines quickly, one after another. The block lasts only 30 s, so the priority=100 rule is gone if you wait too long before the last line.
```
h4 python3 app/client.py --host 10.0.0.5 --attack --count 25 --timeout 0.2
h4 ping -c 2 -W 1 10.0.0.5
h1 python3 app/client.py --host 10.0.0.5
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100

```
Expect about 20 connections to succeed and the rest to fail; h4's ping gets
100% loss; h1's session still works; and a rule like
`priority=100,ip,nw_src=10.0.0.4 actions=drop` with `hard_timeout=30`. The
controller console prints `BLOCK 10.0.0.4 ...`. After about 30 seconds:

```
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100
sh grep BLOCK /tmp/security_events.log
h4 ping -c 2 10.0.0.5
```
Expect no priority 100 rule, a `BLOCK` and an `UNBLOCK` event for 10.0.0.4, and
working pings again.

**5. Brute-force login from h2**

```
h2 python3 app/client.py --host 10.0.0.5 --bad-auth --count 6
sh cat /tmp/app_server.out
sh grep -E "AUTH_FAIL|BLOCK" /tmp/security_events.log
```
Expect `ERR bad_credentials` for the first attempts (the client may then print
`no response`, because h2 is blocked). The app server output shows `reported
AUTH_FAIL for 10.0.0.2 (count=4) to controller`, and the log shows `AUTH_FAIL`
followed by `BLOCK` (reason `brute_force`). After about 30 seconds an
`UNBLOCK` follows.
On a fresh VM all 6 attempts printed ERR bad_credentials, because the block can land after the last attempt.

**6. Logger crash and recovery**

```
sh pkill -f logger_server.py
h1 python3 app/client.py --host 10.0.0.5
```
The session works. The controller console prints `logger unreachable ...
events queued` every 2 seconds. Restart the logger:

```
h6 python3 -u logger/logger_server.py --logfile /tmp/security_events.log > /tmp/logger.out 2>&1 &
sh cat /tmp/security_events.log
```
The queued `ALLOW` event appears; its `recv_ts` is later than its `ts` by about
the time the logger was down.

**Look at the rules and the log at any time**

```
sh ovs-ofctl -O OpenFlow13 dump-flows s1
sh cat /tmp/security_events.log
```
Priority 0 sends unknown packets to the controller, priority 1 are allowed
connections (they expire after 10 s idle), priority 50 are static deny rules
and priority 100 are dynamic blocks.

## Manual run (two terminals)

Use this to watch the controller output live.

Terminal 1, controller:

```bash
source ~/osken/venv/bin/activate
cd ~/sdn-dynamic-firewall
osken-manager --verbose controller/firewall.py
```

Wait for `listening for reports on port 7000`. Terminal 2, topology:

```bash
cd ~/sdn-dynamic-firewall
sudo mn -c
sudo python3 topology/topology.py
```

Terminal 1 prints `switch connected, dpid=1`. Use the walkthrough above at the
`mininet>` prompt. To finish, type `exit` in Mininet and press Ctrl+C in
Terminal 1. Always start the controller before the topology.

Optional: `FW_DYNAMIC=0 osken-manager controller/firewall.py` runs the static
policy only (no flood or login blocking).

## Performance experiments

`experiments/run_experiment.py` measures how a connection flood from h4 affects
h1 for three setups (no firewall, static policy, dynamic firewall) at two link
delays. The exact commands for all six runs and the plot command are in
[experiments/README.md](experiments/README.md).

Summary of the results (details and charts in
[section 9 of docs/architecture.md](docs/architecture.md#9-performance-evaluation)):

- The dynamic firewall stopped about 80% of the flood: 60 of 300 attack
  connections got through, against 298 to 300 with no firewall or a static
  policy.
- The controller blocked the attacker after 953.7 ms (0 ms link delay) and
  2502.7 ms (20 ms), mostly the time the attacker needs to reach the
  threshold of 21 connections.
- h1's RTT and throughput showed no clear difference between setups (within
  the noise of a VM), because established connections do not pass through the
  controller again.

## Troubleshooting

- **Leftovers from an earlier run** (errors about existing interfaces,
  switches or ports): run `sudo mn -c`, then start again.
- **`File exists` for `root-eth0`:** an old root-namespace link is still
  there. Run `sudo mn -c`; if it remains, `sudo ip link del root-eth0`.
- **Controller not connected** (`sh ovs-vsctl show` has no
  `is_connected: true`, the flow table is empty, pings fail, hosts say
  "Destination Host Unreachable"): the controller is not running or not
  listening on 6653. Start it first (`./demo.sh` does this) and look at
  `/tmp/controller.out` or Terminal 1. The switch reconnects by itself within a
  few seconds.
- **Port already in use** (6653, 6000, 5000 or 7000): a previous controller or
  server is still running. Run `sudo mn -c` and `pkill -f osken-manager`.
- **Mininet CLI problems with pasted text:** paste commands one line at a
  time and wait for the prompt. Several lines at once can be merged or lost.
- **Warnings when the controller starts:** `EventletDeprecationWarning` and
  `1 RLock(s) were not greened` come from the OS-Ken/eventlet libraries and
  are harmless.
- **Nothing in the log:** check `sh cat /tmp/logger.out` and that the
  controller console shows `connected to logger 10.0.0.6:6000`. Events are
  queued while the logger is down.

## More documentation

- [docs/architecture.md](docs/architecture.md): design, messages, rule
  priorities, performance evaluation
- [docs/vm-setup.md](docs/vm-setup.md): creating the VM and connecting with
  SSH and VS Code
- [docs/viva-notes.md](docs/viva-notes.md): concepts, walkthroughs, design
  decisions, limitations and likely viva questions
- [tests/README.md](tests/README.md): test cases and observed results
- [experiments/README.md](experiments/README.md): how to run the experiments
