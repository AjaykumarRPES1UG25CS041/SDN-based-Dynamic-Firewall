#!/usr/bin/env python3
"""Main test topology: one OVS switch, six hosts and a root-namespace link.

Run in the VM (controller must already be running on 127.0.0.1:6653):
    sudo python3 topology/topology.py [--bw MBIT] [--delay 5ms]

h1-h3 clients, h4 attacker, h5 app server, h6 logger,
root namespace (controller side) 10.0.0.254/24 via an extra link to s1.

The build/start/stop functions are also used by experiments/run_experiment.py.
"""
import argparse
import os
import subprocess
import sys

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, RemoteController

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGGER_SCRIPT = os.path.join(REPO, "logger", "logger_server.py")
APP_SCRIPT = os.path.join(REPO, "app", "app_server.py")

HOSTS = ["h1", "h2", "h3", "h4", "h5", "h6"]   # h<N> -> 10.0.0.N
ROOT_IP = "10.0.0.254/24"

LOGGER_OUT = "/tmp/logger.out"
LOGGER_LOG = "/tmp/security_events.log"
APP_OUT = "/tmp/app_server.out"


def build_net(bw=None, delay=None):
    """Create s1, h1-h6 and the root link. Returns (net, root, root_link)."""
    # Same shaping options for every link (None means no shaping)
    link_opts = {"bw": bw, "delay": delay}

    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)
    net.addController("c0", controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    for i, name in enumerate(HOSTS, start=1):
        host = net.addHost(name, ip="10.0.0.%d/24" % i,
                           mac="00:00:00:00:00:%02x" % i)
        net.addLink(host, s1, **link_opts)

    # Node in the root namespace, linked to s1 (the controller side)
    root = Node("root", inNamespace=False)
    root_link = TCLink(root, s1, **link_opts)
    return net, root, root_link


def start_net(net, root):
    net.start()
    root.setIP(ROOT_IP, intf="root-eth0")


def start_services(net):
    """Start the logger on h6 and the app server on h5 in the background."""
    h5, h6 = net.get("h5"), net.get("h6")
    procs, files = [], []
    for host, cmd, out in [
        (h6, ["python3", "-u", LOGGER_SCRIPT, "--logfile", LOGGER_LOG],
         LOGGER_OUT),
        (h5, ["python3", "-u", APP_SCRIPT, "--controller-host", "10.0.0.254"],
         APP_OUT),
    ]:
        f = open(out, "w")
        files.append(f)
        procs.append(host.popen(cmd, stdin=subprocess.DEVNULL, stdout=f,
                                stderr=subprocess.STDOUT))
    return procs, files


def stop_net(net, root_link, procs, files):
    """Stop the services, the network and the root link."""
    for proc in procs:
        proc.terminate()
    for f in files:
        f.close()
    net.stop()
    root_link.delete()


def main():
    p = argparse.ArgumentParser(description="Firewall test topology")
    p.add_argument("--bw", type=float, default=None,
                   help="bandwidth limit for every link, in Mbit/s")
    p.add_argument("--delay", default=None,
                   help="delay for every link, e.g. 5ms")
    args = p.parse_args()

    if os.geteuid() != 0:
        sys.exit("run with sudo")

    net, root, root_link = build_net(args.bw, args.delay)
    start_net(net, root)

    procs, files = start_services(net)
    print("*** logger on h6:      output %s, events %s" % (LOGGER_OUT, LOGGER_LOG))
    print("*** app server on h5:  output %s" % APP_OUT)

    CLI(net)

    stop_net(net, root_link, procs, files)


if __name__ == "__main__":
    setLogLevel("info")
    main()
