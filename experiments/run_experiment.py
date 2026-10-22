#!/usr/bin/env python3
"""Run one experiment and append a row to results/results.csv.

Run in the VM (the matching controller must already be running):
    sudo python3 experiments/run_experiment.py --label dynamic --delay 0ms

Labels (which controller to start first):
    no_firewall   osken-manager controller/learning_switch.py
    static        FW_DYNAMIC=0 osken-manager controller/firewall.py
    dynamic       osken-manager controller/firewall.py

One run: build the topology, measure h1 (RTT and throughput) without an
attack, start an attack from h4 and measure h1 again, count the attack
connections that got through, and find how long the controller took to block.
"""
import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "topology"))   # reuse topology.py

CLIENT = os.path.join(REPO, "app", "client.py")
RESULTS = os.path.join(REPO, "results", "results.csv")
EVENT_LOG = "/tmp/security_events.log"   # same file the logger on h6 writes

SERVER_IP = "10.0.0.5"
ATTACKER_IP = "10.0.0.4"
IPERF_PORT = 5001
MESSAGES = 30          # messages sent by h1 for the RTT measurement
IPERF_SECS = 5
ATTACK_MAX_WAIT = 240  # seconds to wait for the attack client to finish

COLUMNS = ["label", "delay", "baseline_rtt_ms", "attack_rtt_ms",
           "baseline_mbps", "attack_mbps", "attack_conns_succeeded",
           "block_response_ms"]


# ---------- helpers that read tool output ----------

def parse_rtt(text):
    """Average RTT in ms from the normal client's output."""
    m = re.search(r"average rtt over \d+ messages: ([\d.]+) ms", text)
    return float(m.group(1)) if m else None


def parse_mbps(text):
    """Throughput in Mbit/s from iperf output (last matching line)."""
    found = re.findall(r"([\d.]+)\s+Mbits/sec", text)
    return float(found[-1]) if found else None


def parse_conns(text):
    """Number of connections that succeeded, from the attack client."""
    m = re.search(r"connections: (\d+) succeeded", text)
    return int(m.group(1)) if m else None


def delay_ms(text):
    """'20ms' -> 20.0 (0 means no delay)."""
    m = re.match(r"\s*([\d.]+)", text)
    return float(m.group(1)) if m else 0.0


def block_response_ms(log_path, ip, start_time):
    """Time from start_time to the first BLOCK event for ip, in ms.
    Returns None if there was no BLOCK."""
    try:
        with open(log_path) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    times = []
    for line in lines:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if (ev.get("event") == "BLOCK" and ev.get("src_ip") == ip
                and ev.get("ts", 0) >= start_time):
            times.append(ev["ts"])
    return (min(times) - start_time) * 1000 if times else None


def append_row(path, row):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    new_file = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(COLUMNS)
        writer.writerow(row)


# ---------- steps that need the running network ----------

def wait_for_controller(timeout=30):
    """Wait until s1 has the table-miss rule (controller connected)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows",
                              "s1"], capture_output=True, text=True).stdout
        if "CONTROLLER" in out:
            return
        time.sleep(0.5)
    raise RuntimeError("the controller did not connect: start it first")


def measure(h1):
    """h1 -> h5: average RTT of a normal client session and iperf throughput."""
    out = h1.cmd("python3 %s --host %s --count %d" % (CLIENT, SERVER_IP, MESSAGES))
    rtt = parse_rtt(out)
    if rtt is None:
        print("WARNING: no RTT in client output:\n" + out)
    out = h1.cmd("iperf -c %s -p %d -t %d -f m" % (SERVER_IP, IPERF_PORT, IPERF_SECS))
    mbps = parse_mbps(out)
    if mbps is None:
        print("WARNING: no throughput in iperf output:\n" + out)
    return rtt, mbps


def run(args):
    import topology            # imports mininet, so only done when running
    from mininet.log import setLogLevel
    setLogLevel("warning")

    if os.geteuid() != 0:
        sys.exit("run with sudo")
    if shutil.which("iperf") is None:
        sys.exit("iperf not found: sudo apt install iperf")

    # Zero delay means no traffic shaping at all
    delay = args.delay if delay_ms(args.delay) > 0 else None
    if os.path.exists(EVENT_LOG):
        os.remove(EVENT_LOG)    # only keep events from this run

    net, root, root_link = topology.build_net(delay=delay)
    procs, files, iperf_server = [], [], None
    try:
        topology.start_net(net, root)
        wait_for_controller()
        procs, files = topology.start_services(net)
        h1, h4, h5 = net.get("h1"), net.get("h4"), net.get("h5")
        iperf_server = h5.popen(["iperf", "-s", "-p", str(IPERF_PORT)],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)

        # Warm-up: checks the app server answers and fills the ARP caches
        for _ in range(5):
            time.sleep(1)
            if "AUTH -> OK" in h1.cmd("python3 %s --host %s --count 1"
                                      % (CLIENT, SERVER_IP)):
                break
        else:
            raise RuntimeError("h1 cannot reach the app server on h5")

        print("baseline measurement ...")
        base_rtt, base_mbps = measure(h1)

        print("attack from h4 (%d connections) and measurement ..."
              % args.attack_count)
        attack_start = time.time()
        attack = h4.popen(["python3", CLIENT, "--host", SERVER_IP, "--attack",
                           "--count", str(args.attack_count),
                           "--timeout", str(args.attack_timeout)],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)
        atk_rtt, atk_mbps = measure(h1)

        try:
            attack_out, _ = attack.communicate(timeout=ATTACK_MAX_WAIT)
        except subprocess.TimeoutExpired:
            attack.kill()
            attack_out, _ = attack.communicate()
            print("WARNING: attack client did not finish in time")
        print(attack_out.strip())
        succeeded = parse_conns(attack_out)

        time.sleep(2)   # let the controller deliver its events to the logger
        block_ms = block_response_ms(EVENT_LOG, ATTACKER_IP, attack_start)
        if args.label == "dynamic" and block_ms is None:
            print("WARNING: no BLOCK logged; is the dynamic controller running?")
    finally:
        if iperf_server:
            iperf_server.terminate()
        topology.stop_net(net, root_link, procs, files)

    def fmt(v, digits):
        return "" if v is None else round(v, digits)

    row = [args.label, args.delay, fmt(base_rtt, 3), fmt(atk_rtt, 3),
           fmt(base_mbps, 1), fmt(atk_mbps, 1),
           "" if succeeded is None else succeeded, fmt(block_ms, 1)]
    append_row(RESULTS, row)
    print(",".join(COLUMNS))
    print(",".join(str(v) for v in row))


def main():
    p = argparse.ArgumentParser(description="Run one firewall experiment")
    p.add_argument("--label", required=True,
                   choices=["no_firewall", "static", "dynamic"],
                   help="which controller is running")
    p.add_argument("--delay", default="0ms",
                   help="delay on every link interface, e.g. 0ms or 20ms")
    p.add_argument("--attack-count", type=int, default=300,
                   help="connections opened by the attacker")
    p.add_argument("--attack-timeout", type=float, default=0.3,
                   help="connect timeout of the attacker, in seconds")
    run(p.parse_args())


if __name__ == "__main__":
    main()
