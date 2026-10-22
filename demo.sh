#!/usr/bin/env bash
# Start the controller and the Mininet topology for the demo (run on the VM).
#
#   ./demo.sh
#
# The controller runs in the background (output in /tmp/controller.out) and the
# Mininet CLI opens in this terminal. When you type "exit" in the CLI, the
# controller is stopped and Mininet is cleaned up.
#
# OSKEN_VENV can point to another virtual environment:
#   OSKEN_VENV=/path/to/venv ./demo.sh

OSKEN_VENV="${OSKEN_VENV:-$HOME/osken/venv}"
CONTROLLER_LOG=/tmp/controller.out
CONTROLLER_PID=""

cd "$(dirname "$0")" || exit 1

if [ ! -x "$OSKEN_VENV/bin/osken-manager" ]; then
    echo "osken-manager not found in $OSKEN_VENV"
    echo "Create the virtual environment first (see README.md, Setup)."
    exit 1
fi

cleanup() {
    trap - EXIT
    echo
    echo "Stopping the controller and cleaning up Mininet ..."
    if [ -n "$CONTROLLER_PID" ]; then
        kill "$CONTROLLER_PID" 2>/dev/null
        wait "$CONTROLLER_PID" 2>/dev/null
    fi
    sudo mn -c >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "Cleaning up old Mininet state ..."
sudo mn -c >/dev/null 2>&1 || { echo "sudo failed"; exit 1; }
sudo rm -f /tmp/security_events.log /tmp/logger.out /tmp/app_server.out

echo "Starting the controller (output: $CONTROLLER_LOG) ..."
"$OSKEN_VENV/bin/osken-manager" controller/firewall.py > "$CONTROLLER_LOG" 2>&1 &
CONTROLLER_PID=$!

# Wait until the controller listens on the OpenFlow port (6653)
for i in $(seq 1 30); do
    if ! kill -0 "$CONTROLLER_PID" 2>/dev/null; then
        echo "The controller stopped. Last lines of $CONTROLLER_LOG:"
        tail -n 15 "$CONTROLLER_LOG"
        CONTROLLER_PID=""
        exit 1
    fi
    if ss -ltn 2>/dev/null | grep -q ':6653 '; then
        break
    fi
    sleep 1
done
if ! ss -ltn 2>/dev/null | grep -q ':6653 '; then
    echo "The controller did not start listening on port 6653."
    tail -n 15 "$CONTROLLER_LOG"
    exit 1
fi
echo "Controller is listening on port 6653."

cat <<'EOF'

==================== DEMO COMMANDS (type at the mininet> prompt) ====================
Paste one line at a time. Hosts: h1-h3 clients, h4 attacker, h5 app server,
h6 logger. Controller side (root namespace): 10.0.0.254.

 1. Normal session (ALLOW):
      h1 python3 app/client.py --host 10.0.0.5

 2. Telnet denied (static rule, times out, DENY):
      h1 python3 app/client.py --host 10.0.0.5 --port 23

 3. h3 to h6 denied (static rule, 100% loss, DENY):
      h3 ping -c 3 -W 1 10.0.0.6

 4. Flood from h4 (BLOCK), h1 still works, block expires after 30 s (UNBLOCK):
      h4 python3 app/client.py --host 10.0.0.5 --attack --count 25 --timeout 0.2
      h4 ping -c 2 -W 1 10.0.0.5
      h1 python3 app/client.py --host 10.0.0.5
      sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100

 5. Brute force from h2 (AUTH_FAIL, BLOCK, then UNBLOCK after 30 s):
      h2 python3 app/client.py --host 10.0.0.5 --bad-auth --count 6

 6. Logger crash and recovery (events are kept and delivered later):
      sh pkill -f logger_server.py
      h1 python3 app/client.py --host 10.0.0.5
      h6 python3 -u logger/logger_server.py --logfile /tmp/security_events.log > /tmp/logger.out 2>&1 &

 Inspect:
      sh ovs-ofctl -O OpenFlow13 dump-flows s1
      sh cat /tmp/security_events.log

 Logs:  /tmp/controller.out   /tmp/logger.out   /tmp/app_server.out
        /tmp/security_events.log  (one JSON event per line)
 Type "exit" to leave Mininet. More details: README.md
=====================================================================================

EOF

sudo python3 topology/topology.py
