#!/usr/bin/env python3
"""TCP application server (runs on h5).

Line protocol (one command per line):
    AUTH <user> <pass>  ->  OK | ERR bad_credentials
    MSG <text>          ->  ECHO <text>   (only after a successful AUTH)
    QUIT                ->  connection is closed

Failed logins are counted per client IP. Once an IP has more than
MAX_FAILS failures, an AUTH_FAIL report is sent to the controller.
"""
import argparse
import json
import socket
import threading
import time

# Small hardcoded user list
USERS = {"alice": "alice123", "bob": "bob123"}

MAX_FAILS = 3        # report after more than this many failed logins
IDLE_TIMEOUT = 120   # drop clients that stay silent this long (seconds)

fail_counts = {}                 # client IP -> number of failed logins
fail_lock = threading.Lock()     # handler threads share fail_counts
print_lock = threading.Lock()    # keeps lines from different threads apart


def log(msg):
    with print_lock:
        print(time.strftime("%H:%M:%S"), msg, flush=True)


def report_to_controller(args, ip, count):
    """Send one AUTH_FAIL JSON line to the controller report port."""
    event = {"event": "AUTH_FAIL", "src_ip": ip, "count": count, "ts": time.time()}
    try:
        with socket.create_connection(
            (args.controller_host, args.controller_port), timeout=2
        ) as s:
            s.sendall((json.dumps(event) + "\n").encode("utf-8"))
        log("reported AUTH_FAIL for %s (count=%d) to controller" % (ip, count))
    except OSError as e:
        # Controller not reachable: warn and keep serving clients
        log("WARNING: cannot reach controller %s:%d (%s)"
            % (args.controller_host, args.controller_port, e))


def handle_client(conn, addr, args):
    ip = addr[0]
    tag = "[%s:%d]" % addr
    log("%s connected" % tag)
    authed = False
    conn.settimeout(IDLE_TIMEOUT)
    try:
        # makefile lets us read the socket one newline-terminated line at a time
        with conn, conn.makefile("r", encoding="utf-8", errors="replace",
                                 newline="\n") as reader:
            for raw in reader:
                line = raw.strip()
                if not line:
                    continue
                parts = line.split(" ", 2)
                cmd = parts[0].upper()

                if cmd == "AUTH":
                    user, pw = (parts[1], parts[2]) if len(parts) == 3 else ("", "")
                    if USERS.get(user) == pw and user != "":
                        authed = True
                        log("%s AUTH %s ok" % (tag, user))
                        conn.sendall(b"OK\n")
                    else:
                        with fail_lock:
                            fail_counts[ip] = fail_counts.get(ip, 0) + 1
                            count = fail_counts[ip]
                        log("%s AUTH %s failed (%d failures from %s)"
                            % (tag, user, count, ip))
                        conn.sendall(b"ERR bad_credentials\n")
                        if count > MAX_FAILS:
                            report_to_controller(args, ip, count)
                elif cmd == "MSG":
                    if not authed:
                        log("%s MSG rejected (not authenticated)" % tag)
                        conn.sendall(b"ERR not_authenticated\n")
                    else:
                        text = line[4:]
                        log("%s MSG %s" % (tag, text))
                        conn.sendall(("ECHO %s\n" % text).encode("utf-8"))
                elif cmd == "QUIT":
                    log("%s QUIT" % tag)
                    break
                else:
                    log("%s unknown command %r" % (tag, cmd))
                    conn.sendall(b"ERR unknown_command\n")
    except OSError as e:
        log("%s connection error: %s" % (tag, e))
    log("%s disconnected" % tag)


def main():
    p = argparse.ArgumentParser(description="TCP app server")
    p.add_argument("--host", default="0.0.0.0", help="address to bind")
    p.add_argument("--port", type=int, default=5000, help="port to listen on")
    p.add_argument("--controller-host", default="10.0.0.254",
                   help="controller address for AUTH_FAIL reports")
    p.add_argument("--controller-port", type=int, default=7000,
                   help="controller report port")
    args = p.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(128)
    srv.settimeout(1.0)  # wake up regularly so Ctrl+C works on Windows too
    log("app server listening on %s:%d" % (args.host, args.port))

    try:
        while True:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            # One thread per client so a slow client does not block others
            threading.Thread(target=handle_client, args=(conn, addr, args),
                             daemon=True).start()
    except KeyboardInterrupt:
        log("shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
