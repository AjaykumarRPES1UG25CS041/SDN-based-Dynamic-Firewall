#!/usr/bin/env python3
"""Central security event logger (runs on h6).

Each reporter connects over TCP and sends one JSON object per line.
Every event is printed in a readable form and appended to a log file as a
JSON line, with a "recv_ts" field added by the logger.
"""
import argparse
import json
import socket
import threading
import time

log_lock = threading.Lock()  # one thread writes to the file/console at a time


def say(msg):
    with log_lock:
        print(msg, flush=True)


def format_event(event, peer):
    """Build a one-line readable summary of an event."""
    stamp = time.strftime("%H:%M:%S", time.localtime(event["recv_ts"]))
    rest = " ".join("%s=%s" % (k, v) for k, v in event.items()
                    if k not in ("event", "recv_ts"))
    return "[%s] %s from %s  %s" % (stamp, event.get("event", "?"), peer, rest)


def handle_reporter(conn, addr, logfile):
    peer = "%s:%d" % addr
    try:
        with conn, conn.makefile("r", encoding="utf-8", errors="replace",
                                 newline="\n") as reader:
            for raw in reader:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("not a JSON object")
                except ValueError as e:
                    say("WARNING: ignoring malformed line from %s: %r (%s)"
                        % (peer, line[:80], e))
                    continue

                event["recv_ts"] = time.time()
                with log_lock:
                    print(format_event(event, peer), flush=True)
                    with open(logfile, "a", encoding="utf-8") as f:
                        f.write(json.dumps(event) + "\n")
    except OSError as e:
        say("WARNING: connection error from %s: %s" % (peer, e))


def main():
    p = argparse.ArgumentParser(description="Security event logger")
    p.add_argument("--host", default="0.0.0.0", help="address to bind")
    p.add_argument("--port", type=int, default=6000, help="port to listen on")
    p.add_argument("--logfile", default="security_events.log",
                   help="file to append events to")
    args = p.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(128)
    srv.settimeout(1.0)  # wake up regularly so Ctrl+C works on Windows too
    say("logger listening on %s:%d, writing to %s"
        % (args.host, args.port, args.logfile))

    try:
        while True:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            # One thread per reporter
            threading.Thread(target=handle_reporter,
                             args=(conn, addr, args.logfile),
                             daemon=True).start()
    except KeyboardInterrupt:
        say("shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
