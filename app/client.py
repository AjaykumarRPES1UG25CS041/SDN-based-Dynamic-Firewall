#!/usr/bin/env python3
"""Client for the app server, with three modes.

    (default)   log in, send --count messages, print round-trip times
    --bad-auth  send --count wrong passwords (brute-force simulation)
    --attack    open --count short TCP connections quickly (flood simulation)
"""
import argparse
import socket
import sys
import time


def open_session(args):
    """Connect and return (socket, line reader)."""
    sock = socket.create_connection((args.host, args.port), timeout=args.timeout)
    reader = sock.makefile("r", encoding="utf-8", errors="replace", newline="\n")
    return sock, reader


def request(sock, reader, line):
    """Send one line and return the server's one-line reply."""
    sock.sendall((line + "\n").encode("utf-8"))
    reply = reader.readline()
    if not reply:
        raise ConnectionError("server closed the connection")
    return reply.rstrip("\r\n")


def normal_mode(args):
    sock, reader = open_session(args)
    with sock, reader:
        reply = request(sock, reader, "AUTH %s %s" % (args.user, args.password))
        print("AUTH ->", reply)
        if reply != "OK":
            return 1

        rtts = []
        for i in range(1, args.count + 1):
            start = time.perf_counter()
            reply = request(sock, reader, "MSG hello %d" % i)
            rtt_ms = (time.perf_counter() - start) * 1000
            rtts.append(rtt_ms)
            print("msg %d -> %s  (rtt %.3f ms)" % (i, reply, rtt_ms))

        if rtts:
            print("average rtt over %d messages: %.3f ms"
                  % (len(rtts), sum(rtts) / len(rtts)))
        sock.sendall(b"QUIT\n")
    return 0


def bad_auth_mode(args):
    sock, reader = open_session(args)
    with sock, reader:
        for i in range(1, args.count + 1):
            reply = request(sock, reader, "AUTH %s wrong%d" % (args.user, i))
            print("attempt %d -> %s" % (i, reply))
        sock.sendall(b"QUIT\n")
    return 0


def attack_mode(args):
    ok = failed = 0
    start = time.perf_counter()
    for _ in range(args.count):
        try:
            # Connect and close straight away, no data is sent
            socket.create_connection((args.host, args.port),
                                     timeout=args.timeout).close()
            ok += 1
        except OSError:
            failed += 1
    elapsed = time.perf_counter() - start
    print("connections: %d succeeded, %d failed in %.3f s (%.0f per second)"
          % (ok, failed, elapsed, args.count / elapsed if elapsed else 0))
    return 0


def main():
    p = argparse.ArgumentParser(description="App client")
    p.add_argument("--host", default="10.0.0.5", help="app server address")
    p.add_argument("--port", type=int, default=5000, help="app server port")
    p.add_argument("--user", default="alice")
    p.add_argument("--password", default="alice123")
    p.add_argument("--count", type=int, default=None,
                   help="messages / attempts / connections (default 5, 5, 50)")
    p.add_argument("--timeout", type=float, default=3.0,
                   help="socket timeout in seconds")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--bad-auth", action="store_true",
                      help="try wrong passwords repeatedly")
    mode.add_argument("--attack", action="store_true",
                      help="open many short connections")
    args = p.parse_args()

    if args.count is None:
        args.count = 50 if args.attack else 5

    try:
        if args.attack:
            return attack_mode(args)
        if args.bad_auth:
            return bad_auth_mode(args)
        return normal_mode(args)
    except ConnectionRefusedError:
        print("error: connection to %s:%d was refused (nothing is listening)"
              % (args.host, args.port))
        return 1
    except socket.timeout:
        print("error: no response from %s:%d within %.1f s "
              "(host down, or packets are being dropped)"
              % (args.host, args.port, args.timeout))
        return 1
    except OSError as e:
        print("error: connection to %s:%d failed: %s"
              % (args.host, args.port, e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
