#!/usr/bin/env python3
"""Runs a built collector the way the plugin does and checks what it writes.

usage: validate.py <collector executable> [seconds]

Exercises the file protocol (heartbeat, owner, snapshot.json, collector.err)
and the numbers: a child process spins one core for the whole run, and the
collector must report it at about one core's share of the machine. Exits
non-zero with a reason on any failure.
"""

import json
import os
import subprocess
import sys
import tempfile
import time


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def check_snapshot(s):
    for key in ("v", "seq", "at", "interval", "os", "cpuName", "up", "cpu", "mem", "io", "disk", "net", "proc"):
        if key not in s:
            fail("snapshot lacks %r" % key)
    if "host" in s:
        fail("snapshot carries the host name; it must stay anonymous")
    if s["v"] != 1:
        fail("unknown version %r" % s["v"])
    cores = s["cpu"]["cores"]
    expected = os.cpu_count()
    if not cores or (expected and len(cores) != expected):
        fail("%d cores reported, os.cpu_count() says %r" % (len(cores), expected))
    for v in cores + [s["cpu"]["total"]]:
        if not 0 <= v <= 100:
            fail("cpu value out of range: %r" % v)
    m = s["mem"]
    if not m["total"] > 0 or not 0 <= m["avail"] <= m["total"]:
        fail("bad memory figures: %r" % m)
    if abs(s["at"] / 1000 - time.time()) > 30:
        fail("timestamp is off: %r" % s["at"])
    if s["up"] <= 0:
        fail("uptime is %r" % s["up"])
    procs = s["proc"]
    if len(procs) < 5:
        fail("only %d processes" % len(procs))
    pids = set()
    for p in procs:
        if len(p) != 7:
            fail("process row has %d fields: %r" % (len(p), p))
        pid, name, cpu, ws, priv, threads, io = p
        if not isinstance(pid, int) or pid <= 0 or pid in pids:
            fail("bad or repeated pid %r" % pid)
        pids.add(pid)
        if not isinstance(name, str):
            fail("process %d has no name" % pid)
        if cpu < 0 or cpu > 100.5 or ws < 0 or priv < 0 or threads < 0 or io < 0:
            fail("process row out of range: %r" % p)
    if os.getpid() not in pids:
        fail("this script's own pid %d is not listed" % os.getpid())
    if not s["disk"]:
        fail("no volumes")
    for d in s["disk"]:
        if d["size"] <= 0 or not 0 <= d["free"] <= d["size"]:
            fail("bad volume: %r" % d)
    for n in s["net"]:
        if n["rx"] < 0 or n["tx"] < 0:
            fail("bad interface rate: %r" % n)


def main():
    exe = os.path.abspath(sys.argv[1])
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 6
    data = tempfile.mkdtemp(prefix="sysmon-")
    token = "ci-%d" % os.getpid()
    with open(os.path.join(data, "owner"), "w") as f:
        f.write(token)

    def beat():
        with open(os.path.join(data, "heartbeat"), "w") as f:
            f.write("1000")

    beat()
    # A child spinning one core for the whole run: the collector must see it.
    spinner = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    proc = subprocess.Popen([exe, data, token])
    snap_path = os.path.join(data, "snapshot.json")
    seqs = []
    last = None
    deadline = time.time() + seconds
    while time.time() < deadline:
        beat()
        time.sleep(0.25)
        if proc.poll() is not None:
            spinner.kill()
            err = os.path.join(data, "collector.err")
            fail("collector exited early (%d): %s" % (proc.returncode, open(err).read() if os.path.exists(err) else ""))
        if os.path.exists(snap_path):
            try:
                with open(snap_path, encoding="utf-8") as f:
                    s = json.loads(f.read())
            except PermissionError:
                continue  # Windows: caught mid-replace; the plugin retries the same way
            if not seqs or s["seq"] != seqs[-1]:
                seqs.append(s["seq"])
                last = s
    spinner_pid = spinner.pid
    spinner.kill()
    if len(seqs) < 3:
        fail("only %d snapshots in %.0fs at a 1 s interval" % (len(seqs), seconds))
    check_snapshot(last)

    cores = len(last["cpu"]["cores"])
    one_core = 100.0 / cores
    procs = last["proc"]
    spin = next((p for p in procs if p[0] == spinner_pid), None)
    print("os=%r cpu=%r" % (last["os"], last["cpuName"]))
    print("cores=%d total=%.2f%% mem avail/total=%d/%d procs=%d snapshots=%d" % (
        cores, last["cpu"]["total"], last["mem"]["avail"], last["mem"]["total"], len(procs), len(seqs)))
    print("mem=%r" % last["mem"])
    print("counts=%r io=%r" % (last.get("counts"), last["io"]))
    print("disk=%r" % last["disk"])
    print("net=%r" % last["net"])
    print("busiest=%r" % sorted(procs, key=lambda p: -p[2])[:5])
    print("processes with CPU readings: %d of %d" % (sum(1 for p in procs if p[2] > 0), len(procs)))
    if spin is None:
        fail("the spinning child %d is not listed" % spinner_pid)
    # One busy core is 100/cores percent of the machine; allow for scheduling noise.
    if not 0.6 * one_core <= spin[2] <= 1.25 * one_core:
        fail("spinning child shows %.2f%% of the machine, expected about %.2f%%" % (spin[2], one_core))
    if last["cpu"]["total"] < 0.6 * one_core:
        fail("total CPU %.2f%% is below one busy core (%.2f%%)" % (last["cpu"]["total"], one_core))
    print("spinning child: %.2f%% (one core = %.2f%%)" % (spin[2], one_core))

    # Hand-off: a new owner token must stop the collector within one interval.
    with open(os.path.join(data, "owner"), "w") as f:
        f.write("someone-else")
    try:
        code = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        fail("collector ignored the owner hand-off")
    if code != 0:
        fail("collector exited %d after the hand-off" % code)

    # Bad arguments: exit 1 and say why in collector.err.
    code = subprocess.call([exe, data], stderr=subprocess.DEVNULL)
    if code != 1 or not os.path.exists(os.path.join(data, "collector.err")):
        fail("bad arguments gave exit %d and no collector.err" % code)
    print("OK")


if __name__ == "__main__":
    main()
