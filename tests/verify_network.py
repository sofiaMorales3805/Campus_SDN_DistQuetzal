#!/usr/bin/env python3
"""Validacion real de Campus SDN; ejecutar con sudo y Python del sistema."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

from topology.campus import (
    CampusTopo, configurar_rutas, detener_servidor, iniciar_servidor,
)


def command(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def frames(path):
    """Leer PCAP Ethernet clasico sin dependencias externas."""
    data = path.read_bytes()
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError(f"Formato PCAP no reconocido: {path}")
    if struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise ValueError(f"La captura no es Ethernet: {path}")
    offset = 24
    result = []
    while offset < len(data):
        size = struct.unpack_from(endian + "I", data, offset + 8)[0]
        raw = data[offset + 16:offset + 16 + size]
        offset += 16 + size
        if len(raw) < 14:
            raise ValueError(f"Trama incompleta: {path}")
        ethertype = struct.unpack_from("!H", raw, 12)[0]
        item = {
            "dst_mac": raw[:6].hex(":"),
            "src_mac": raw[6:12].hex(":"),
            "vlan": None,
        }
        start = 14
        if ethertype == 0x8100:
            tag, ethertype = struct.unpack_from("!HH", raw, 14)
            item["vlan"] = tag & 0xFFF
            start = 18
        item["type"] = ethertype
        item["payload"] = raw[start:]
        if ethertype == 0x0800 and len(raw) >= start + 20:
            item.update(
                src=socket.inet_ntoa(raw[start + 12:start + 16]),
                dst=socket.inet_ntoa(raw[start + 16:start + 20]),
                ttl=raw[start + 8], proto=raw[start + 9],
            )
        result.append(item)
    return result


def run(output):
    if os.geteuid() != 0:
        raise RuntimeError("Se necesita sudo; no enviar contrasenas al asistente.")
    existing = set(command(["ovs-vsctl", "list-br"]).split())
    if existing.intersection({"s1", "s2", "s3"}):
        raise RuntimeError("Hay switches Campus activos; no se modificaran.")
    old_pcaps = {
        p: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (ROOT / "evidencias").glob("*.pcap")
    }
    output.mkdir(parents=True, exist_ok=False)
    results = []
    captures = {}
    processes = []
    net = Mininet(
        topo=CampusTopo(), controller=None, switch=OVSSwitch,
        autoSetMacs=False, autoStaticArp=False, waitConnected=False,
    )
    net.addController(
        "c0", controller=RemoteController, ip="127.0.0.1", port=6653,
    )

    def check(name, passed, detail=""):
        results.append({"test": name, "passed": bool(passed), "detail": detail})
        print(f"{'PASS' if passed else 'FAIL'} {name}: {detail}", flush=True)

    def host_cmd(name, args, timeout=8):
        proc = net.get(name).popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        try:
            data, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            data, _ = proc.communicate()
            raise RuntimeError(f"Comando bloqueado en {name}: {args}; {data!r}")
        return proc.returncode, data.decode(errors="replace")

    def dump(switch):
        return command(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch])

    def controller_packets():
        return sum(
            int(re.search(r"n_packets=(\d+)", line)[1])
            for line in dump("s1").splitlines() if "CONTROLLER" in line
        )

    def stop_captures():
        for proc, log in captures.values():
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)
            log.close()

    started = False
    try:
        net.start()
        started = True
        configurar_rutas(net)
        iniciar_servidor(net)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            flows = {s: dump(s) for s in ("s1", "s2", "s3")}
            if (
                "table=3" in flows["s1"] and "dec_ttl" in flows["s1"]
                and all("priority=200" in flows[s] for s in ("s2", "s3"))
            ):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("No se instalaron las reglas proactivas en 15 s.")

        for sw, text in flows.items():
            (output / f"{sw}_before.txt").write_text(text)
            check(f"{sw}: sin NORMAL", "NORMAL" not in text)
            if sw != "s1":
                check(f"{sw}: solo capa 2", "dec_ttl" not in text and "nw_dst" not in text)
        core = flows["s1"]
        check("ACL instaladas antes del trafico",
              all(term in core for term in (
                  "table=2", "tp_dst=80", "tp_src=80",
                  "nw_dst=10.0.20.0/24", "actions=drop",
              )) and "IN_PORT" in core)
        for sw in ("s1", "s2", "s3"):
            for intf in net.get(sw).intfList():
                if intf.name == "lo":
                    continue
                value = command([
                    "ovs-vsctl", "get", "Port", intf.name, "tag", "trunks",
                ]).strip()
                check(f"{intf.name}: sin tag/trunks OVS", value == "[]\n[]", value)

        locations = {
            "trunk_s2": (None, "s1-eth1"),
            "trunk_s3": (None, "s1-eth2"),
            **{name: (net.get(name), f"{name}-eth0")
               for name in ("h1", "h2", "h3", "h4", "srv")},
        }
        for name, (host, intf) in locations.items():
            log = (output / f"{name}_tcpdump.log").open("w")
            args = [
                "tcpdump", "-U", "-n", "-i", intf,
                "-w", str(output / f"{name}.pcap"),
            ]
            proc = (host.popen if host else subprocess.Popen)(
                args, stdout=log, stderr=log,
            )
            captures[name] = (proc, log)
        time.sleep(0.6)
        check("Capturadores activos", all(p.poll() is None for p, _ in captures.values()))
        if not results[-1]["passed"]:
            raise RuntimeError("No se puede verificar el trafico sin capturas.")

        ips = {
            "h1": "10.0.10.11", "h2": "10.0.10.12",
            "h3": "10.0.20.21", "h4": "10.0.20.22",
            "srv": "10.0.30.10",
        }
        vids = {"h1": 10, "h2": 10, "h3": 20, "h4": 20, "srv": 30}
        for name in ips:
            rc, detail = host_cmd(name, ["ip", "neigh", "flush", "all"])
            check(f"{name}: limpiar ARP dinamico", rc == 0, detail.strip())
        for src in ips:
            for dst in ips:
                if src == dst:
                    continue
                allowed = {vids[src], vids[dst]} != {10, 20}
                rc, detail = host_cmd(src, [
                    "ping", "-n", "-c", "1", "-W", "1", ips[dst],
                ])
                check(f"ICMP {src}->{dst}",
                      rc == 0 if allowed else rc == 1 and "100% packet loss" in detail,
                      f"esperado={'permitir' if allowed else 'denegar'}; {detail.strip()}")

        for name in ips:
            rc, detail = host_cmd(name, ["ip", "neigh", "show"])
            gateway = f"10.0.{vids[name]}.1"
            check(f"{name}: ARP gateway dinamico",
                  rc == 0 and any(
                      gateway in line and "02:00:00:00:00:01" in line
                      and "PERMANENT" not in line for line in detail.splitlines()
                  ), detail.strip())

        for name in ips:
            for port in (80, 8080):
                rc, detail = host_cmd(name, [
                    "curl", "--noproxy", "*", "-fsS",
                    "--connect-timeout", "1", "--max-time", "2",
                    f"http://10.0.30.10:{port}/",
                ])
                allowed = not (vids[name] == 10 and port == 8080)
                expected = "Portal interno" if port == 80 else "Panel de administracion"
                check(f"HTTP {name}->srv:{port}",
                      (rc == 0 and expected in detail) if allowed else rc == 28,
                      detail.strip())

        # Un eco UDP comprueba el permiso general de Contabilidad y la ACL de Ventas.
        echo_code = (
            "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
            "s.bind(('10.0.30.10',9000));"
            "\nwhile True:\n d,a=s.recvfrom(1024);s.sendto(d,a)\n"
        )
        echo = net.get("srv").popen(["python3", "-u", "-c", echo_code])
        processes.append(echo)
        time.sleep(0.2)
        for name in ("h1", "h2", "h3", "h4"):
            code = (
                "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                "s.settimeout(1);s.sendto(b'campus-udp',('10.0.30.10',9000));"
                "\ntry:\n d,a=s.recvfrom(1024);print(d.decode())"
                "\nexcept TimeoutError:\n print('TIMEOUT')\n"
            )
            rc, detail = host_cmd(name, ["python3", "-c", code])
            check(f"UDP {name}->srv", rc == 0 and
                  (("campus-udp" in detail) == (vids[name] == 20)), detail.strip())

        before = controller_packets()
        before_drop = dump("s1")
        for _ in range(3):
            host_cmd("h1", ["ping", "-n", "-c", "1", "-W", "1", ips["h3"]])
            host_cmd("h1", [
                "curl", "--noproxy", "*", "-fsS", "--max-time", "1",
                "http://10.0.30.10:8080/",
            ])
        after_drop = dump("s1")
        check("Denegados sin PacketIn", controller_packets() == before,
              f"PacketIn ARP antes={before}, despues={controller_packets()}")
        def drops(text):
            return sum(
                int(re.search(r"n_packets=(\d+)", line)[1])
                for line in text.splitlines()
                if "table=2" in line and "actions=drop" in line
            )
        check("Denegados incrementan contadores drop",
              drops(after_drop) > drops(before_drop),
              f"antes={drops(before_drop)}, despues={drops(after_drop)}")

        marker = b"CAMPUS_R2_BROADCAST_ISOLATION"
        raw = bytes.fromhex("ffffffffffff00000000101188b5") + marker
        code = (
            "import socket;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);"
            f"s.bind(('h1-eth0',0));s.send(bytes.fromhex('{raw.hex()}'))"
        )
        rc, detail = host_cmd("h1", ["python3", "-c", code])
        check("Emision broadcast de prueba", rc == 0, detail.strip())
        rc, detail = host_cmd("h2", [
            "ping", "-n", "-c", "1", "-W", "1", "-t", "1", ips["srv"],
        ])
        check("TTL=1 no llega al destino",
              rc == 1 and "100% packet loss" in detail, detail.strip())
        time.sleep(0.3)
        stop_captures()
        traces = {name: frames(output / f"{name}.pcap") for name in locations}
        for name in ips:
            check(f"{name}: acceso sin etiquetas",
                  bool(traces[name]) and all(f["vlan"] is None for f in traces[name]))
            broadcast = any(marker in f["payload"] for f in traces[name])
            check(f"{name}: aislamiento broadcast VLAN10",
                  broadcast == (name in ("h1", "h2")))
        for name in ("trunk_s2", "trunk_s3"):
            relevant = [
                f for f in traces[name]
                if f["type"] in (0x0800, 0x0806, 0x88B5)
            ]
            check(f"{name}: datos siempre etiquetados",
                  bool(relevant) and all(f["vlan"] in (10, 20, 30) for f in relevant))
        for src in ("h1", "h2", "h3", "h4"):
            source_mac = {
                "h1": "00:00:00:00:10:11", "h2": "00:00:00:00:10:12",
                "h3": "00:00:00:00:20:21", "h4": "00:00:00:00:20:22",
            }[src]
            ingress = [
                f for f in traces["trunk_s2" if src in ("h1", "h3") else "trunk_s3"]
                if f.get("src") == ips[src] and f.get("dst") == ips["srv"]
                and f.get("proto") == 1 and f["ttl"] == 64
                and f["src_mac"] == source_mac and f["vlan"] == vids[src]
            ]
            egress = [
                f for f in traces["trunk_s3"]
                if f.get("src") == ips[src] and f.get("dst") == ips["srv"]
                and f.get("proto") == 1 and f["ttl"] == 63
                and f["src_mac"] == "02:00:00:00:00:01"
                and f["dst_mac"] == "00:00:00:00:30:10" and f["vlan"] == 30
            ]
            received = [
                f for f in traces["srv"]
                if f.get("src") == ips[src] and f.get("dst") == ips["srv"]
                and f.get("proto") == 1 and f["ttl"] == 63
                and f["src_mac"] == "02:00:00:00:00:01"
            ]
            check(f"{src}->srv: TTL 64->63, MAC y VLAN de destino",
                  bool(ingress and egress and received),
                  f"ingreso={len(ingress)}, egreso={len(egress)}, recibido={len(received)}")
        check("TTL=1 descartado antes de srv", not any(
            f.get("src") == ips["h2"] and f.get("dst") == ips["srv"]
            and f.get("ttl") in (0, 1) for f in traces["srv"]
        ))
        for sw in ("s1", "s2", "s3"):
            (output / f"{sw}_after.txt").write_text(dump(sw))
        for p, digest in old_pcaps.items():
            check(f"PCAP original intacto: {p.name}",
                  hashlib.sha256(p.read_bytes()).hexdigest() == digest)
    finally:
        stop_captures()
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=5)
        if started:
            detener_servidor(net)
        net.stop()
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    failures = sum(not r["passed"] for r in results)
    print(f"RESULTADO: {len(results) - failures}/{len(results)}; fallos={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="Directorio NUEVO para resultados y PCAP")
    args = parser.parse_args()
    setLogLevel("warning")
    sys.exit(run(args.output.resolve()))
