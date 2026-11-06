
#!/usr/bin/env python3
"""
Campus SDN - Distribuidora Quetzal, S.A.
Topologia Mininet para OpenFlow 1.3.

La configuracion de VLAN, ARP, ruteo y ACL
corresponde exclusivamente al controlador os-ken.
"""

import argparse
from pathlib import Path

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.log import setLogLevel, info


GATEWAYS = {
    10: "10.0.10.1",
    20: "10.0.20.1",
    30: "10.0.30.1",
    99: "10.0.99.1",
}


class CampusTopo(Topo):
    def build(self, invitados=False):

        # Switches: solo OpenFlow 1.3 y modo seguro.
        switch_opts = {
            "protocols": "OpenFlow13",
            "failMode": "secure",
        }

        s1 = self.addSwitch("s1", dpid="0000000000000001",
                            **switch_opts)
        s2 = self.addSwitch("s2", dpid="0000000000000002",
                            **switch_opts)
        s3 = self.addSwitch("s3", dpid="0000000000000003",
                            **switch_opts)

        # Hosts con direcciones exactas del enunciado.
        h1 = self.addHost(
            "h1", ip="10.0.10.11/24",
            mac="00:00:00:00:10:11"
        )
        h2 = self.addHost(
            "h2", ip="10.0.10.12/24",
            mac="00:00:00:00:10:12"
        )
        h3 = self.addHost(
            "h3", ip="10.0.20.21/24",
            mac="00:00:00:00:20:21"
        )
        h4 = self.addHost(
            "h4", ip="10.0.20.22/24",
            mac="00:00:00:00:20:22"
        )
        srv = self.addHost(
            "srv", ip="10.0.30.10/24",
            mac="00:00:00:00:30:10"
        )

        # Enlaces troncales: puertos exactos.
        self.addLink(s1, s2, port1=1, port2=1)
        self.addLink(s1, s3, port1=2, port2=1)

        # Acceso piso 1.
        self.addLink(s2, h1, port1=2, port2=0)
        self.addLink(s2, h3, port1=3, port2=0)

        # Acceso piso 2.
        self.addLink(s3, h2, port1=2, port2=0)
        self.addLink(s3, h4, port1=3, port2=0)
        self.addLink(s3, srv, port1=4, port2=0)

        # Extension opcional X1.
        if invitados:
            h5 = self.addHost(
                "h5", ip="10.0.99.50/24",
                mac="00:00:00:00:99:50"
            )
            self.addLink(s2, h5, port1=4, port2=0)


def configurar_rutas(net, invitados=False):
    rutas = {
        "h1": GATEWAYS[10],
        "h2": GATEWAYS[10],
        "h3": GATEWAYS[20],
        "h4": GATEWAYS[20],
        "srv": GATEWAYS[30],
    }

    if invitados:
        rutas["h5"] = GATEWAYS[99]

    for nombre, gateway in rutas.items():
        host = net.get(nombre)
        host.cmd(
            f"ip route replace default via {gateway}"
        )


def iniciar_servidor(net):
    www = Path("/tmp/srv_www")
    admin = Path("/tmp/srv_admin")
    www.mkdir(parents=True, exist_ok=True)
    admin.mkdir(parents=True, exist_ok=True)

    (www / "index.html").write_text(
        "<h1>Portal interno - Distribuidora Quetzal</h1>\n",
        encoding="utf-8"
    )
    (admin / "index.html").write_text(
        "<h1>Panel de administracion</h1>\n",
        encoding="utf-8"
    )

    srv = net.get("srv")

    for puerto, directorio in [
        (80, www),
        (8080, admin),
    ]:
        comando = (
            f"python3 -m http.server {puerto} "
            f"--bind 10.0.30.10 "
            f"--directory {directorio} "
            f"> /tmp/campus_http_{puerto}.log 2>&1 "
            f"& echo $! > /tmp/campus_http_{puerto}.pid"
        )
        srv.cmd(comando)


def detener_servidor(net):
    srv = net.get("srv")
    for puerto in (80, 8080):
        archivo = f"/tmp/campus_http_{puerto}.pid"
        srv.cmd(
            f"if test -f {archivo}; then "
            f"kill $(cat {archivo}) 2>/dev/null; "
            f"rm -f {archivo}; fi"
        )


def ejecutar(invitados=False):
    topo = CampusTopo(invitados=invitados)

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=False,
        autoStaticArp=False,
        waitConnected=False,
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653,
    )

    try:
        info("*** Iniciando Campus SDN\n")
        net.start()

        configurar_rutas(net, invitados)
        iniciar_servidor(net)

        info("*** Topologia preparada\n")
        info("*** VLAN y ruteo pendientes del controlador\n")
        info("*** Escriba 'nodes', 'net' o 'links'\n")

        CLI(net)

    finally:
        detener_servidor(net)
        net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--invitados",
        action="store_true",
        help="Activar extension opcional X1",
    )
    args = parser.parse_args()

    setLogLevel("info")
    ejecutar(invitados=args.invitados)
