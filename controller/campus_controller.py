
#!/usr/bin/env python3
"""
Campus SDN - Distribuidora Quetzal, S.A.
Controlador os-ken 3.1.1 / OpenFlow 1.3

Version 0.3 - Requisitos R2, R3 y R4:
- Puertos de acceso sin etiquetas.
- Enlaces troncales con 802.1Q.
- Comunicacion L2 dentro de la misma VLAN.
- Aislamiento entre VLAN.
- Reglas proactivas instaladas por el controlador.

Ruteo y ACL proactivas exclusivamente en s1.
Gateways con ARP dinamico y MAC virtual compartida.
HTTP de retorno: ACL sin estado por puerto TCP de origen 80.
"""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import arp, ethernet, ether_types, packet, vlan


class CampusController(app_manager.OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    SWITCHES = {
        1: "s1 - Nucleo",
        2: "s2 - Piso 1",
        3: "s3 - Piso 2",
    }

    # Puertos de acceso: switch -> puerto -> VLAN
    ACCESOS = {
        1: {},
        2: {2: 10, 3: 20},
        3: {2: 10, 3: 20, 4: 30},
    }

    # Puertos troncales y VLAN admitidas.
    TRONCALES = {
        1: {1: {10, 20}, 2: {10, 20, 30}},
        2: {1: {10, 20}},
        3: {1: {10, 20, 30}},
    }

    # MAC, VLAN y ubicacion fisica exacta.
    HOSTS = {
        "h1": (10, "00:00:00:00:10:11", 2, 2),
        "h2": (10, "00:00:00:00:10:12", 3, 2),
        "h3": (20, "00:00:00:00:20:21", 2, 3),
        "h4": (20, "00:00:00:00:20:22", 3, 3),
        "srv": (30, "00:00:00:00:30:10", 3, 4),
    }

    IPS = {
        "h1": "10.0.10.11",
        "h2": "10.0.10.12",
        "h3": "10.0.20.21",
        "h4": "10.0.20.22",
        "srv": "10.0.30.10",
    }
    GATEWAYS = {
        10: "10.0.10.1",
        20: "10.0.20.1",
        30: "10.0.30.1",
    }
    MAC_GATEWAY = "02:00:00:00:00:01"

    def instalar(self, dp, tabla, prioridad, match,
                 acciones=None, siguiente=None):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        instrucciones = []

        if acciones is not None:
            instrucciones.append(
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    acciones
                )
            )

        if siguiente is not None:
            instrucciones.append(
                parser.OFPInstructionGotoTable(siguiente)
            )

        dp.send_msg(
            parser.OFPFlowMod(
                datapath=dp,
                table_id=tabla,
                priority=prioridad,
                match=match,
                instructions=instrucciones,
                idle_timeout=0,
                hard_timeout=0
            )
        )

    def etiqueta(self, dp, vlan):
        return dp.ofproto.OFPVID_PRESENT | vlan

    def puertos_vlan(self, dpid, vlan):
        puertos = {}

        for puerto, vid in self.ACCESOS[dpid].items():
            if vid == vlan:
                puertos[puerto] = "acceso"

        for puerto, vids in self.TRONCALES[dpid].items():
            if vlan in vids:
                puertos[puerto] = "troncal"

        return puertos

    def salida_host(self, dpid, destino):
        vlan, mac, sw_destino, puerto = destino

        if dpid == sw_destino:
            return puerto, True

        if dpid == 1:
            return (1 if sw_destino == 2 else 2), False

        # Desde un switch de acceso hacia el nucleo.
        return 1, False

    def instalar_entrada(self, dp):
        dpid = dp.id
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Todo lo no autorizado se descarta.
        for tabla in (0, 1, 2, 3):
            self.instalar(
                dp, tabla, 0, parser.OFPMatch(), []
            )

        # Puertos de acceso: aceptar solo SIN VLAN.
        for puerto, vlan in self.ACCESOS[dpid].items():
            acciones = [
                parser.OFPActionPushVlan(0x8100),
                parser.OFPActionSetField(
                    vlan_vid=self.etiqueta(dp, vlan)
                ),
            ]

            self.instalar(
                dp,
                tabla=0,
                prioridad=200,
                match=parser.OFPMatch(
                    in_port=puerto,
                    vlan_vid=ofp.OFPVID_NONE
                ),
                acciones=acciones,
                siguiente=1
            )

        # Troncales: admitir solo VLAN etiquetadas.
        for puerto, vlans in self.TRONCALES[dpid].items():
            for vlan in sorted(vlans):
                self.instalar(
                    dp,
                    tabla=0,
                    prioridad=200,
                    match=parser.OFPMatch(
                        in_port=puerto,
                        vlan_vid=self.etiqueta(dp, vlan)
                    ),
                    acciones=[],
                    siguiente=1
                )

    def instalar_unicast(self, dp):
        dpid = dp.id
        parser = dp.ofproto_parser

        for nombre, destino in self.HOSTS.items():
            vlan, mac, _, _ = destino
            puerto, es_acceso = self.salida_host(
                dpid, destino
            )

            if puerto not in self.puertos_vlan(dpid, vlan):
                continue

            acciones = []

            if es_acceso:
                acciones.append(parser.OFPActionPopVlan())

            acciones.append(parser.OFPActionOutput(puerto))

            self.instalar(
                dp,
                tabla=1,
                prioridad=100,
                match=parser.OFPMatch(
                    vlan_vid=self.etiqueta(dp, vlan),
                    eth_dst=mac
                ),
                acciones=acciones
            )

            self.logger.info(
                "%s: destino %s, VLAN %s, salida %s",
                self.SWITCHES[dpid],
                nombre, vlan, puerto
            )

    def instalar_broadcast(self, dp):
        dpid = dp.id
        parser = dp.ofproto_parser

        # Reenvio de broadcast solo dentro de su VLAN.
        for vlan in (10, 20, 30):
            puertos = self.puertos_vlan(dpid, vlan)

            for entrada in sorted(puertos):
                acciones = []

                # Primero salen copias por troncales.
                for salida in sorted(puertos):
                    if salida == entrada:
                        continue

                    if puertos[salida] == "troncal":
                        acciones.append(
                            parser.OFPActionOutput(salida)
                        )

                # Despues se retira la etiqueta para
                # los puertos de acceso de la misma VLAN.
                accesos = [
                    p for p in sorted(puertos)
                    if p != entrada
                    and puertos[p] == "acceso"
                ]

                if accesos:
                    acciones.append(
                        parser.OFPActionPopVlan()
                    )

                    for salida in accesos:
                        acciones.append(
                            parser.OFPActionOutput(salida)
                        )

                if not acciones:
                    continue

                self.instalar(
                    dp,
                    tabla=1,
                    prioridad=90,
                    match=parser.OFPMatch(
                        in_port=entrada,
                        vlan_vid=self.etiqueta(dp, vlan),
                        eth_dst="ff:ff:ff:ff:ff:ff"
                    ),
                    acciones=acciones
                )

    def instalar_gateways(self, dp):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        if dp.id != 1:
            # Los switches de acceso solo transportan la MAC virtual a s1.
            for vid in self.GATEWAYS:
                if 1 in self.puertos_vlan(dp.id, vid):
                    self.instalar(
                        dp, 1, 200,
                        parser.OFPMatch(
                            vlan_vid=self.etiqueta(dp, vid),
                            eth_dst=self.MAC_GATEWAY,
                        ),
                        [parser.OFPActionOutput(1)],
                    )
            return

        # Ningun paquete no validado dirigido al router llega a las ACL.
        self.instalar(
            dp, 1, 250,
            parser.OFPMatch(eth_dst=self.MAC_GATEWAY), [],
        )
        for nombre, (vid, mac, sw, _) in self.HOSTS.items():
            entrada = 1 if sw == 2 else 2
            comunes = dict(
                in_port=entrada, vlan_vid=self.etiqueta(dp, vid),
                eth_src=mac,
            )
            self.instalar(
                dp, 1, 300,
                parser.OFPMatch(
                    **comunes, eth_dst=self.MAC_GATEWAY,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=self.IPS[nombre],
                ),
                [], siguiente=2,
            )
            self.instalar(
                dp, 1, 300,
                parser.OFPMatch(
                    **comunes, eth_dst="ff:ff:ff:ff:ff:ff",
                    eth_type=ether_types.ETH_TYPE_ARP,
                    arp_op=arp.ARP_REQUEST, arp_sha=mac,
                    arp_spa=self.IPS[nombre],
                    arp_tpa=self.GATEWAYS[vid],
                ),
                [parser.OFPActionOutput(
                    ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER,
                )],
            )

    def instalar_acl(self, dp):
        if dp.id != 1:
            return
        parser = dp.ofproto_parser
        for origen in self.GATEWAYS:
            for destino in self.GATEWAYS:
                if origen == destino:
                    continue
                campos = dict(
                    vlan_vid=self.etiqueta(dp, origen),
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=(f"10.0.{destino}.0", "255.255.255.0"),
                )
                # Denegacion explicita, incluso para protocolos no autorizados.
                self.instalar(
                    dp, 2, 100, parser.OFPMatch(**campos), [],
                )
                if (origen, destino) in ((10, 20), (20, 10)):
                    continue
                if {origen, destino} == {10, 30}:
                    self.instalar(
                        dp, 2, 200,
                        parser.OFPMatch(**campos, ip_proto=1),
                        [], siguiente=3,
                    )
                    puerto = (
                        {"tcp_dst": 80} if origen == 10
                        else {"tcp_src": 80}
                    )
                    self.instalar(
                        dp, 2, 200,
                        parser.OFPMatch(**campos, ip_proto=6, **puerto),
                        [], siguiente=3,
                    )
                else:
                    self.instalar(
                        dp, 2, 200, parser.OFPMatch(**campos),
                        [], siguiente=3,
                    )

    def instalar_rutas(self, dp):
        if dp.id != 1:
            return
        parser = dp.ofproto_parser
        for origen in self.GATEWAYS:
            for nombre, destino in self.HOSTS.items():
                vid, mac, _, _ = destino
                if origen == vid:
                    continue
                salida, _ = self.salida_host(1, destino)
                for entrada in self.puertos_vlan(1, origen):
                    # OpenFlow suprime output al puerto fisico de entrada.
                    puerto = (
                        dp.ofproto.OFPP_IN_PORT
                        if entrada == salida else salida
                    )
                    self.instalar(
                        dp, 3, 100,
                        parser.OFPMatch(
                            in_port=entrada,
                            vlan_vid=self.etiqueta(dp, origen),
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_dst=self.IPS[nombre],
                        ),
                        [
                            parser.OFPActionDecNwTtl(),
                            parser.OFPActionSetField(eth_src=self.MAC_GATEWAY),
                            parser.OFPActionSetField(eth_dst=mac),
                            parser.OFPActionSetField(
                                vlan_vid=self.etiqueta(dp, vid),
                            ),
                            parser.OFPActionOutput(puerto),
                        ],
                    )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def responder_arp(self, ev):
        msg = ev.msg
        dp = msg.datapath
        trama = packet.Packet(msg.data)
        solicitud = trama.get_protocol(arp.arp)
        etiqueta = trama.get_protocol(vlan.vlan)
        eth = trama.get_protocol(ethernet.ethernet)
        entrada = msg.match.get("in_port")
        if (
            dp.id != 1 or solicitud is None or etiqueta is None
            or eth is None or solicitud.opcode != arp.ARP_REQUEST
            or self.GATEWAYS.get(etiqueta.vid) != solicitud.dst_ip
        ):
            self.logger.warning("PacketIn inesperado en DPID=%s", dp.id)
            return
        autorizado = any(
            vid == etiqueta.vid and mac == eth.src == solicitud.src_mac
            and self.IPS[nombre] == solicitud.src_ip
            and entrada == (1 if sw == 2 else 2)
            for nombre, (vid, mac, sw, _) in self.HOSTS.items()
        )
        if not autorizado:
            self.logger.warning("ARP de gateway no autorizado en s1")
            return
        respuesta = packet.Packet()
        respuesta.add_protocol(ethernet.ethernet(
            dst=solicitud.src_mac, src=self.MAC_GATEWAY,
            ethertype=ether_types.ETH_TYPE_8021Q,
        ))
        respuesta.add_protocol(vlan.vlan(
            vid=etiqueta.vid, ethertype=ether_types.ETH_TYPE_ARP,
        ))
        respuesta.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY, src_mac=self.MAC_GATEWAY,
            src_ip=solicitud.dst_ip, dst_mac=solicitud.src_mac,
            dst_ip=solicitud.src_ip,
        ))
        respuesta.serialize()
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(entrada)],
            data=respuesta.data,
        ))

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_openflow(self, ev):
        self.logger.error(
            "Error OpenFlow DPID=%s tipo=%s codigo=%s datos=%s",
            ev.msg.datapath.id, ev.msg.type, ev.msg.code,
            ev.msg.data.hex(),
        )

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def reglas_confirmadas(self, ev):
        self.logger.info(
            "Reglas R2/R3/R4 confirmadas por %s",
            self.SWITCHES[ev.msg.datapath.id],
        )

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_conectado(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id

        if dpid not in self.SWITCHES:
            self.logger.error(
                "Switch no autorizado: DPID=%s", dpid
            )
            return

        self.logger.info(
            "Configurando %s (DPID=%s)",
            self.SWITCHES[dpid], dpid
        )

        # Reconectar no debe conservar reglas de una version anterior.
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, table_id=ofp.OFPTT_ALL,
            command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY, match=parser.OFPMatch(),
        ))
        self.instalar_entrada(dp)
        self.instalar_unicast(dp)
        self.instalar_broadcast(dp)
        self.instalar_gateways(dp)
        self.instalar_acl(dp)
        self.instalar_rutas(dp)

        # Esperar confirmacion de procesamiento de reglas.
        dp.send_msg(
            dp.ofproto_parser.OFPBarrierRequest(dp)
        )

        self.logger.info(
            "Reglas R2/R3/R4 enviadas a %s",
            self.SWITCHES[dpid]
        )
