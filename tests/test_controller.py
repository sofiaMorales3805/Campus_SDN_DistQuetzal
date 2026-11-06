"""Pruebas de reglas y ARP sin privilegios ni switches activos."""

import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import SimpleNamespace

from os_ken.lib.packet import arp, ethernet, ether_types, packet, vlan
from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser

from controller.campus_controller import CampusController


class Datapath:
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def __init__(self, dpid):
        self.id = dpid
        self.messages = []

    def send_msg(self, msg):
        msg.serialize()
        self.messages.append(msg)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.app = CampusController()

    def rules(self, dpid):
        dp = Datapath(dpid)
        self.app.switch_conectado(
            SimpleNamespace(msg=SimpleNamespace(datapath=dp)),
        )
        return [
            msg for msg in dp.messages
            if isinstance(msg, ofproto_v1_3_parser.OFPFlowMod)
            and msg.command == ofproto_v1_3.OFPFC_ADD
        ]

    def test_all_messages_serialize_and_tables_drop_by_default(self):
        for dpid in (1, 2, 3):
            rules = self.rules(dpid)
            self.assertEqual(
                {r.table_id for r in rules if r.priority == 0},
                {0, 1, 2, 3},
            )
            for rule in rules:
                self.assertEqual(rule.idle_timeout, 0)
                self.assertEqual(rule.hard_timeout, 0)

    def test_r2_rules_preserved_against_backup(self):
        path = Path(__file__).resolve().parents[1] / "controller/campus_controller_r2.py.bak"
        loader = SourceFileLoader("campus_r2_backup", str(path))
        spec = spec_from_loader(loader.name, loader)
        if spec is None:
            raise RuntimeError("No se pudo cargar el respaldo R2")
        original = module_from_spec(spec)
        loader.exec_module(original)
        for dpid in (1, 2, 3):
            installed = []
            for app in (original.CampusController(), self.app):
                dp = Datapath(dpid)
                app.instalar_entrada(dp)
                app.instalar_unicast(dp)
                app.instalar_broadcast(dp)
                installed.append([
                    bytes(msg.buf) for msg in dp.messages if msg.table_id < 2
                ])
            self.assertEqual(installed[0], installed[1])

    def test_access_switches_have_no_routing_or_acl(self):
        for dpid in (2, 3):
            for rule in self.rules(dpid):
                if rule.priority:
                    self.assertIn(rule.table_id, (0, 1))
                for instruction in rule.instructions:
                    for action in getattr(instruction, "actions", []):
                        self.assertNotIsInstance(
                            action, ofproto_v1_3_parser.OFPActionDecNwTtl,
                        )

    def test_acl_matrix(self):
        rules = [r for r in self.rules(1) if r.table_id == 2 and r.priority]
        for src in (10, 20, 30):
            for dst in (10, 20, 30):
                if src == dst:
                    continue
                pair = [
                    r for r in rules
                    if r.match["vlan_vid"] == 0x1000 | src
                    and r.match["ipv4_dst"][0] == f"10.0.{dst}.0"
                ]
                self.assertEqual(sum(r.priority == 100 for r in pair), 1)
                allowed = [r for r in pair if r.priority == 200]
                if {src, dst} == {10, 20}:
                    self.assertEqual(allowed, [])
                elif {src, dst} == {10, 30}:
                    self.assertEqual({r.match["ip_proto"] for r in allowed}, {1, 6})
                    tcp = next(r for r in allowed if r.match["ip_proto"] == 6)
                    self.assertEqual(tcp.match["tcp_dst" if src == 10 else "tcp_src"], 80)
                else:
                    self.assertEqual(len(allowed), 1)
                    self.assertNotIn("ip_proto", dict(allowed[0].match.items()))

    def test_routing_actions_and_hairpin(self):
        routes = [r for r in self.rules(1) if r.table_id == 3 and r.priority]
        self.assertEqual(len(routes), 16)
        hairpins = 0
        for rule in routes:
            actions = rule.instructions[0].actions
            self.assertIsInstance(actions[0], ofproto_v1_3_parser.OFPActionDecNwTtl)
            self.assertEqual(actions[1].value, self.app.MAC_GATEWAY)
            self.assertEqual(actions[3].key, "vlan_vid")
            hairpins += actions[4].port == ofproto_v1_3.OFPP_IN_PORT
        self.assertGreater(hairpins, 0)

    def test_dynamic_gateway_arp(self):
        for name, (vid, mac, sw, _) in self.app.HOSTS.items():
            dp = Datapath(1)
            request = packet.Packet()
            request.add_protocol(ethernet.ethernet(
                dst="ff:ff:ff:ff:ff:ff", src=mac,
                ethertype=ether_types.ETH_TYPE_8021Q,
            ))
            request.add_protocol(vlan.vlan(
                vid=vid, ethertype=ether_types.ETH_TYPE_ARP,
            ))
            request.add_protocol(arp.arp(
                opcode=arp.ARP_REQUEST, src_mac=mac,
                src_ip=self.app.IPS[name], dst_ip=self.app.GATEWAYS[vid],
            ))
            request.serialize()
            self.app.responder_arp(SimpleNamespace(msg=SimpleNamespace(
                datapath=dp, data=request.data,
                match={"in_port": 1 if sw == 2 else 2},
            )))
            self.assertEqual(len(dp.messages), 1)
            reply = packet.Packet(dp.messages[0].data)
            self.assertEqual(reply.get_protocol(vlan.vlan).vid, vid)
            answer = reply.get_protocol(arp.arp)
            self.assertEqual(answer.opcode, arp.ARP_REPLY)
            self.assertEqual(answer.src_mac, self.app.MAC_GATEWAY)
            self.assertEqual(answer.src_ip, self.app.GATEWAYS[vid])
            self.assertEqual(answer.dst_mac, mac)

    def test_unexpected_packet_in_does_not_get_a_reply(self):
        dp = Datapath(2)
        with self.assertLogs(self.app.logger, level="WARNING"):
            self.app.responder_arp(SimpleNamespace(msg=SimpleNamespace(
                datapath=dp, data=b"", match={"in_port": 1},
            )))
        self.assertEqual(dp.messages, [])


if __name__ == "__main__":
    unittest.main()
