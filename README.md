# Campus SDN — Distribuidora Quetzal

Proyecto individual de Telecomunicaciones: requisitos **R1–R6** implementados en Mininet / Open vSwitch con **os-ken 3.1.1**, **OpenFlow 1.3** y canal de control TCP **6653**.

## Requisitos

Entorno validado: Ubuntu Server 24.04.5 LTS, Python 3.12, Mininet 2.3.0, Open vSwitch 3.3.9 y os-ken 3.1.1. Se requieren Git, Python 3 con `venv`, Mininet, Open vSwitch, `tcpdump`, `curl`, `ip` y `sudo`. El Python del sistema debe poder importar `mininet`.

## Instalación desde GitHub

Desde cualquier carpeta de trabajo en Ubuntu:

```bash
git clone https://github.com/sofiaMorales3805/Campus_SDN_DistQuetzal.git
cd Campus_SDN_DistQuetzal
python3 -m venv .venv
.venv/bin/python -m pip install 'os-ken==3.1.1'
.venv/bin/python -c "import importlib.metadata as m; print(m.version('os-ken'))"
```

La última instrucción debe imprimir `3.1.1`. Mininet se utiliza desde el Python del sistema; compruebe con `/usr/bin/python3 -c 'import mininet'`. La carpeta `.venv` no se incluye en GitHub. **Todas las instrucciones posteriores se ejecutan desde la raíz del repositorio clonado**; en cada terminal nueva, navegue primero hasta esa carpeta.

## Arranque — dos terminales

Antes de arrancar, cerrar una topología previa con `exit` en `mininet>` y detener el controlador anterior con Ctrl+C. No lanzar dos controladores a la vez sobre el puerto 6653. Si existen restos de una ejecución propia, `sudo mn -c` puede limpiarlos, pero no debe ejecutarse cuando existan otras redes Mininet que preservar.

**Terminal 1 — controlador:**

```bash
.venv/bin/osken-manager --ofp-tcp-listen-port 6653 controller/campus_controller.py
```

**Terminal 2 — topología interactiva:**

```bash
sudo /usr/bin/python3 topology/campus.py
```

Esperar el prompt `mininet>` y las confirmaciones `Reglas R2/R3/R4 confirmadas` para s1, s2 y s3 en la terminal del controlador. La topología configura las rutas por defecto e inicia automáticamente el portal HTTP/80 y el panel HTTP/8080 en `srv`.

Desde Mininet:

```text
sh ovs-vsctl show
h1 ping -c 2 h2
h3 ping -c 2 h4
h1 ping -c 2 srv
h4 ping -c 2 srv
h1 ping -c 2 h3
h1 curl --noproxy '*' -fsS --max-time 3 http://10.0.30.10:80/
h1 curl --noproxy '*' -fsS --max-time 3 http://10.0.30.10:8080/
h3 curl --noproxy '*' -fsS --max-time 3 http://10.0.30.10:8080/
h1 ip neigh show
```

Resultados esperados: s1/s2/s3 con `is_connected: true` y `fail_mode: secure`; comunicación L2 dentro de la misma VLAN con TTL 64; h1→srv con TTL 63; Ventas→Contabilidad denegado; portal /80 permitido para Ventas, panel /8080 denegado para Ventas y permitido para Contabilidad. El gateway ARP resuelve la MAC `02:00:00:00:00:01`. h4 y srv están en s3, pero en distintas VLAN: la ruta pasa por s1 y retorna por la misma troncal gracias a `OFPP_IN_PORT`.

## Arquitectura y restricciones

- **s1 (DPID 1):** núcleo L3, ACL y reescritura de TTL/MAC/VLAN. **s2 (DPID 2)** y **s3 (DPID 3):** solo conmutación L2.
- **VLAN 10:** h1 10.0.10.11 y h2 10.0.10.12; gateway 10.0.10.1.
- **VLAN 20:** h3 10.0.20.21 y h4 10.0.20.22; gateway 10.0.20.1.
- **VLAN 30:** srv 10.0.30.10; gateway 10.0.30.1.
- **Tabla 0:** acceso/troncal y etiquetas 802.1Q. **Tabla 1:** L2, validación de origen y solicitudes ARP de gateway. **Tabla 2 (s1):** ACL proactivas. **Tabla 3 (s1):** rutas proactivas y `dec_ttl` / `set_field`.
- El controlador envía los `FLOW_MOD` en `EventOFPSwitchFeatures`, descarta tráfico no autorizado en el switch y confirma procesamiento con `BARRIER_REPLY`. Para responder ARP de gateways autorizados utiliza `Packet-In` y `Packet-Out`.
- No se usan acción `NORMAL`, atributos OVS `tag/trunks`, routers Linux, IP forwarding en hosts ni `ovs-ofctl add-flow`.

La ACL para respuestas HTTP es **sin estado**: permite TCP con puerto de origen 80 desde Servidores hacia Ventas, pero no comprueba pertenencia a una sesión previa. **X1** (VLAN invitados con meters de 2 Mbps) y **X2** (respuesta ICMP del gateway) son opcionales y **no están implementados**. La topología dispone de `--invitados` como posibilidad de escenario, pero el controlador publicado no implementa X1: no se debe usar como demostración funcional.

## Inspección y pruebas automatizadas

En Mininet, anteponer `sh` a los comandos del sistema; en Bash Ubuntu, utilizar `sudo` y omitir `sh`.

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s2
sudo ovs-ofctl -O OpenFlow13 dump-flows s3
sudo ovs-vsctl get Port s1-eth1 tag trunks
```

Para las pruebas unitarias:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

Para las pruebas reales automatizadas: detener y cerrar primero la topología interactiva, pero mantener os-ken ejecutándose en otra terminal. El verificador inicia su propia topología y crea una carpeta de resultados **nueva**:

```bash
sudo /usr/bin/python3 tests/verify_network.py --output "evidencias/r3_r4_$(date +%Y%m%d_%H%M%S)"
```

**Resultados realmente obtenidos:** 7/7 pruebas unitarias correctas y **83/83 comprobaciones reales correctas**, sin fallos. Evidencia: `evidencias/r3_r4_validacion_02/results.json`, reglas y archivos PCAP de la misma carpeta. Se comprobaron conectividad, VLAN, ARP, ACL, HTTP, UDP, TTL, reescritura MAC/VLAN y descarte local (contador drop: 12→18; Packet-In ARP: 5→5).

## Recuperación R6 — solamente en laboratorio

1. Mantener Mininet ejecutándose y comprobar los pings antes del procedimiento.
2. Detener os-ken (Ctrl+C en Terminal 1).
3. En una terminal Bash Ubuntu, **solo con el controlador detenido**, ejecutar:

```bash
sudo ovs-ofctl -O OpenFlow13 del-flows s1
sudo ovs-ofctl -O OpenFlow13 del-flows s2
sudo ovs-ofctl -O OpenFlow13 del-flows s3
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

4. Comprobar tablas vacías; reiniciar os-ken con el comando original; esperar las confirmaciones de los tres switches.
5. Repetir h1→h2, h1→srv, h1→h3 y HTTP/80. Los resultados registrados fueron 2/2, 2/2, 0/2 y portal disponible, respectivamente.

El uso de `del-flows` se limita a simular borrado durante R6; **nunca se agregan flujos manualmente**. Evidencias: `evidencias/r6_s1_antes.txt`, `r6_s1_despues.txt` y equivalentes de s2 y s3.

## Evidencias para la entrega

- `evidencias/r2_troncal_s1_s2.pcap`: troncal con etiquetas IEEE 802.1Q **VLAN 10 y VLAN 20**.
- `evidencias/r2_acceso_h1.pcap`: tráfico de acceso sin etiqueta.
- `evidencias/openflow_control_6653.pcap`: captura de control OpenFlow TCP/6653 (179 paquetes): **6 HELLO, 3 FEATURES_REQUEST, 3 FEATURES_REPLY, 102 FLOW_MOD, 3 BARRIER_REQUEST y 3 BARRIER_REPLY**.
- `evidencias/r3_r4_validacion_02/results.json`: detalle de 83 comprobaciones.
- `evidencias/r3_r4_validacion_02/trunk_s2.pcap`, `trunk_s3.pcap` y `srv.pcap`: evidencia de reenvío, TTL y VLAN.
- `evidencias/r6_s*_antes.txt` y `r6_s*_despues.txt`: reglas antes/después del reinicio.

Abrir los PCAP con Wireshark; filtros útiles: `vlan.id == 10`, `vlan.id == 20`, `openflow_v4.type == 14` para FLOW_MOD y `openflow_v4.type == 20 || openflow_v4.type == 21` para BARRIER. El informe técnico describe el significado de las capturas.

## Cierre

Para cerrar Mininet escribir `exit` en `mininet>`, detener el controlador con Ctrl+C y usar `sudo mn -c` solo si quedan recursos residuales propios. No alterar reglas manualmente fuera del procedimiento R6.
