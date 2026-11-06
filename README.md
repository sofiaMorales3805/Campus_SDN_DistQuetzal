# Campus SDN: R2, R3 y R4

Controlador os-ken 3.1.1 con OpenFlow 1.3. La topologia fisica,
DPID, puertos y direcciones de `topology/campus.py` no se modificaron.
El estado anterior esta en `controller/campus_controller_r2.py.bak`.

## Diseño para la sustentacion

- **Tabla 0:** conserva R2. Acepta tramas sin etiqueta en accesos,
  agrega la VLAN del puerto y admite solo VLAN autorizadas en troncales.
- **Tabla 1:** conserva unicast y broadcast R2. s2/s3 transportan la
  MAC virtual hacia s1, sin decidir rutas IP. En s1, solo los hosts del
  inventario, con IP, MAC, VLAN y troncal de origen coherentes, pueden
  enviar IPv4 a la MAC del gateway. Esos paquetes pasan a la tabla 2.
  Las solicitudes ARP validas para el gateway se envian al controlador.
- **Tabla 2, solo s1:** ACL IPv4 proactivas por VLAN de origen y
  subred de destino. Las excepciones permitidas tienen prioridad 200;
  las denegaciones explicitas, prioridad 100. El resto se descarta.
- **Tabla 3, solo s1:** rutas hacia los cinco hosts del inventario.
  Cada ruta decrementa TTL, cambia ambas MAC, cambia la VLAN a la de
  destino y sale por la troncal correspondiente.

Cuando origen y destino estan en el mismo switch de acceso, s1 debe
devolver la trama por su troncal de entrada. OpenFlow no permite hacerlo
con `output:<numero_fisico_de_entrada>`: suprime esa salida. Por eso se
utiliza la salida estandar `OFPP_IN_PORT`. s2/s3 reciben la nueva VLAN
y entregan la trama sin etiqueta al host de destino.

Los gateways `10.0.10.1`, `10.0.20.1` y `10.0.30.1` responden ARP con
`02:00:00:00:00:01`. El controlador responde desde s1 con una trama
802.1Q; el switch de acceso retira la etiqueta. No se instalan vecinos
ARP estaticos en los hosts. Las MAC de destino del router provienen del
inventario fijo del enunciado, no de entradas estaticas en los hosts.
No se implementa ping al propio gateway: su servicio requerido es ARP.

No se usa `NORMAL`, routers Linux, IP forwarding, configuracion
`tag/trunks` de OVS, reglas manuales `ovs-ofctl` ni controladores Ryu.
`ovs-ofctl` se utiliza exclusivamente para consultar reglas.
Las reglas no tienen expiracion. En una reconexion, el controlador
reemplaza las reglas anteriores del switch Campus; no debe compartirse
con otros controladores sobre esos mismos switches.

## Politica R4

| Origen | Ventas (10) | Contabilidad (20) | Servidores (30) |
|---|---|---|---|
| Ventas (10) | L2 permitido | Denegado | ICMP y TCP destino 80 |
| Contabilidad (20) | Denegado | L2 permitido | IPv4 permitido |
| Servidores (30) | ICMP y TCP origen 80 | IPv4 permitido | L2 permitido |

**Limitacion aceptada explicitamente:** la ACL HTTP es sin estado.
OpenFlow 1.3 estandar no permite demostrar que un paquete TCP con
origen 80 responde a una conexion previa. Esta regla tambien permite
trafico iniciado por un servidor que utilice ese puerto de origen.
No se afirma que exista un firewall con seguimiento de conexiones.
No se emplean extensiones conntrack de OVS ni aperturas reactivas.

Los paquetes denegados se descartan en s1, no se envian al controlador.
Un host puede necesitar resolver primero su gateway mediante ARP;
ese PacketIn es independiente del descarte posterior del trafico IP.
Solo las solicitudes ARP de gateways autorizadas generan PacketIn.
IPv6 y destinos de ruteo fuera del inventario no estan habilitados.

## Ejecucion interactiva: dos terminales

Primero cerrar cualquier Campus anterior: `exit` en su CLI Mininet y
Ctrl+C en su controlador. No iniciar dos topologias con los mismos
nombres de interfaces. No ejecutar limpiezas globales sobre redes ajenas.

Terminal 1:

```bash
cd /home/sdnadmin/campus-sdn
.venv/bin/osken-manager --ofp-tcp-listen-port 6653 controller/campus_controller.py
```

Terminal 2:

```bash
cd /home/sdnadmin/campus-sdn
sudo /usr/bin/python3 topology/campus.py
```

Esperar las confirmaciones `Reglas R2/R3/R4 confirmadas` de los tres
switches antes de generar trafico. Los errores OpenFlow se registran
explicitamente en el controlador y deben corregirse antes de probar.

La topologia existente inicia automaticamente HTTP/80 desde
`/tmp/srv_www` y HTTP/8080 desde `/tmp/srv_admin`. No fue necesario
modificarla. Comandos en la CLI Mininet:

```text
h1 ping -c 2 10.0.10.12
h3 ping -c 2 10.0.20.22
h1 ping -c 2 10.0.30.10
h2 ping -c 2 10.0.30.10
h4 ping -c 2 10.0.30.10
h1 ping -c 2 10.0.20.21
h1 curl --noproxy '*' -fsS --max-time 3 http://10.0.30.10/
h1 curl --noproxy '*' -fsS --max-time 3 http://10.0.30.10:8080/
h3 curl --noproxy '*' -fsS --max-time 3 http://10.0.30.10:8080/
h1 ip neigh show
```

El ping Ventas -> Contabilidad y el curl Ventas -> 8080 deben fallar.
Los demas comandos anteriores deben alcanzar sus destinos.

Consultas desde otra terminal, sin instalar reglas:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s2
sudo ovs-ofctl -O OpenFlow13 dump-flows s3
sudo ovs-vsctl get Port s1-eth1 tag trunks
```

## Validacion reproducible

Pruebas sin privilegios:

```bash
cd /home/sdnadmin/campus-sdn
.venv/bin/python -m py_compile controller/campus_controller.py tests/test_controller.py tests/verify_network.py
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

Prueba real automatizada: mantener el controlador de la terminal 1
en 6653 y **cerrar la topologia interactiva**. En la terminal 2:

```bash
cd /home/sdnadmin/campus-sdn
sudo /usr/bin/python3 tests/verify_network.py \
  --output "/home/sdnadmin/campus-sdn/evidencias/r3_r4_$(date +%Y%m%d_%H%M%S)"
```

La prueba usa `CampusTopo`, las rutas y los servicios originales.
Se niega a crear la red si existen s1, s2 o s3. El directorio de salida
debe ser nuevo. Al terminar detiene solamente la topologia, servicios
y capturadores de esa ejecucion; no detiene el controlador externo.

Comprueba:

- Reglas proactivas antes del trafico, sin NORMAL ni VLAN OVS.
- Las 20 parejas dirigidas ICMP de los cinco hosts.
- ARP dinamico para los cinco hosts y los tres gateways.
- HTTP/80 y HTTP/8080 desde cada host, validando contenido o timeout.
- UDP de Ventas denegado y de Contabilidad permitido.
- Descartes R4 con contadores crecientes, sin nuevos PacketIn.
- Broadcast de prueba recibido solo dentro de VLAN 10.
- Accesos sin etiquetas y troncales con 802.1Q.
- TTL 64 -> 63, MAC de gateway, MAC destino y VLAN 30 para las
  cuatro rutas hacia srv, incluidas las de retorno por la misma troncal.
- TTL 1 descartado antes de srv.
- Integridad SHA-256 de los PCAP originales.

Guarda `results.json`, reglas antes/despues, capturas nuevas y logs
tcpdump. No abre los PCAP anteriores para escritura. Un fallo de
asercion devuelve codigo 1; errores de infraestructura abortan con
excepcion y no deben interpretarse como una ejecucion completa.
Unicamente un resumen final sin fallos acredita la prueba completa.

## Resultados realmente obtenidos en esta entrega

| Comprobacion | Resultado |
|---|---|
| Version instalada de os-ken | 3.1.1 |
| Sintaxis del controlador y pruebas con Python | Correcta |
| Sintaxis con Pylance del controlador y prueba de red | Sin errores |
| Pruebas unitarias | 7/7 correctas |
| Reglas R2 frente al respaldo, tablas 0/1 | Identicas byte a byte en s1/s2/s3 |
| Serializacion de FlowMod y PacketOut OF1.3 | Correcta en pruebas unitarias |
| ACL, rutas, hairpin y ARP de los cinco hosts | Verificados con datapath simulado |
| Arranque real del controlador en puerto libre 6654 | Correcto, PID temporal 23293 |
| Conexion TCP y saludo OpenFlow 1.3 | Recibido `040000084163711f` |
| Controlador temporal | Detenido al finalizar la comprobacion |
| Pruebas reales de trafico Mininet/OVS | **PENDIENTES, no ejecutadas** |

No se puede declarar R3/R4 operativos en la red hasta ejecutar la
validacion Mininet. En las comprobaciones realizadas seguian activos
el controlador anterior PID 19798 en 6653 y Mininet PID 19990.
`sudo -n /usr/bin/python3` devolvio `sudo: a password is required`.
No se detuvieron ni se reconfiguraron esas sesiones. El arranque en
6654 no se conecto a los switches y no acredita reenvio real.

Logs reales: `evidencias/r3_r4_unit_tests.log` y
`evidencias/r3_r4_controller_startup.log`. El aviso EventletDeprecated
procede de una dependencia existente de os-ken; no impidio el arranque.
Tambien se registro `1 RLock(s) were not greened`. No se modifico el
arranque de os-ken para ocultarlo; se verificaron escucha y saludo,
pero su efecto durante una sesion con trafico no se ha evaluado.
No se instalaron dependencias.

### Integridad preservada

```text
controller/campus_controller_r2.py.bak
24f0817bd9485e15eebdef0b264dd44d5498ec05b8d69854ea4ef965c3af03d0

evidencias/r2_acceso_h1.pcap
cc33073b66ad2e869a1363e758261db63ed9704bfc5697cd9d6059bf0d17c213

evidencias/r2_troncal_s1_s2.pcap
f9b77d1b534ef6231fb20a4d0868e0bbf2f1aecca8bf3b5f19d975550f9a1d3f
```

### Comandos de comprobacion ejecutados

Ademas de leer los archivos y comprobar procesos/puertos:

```bash
cp -p -n controller/campus_controller.py controller/campus_controller_r2.py.bak
sha256sum controller/campus_controller.py controller/campus_controller_r2.py.bak
.venv/bin/python -c "import importlib.metadata; print('os-ken', importlib.metadata.version('os-ken'))"
.venv/bin/python -m py_compile controller/campus_controller.py tests/test_controller.py tests/verify_network.py
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v 2>&1 | tee evidencias/r3_r4_unit_tests.log
.venv/bin/osken-manager --ofp-tcp-listen-port 6654 controller/campus_controller.py > evidencias/r3_r4_controller_startup.log 2>&1
.venv/bin/python -c "import socket; s=socket.create_connection(('127.0.0.1',6654),timeout=3); data=s.recv(8); print('OpenFlow hello:',data.hex()); assert data[0]==4 and data[1]==0; s.close()"
ss -ltnp 'sport = :6654'
sudo -n /usr/bin/python3 tests/verify_network.py --output /home/sdnadmin/campus-sdn/evidencias/r3_r4_network_20261106
sha256sum controller/campus_controller_r2.py.bak evidencias/r2_acceso_h1.pcap evidencias/r2_troncal_s1_s2.pcap
```

El comando `sudo -n` de red fallo antes de ejecutar el script. No
existen capturas ni resultados de red R3/R4 de esa invocacion.
