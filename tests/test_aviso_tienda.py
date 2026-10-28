"""Relay real, sockets ASGI en memoria; ninguna llamada a servicios reales."""
import asyncio
import hashlib
import hmac
import importlib.util
import json
import socket
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

spec = importlib.util.spec_from_file_location("relay_ficha73", Path(__file__).parents[1] / "main.py")
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
CUIT = "20123456789"
SECRETO = "ficha73-vector-secreto-solo-prueba-32"
VECTOR = '{"cuit":"20123456789","ts":1767000000,"nonce":"abcdefghijklmnop","motivo":"pedido_pagado"}'
# Mismo vector fijo en TypeScript y prueba integrada.
HEX = hmac.new(SECRETO.encode(), VECTOR.encode(), hashlib.sha256).hexdigest()
CONNECT = socket.socket.connect

@pytest.fixture(autouse=True)
def aislado(monkeypatch):
    monkeypatch.setenv("RELAY_AVISO_SECRETO", SECRETO)
    monkeypatch.setenv("RELAY_PERMITIR_SIN_CLAVE", "1")
    monkeypatch.setattr(relay, "LATIDO_SEGUNDOS", 3600)
    def solo_local(sock, address):
        assert address[0] in {"127.0.0.1", "::1"}, "Red externa prohibida"
        return CONNECT(sock, address)
    monkeypatch.setattr(socket.socket, "connect", solo_local)
    for nombre in ("connections", "pending", "capacidades", "avisos_pendientes", "ultimos_avisos", "nonces",
                   "rechazos", "intentos_ip", "intentos_global", "autenticadas"):
        getattr(relay, nombre).clear()
    monkeypatch.setattr(relay, "obtener_acceso_web", AsyncMock(return_value={"habilitado": True}))
    yield
    assert not relay.connections
    assert not relay.capacidades
    assert not relay.autenticadas

@pytest.fixture
def client():
    with TestClient(relay.app) as c:
        yield c

def aviso(client, *, ts=None, nonce=None, firma=True, cuit=CUIT, extra=None):
    datos = {"cuit": cuit, "ts": int(time.time()) if ts is None else ts, "nonce": nonce or uuid.uuid4().hex, "motivo": "pedido_pagado"}
    datos.update(extra or {})
    raw = json.dumps(datos, separators=(",", ":")).encode()
    headers = {"x-aviso-firma": "sha256=" + hmac.new(SECRETO.encode(), raw, hashlib.sha256).hexdigest()} if firma else {}
    return client.post("/tienda/aviso", content=raw, headers=headers)

def hola(ws, caps=None):
    ws.send_json({"tipo": "hola", "version": "1.5.2", "capacidades": ["aviso_tienda", "latido"] if caps is None else caps})
    assert ws.receive_json() == {"tipo": "hola_ok", "relay": 2}

def test_vector_fijo():
    assert HEX == "72a24a536f4aff08985b20f9c043c92a5701a4157e3ed1a1a4ac80b3ae874a72"

def test_entrega_normalizada_antes_del_proxy(client):
    with client.websocket_connect("/ws/20-12345678-9") as ws:
        hola(ws)
        assert aviso(client).json() == {"entregado": True}
        assert ws.receive_json() == {"tipo": "aviso_tienda"}
    relay.obtener_acceso_web.assert_not_called()

@pytest.mark.parametrize("cambio", [{"firma": False}, {"ts": 1}, {"ts": 9999999999}, {"extra": {"nombre": "no admitido"}}, {"nonce": "corto"}])
def test_rechazos_no_entregan(client, cambio):
    with client.websocket_connect(f"/ws/{CUIT}") as ws:
        hola(ws)
        r = aviso(client, **cambio)
        assert r.status_code == 401
        assert r.json() == {"detail": "Aviso no autorizado."}
        # Eco como barrera: si hubo aviso se recibiría antes del eco.
        ws.send_json({"tipo": "eco"})
        assert ws.receive_json() == {"tipo": "eco_ok"}

def test_firma_mala_y_replay(client):
    assert client.post("/tienda/aviso", content=b"{}", headers={"x-aviso-firma": "sha256=mal"}).status_code == 401
    nonce = uuid.uuid4().hex
    assert aviso(client, nonce=nonce).status_code == 202
    assert aviso(client, nonce=nonce).status_code == 401

@pytest.mark.parametrize("secreto", ["", "corto"])
def test_no_configurado(client, monkeypatch, secreto):
    monkeypatch.setenv("RELAY_AVISO_SECRETO", secreto)
    assert aviso(client).status_code == 503

def test_limite_cuerpo_y_cuit(client):
    assert client.post("/tienda/aviso", content=b"x" * 1025).status_code == 413
    assert aviso(client, cuit="123").status_code == 400

def test_legacy_sin_tipos_y_entrega_guardada(client):
    with client.websocket_connect(f"/ws/{CUIT}") as ws:
        assert aviso(client).json() == {"entregado": False, "guardado": True}
        # La primera respuesta luego del saludo debe ser hola_ok, no un aviso previo.
        hola(ws)
        assert ws.receive_json() == {"tipo": "aviso_tienda"}
        assert CUIT not in relay.avisos_pendientes

def test_guardado_vence_y_sin_capacidad_no_se_borra(client):
    relay.avisos_pendientes[CUIT] = time.time() - 86401
    with client.websocket_connect(f"/ws/{CUIT}") as ws:
        hola(ws)
        ws.send_json({"tipo": "eco"}); assert ws.receive_json() == {"tipo": "eco_ok"}
    aviso(client)
    with client.websocket_connect(f"/ws/{CUIT}") as ws:
        hola(ws, ["latido"])
        assert CUIT in relay.avisos_pendientes

def test_agrupa_y_json_invalido_no_corta(client):
    with client.websocket_connect(f"/ws/{CUIT}") as ws:
        ws.send_text("no es json"); ws.send_json([]); hola(ws)
        assert aviso(client).json() == {"entregado": True}
        assert ws.receive_json() == {"tipo": "aviso_tienda"}
        assert aviso(client).json() == {"entregado": True, "agrupado": True}
        ws.send_json({"tipo": "desconocido"}); ws.send_json({"tipo": "eco"})
        assert ws.receive_json() == {"tipo": "eco_ok"}

def test_latido_solo_con_capacidad(client, monkeypatch):
    monkeypatch.setattr(relay, "LATIDO_SEGUNDOS", .01)
    with client.websocket_connect(f"/ws/{CUIT}") as ws:
        time.sleep(.03)
        hola(ws)
        assert ws.receive_json() == {"tipo": "latido"}

def test_proxy_movil_intacto(client):
    import concurrent.futures
    with client.websocket_connect("/ws/20-12345678-9") as ws:
        with concurrent.futures.ThreadPoolExecutor() as pool:
            respuesta = pool.submit(client.get, f"/{CUIT}/api/algo")
            msg = ws.receive_json()
            assert msg["path"] == "/api/algo"
            ws.send_json({"request_id": msg["request_id"], "status": 201, "body": {"listo": True}})
            assert respuesta.result(timeout=3).json() == {"listo": True}
    relay.obtener_acceso_web.assert_awaited_once_with(CUIT)

def test_health_no_expone_cuits(client):
    with client.websocket_connect(f"/ws/{CUIT}"):
        salud = client.get("/").json()
        assert salud == {"status": "ok", "clientes_conectados": 1, "relay": 2, "avisos_tienda": True}
        assert CUIT not in json.dumps(salud)

def test_auth_sin_clave_rechaza_por_defecto(client, monkeypatch):
    monkeypatch.delenv("RELAY_PERMITIR_SIN_CLAVE")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/{CUIT}"):
            pytest.fail("No debe aceptar")

def credencial(texto):
    """M2: el escritorio manda sha256(clave), nunca la clave."""
    return hashlib.sha256(texto.encode()).hexdigest()

BUENA = credencial("clave-prueba")

def tienda_simulada(monkeypatch, responder):
    monkeypatch.setenv("RELAY_AUTH_URL", "https://tienda.test/api/sync/v1/relay-auth")
    original = httpx.AsyncClient
    llamadas = []
    def tienda(req):
        llamadas.append(req.headers["authorization"])
        return responder(req)
    monkeypatch.setattr(relay.httpx, "AsyncClient", lambda **kw: original(**kw, transport=httpx.MockTransport(tienda)))
    return llamadas

def autoriza_solo(valida):
    return lambda req: httpx.Response(200, json={"autorizado": True}) if req.headers["authorization"] == f"Bearer {valida}" else httpx.Response(401, json={"autorizado": False})

def rechazada(client, cred, cuit=CUIT):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/{cuit}", headers={"authorization": f"Bearer {cred}"}):
            pytest.fail("No debe aceptar")

@pytest.mark.parametrize("clave", ["mala", "clave-otro-cuit"])
def test_auth_rechaza_mala_o_de_otro_cuit_aun_con_legacy(client, monkeypatch, clave):
    # Ejecutar verificación real del relay con HTTP de tienda simulado.
    def tienda(req):
        assert json.loads(req.content) == {"cuit": CUIT}
        assert req.headers["authorization"] == f"Bearer {credencial(clave)}"
        return httpx.Response(401, json={"autorizado": False})
    llamadas = tienda_simulada(monkeypatch, tienda)
    rechazada(client, credencial(clave))
    assert len(llamadas) == 1

def test_auth_correcta_sin_guardar_clave(client, monkeypatch):
    llamadas = tienda_simulada(monkeypatch, autoriza_solo(BUENA))
    with client.websocket_connect(f"/ws/{CUIT}", headers={"authorization": f"Bearer {BUENA}"}) as ws:
        hola(ws)
    assert llamadas == [f"Bearer {BUENA}"]
    assert BUENA not in repr((relay.capacidades, relay.rechazos, relay.intentos_ip))

@pytest.mark.parametrize("cred", ["clave-prueba", "A" * 64, BUENA[:63], BUENA + "0"])
def test_auth_formato_invalido_no_consulta_tienda(client, monkeypatch, cred):
    # La clave en claro (o cualquier cosa que no sea un sha256 hex) se rechaza sin costo.
    llamadas = tienda_simulada(monkeypatch, autoriza_solo(cred))
    rechazada(client, cred)
    assert llamadas == []

def test_m1_rechazo_recordado_sin_volver_a_consultar(client, monkeypatch):
    llamadas = tienda_simulada(monkeypatch, autoriza_solo(BUENA))
    mala = credencial("mala")
    rechazada(client, mala); rechazada(client, mala)
    assert len(llamadas) == 1
    # Vencido el recuerdo, vuelve a preguntar.
    for huella in relay.rechazos:
        relay.rechazos[huella] -= relay.RECHAZO_RECORDAR_SEGUNDOS + 1
    rechazada(client, mala)
    assert len(llamadas) == 2

def test_m1_tienda_caida_no_se_recuerda(client, monkeypatch):
    llamadas = tienda_simulada(monkeypatch, lambda req: httpx.Response(503, json={"autorizado": False}))
    rechazada(client, BUENA); rechazada(client, BUENA)
    assert len(llamadas) == 2 and not relay.rechazos

def test_m1_limite_por_ip_y_global(client, monkeypatch):
    monkeypatch.setattr(relay, "AUTH_POR_IP_MAX", 2)
    llamadas = tienda_simulada(monkeypatch, autoriza_solo(BUENA))
    for n in range(4):
        rechazada(client, credencial(f"mala-{n}"))
    assert len(llamadas) == 2
    # Otra IP (último tramo de X-Forwarded-For, el que agrega Render) sí puede.
    for izquierda in ("1.1.1.1", "2.2.2.2"):
        with client.websocket_connect(f"/ws/{CUIT}", headers={"authorization": f"Bearer {BUENA}", "x-forwarded-for": f"{izquierda}, 9.9.9.9"}) as ws:
            hola(ws)
    assert len(llamadas) == 4
    # Inventar la IP de la izquierda no saltea el límite de la IP real.
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/{CUIT}", headers={"authorization": f"Bearer {BUENA}", "x-forwarded-for": "5.5.5.5, 9.9.9.9"}):
            pytest.fail("No debe aceptar")
    assert len(llamadas) == 4
    monkeypatch.setattr(relay, "AUTH_POR_IP_MAX", 100)
    monkeypatch.setattr(relay, "AUTH_GLOBAL_MAX", len(relay.intentos_global))
    rechazada(client, credencial("otra"))
    assert len(llamadas) == 4

def test_a1_sin_clave_no_desplaza_a_la_autenticada(client, monkeypatch):
    tienda_simulada(monkeypatch, autoriza_solo(BUENA))
    with client.websocket_connect(f"/ws/{CUIT}", headers={"authorization": f"Bearer {BUENA}"}) as ws:
        hola(ws)
        legitima = relay.connections[CUIT]
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/ws/{CUIT}"):
                pytest.fail("Un tercero sin clave no debe ocupar el lugar")
        assert relay.connections[CUIT] is legitima
        assert aviso(client).json() == {"entregado": True}
        assert ws.receive_json() == {"tipo": "aviso_tienda"}

def test_a1_autenticada_cierra_a_la_sin_clave(client, monkeypatch):
    tienda_simulada(monkeypatch, autoriza_solo(BUENA))
    with client.websocket_connect(f"/ws/{CUIT}") as intruso:
        with client.websocket_connect(f"/ws/{CUIT}", headers={"authorization": f"Bearer {BUENA}"}) as ws:
            with pytest.raises(WebSocketDisconnect) as cierre:
                intruso.receive_json()
            assert cierre.value.code == 4001
            hola(ws)
            assert id(relay.connections[CUIT]) in relay.autenticadas

def test_poda_ttl_y_topes():
    mapa = {str(n): n for n in range(1002)}
    relay._podar(mapa, 1002, 2000, 1000)
    assert len(mapa) == 1000 and "0" not in mapa
    relay._podar(mapa, 4000, 600, 1000)
    assert mapa == {}

def test_falla_envio_guarda(client):
    class Roto:
        async def send_json(self, msg):
            raise RuntimeError("simulado")
    roto = Roto(); relay.connections[CUIT] = roto; relay.capacidades[id(roto)] = {"aviso_tienda"}
    try:
        assert aviso(client).json() == {"entregado": False, "guardado": True}
    finally:
        relay.connections.clear(); relay.capacidades.clear()

def test_post_concurrentes_agrupados_antes_de_esperar_envio(client):
    import concurrent.futures
    recibido = __import__("threading").Event()
    liberar = __import__("threading").Event()
    class Lento:
        enviados = 0
        async def send_json(self, msg):
            self.enviados += 1
            recibido.set()
            while not liberar.is_set():
                await asyncio.sleep(.01)
    ws = Lento(); relay.connections[CUIT] = ws; relay.capacidades[id(ws)] = {"aviso_tienda"}
    try:
        with concurrent.futures.ThreadPoolExecutor() as pool:
            primero = pool.submit(aviso, client)
            assert recibido.wait(2)
            try:
                assert aviso(client).json() == {"entregado": True, "agrupado": True}
            finally:
                liberar.set()
            assert primero.result(timeout=2).json() == {"entregado": True}
        assert ws.enviados == 1
    finally:
        liberar.set(); relay.connections.clear(); relay.capacidades.clear()
