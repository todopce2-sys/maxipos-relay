"""
MaxiPOS Relay Server
--------------------
Permite que la app móvil se comunique con MaxiPOS aunque la PC del
cliente esté detrás de un router sin IP fija ni puerto abierto.

Flujo:
  [App móvil] ──HTTP──► [Relay] ──WebSocket──► [MaxiPOS en PC cliente]
                                ◄──────────────────────────────────────
"""

import asyncio
import json
import hashlib
import hmac
import re
from urllib.parse import urlparse
import logging
import os
import time
import uuid
from typing import Dict, Optional

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="MaxiPOS Relay", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# cuit → WebSocket activo
connections: Dict[str, WebSocket] = {}

# request_id → Future con la respuesta pendiente
pending: Dict[str, asyncio.Future] = {}

TIMEOUT_SECS = 20
LICENCIAS_URL = os.getenv("LICENCIAS_URL", "https://maxipos-licencias.onrender.com").rstrip("/")
WEB_ACCESS_CACHE_SECS = 15
web_access_cache: Dict[str, tuple[float, dict]] = {}


async def obtener_acceso_web(cuit: str) -> dict | None:
    """Consulta la vigencia del adicional y conserva una cache corta por CUIT."""
    cacheado = web_access_cache.get(cuit)
    ahora = time.monotonic()
    if cacheado and cacheado[0] > ahora:
        return cacheado[1]

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            respuesta = await client.get(
                f"{LICENCIAS_URL}/licencia/web-acceso",
                params={"cuit": cuit},
            )
        respuesta.raise_for_status()
        acceso = respuesta.json()
    except (httpx.HTTPError, ValueError) as error:
        log.warning("No se pudo verificar MaxiPOS Web para CUIT=%s: %s", cuit, error)
        return None

    web_access_cache[cuit] = (ahora + WEB_ACCESS_CACHE_SECS, acceso)
    return acceso


# Estado efímero acotado. Nunca se conservan claves ni datos de pedidos.
LATIDO_SEGUNDOS = 30
AGRUPAR_SEGUNDOS = 3
capacidades: Dict[int, set] = {}
avisos_pendientes: Dict[str, float] = {}
ultimos_avisos: Dict[str, float] = {}
nonces: Dict[str, float] = {}


def _clave_cuit(texto: str) -> str:
    return re.sub(r"\D", "", texto)


def _podar(mapa: dict, ahora: float, ttl: float, maximo: int) -> None:
    for clave, momento in list(mapa.items()):
        if ahora - momento >= ttl:
            mapa.pop(clave, None)
    while len(mapa) > maximo:
        mapa.pop(min(mapa, key=mapa.get), None)


# D5 (Revisión Opus 2): el escritorio NO manda su clave de sincronización, sino
# sha256(clave) en hex, que es el mismo hash que la tienda ya guarda en
# claveSync. Ese valor solo sirve para este handshake: /pedidos y /cambios
# vuelven a calcular el hash de lo que reciben, así que con el hash no se leen
# pedidos ni se escribe stock. El relay nunca ve la clave completa.
CREDENCIAL = re.compile(r"[0-9a-f]{64}")
RECHAZO_RECORDAR_SEGUNDOS = 600   # un rechazo de la tienda se recuerda 10 min
AUTH_POR_IP_MAX = 10              # verificaciones contra la tienda por IP y minuto
AUTH_GLOBAL_MAX = 60              # tope total por minuto: cuida el costo de Vercel
rechazos: Dict[str, float] = {}           # sha256(cuit:credencial) -> momento
intentos_ip: Dict[str, list] = {}         # IP -> momentos de verificación
intentos_global: list = []
autenticadas: set = set()                 # id(websocket) de conexiones con clave


def _ip_cliente(websocket: WebSocket) -> str:
    # Render agrega la IP real al final de X-Forwarded-For; lo de la izquierda
    # lo puede inventar el cliente, así que se toma el último tramo.
    reenviado = websocket.headers.get("x-forwarded-for", "")
    if reenviado.strip():
        return reenviado.split(",")[-1].strip()
    return websocket.client.host if websocket.client else "desconocida"


def _permitir_verificacion(ip: str, ahora: float) -> bool:
    intentos_global[:] = [t for t in intentos_global if ahora - t < 60]
    for clave in list(intentos_ip):
        intentos_ip[clave] = [t for t in intentos_ip[clave] if ahora - t < 60]
        if not intentos_ip[clave]:
            intentos_ip.pop(clave, None)
    propios = intentos_ip.get(ip, [])
    if len(propios) >= AUTH_POR_IP_MAX or len(intentos_global) >= AUTH_GLOBAL_MAX or len(intentos_ip) >= 10000:
        return False
    intentos_ip[ip] = propios + [ahora]
    intentos_global.append(ahora)
    return True


async def verificar_clave_relay(cuit: str, credencial: str) -> Optional[bool]:
    """D5: verificar en tienda en cada handshake; no persistir la credencial.

    True = autorizada; False = la tienda la rechazó (se puede recordar);
    None = no se pudo preguntar (tienda caída, 5xx): se rechaza sin recordar.
    HTTPS obligatorio salvo loopback de pruebas. Sin redirecciones.
    """
    url = os.getenv("RELAY_AUTH_URL", "").strip()
    destino = urlparse(url)
    if destino.scheme != "https" and not (
        destino.scheme == "http" and destino.hostname in {"127.0.0.1", "::1"}
    ):
        log.warning("[auth] RELAY_AUTH_URL no está configurada")
        return None
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False, trust_env=False) as client:
            respuesta = await client.post(url, headers={"Authorization": f"Bearer {credencial}"}, json={"cuit": cuit})
        if respuesta.status_code == 200:
            return respuesta.json().get("autorizado") is True
        if respuesta.status_code in (401, 403):
            return False
        log.warning("[auth] La tienda respondió %s al verificar MaxiPOS", respuesta.status_code)
        return None
    except Exception:
        log.warning("[auth] No se pudo verificar la conexión de MaxiPOS")
        return None


async def _autenticar(websocket: WebSocket, cuit: str, credencial: str) -> bool:
    ahora = time.time()
    huella = hashlib.sha256(f"{cuit}:{credencial}".encode()).hexdigest()
    _podar(rechazos, ahora, RECHAZO_RECORDAR_SEGUNDOS, 10000)
    if huella in rechazos:
        log.warning("[auth] CUIT=…%s rechazado:recordado", cuit[-4:])
        return False
    if not _permitir_verificacion(_ip_cliente(websocket), ahora):
        log.warning("[auth] CUIT=…%s rechazado:limite", cuit[-4:])
        return False
    resultado = await verificar_clave_relay(cuit, credencial)
    if resultado is False:
        rechazos[huella] = time.time()
        log.warning("[auth] CUIT=…%s rechazado:tienda", cuit[-4:])
    return resultado is True


async def _latidos(websocket: WebSocket) -> None:
    while True:
        await asyncio.sleep(LATIDO_SEGUNDOS)
        if "latido" in capacidades.get(id(websocket), set()):
            await websocket.send_json({"tipo": "latido"})


# ── WebSocket: MaxiPOS desktop se conecta acá ─────────────────────────────────

@app.websocket("/ws/{cuit}")
async def ws_maxipos(websocket: WebSocket, cuit: str):
    cuit = _clave_cuit(cuit)
    bearer = websocket.headers.get("authorization", "")
    if len(cuit) != 11:
        await websocket.close(code=1008, reason="Conexión no autorizada.")
        return
    if bearer:
        credencial = bearer[7:].strip() if bearer.startswith("Bearer ") else ""
        # Formato inválido: se rechaza sin preguntarle a la tienda (cero costo).
        if not CREDENCIAL.fullmatch(credencial) or not await _autenticar(websocket, cuit, credencial):
            await websocket.close(code=1008, reason="Conexión no autorizada.")
            return
        con_clave = True
    elif os.getenv("RELAY_PERMITIR_SIN_CLAVE") == "1":
        # A1: una conexión sin clave nunca desplaza a una autenticada del mismo CUIT.
        actual = connections.get(cuit)
        if actual is not None and id(actual) in autenticadas:
            log.warning("[auth] CUIT=…%s sin clave rechazado: ya hay una conexión con clave", cuit[-4:])
            await websocket.close(code=1008, reason="Conexión no autorizada.")
            return
        log.warning("[auth] Conexión antigua sin clave CUIT=…%s", cuit[-4:])
        con_clave = False
    else:
        await websocket.close(code=1008, reason="Conexión no autorizada.")
        return
    await websocket.accept()
    anterior = connections.get(cuit)
    connections[cuit] = websocket
    if con_clave:
        autenticadas.add(id(websocket))
        # A1: la conexión sin clave desplazada se cierra (podía ser de un tercero).
        # Entre dos conexiones con clave se mantiene "gana la más reciente" sin
        # cerrar, para no generar reconexiones cruzadas (cada una cuesta una
        # verificación en Vercel).
        if anterior is not None and anterior is not websocket and id(anterior) not in autenticadas:
            try:
                await anterior.close(code=4001, reason="Reemplazada por una conexión con clave.")
            except Exception:
                pass
    capacidades[id(websocket)] = set()
    latido = asyncio.create_task(_latidos(websocket))
    log.info("[+] MaxiPOS conectado CUIT=…%s total=%s", cuit[-4:], len(connections))
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except (ValueError, TypeError):
                log.warning("[WS] Mensaje inválido ignorado")
                continue
            if not isinstance(msg, dict):
                continue
            if "tipo" in msg:
                if msg["tipo"] == "hola":
                    declaradas = msg.get("capacidades", [])
                    capacidades[id(websocket)] = {x for x in declaradas if isinstance(x, str)} if isinstance(declaradas, list) else set()
                    await websocket.send_json({"tipo": "hola_ok", "relay": 2})
                    _podar(avisos_pendientes, time.time(), 24 * 3600, 1000)
                    if cuit in avisos_pendientes and "aviso_tienda" in capacidades[id(websocket)]:
                        await websocket.send_json({"tipo": "aviso_tienda"})
                        avisos_pendientes.pop(cuit, None)
                        ultimos_avisos[cuit] = time.time()
                        _podar(ultimos_avisos, time.time(), 24 * 3600, 1000)
                elif msg["tipo"] == "eco" and capacidades[id(websocket)]:
                    await websocket.send_json({"tipo": "eco_ok"})
                continue
            req_id = msg.get("request_id")
            if req_id and req_id in pending:
                future = pending[req_id]
                if not future.done():
                    future.set_result(msg)
    except WebSocketDisconnect:
        pass
    except Exception:
        log.warning("[WS] Conexión interrumpida CUIT=…%s", cuit[-4:])
    finally:
        latido.cancel()
        capacidades.pop(id(websocket), None)
        autenticadas.discard(id(websocket))
        # No eliminar una conexión nueva al cerrarse la anterior.
        if connections.get(cuit) is websocket:
            connections.pop(cuit, None)
        log.info("[-] MaxiPOS desconectado CUIT=…%s total=%s", cuit[-4:], len(connections))
        await asyncio.gather(latido, return_exceptions=True)


# Debe registrarse antes del proxy comodín /{cuit}/{path:path}.
@app.post("/tienda/aviso", status_code=202)
async def aviso_tienda(request: Request):
    secreto = os.getenv("RELAY_AVISO_SECRETO", "")
    if len(secreto) < 32:
        raise HTTPException(503, "El aviso de la tienda no está configurado.")
    cuerpo = bytearray()
    async for bloque in request.stream():
        cuerpo.extend(bloque)
        if len(cuerpo) > 1024:
            raise HTTPException(413, "El aviso es demasiado largo.")

    def rechazar(motivo: str, cuit: str = ""):
        log.warning("[aviso] CUIT=…%s rechazado:%s", cuit[-4:], motivo)
        raise HTTPException(401, "Aviso no autorizado.")

    firma = "sha256=" + hmac.new(secreto.encode(), cuerpo, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(firma.encode(), request.headers.get("x-aviso-firma", "").encode()):
        rechazar("firma")
    try:
        datos = json.loads(cuerpo)
    except (ValueError, TypeError):
        rechazar("datos")
    if not isinstance(datos, dict) or set(datos) != {"cuit", "ts", "nonce", "motivo"} or not isinstance(datos["cuit"], str):
        rechazar("datos")
    cuit = _clave_cuit(datos["cuit"])
    if len(cuit) != 11:
        raise HTTPException(400, "Datos del aviso inválidos.")
    ahora = time.time()
    if type(datos["ts"]) is not int or abs(ahora - datos["ts"]) > 300:
        rechazar("hora", cuit)
    nonce = datos["nonce"]
    if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", nonce) or datos["motivo"] != "pedido_pagado":
        rechazar("datos", cuit)
    _podar(nonces, ahora, 600, 10000)
    if nonce in nonces:
        rechazar("repetido", cuit)
    nonces[nonce] = ahora
    _podar(nonces, ahora, 600, 10000)
    _podar(avisos_pendientes, ahora, 24 * 3600, 1000)
    _podar(ultimos_avisos, ahora, 24 * 3600, 1000)
    ws = connections.get(cuit)
    if ws and "aviso_tienda" in capacidades.get(id(ws), set()):
        if cuit in ultimos_avisos and ahora - ultimos_avisos[cuit] < AGRUPAR_SEGUNDOS:
            log.info("[aviso] CUIT=…%s agrupado", cuit[-4:])
            return {"entregado": True, "agrupado": True}
        # Reservar antes del await también agrupa POST concurrentes.
        ultimos_avisos[cuit] = ahora
        try:
            await ws.send_json({"tipo": "aviso_tienda"})
            avisos_pendientes.pop(cuit, None)
            _podar(ultimos_avisos, ahora, 24 * 3600, 1000)
            log.info("[aviso] CUIT=…%s entregado", cuit[-4:])
            return {"entregado": True}
        except Exception:
            ultimos_avisos.pop(cuit, None)
    avisos_pendientes[cuit] = ahora
    _podar(avisos_pendientes, ahora, 24 * 3600, 1000)
    log.info("[aviso] CUIT=…%s guardado", cuit[-4:])
    return {"entregado": False, "guardado": True}


# ── HTTP: App móvil hace sus requests acá ────────────────────────────────────

@app.api_route(
    "/{cuit}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def proxy(cuit: str, path: str, request: Request):
    acceso = await obtener_acceso_web(cuit)
    if acceso is None:
        raise HTTPException(
            status_code=503,
            detail="No se pudo verificar la licencia de MaxiPOS Web. Intentá nuevamente.",
        )
    if not acceso.get("habilitado"):
        raise HTTPException(
            status_code=403,
            detail=acceso.get("mensaje") or "El adicional MaxiPOS Web no está activo.",
        )

    ws = connections.get(_clave_cuit(cuit))
    if not ws:
        raise HTTPException(
            status_code=503,
            detail=(
                "El servidor MaxiPOS no está conectado. "
                "Verificá que la PC del comercio esté encendida y MaxiPOS abierto."
            ),
        )

    req_id   = str(uuid.uuid4())
    body_raw = await request.body()

    # Pasamos los headers relevantes (Authorization, Content-Type)
    fwd_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() in ("authorization", "content-type", "accept")
    }

    msg = {
        "request_id": req_id,
        "method":     request.method,
        "path":       f"/{path}",
        "query":      str(request.url.query),
        "headers":    fwd_headers,
        "body":       body_raw.decode("utf-8") if body_raw else None,
    }

    loop   = asyncio.get_event_loop()
    future: asyncio.Future = loop.create_future()
    pending[req_id] = future

    try:
        await ws.send_text(json.dumps(msg))
        response = await asyncio.wait_for(future, timeout=TIMEOUT_SECS)

        status = response.get("status", 200)
        body   = response.get("body")
        return JSONResponse(content=body, status_code=status)

    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail="MaxiPOS no respondió a tiempo. Intentá de nuevo.",
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
    finally:
        pending.pop(req_id, None)


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {
        "status": "ok",
        "clientes_conectados": len(connections),
        "relay": 2,
        "avisos_tienda": True,
    }


@app.get("/ping")
@app.head("/ping")
def ping():
    return {"status": "ok"}
