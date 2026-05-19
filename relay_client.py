"""
MaxiPOS Relay Client
--------------------
Se ejecuta como hilo de fondo dentro de MaxiPOS desktop.
Mantiene una conexión WebSocket con el relay de DSL y reenvía
cada request HTTP al servidor local (localhost:8000).

Uso:
    from relay_client import RelayClient

    relay = RelayClient(cuit="20345678901")
    relay.start()          # arranca en segundo plano
    # ... al cerrar la app:
    relay.stop()
"""

import asyncio
import json
import logging
import threading

import httpx
import websockets
from websockets.exceptions import ConnectionClosed

log = logging.getLogger(__name__)

RELAY_WS  = "wss://maxipos-relay.onrender.com/ws"
LOCAL_API = "http://localhost:8000"
RECONNECT_DELAY = 5   # segundos entre reconexiones
REQUEST_TIMEOUT = 15  # segundos para responder al relay


class RelayClient:
    def __init__(self, cuit: str):
        self.cuit     = cuit
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True, name="relay-client")
        self._thread.start()
        log.info(f"[Relay] Cliente iniciado para CUIT={self.cuit}")

    def stop(self) -> None:
        self._running = False
        log.info("[Relay] Cliente detenido")

    # ── Hilo principal ────────────────────────────────────────────────────────

    def _run(self) -> None:
        asyncio.run(self._loop())

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._connect()
            except Exception as e:
                if self._running:
                    log.warning(f"[Relay] Desconectado: {e}. Reconectando en {RECONNECT_DELAY}s...")
                    await asyncio.sleep(RECONNECT_DELAY)

    # ── Conexión WebSocket ────────────────────────────────────────────────────

    async def _connect(self) -> None:
        url = f"{RELAY_WS}/{self.cuit}"
        log.info(f"[Relay] Conectando a {url}")
        async with websockets.connect(url, ping_interval=30, ping_timeout=10) as ws:
            log.info(f"[Relay] Conectado ✓  CUIT={self.cuit}")
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                    # Cada request se maneja concurrentemente
                    asyncio.create_task(self._handle(ws, msg))
                except Exception as e:
                    log.error(f"[Relay] Error procesando mensaje: {e}")

    # ── Procesar un request del relay ─────────────────────────────────────────

    async def _handle(self, ws, msg: dict) -> None:
        req_id = msg.get("request_id", "")
        method  = msg.get("method", "GET")
        path    = msg.get("path", "/")
        query   = msg.get("query", "")
        headers = msg.get("headers", {})
        body    = msg.get("body")

        url = f"{LOCAL_API}{path}"
        if query:
            url += f"?{query}"

        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                r = await client.request(
                    method,
                    url,
                    content=body.encode("utf-8") if body else None,
                    headers={
                        "Content-Type":  headers.get("content-type", "application/json"),
                        "Authorization": headers.get("authorization", ""),
                    },
                )
            response = {
                "request_id": req_id,
                "status":     r.status_code,
                "body":       r.json() if r.content else None,
            }
        except httpx.ConnectError:
            log.error("[Relay] No se pudo conectar a localhost:8000 — ¿está corriendo MaxiPOS?")
            response = {
                "request_id": req_id,
                "status":     503,
                "body":       {"detail": "El servicio MaxiPOS no está disponible en este momento."},
            }
        except Exception as e:
            log.error(f"[Relay] Error en request local: {e}")
            response = {
                "request_id": req_id,
                "status":     500,
                "body":       {"detail": str(e)},
            }

        try:
            await ws.send(json.dumps(response))
        except ConnectionClosed:
            pass
