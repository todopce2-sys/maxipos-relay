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
import logging
import uuid
from typing import Dict, Optional

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


# ── WebSocket: MaxiPOS desktop se conecta acá ─────────────────────────────────

@app.websocket("/ws/{cuit}")
async def ws_maxipos(websocket: WebSocket, cuit: str):
    await websocket.accept()
    connections[cuit] = websocket
    log.info(f"[+] MaxiPOS conectado  CUIT={cuit}  total={len(connections)}")
    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            req_id = msg.get("request_id")
            if req_id and req_id in pending:
                future = pending[req_id]
                if not future.done():
                    future.set_result(msg)
    except WebSocketDisconnect:
        connections.pop(cuit, None)
        log.info(f"[-] MaxiPOS desconectado CUIT={cuit}  total={len(connections)}")
    except Exception as e:
        connections.pop(cuit, None)
        log.warning(f"[!] Error WS CUIT={cuit}: {e}")


# ── HTTP: App móvil hace sus requests acá ────────────────────────────────────

@app.api_route(
    "/{cuit}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def proxy(cuit: str, path: str, request: Request):
    ws = connections.get(cuit)
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
        "cuits": list(connections.keys()),
    }
