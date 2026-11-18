"""演示用目标 Web 服务。

同一进程监听：
* 8080/tcp HTTP（允许目标 172.31.10.10 与禁止目标 172.31.20.10 都运行本服务）；
* 8443/tcp HTTPS（使用受信演示 CA 签发的证书，含全部演示域名 SAN）。

按 Host 头提供不同路径行为：正常 200、跳转至允许/禁止目标、跳转链、
回显请求来源等。``/_requests`` 记录本进程收到的请求，供演示脚本验证
“被策略拒绝的目标从未收到探测请求”。

可控故障目标（配合探测端熔断演示）：
* 独立端口 ``FAULT_PORT``（默认 8899）上的裸 TCP 监听，行为可热切换：
  - ``ok``      正常应答 200；
  - ``timeout`` 接受连接但永不应答（触发探测端读取超时）；
  - ``closed``  关闭监听（触发探测端连接拒绝）；
* 控制面：``GET /_fault`` 查看，``POST /_fault {"mode": "..."}`` 切换；
* 故障端口收到的请求同样记入 ``/_requests``。
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

CERT_DIR = os.getenv("CERT_DIR", "/app/certs")
FAULT_PORT = int(os.getenv("FAULT_PORT", "8899"))
FAULT_MODE_DEFAULT = os.getenv("FAULT_MODE", "ok")
FAULT_MODES = ("ok", "timeout", "closed")
RECENT_REQUESTS: deque[dict] = deque(maxlen=200)


class FaultListener:
    """独立端口上的可控故障监听（连接拒绝 / 读取超时 / 正常应答）。"""

    def __init__(self) -> None:
        self.mode = FAULT_MODE_DEFAULT
        self._server: asyncio.base_events.Server | None = None
        self._pending: set[asyncio.Task] = set()
        self._lock = asyncio.Lock()

    async def apply(self, mode: str) -> None:
        async with self._lock:
            self.mode = mode
            if mode == "closed":
                if self._server is not None:
                    self._server.close()
                    await self._server.wait_closed()
                    self._server = None
                for task in list(self._pending):
                    task.cancel()
                return
            if self._server is None:
                self._server = await asyncio.start_server(
                    self._handle, "0.0.0.0", FAULT_PORT
                )

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        mode = self.mode  # 接受连接时的模式快照
        peer = writer.get_extra_info("peername")
        try:
            head = await asyncio.wait_for(self._read_head(reader), timeout=5.0)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            head = ("", "", "")
        method, path, host = head
        RECENT_REQUESTS.appendleft(
            {
                "ts": round(time.time(), 3),
                "method": method or "?",
                "host": host or None,
                "path": path or "?",
                "peer": peer[0] if peer else None,
                "user_agent": None,
                "fault_port": FAULT_PORT,
                "fault_mode": mode,
            }
        )
        if mode == "timeout":
            # 接受并读取请求，但永不应答：探测端将读取超时
            task = asyncio.current_task()
            if task is not None:
                self._pending.add(task)
                task.add_done_callback(self._pending.discard)
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                pass
            finally:
                await self._close(writer)
            return
        # ok 模式：正常应答 200
        try:
            body = b'{"message": "fault target ok"}'
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            await self._close(writer)

    @staticmethod
    async def _read_head(reader: asyncio.StreamReader) -> tuple[str, str, str]:
        data = b""
        while b"\r\n\r\n" not in data and len(data) <= 8192:
            chunk = await reader.read(1024)
            if not chunk:
                break
            data += chunk
        lines = data.decode("iso-8859-1", errors="replace").split("\r\n")
        method, path = "", ""
        if lines and " " in lines[0]:
            parts = lines[0].split(" ")
            method, path = parts[0], parts[1] if len(parts) > 1 else ""
        host = ""
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return method, path, host

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


fault_listener = FaultListener()


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    await fault_listener.apply(FAULT_MODE_DEFAULT)
    try:
        yield
    finally:
        await fault_listener.apply("closed")


app = FastAPI(
    title="demo-targets",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=_lifespan,
)


@app.middleware("http")
async def record_requests(request: Request, call_next):
    RECENT_REQUESTS.appendleft(
        {
            "ts": round(time.time(), 3),
            "method": request.method,
            "host": request.headers.get("host"),
            "path": request.url.path,
            "peer": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
    )
    return await call_next(request)


@app.get("/")
async def root(request: Request):
    return JSONResponse(
        {
            "service": "demo-targets",
            "host": request.headers.get("host"),
            "peer": request.client.host if request.client else None,
            "tls": request.url.scheme == "https",
            "message": "目标可达",
        }
    )


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


@app.get("/_requests")
async def list_requests():
    return JSONResponse(list(RECENT_REQUESTS))


@app.get("/_fault")
async def get_fault():
    return JSONResponse(
        {
            "mode": fault_listener.mode,
            "port": FAULT_PORT,
            "modes": list(FAULT_MODES),
            "listening": fault_listener.mode != "closed",
        }
    )


@app.post("/_fault")
async def set_fault(request: Request):
    """热切换故障模式：ok（正常应答）/ timeout（不应答）/ closed（拒绝连接）。"""
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - 非法 JSON 一律按 422 处理
        return JSONResponse({"error": "请求体必须是 JSON"}, status_code=422)
    mode = str(body.get("mode", "")).lower()
    if mode not in FAULT_MODES:
        return JSONResponse(
            {"error": f"未知故障模式: {mode!r}", "modes": list(FAULT_MODES)},
            status_code=422,
        )
    await fault_listener.apply(mode)
    return JSONResponse({"mode": fault_listener.mode, "port": FAULT_PORT})


@app.get("/redirect-allowed")
async def redirect_allowed():
    return RedirectResponse(url="http://redirect-final.demo.test/final", status_code=302)


@app.get("/redirect-https")
async def redirect_https():
    return RedirectResponse(
        url="https://https.allowed.demo.test/secure", status_code=302
    )


@app.get("/redirect-forbidden")
async def redirect_forbidden():
    # 跳到禁止网段的目标：探测方必须在第二跳解析校验时拦截
    return RedirectResponse(url="http://forbidden.demo.test/secret", status_code=302)


@app.get("/redirect-scheme")
async def redirect_scheme():
    # 跳到非 HTTP(S) 协议：探测方应拒绝
    return RedirectResponse(url="file:///etc/passwd", status_code=302)


@app.get("/final")
async def final():
    return JSONResponse({"message": "跳转链终点，可达"})


@app.get("/secure")
async def secure(request: Request):
    return JSONResponse(
        {
            "message": "HTTPS 目标可达，证书按原域名验证通过",
            "host": request.headers.get("host"),
            "scheme": request.url.scheme,
        }
    )


# 跳转链：loop1/loop/1 -> loop2/loop/2 -> loop3/loop/3 -> loop4/loop/4 -> loop1 …
@app.get("/loop/{n}")
async def loop_chain(n: int):
    next_n = 1 if n >= 4 else n + 1
    return RedirectResponse(
        url=f"http://loop{next_n}.demo.test/loop/{next_n}",
        status_code=307,
    )


@app.get("/secret")
async def secret():
    return JSONResponse({"message": "禁止网段目标不应被任何探测请求到达"})


def _server_kwargs() -> dict:
    return {
        "app": app,
        "log_level": "warning",
        "access_log": False,
    }


async def _one_server(port: int, ssl_cert: str | None = None,
                      ssl_key: str | None = None) -> uvicorn.Server:
    cfg_kwargs = dict(host="0.0.0.0", port=port, **_server_kwargs())
    if ssl_cert and ssl_key:
        cfg_kwargs.update(ssl_certfile=ssl_cert, ssl_keyfile=ssl_key)
    server = uvicorn.Server(uvicorn.Config(**cfg_kwargs))
    # 直接返回由 gather 驱动；这里只构造，不阻塞
    return server


async def serve() -> None:
    # 同时监听标准端口（80/443，供跳转 URL 直接使用）与演示端口（8080/8443）。
    # 容器以 root 启动可绑定特权端口；本地非特权演示可经环境变量改为高位端口。
    http_ports = [int(p) for p in os.getenv("TARGET_HTTP_PORTS", "80,8080").split(",")]
    https_ports = [int(p) for p in os.getenv("TARGET_HTTPS_PORTS", "443,8443").split(",")]
    cert = f"{CERT_DIR}/targets.fullchain.pem"
    key = f"{CERT_DIR}/targets.key.pem"
    servers: list[uvicorn.Server] = []
    for p in http_ports:
        servers.append(await _one_server(p))
    for p in https_ports:
        servers.append(await _one_server(p, cert, key))
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(serve())
