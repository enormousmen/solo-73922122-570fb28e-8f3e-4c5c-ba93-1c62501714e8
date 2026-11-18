"""HTTP/HTTPS 出站探测引擎。

安全模型（每一跳都完整执行，跳转目标也不例外）：

  URL 静态校验 → DNS A 记录查询 → *全部* 解析地址过白名单
  → 仅向已批准 IP 建 TCP（运行时不再解析）→ HTTPS 按原域名校验证书
  → 发送一次请求 → 读取响应 → 若是跳转则对 Location 重复上述流程

因此：
* DNS 在检查后变化、连接重试、HTTP 跳转都不会让请求进入未获准网段；
* 被策略拒绝的目标在任何 socket 建立之前就被拦下，收不到探测请求；
* 每跳最多把已批准的地址各试一次，重试绝不重新解析 DNS。

熔断（可选，由 main 注入 CircuitBreaker）：
* 每跳在 URL 静态校验之后、DNS 解析之前做熔断准入判定；
  熔断中的目标直接报告 circuit_open 与剩余冷却时间，不解析、不连接；
* 逐跳按 (规范化主机名, 端口) 各自计数：全部已批准地址均连接失败或
  读取超时记一次故障；策略拒绝与证书校验失败不计；
* 跳转各跳独立计数，已发出请求的跳在报告中保留 request_sent 等事实。
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from .breaker import COUNTABLE_KINDS, Admission, CircuitBreaker
from .connection import (
    CertVerificationError,
    TlsInfo,
    build_ssl_context,
    open_tcp,
    start_tls,
)
from .dns_client import DnsError, DnsResolver
from .policy import (
    AddressPolicy,
    PolicyError,
    is_ip_literal,
    parse_target,
)

DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 3
MAX_BYTES = 64 * 1024


@dataclass
class HopReport:
    hop: int
    url: str
    scheme: str
    hostname: str
    port: int
    resolved_addresses: list[str] = field(default_factory=list)
    approved_addresses: list[str] = field(default_factory=list)
    connected_peer: str | None = None
    tls: dict | None = None
    request_sent: bool = False
    status_code: int | None = None
    reason: str | None = None
    location: str | None = None
    redirect_count: int = 0
    outcome: str = "pending"  # ok | redirected | blocked | error | circuit_open
    reject_reason: str | None = None
    error: str | None = None
    # 故障分类（供熔断计数）：connect / read_timeout 计入熔断；
    # cert（证书校验失败）/ other 不计；blocked 跳保持 None。
    failure_kind: str | None = None
    circuit_retry_after_ms: int | None = None

    def mark_blocked(self, reason: str) -> None:
        self.outcome = "blocked"
        self.reject_reason = reason
        self.reason = reason

    def mark_error(self, message: str, failure_kind: str | None = None) -> None:
        self.outcome = "error"
        self.error = message
        self.reason = message
        if failure_kind is not None:
            self.failure_kind = failure_kind

    def mark_circuit_open(self, admission: Admission, key_host: str) -> None:
        """熔断拦截：本跳未解析、未连接，直接报告熔断状态与剩余时间。"""
        self.outcome = "circuit_open"
        self.circuit_retry_after_ms = admission.retry_after_ms
        if admission.state == "half_open":
            message = (
                f"目标 {key_host}:{self.port} 熔断恢复试探进行中，"
                "本次请求被拦截（未解析、未连接），请稍后重试"
            )
        else:
            secs = (admission.retry_after_ms or 0) / 1000
            message = (
                f"目标 {key_host}:{self.port} 处于熔断冷却期，"
                f"剩余约 {secs:.1f} 秒；本次请求未解析、未连接"
            )
        self.error = message
        self.reason = message


class Prober:
    def __init__(
        self,
        policy: AddressPolicy,
        resolver: DnsResolver,
        ca_bundle: str | None = None,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        tls_timeout: float = 8.0,
        max_redirects: int = MAX_REDIRECTS,
        max_bytes: int = MAX_BYTES,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._ssl = build_ssl_context(ca_bundle)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._tls_timeout = tls_timeout
        self._max_redirects = max_redirects
        self._max_bytes = max_bytes
        self._breaker = breaker

    async def probe(self, url: str, method: str = "GET") -> list[HopReport]:
        method = method.upper()
        if method not in ("GET", "HEAD"):
            raise PolicyError("探测仅支持 GET/HEAD 方法")
        hops: list[HopReport] = []
        redirects = 0
        current = url
        while True:
            hop_idx = len(hops) + 1
            hop = HopReport(hop=hop_idx, url=current, scheme="", hostname="", port=0)
            hops.append(hop)
            next_url = await self._do_hop(hop, current, method)
            if hop.outcome in ("blocked", "error", "circuit_open"):
                return hops
            if next_url is None:
                hop.outcome = "ok"
                return hops
            # 发生跳转
            redirects += 1
            hop.redirect_count = redirects
            hop.outcome = "redirected"
            if redirects > self._max_redirects:
                limit_hop = HopReport(
                    hop=len(hops) + 1,
                    url=next_url,
                    scheme="",
                    hostname="",
                    port=0,
                )
                limit_hop.mark_blocked(
                    f"已跟随 {self._max_redirects} 次跳转，达到上限，"
                    f"拒绝继续访问: {next_url}"
                )
                hops.append(limit_hop)
                return hops
            current = next_url

    async def _do_hop(self, hop: HopReport, url: str, method: str) -> str | None:
        # 1) URL 静态校验（不产生任何网络流量）
        try:
            scheme, host, port, _user, raw = parse_target(url)
        except PolicyError as exc:
            hop.mark_blocked(str(exc))
            return None
        hop.scheme = scheme
        hop.hostname = host
        hop.port = port or DEFAULT_PORTS[scheme]

        # 2) 熔断准入：在 DNS 解析与任何连接之前判定；
        #    熔断中的目标直接报告，不产生任何流量
        admission: Admission | None = None
        if self._breaker is not None:
            admission = self._breaker.admit(host, hop.port)
            if not admission.admitted:
                hop.mark_circuit_open(admission, host)
                return None

        try:
            next_url = await self._do_hop_network(hop, scheme, host, method, url)
        except asyncio.CancelledError:
            # 客户端断开或单请求总超时：试探取消必须重新冷却
            if admission is not None:
                self._breaker.record_cancelled(host, hop.port, admission)
            raise
        except Exception:
            # 异常逃逸（实现缺陷等）：按“未收到响应”回执，避免试探卡死半开
            if admission is not None:
                self._breaker.record_neutral(host, hop.port, admission)
            raise
        if admission is not None:
            self._record_hop_outcome(host, hop, admission)
        return next_url

    def _record_hop_outcome(
        self, host: str, hop: HopReport, admission: Admission
    ) -> None:
        """把本跳结果回执给熔断器（每个准入令牌恰好一次）。"""
        assert self._breaker is not None
        if hop.status_code is not None:
            # 收到 HTTP 响应（含 3xx/4xx/5xx）：目标可达，清零
            self._breaker.record_success(host, hop.port, admission)
        elif hop.failure_kind in COUNTABLE_KINDS:
            self._breaker.record_failure(host, hop.port, admission)
        else:
            # 策略拒绝、证书校验失败、其他协议/读写错误：不计故障
            self._breaker.record_neutral(host, hop.port, admission)

    async def _do_hop_network(
        self, hop: HopReport, scheme: str, host: str, method: str, url: str
    ) -> str | None:
        # 3) 解析 + 白名单：IP 字面量直接校验；域名只问配置的解析器
        try:
            if is_ip_literal(host):
                resolved = [host]
            else:
                resolved = await self._resolver.resolve_a(host)
            hop.resolved_addresses = list(resolved)
            approved = self._policy.check_resolved(resolved)
            hop.approved_addresses = [str(ip) for ip in approved]
        except (PolicyError, DnsError) as exc:
            # 策略拒绝 / DNS 失败：不计熔断故障（failure_kind 保持 None）
            hop.mark_blocked(str(exc))
            return None

        # 4) 仅对已批准地址尝试连接，每个地址一次，绝不重新解析
        kinds: list[str] = []
        last_err: str | None = None
        for ip in approved:
            connected, kind = await self._try_one_address(hop, ip, scheme, host)
            if connected is not None:
                # 该地址连接成功：清除此前地址尝试留下的错误，避免残留
                hop.error = None
                reader, writer, tls_info = connected
                try:
                    return await self._send_and_read(
                        hop, reader, writer, method, host, hop.port, url
                    )
                except PolicyError as exc:
                    # 响应阶段的策略性错误（如响应头超限、非法状态行）：
                    # 记录为本跳错误，不逃逸到 API 入口；不计熔断故障
                    hop.mark_error(str(exc), failure_kind="other")
                    return None
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, ssl.SSLError):
                        pass
            kinds.append(kind)
            last_err = hop.error or hop.reject_reason
        # 所有已批准地址均连接失败
        hop.mark_error(
            f"全部已批准地址连接失败（未尝试任何未获准地址）: {last_err}",
            failure_kind=self._classify_connect_failures(kinds),
        )
        return None

    @staticmethod
    def _classify_connect_failures(kinds: list[str]) -> str:
        """全部地址失败后的整跳分类。

        只有“每个地址都是连接类失败”才计入熔断；只要混入证书校验失败，
        整跳即不计故障（证书问题需要修证书，不应按目标宕机熔断）。
        """
        if kinds and all(k == "connect" for k in kinds):
            return "connect"
        if kinds and all(k == "cert" for k in kinds):
            return "cert"
        return "other"

    async def _try_one_address(self, hop: HopReport, ip: ipaddress.IPv4Address,
                               scheme: str, host: str):
        """尝试单个已批准地址，返回 (连接元组 | None, 失败分类 | None)。"""
        try:
            reader, writer, peer = await open_tcp(
                ip, hop.port, self._connect_timeout
            )
            hop.connected_peer = peer
            if scheme == "https":
                reader, writer, tls_info = await start_tls(
                    writer, reader, host, self._ssl, self._tls_timeout
                )
                hop.tls = asdict(tls_info)
            return (reader, writer, tls_info if scheme == "https" else None), None
        except CertVerificationError as exc:
            # 证书校验失败：不计熔断故障
            hop.connected_peer = None
            hop.tls = None
            hop.error = str(exc)
            return None, "cert"
        except PolicyError as exc:
            # TCP/TLS 建连失败：记录失败原因后继续试下一个 *已批准* 地址
            hop.connected_peer = None
            hop.tls = None
            hop.error = str(exc)
            return None, "connect"

    async def _send_and_read(
        self, hop: HopReport, reader, writer, method: str,
        host: str, port: int, url: str,
    ) -> str | None:
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        authority = host if (
            (parts.scheme == "http" and port == 80)
            or (parts.scheme == "https" and port == 443)
        ) else f"{host}:{port}"
        request_lines = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "User-Agent: egress-probe/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        try:
            writer.write(request_lines.encode("ascii", errors="replace"))
            await writer.drain()
            hop.request_sent = True
            response = await asyncio.wait_for(
                self._read_response(reader), timeout=self._read_timeout
            )
        except asyncio.TimeoutError as exc:
            # 读取超时计入熔断故障
            hop.mark_error(
                f"读取响应超时（{self._read_timeout}s）",
                failure_kind="read_timeout",
            )
            return None
        except OSError as exc:
            # 读写中的连接错误：目标可达但会话异常，不计熔断故障
            hop.mark_error(f"连接读写错误: {exc}", failure_kind="other")
            return None

        hop.status_code = response["status"]
        hop.reason = response["reason"]
        if response["status"] in REDIRECT_STATUSES:
            location = response["headers"].get("location")
            hop.location = location
            if not location:
                hop.mark_error(f"收到 {response['status']} 跳转但缺少 Location 头")
                return None
            try:
                next_url = normalize_redirect(url, location)
            except PolicyError as exc:
                # 跳转目标违反策略（非 HTTP(S)、userinfo 等）：在建立任何
                # 到目标的连接前拒绝，标记为 blocked 并保留已收到的 Location
                hop.mark_blocked(str(exc))
                return None
            return next_url
        return None

    async def _read_response(self, reader) -> dict:
        # 逐字节读到头部结束（慢服务器一次只发几个字节也能正确处理）；
        # body 在 Connection: close 下读到对端关闭即可，
        # 但为保护自身只读取上限字节，超出即截断。
        header_blob = b""
        while b"\r\n\r\n" not in header_blob:
            chunk = await reader.read(1)
            if not chunk:
                break
            header_blob += chunk
            if len(header_blob) > self._max_bytes:
                raise PolicyError("响应头部超过大小上限")
        text = header_blob.decode("iso-8859-1")
        lines = text.split("\r\n")
        status_line = lines[0]
        if not status_line.startswith("HTTP/"):
            raise PolicyError(f"非法 HTTP 响应行: {status_line[:80]!r}")
        try:
            _proto, rest = status_line.split(" ", 1)
            status_text, reason = rest.split(" ", 1) if " " in rest else (rest, "")
            status = int(status_text)
        except (IndexError, ValueError) as exc:
            raise PolicyError(f"无法解析状态行: {status_line[:80]!r}") from exc
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        body_read = 0
        while body_read < self._max_bytes:
            chunk = await reader.read(4096)
            if not chunk:
                break
            body_read += len(chunk)
        return {"status": status, "reason": reason, "headers": headers}


def normalize_redirect(base_url: str, location: str) -> str:
    """规范化跳转目标，并限制 scheme 为 http/https（相对 Location 也支持）。"""
    location = location.strip()
    if len(location) > 2048:
        raise PolicyError("跳转 Location 过长")
    if location.startswith("//"):
        # 协议相对 URL：继承当前 scheme
        location = urlsplit(base_url).scheme + ":" + location
    next_url = urljoin(base_url, location)
    scheme = urlsplit(next_url).scheme.lower()
    if scheme not in ("http", "https"):
        raise PolicyError(
            f"跳转到非 HTTP(S) 协议 {scheme!r}，拒绝: {next_url}"
        )
    if urlsplit(next_url).username is not None:
        raise PolicyError("跳转目标 URL 禁止携带 userinfo")
    return next_url
