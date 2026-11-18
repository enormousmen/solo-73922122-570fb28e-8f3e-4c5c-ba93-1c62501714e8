"""进程内熔断测试。

覆盖需求关键点：
* 同一 (规范化主机名, 端口) 连续 3 次“全部地址连接失败 / 读取超时”后冷却；
* 冷却期请求直接报告熔断与剩余时间，不解析、不连接；
* 到期仅放行一笔试探：成功则清零，失败/取消则重新冷却，其余并发仍被拦；
* 策略拒绝与证书校验失败不计故障；
* 熔断前已放行探测的晚到结果不改写新一轮状态（epoch 隔离）；
* 跳转各跳分别计数，已发请求的跳保留 request_sent 等事实。
"""

import asyncio
import socket

import pytest

from app.probe.breaker import CircuitBreaker
from app.probe.dns_client import DnsResolver
from app.probe.http_probe import Prober
from app.probe.policy import AddressPolicy


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def unused_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ModeServer:
    """可控行为裸 TCP 服务器：ok=立即 200；hang=挂起直到 release 放行。"""

    def __init__(self) -> None:
        self.mode = "ok"
        self.release = asyncio.Event()
        self.connections = 0
        self._server: asyncio.base_events.Server | None = None
        self.port = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self.release.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader, writer):  # noqa: ANN001
        self.connections += 1
        try:
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = await reader.read(1024)
                if not chunk:
                    break
                data += chunk
            if self.mode == "hang":
                await self.release.wait()
            if self.mode == "ok":
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Connection: close\r\n\r\nok"
                )
                await writer.drain()
            # mode 仍为 hang：直接关闭（不应答）
        except (ConnectionError, asyncio.CancelledError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass


@pytest.fixture()
async def mode_server():
    srv = ModeServer()
    await srv.start()
    try:
        yield srv
    finally:
        await srv.stop()


def make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=0.3):
    """与 conftest.make_prober 等效但共享传入的 breaker，便于多 prober 场景。"""
    _cert, _key, cafile = demo_certs
    resolver = DnsResolver("127.0.0.1", port=fake_dns.port, retries=0)
    return Prober(
        policy=AddressPolicy.from_cidrs(["127.0.0.1/32"]),
        resolver=resolver,
        ca_bundle=str(cafile),
        connect_timeout=0.5,
        read_timeout=read_timeout,
        tls_timeout=2.0,
        breaker=breaker,
    )


# ------------------------------------------------------------------ 状态机
class TestBreakerUnit:
    def test_opens_after_threshold_and_reports_remaining(self):
        clock = FakeClock()
        b = CircuitBreaker(threshold=3, cooldown=30.0, clock=clock)
        for _ in range(3):
            adm = b.admit("Host.Example.", 8080)  # 规范化：大小写/根域点无关
            assert adm.admitted
            b.record_failure("host.example", 8080, adm)
        adm = b.admit("HOST.EXAMPLE.", 8080)
        assert not adm.admitted
        assert adm.state == "open"
        assert 29_000 <= adm.retry_after_ms <= 30_500
        clock.advance(15)
        adm = b.admit("host.example", 8080)
        assert not adm.admitted
        assert 14_000 <= adm.retry_after_ms <= 15_500

    def test_neutral_and_success_do_not_count(self):
        clock = FakeClock()
        b = CircuitBreaker(threshold=2, cooldown=30.0, clock=clock)
        for _ in range(5):
            adm = b.admit("a", 80)
            b.record_neutral("a", 80, adm)  # 策略拒绝/证书失败等不计
            adm = b.admit("a", 80)
            assert adm.admitted  # 从未熔断
        adm = b.admit("a", 80)
        b.record_failure("a", 80, adm)
        adm = b.admit("a", 80)
        b.record_success("a", 80, adm)  # 成功清零
        adm = b.admit("a", 80)
        b.record_failure("a", 80, adm)
        adm = b.admit("a", 80)
        assert adm.admitted  # 仅连续 1 次，未达阈值

    def test_ports_are_isolated(self):
        clock = FakeClock()
        b = CircuitBreaker(threshold=1, cooldown=30.0, clock=clock)
        adm = b.admit("a", 80)
        b.record_failure("a", 80, adm)
        assert not b.admit("a", 80).admitted
        assert b.admit("a", 443).admitted  # 不同端口互不影响
        assert b.admit("b", 80).admitted  # 不同主机互不影响

    def test_single_trial_and_success_closes(self):
        clock = FakeClock()
        b = CircuitBreaker(threshold=1, cooldown=30.0, clock=clock)
        adm = b.admit("a", 80)
        b.record_failure("a", 80, adm)
        clock.advance(31)
        trial = b.admit("a", 80)
        assert trial.admitted and trial.is_trial
        # 试探在飞，其余并发继续被拦
        other = b.admit("a", 80)
        assert not other.admitted
        assert other.state == "half_open"
        assert other.retry_after_ms is None
        b.record_success("a", 80, trial)
        adm = b.admit("a", 80)
        assert adm.admitted and not adm.is_trial  # 已关闭
        assert b.snapshot()[0]["consecutive_failures"] == 0

    def test_trial_failure_reopens_with_fresh_cooldown(self):
        clock = FakeClock()
        b = CircuitBreaker(threshold=1, cooldown=30.0, clock=clock)
        adm = b.admit("a", 80)
        b.record_failure("a", 80, adm)
        clock.advance(31)
        trial = b.admit("a", 80)
        assert trial.is_trial
        b.record_failure("a", 80, trial)
        adm = b.admit("a", 80)
        assert not adm.admitted
        assert 29_000 <= adm.retry_after_ms <= 30_500  # 重新冷却完整时长

    def test_trial_neutral_and_cancel_reopen(self):
        clock = FakeClock()
        b = CircuitBreaker(threshold=1, cooldown=30.0, clock=clock)
        adm = b.admit("a", 80)
        b.record_failure("a", 80, adm)
        clock.advance(31)
        trial = b.admit("a", 80)
        b.record_neutral("a", 80, trial)  # 试探未收到响应 → 重新冷却
        assert not b.admit("a", 80).admitted
        clock.advance(31)
        trial = b.admit("a", 80)
        b.record_cancelled("a", 80, trial)  # 试探被取消 → 重新冷却
        assert not b.admit("a", 80).admitted

    def test_closed_state_cancel_is_neutral(self):
        clock = FakeClock()
        b = CircuitBreaker(threshold=1, cooldown=30.0, clock=clock)
        adm = b.admit("a", 80)
        b.record_cancelled("a", 80, adm)  # 非试探取消不计故障
        assert b.admit("a", 80).admitted

    def test_late_results_do_not_rewrite_new_epoch(self):
        clock = FakeClock()
        b = CircuitBreaker(threshold=2, cooldown=30.0, clock=clock)
        adm = b.admit("a", 80)
        b.record_failure("a", 80, adm)  # count=1
        stale = b.admit("a", 80)  # 熔断前已放行，仍在飞
        adm = b.admit("a", 80)
        b.record_failure("a", 80, adm)  # count=2 → 熔断，epoch+1
        opened_at = b._circuits[("a", 80)].opened_at
        # 晚到的失败与成功都不得改写新一轮状态
        b.record_failure("a", 80, stale)
        assert b._circuits[("a", 80)].opened_at == opened_at
        b.record_success("a", 80, stale)
        assert not b.admit("a", 80).admitted  # 熔断未被晚到成功关闭

    def test_sweep_keeps_open_circuits(self):
        clock = FakeClock()
        b = CircuitBreaker(threshold=1, cooldown=30.0, clock=clock, max_circuits=3)
        adm = b.admit("x", 80)
        b.record_failure("x", 80, adm)  # x 熔断
        for i in range(10):
            b.admit(f"h{i}", 80)
        snap = {c["hostname"]: c for c in b.snapshot()}
        assert snap["x"]["state"] == "open"  # 熔断条目不被清扫
        assert len(snap) <= 4

    def test_invalid_params_rejected(self):
        with pytest.raises(ValueError):
            CircuitBreaker(threshold=0)
        with pytest.raises(ValueError):
            CircuitBreaker(cooldown=0)


# ------------------------------------------------------------------ 端到端
class TestBreakerIntegration:
    async def test_connect_failures_open_circuit_and_block_traffic(
        self, fake_dns, demo_certs
    ):
        port = unused_port()  # 无服务监听：连接被拒绝
        fake_dns.set_zones({"dead.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=30.0)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker)

        for _ in range(3):
            hops = await prober.probe(f"http://dead.test:{port}/")
            assert hops[-1].outcome == "error"
            assert hops[-1].failure_kind == "connect"

        queries_before = len(fake_dns.queried_names)
        hops = await prober.probe(f"http://dead.test:{port}/")
        hop = hops[-1]
        assert hop.outcome == "circuit_open"
        assert hop.request_sent is False
        assert hop.resolved_addresses == []  # 未解析
        assert hop.connected_peer is None  # 未连接
        assert hop.circuit_retry_after_ms is not None
        assert 29_000 <= hop.circuit_retry_after_ms <= 30_500
        assert len(fake_dns.queried_names) == queries_before  # 确实没有发 DNS

    async def test_read_timeouts_open_circuit(self, fake_dns, demo_certs, mode_server):
        mode_server.mode = "hang"
        fake_dns.set_zones({"slow.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=30.0)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=0.3)

        for _ in range(3):
            hops = await prober.probe(f"http://slow.test:{mode_server.port}/")
            assert hops[-1].outcome == "error"
            assert hops[-1].failure_kind == "read_timeout"

        hops = await prober.probe(f"http://slow.test:{mode_server.port}/")
        assert hops[-1].outcome == "circuit_open"

    async def test_policy_blocks_do_not_count(self, fake_dns, demo_certs):
        fake_dns.set_zones({"blocked.test": ["8.8.8.8"]})  # 不在白名单
        breaker = CircuitBreaker(threshold=3, cooldown=30.0)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker)

        for _ in range(4):
            hops = await prober.probe("http://blocked.test/")
            # 每次都真实走到策略判定（blocked 而非 circuit_open）
            assert hops[-1].outcome == "blocked"
        assert breaker.snapshot()[0]["consecutive_failures"] == 0

    async def test_cert_failures_do_not_count(
        self, fake_dns, https_server, demo_certs
    ):
        # 服务器证书不含 wrong-name.test → 主机名校验失败，不计熔断
        fake_dns.set_zones({"wrong-name.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=30.0)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker)

        for _ in range(4):
            hops = await prober.probe(f"https://wrong-name.test:{https_server.port}/")
            assert hops[-1].outcome == "error"
            assert hops[-1].failure_kind == "cert"
            assert "证书校验失败" in hops[-1].error
        assert breaker.snapshot()[0]["consecutive_failures"] == 0

    async def test_success_resets_consecutive_count(
        self, fake_dns, demo_certs, mode_server
    ):
        # 同一目标先坏后好再坏：成功必须清零连续计数
        fake_dns.set_zones({"flap.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=30.0)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=0.2)
        url = f"http://flap.test:{mode_server.port}/"

        mode_server.mode = "hang"
        for _ in range(2):
            hops = await prober.probe(url)
            assert hops[-1].failure_kind == "read_timeout"
        mode_server.mode = "ok"
        hops = await prober.probe(url)  # 成功 → 清零
        assert hops[-1].outcome == "ok"
        mode_server.mode = "hang"
        for _ in range(2):
            hops = await prober.probe(url)
            assert hops[-1].failure_kind == "read_timeout"
        # 连续仅 2 次，未熔断
        hops = await prober.probe(url)
        assert hops[-1].outcome == "error"
        assert hops[-1].failure_kind == "read_timeout"

    async def test_recovery_after_cooldown(self, fake_dns, demo_certs, mode_server):
        fake_dns.set_zones({"flaky.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=0.4)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=0.2)
        url = f"http://flaky.test:{mode_server.port}/"

        mode_server.mode = "hang"
        for _ in range(3):
            await prober.probe(url)
        hops = await prober.probe(url)
        assert hops[-1].outcome == "circuit_open"

        mode_server.mode = "ok"  # 目标恢复
        await asyncio.sleep(0.5)  # 冷却到期
        hops = await prober.probe(url)  # 唯一试探成功 → 清零
        assert hops[-1].outcome == "ok"
        assert hops[-1].status_code == 200
        hops = await prober.probe(url)  # 已正常放行
        assert hops[-1].outcome == "ok"
        entry = breaker.snapshot()[0]
        assert entry["state"] == "closed"
        assert entry["consecutive_failures"] == 0

    async def test_trial_failure_reopens(self, fake_dns, demo_certs, mode_server):
        fake_dns.set_zones({"flaky.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=0.4)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=0.2)
        url = f"http://flaky.test:{mode_server.port}/"

        mode_server.mode = "hang"
        for _ in range(3):
            await prober.probe(url)
        assert (await prober.probe(url))[-1].outcome == "circuit_open"

        await asyncio.sleep(0.5)  # 冷却到期，但目标仍未恢复
        hops = await prober.probe(url)  # 试探：读取超时
        assert hops[-1].outcome == "error"
        assert hops[-1].failure_kind == "read_timeout"
        hops = await prober.probe(url)  # 重新冷却，继续拦截
        assert hops[-1].outcome == "circuit_open"
        assert hops[-1].circuit_retry_after_ms is not None

    async def test_only_one_trial_admitted(self, fake_dns, demo_certs, mode_server):
        fake_dns.set_zones({"flaky.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=0.4)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=2.0)
        url = f"http://flaky.test:{mode_server.port}/"

        mode_server.mode = "hang"
        for _ in range(3):
            await prober.probe(url)
        await asyncio.sleep(0.5)  # 冷却到期

        trial_task = asyncio.create_task(prober.probe(url))  # 占住唯一试探
        await asyncio.sleep(0.1)  # 确保试探已在飞
        hops = await prober.probe(url)  # 并发请求继续被拦
        assert hops[-1].outcome == "circuit_open"
        assert hops[-1].circuit_retry_after_ms is None  # 半开：无剩余时间可报

        mode_server.mode = "ok"
        mode_server.release.set()  # 放行挂起的试探连接
        trial_hops = await trial_task
        assert trial_hops[-1].outcome == "ok"
        hops = await prober.probe(url)  # 熔断已关闭
        assert hops[-1].outcome == "ok"

    async def test_cancelled_trial_reopens(self, fake_dns, demo_certs, mode_server):
        fake_dns.set_zones({"flaky.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=0.4)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=5.0)
        url = f"http://flaky.test:{mode_server.port}/"

        mode_server.mode = "hang"
        for _ in range(3):
            await prober.probe(url)
        await asyncio.sleep(0.5)

        trial_task = asyncio.create_task(prober.probe(url))  # 试探在飞
        await asyncio.sleep(0.1)
        trial_task.cancel()  # 模拟客户端断开 / 总超时取消
        with pytest.raises(asyncio.CancelledError):
            await trial_task
        hops = await prober.probe(url)  # 试探取消 → 重新冷却
        assert hops[-1].outcome == "circuit_open"

    async def test_late_success_does_not_close_circuit(
        self, fake_dns, demo_certs, mode_server
    ):
        fake_dns.set_zones({"flaky.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=30.0)
        url = f"http://flaky.test:{mode_server.port}/"
        fast = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=0.2)
        slow = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=5.0)

        mode_server.mode = "hang"
        for _ in range(2):  # count=2
            await fast.probe(url)
        slow_task = asyncio.create_task(slow.probe(url))  # 熔断前放行，在飞
        await asyncio.sleep(0.1)
        await fast.probe(url)  # count=3 → 熔断
        assert (await fast.probe(url))[-1].outcome == "circuit_open"

        mode_server.mode = "ok"
        mode_server.release.set()  # 慢探测此刻才成功返回（晚到结果）
        late_hops = await slow_task
        assert late_hops[-1].outcome == "ok"

        hops = await fast.probe(url)  # 晚到成功不得关闭新一轮熔断
        assert hops[-1].outcome == "circuit_open"

    async def test_late_failure_does_not_extend_cooldown(
        self, fake_dns, demo_certs, mode_server
    ):
        fake_dns.set_zones({"flaky.test": ["127.0.0.1"]})
        breaker = CircuitBreaker(threshold=3, cooldown=30.0)
        url = f"http://flaky.test:{mode_server.port}/"
        fast = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=0.2)
        slow = make_breaker_prober(fake_dns, demo_certs, breaker, read_timeout=0.8)

        mode_server.mode = "hang"
        for _ in range(2):  # count=2
            await fast.probe(url)
        slow_task = asyncio.create_task(slow.probe(url))  # 在飞，0.8s 后超时
        await asyncio.sleep(0.1)
        await fast.probe(url)  # count=3 → 熔断，opened_at=此刻
        opened_at = breaker._circuits[("flaky.test", mode_server.port)].opened_at
        await slow_task  # 晚到的读取超时
        # 晚到失败不得推迟熔断起点（否则冷却被无限延长）
        assert breaker._circuits[("flaky.test", mode_server.port)].opened_at == opened_at

    async def test_redirect_hops_counted_separately(
        self, fake_dns, http_server, demo_certs
    ):
        port = unused_port()  # 跳转目标连接必失败
        fake_dns.set_zones({
            "start.test": ["127.0.0.1"],
            "dead.test": ["127.0.0.1"],
        })
        http_server.route(
            "start.test", "/go",
            status=302,
            headers=[("Location", f"http://dead.test:{port}/end")],
        )
        breaker = CircuitBreaker(threshold=3, cooldown=30.0)
        prober = make_breaker_prober(fake_dns, demo_certs, breaker)

        for _ in range(3):
            hops = await prober.probe(f"http://start.test:{http_server.port}/go")
            assert [h.outcome for h in hops] == ["redirected", "error"]
            assert hops[0].request_sent is True  # 第一跳事实保留
            assert hops[0].status_code == 302
            assert hops[1].failure_kind == "connect"

        hops = await prober.probe(f"http://start.test:{http_server.port}/go")
        # start.test 一直收到响应（302），不计故障、不熔断；
        # dead.test 已熔断：第二跳直接报告，不再解析/连接
        assert [h.outcome for h in hops] == ["redirected", "circuit_open"]
        assert hops[0].request_sent is True
        assert hops[1].request_sent is False
        assert hops[1].resolved_addresses == []
