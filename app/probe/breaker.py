"""进程内探测熔断器：按 (规范化主机名, 端口) 隔离。

用途：网络值班员连续核验故障回调时，熔断器会暂缓对该目标的探测，
目标恢复后（冷却到期、试探收到响应）自动放行。

状态机（全部方法为同步、无 await，单事件循环内判定原子）：

    closed ── 连续 threshold 次可计故障 ──▶ open（冷却 cooldown 秒）
    open   ── 冷却到期 ──▶ half_open（仅放行一笔试探，其余请求继续拦）
    half_open ── 试探收到响应 ──▶ closed（故障计数清零）
    half_open ── 试探失败 / 中立结果 / 取消 / 总超时 ──▶ open（重新冷却）

“熔断前已放行的探测可完成，但晚到结果不得改写新一轮状态”：
每次进入 open 时令元 epoch +1；admit 发放的准入令牌携带当时 epoch，
record_* 只接受与当前 epoch 相等的结果，过期（晚到）结果直接忽略。

可计故障（与 http_probe 的分类约定一致）：
    * 全部已批准地址均连接失败（TCP 建连失败/超时、TLS 握手失败）；
    * 读取响应超时。
不计故障：策略拒绝（blocked）、TLS 证书校验失败、其他协议/读写错误。
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Callable

# 可计故障的分类标签（http_probe.HopReport.failure_kind 的子集）
COUNTABLE_KINDS = frozenset({"connect", "read_timeout"})


@dataclass(frozen=True)
class Admission:
    """admit 的判定结果。admitted=True 时调用方欠一次 record_* 回执。"""

    admitted: bool
    epoch: int = 0
    is_trial: bool = False
    state: str = "closed"  # 拒绝时的熔断状态：open | half_open
    retry_after_ms: int | None = None  # open 时为剩余冷却毫秒数；half_open 时为 None


@dataclass
class _Circuit:
    consecutive_failures: int = 0
    state: str = "closed"  # closed | open | half_open
    opened_at: float = 0.0
    trial_in_flight: bool = False
    epoch: int = 0
    touched_at: float = 0.0  # 最近一次准入/回执时间，用于闲置清扫


class CircuitBreaker:
    """按 (hostname, port) 隔离的进程内熔断器集合。"""

    def __init__(
        self,
        threshold: int = 3,
        cooldown: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        max_circuits: int = 10000,
    ) -> None:
        if threshold < 1:
            raise ValueError("熔断阈值 threshold 必须 >= 1")
        if cooldown <= 0:
            raise ValueError("熔断冷却 cooldown 必须 > 0")
        self._threshold = threshold
        self._cooldown = cooldown
        self._clock = clock
        self._max_circuits = max_circuits
        self._circuits: dict[tuple[str, int], _Circuit] = {}

    @staticmethod
    def normalize(host: str) -> str:
        """规范化主机名：小写、去结尾根域点，保证同名目标共用一条熔断。"""
        return host.lower().rstrip(".")

    @property
    def threshold(self) -> int:
        return self._threshold

    @property
    def cooldown(self) -> float:
        return self._cooldown

    # ------------------------------------------------------------ 准入判定
    def admit(self, host: str, port: int) -> Admission:
        """在任何 DNS 解析 / 连接之前调用。

        返回 admitted=True 时，调用方必须在探测结束后回执恰好一次
        （record_success / record_failure / record_neutral / record_cancelled）。
        """
        key = (self.normalize(host), port)
        now = self._clock()
        self._maybe_sweep(now)
        circuit = self._circuits.setdefault(key, _Circuit())
        circuit.touched_at = now

        if circuit.state == "closed":
            return Admission(admitted=True, epoch=circuit.epoch)
        if circuit.state == "open":
            remaining = circuit.opened_at + self._cooldown - now
            if remaining > 0:
                return Admission(
                    admitted=False,
                    state="open",
                    retry_after_ms=max(1, math.ceil(remaining * 1000)),
                )
            # 冷却到期：转入半开，只放行这一笔试探
            circuit.state = "half_open"
            circuit.trial_in_flight = True
            return Admission(admitted=True, epoch=circuit.epoch, is_trial=True)
        # half_open：试探进行中，其余并发请求继续被拦
        return Admission(admitted=False, state="half_open", retry_after_ms=None)

    # ------------------------------------------------------------ 结果回执
    def record_success(self, host: str, port: int, admission: Admission) -> None:
        """探测收到了 HTTP 响应：清零；试探成功则关闭熔断。"""
        circuit = self._current(host, port, admission)
        if circuit is None:
            return
        circuit.touched_at = self._clock()
        if admission.is_trial:
            circuit.state = "closed"
            circuit.trial_in_flight = False
            circuit.consecutive_failures = 0
        elif circuit.state == "closed":
            circuit.consecutive_failures = 0

    def record_failure(self, host: str, port: int, admission: Admission) -> None:
        """可计故障（全部地址连接失败 / 读取超时）：累计并按阈值熔断。"""
        circuit = self._current(host, port, admission)
        if circuit is None:
            return
        circuit.touched_at = self._clock()
        if admission.is_trial:
            self._reopen(circuit)
            return
        if circuit.state != "closed":
            return
        circuit.consecutive_failures += 1
        if circuit.consecutive_failures >= self._threshold:
            self._open(circuit)

    def record_neutral(self, host: str, port: int, admission: Admission) -> None:
        """中立结果（策略拒绝 / 证书校验失败 / 其他错误）：不计故障。

        试探收到中立结果视为“未收到响应”，重新冷却。
        """
        circuit = self._current(host, port, admission)
        if circuit is None:
            return
        circuit.touched_at = self._clock()
        if admission.is_trial:
            self._reopen(circuit)

    def record_cancelled(self, host: str, port: int, admission: Admission) -> None:
        """探测被取消（含单请求总超时）：不计故障；试探取消则重新冷却。"""
        circuit = self._current(host, port, admission)
        if circuit is None:
            return
        circuit.touched_at = self._clock()
        if admission.is_trial:
            self._reopen(circuit)

    # ------------------------------------------------------------ 内部状态
    def _current(
        self, host: str, port: int, admission: Admission
    ) -> _Circuit | None:
        """返回与准入令牌同一代的熔断记录；晚到结果（epoch 不等）返回 None。"""
        circuit = self._circuits.get((self.normalize(host), port))
        if circuit is None or circuit.epoch != admission.epoch:
            return None
        return circuit

    def _open(self, circuit: _Circuit) -> None:
        circuit.state = "open"
        circuit.opened_at = self._clock()
        circuit.epoch += 1  # 新的一代：此前已放行探测的晚到结果将被忽略

    def _reopen(self, circuit: _Circuit) -> None:
        circuit.trial_in_flight = False
        circuit.consecutive_failures = max(
            circuit.consecutive_failures, self._threshold
        )
        self._open(circuit)

    def _maybe_sweep(self, now: float) -> None:
        """容量上限时的惰性清扫：只清 closed 且闲置的条目，不影响熔断判定。"""
        if len(self._circuits) <= self._max_circuits:
            return
        idle_ttl = max(4 * self._cooldown, 600.0)
        stale = [
            key
            for key, c in self._circuits.items()
            if c.state == "closed"
            and (c.consecutive_failures == 0 or now - c.touched_at > idle_ttl)
        ]
        for key in stale:
            del self._circuits[key]

    # ------------------------------------------------------------ 观测
    def snapshot(self) -> list[dict]:
        """当前全部熔断条目（供 /api/v1/breakers 与测试观测）。"""
        now = self._clock()
        out: list[dict] = []
        for (host, port), c in sorted(self._circuits.items()):
            entry: dict = {
                "hostname": host,
                "port": port,
                "state": c.state,
                "consecutive_failures": c.consecutive_failures,
                "trial_in_flight": c.trial_in_flight,
                "retry_after_ms": None,
            }
            if c.state == "open":
                remaining = c.opened_at + self._cooldown - now
                entry["retry_after_ms"] = max(0, math.ceil(remaining * 1000))
            out.append(entry)
        return out
