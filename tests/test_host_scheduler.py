from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys

import pytest

from p42_prizes.host_scheduler import (
    HostCapacity,
    HostSchedulerError,
    HostSchedulerPolicy,
    acknowledge_oom_count,
    release_host_slot,
    request_host_slot,
    validate_host_scheduler_state,
)
from p42_prizes.runner_queue import MemorySnapshot


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 18, 22, 0, tzinfo=timezone.utc)
POLICY = HostSchedulerPolicy(
    reserve_memory_mb=1024,
    max_swap_used_mb=128,
    memory_safety_factor=2,
    request_stale_seconds=30,
    holder_stale_seconds=20,
)


def capacity(*, available: int = 12_000, swap: int = 0, oom: int = 0, boot: str = "boot-a") -> HostCapacity:
    return HostCapacity(
        memory=MemorySnapshot(total_mb=16_000, available_mb=available, swap_used_mb=swap),
        oom_kills=oom,
        boot_id=boot,
    )


def request(path: Path, request_id: str, *, now: datetime = NOW, host_capacity: HostCapacity | None = None):
    return request_host_slot(
        path,
        host_id="chronos-dgx",
        request_id=request_id,
        board_id=f"84532:{request_id}",
        required_memory_mb=2048,
        policy=POLICY,
        capacity=host_capacity or capacity(),
        now=now,
    )


def release(path: Path, decision: dict, *, now: datetime = NOW, host_capacity: HostCapacity | None = None):
    release_host_slot(
        path,
        host_id="chronos-dgx",
        request_id=decision["request_id"],
        lease_token=decision["lease_token"],
        capacity=host_capacity or capacity(),
        now=now,
    )


def test_scheduler_serializes_all_boards_and_preserves_fifo_fairness(tmp_path: Path) -> None:
    state = tmp_path / "host" / "state.json"
    first = request(state, "board-1")
    assert first["decision"] == "acquired"

    second = request(state, "board-2")
    third = request(state, "board-3")
    assert (second["reason"], second["ticket"], second["queue_position"]) == ("host_slot_busy", 2, 0)
    assert (third["reason"], third["ticket"], third["queue_position"]) == ("host_slot_busy", 3, 1)

    release(state, first)
    assert request(state, "board-3")["reason"] == "fairness_queue"
    second = request(state, "board-2")
    assert second["decision"] == "acquired"
    release(state, second)
    third = request(state, "board-3")
    assert third["decision"] == "acquired"
    release(state, third)

    saved = validate_host_scheduler_state(json.loads(state.read_text(encoding="utf-8")))
    assert saved["holder"] is None
    assert saved["requests"] == []
    assert saved["counters"]["grants"] == 3
    assert saved["counters"]["releases"] == 3


@pytest.mark.parametrize(
    ("host_capacity", "reason"),
    [
        (capacity(available=5000), "memory_guard_tripped"),
        (capacity(swap=129), "swap_guard_tripped"),
        (HostCapacity(MemorySnapshot(total_mb=4000, available_mb=4000, swap_used_mb=0), 0, "boot-a"), "job_exceeds_host_capacity"),
    ],
)
def test_scheduler_fails_closed_on_host_capacity(tmp_path: Path, host_capacity: HostCapacity, reason: str) -> None:
    result = request(tmp_path / "state.json", "board-1", host_capacity=host_capacity)
    assert result["decision"] == "wait"
    assert result["reason"] == reason


def test_new_oom_kill_blocks_until_exact_idle_acknowledgement(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    blocked = request(state, "board-1", host_capacity=capacity(oom=1))
    # A new state takes the current cumulative counter as its baseline.
    assert blocked["decision"] == "acquired"
    release(state, blocked, host_capacity=capacity(oom=1))

    blocked = request(state, "board-2", host_capacity=capacity(oom=2))
    assert blocked["reason"] == "oom_guard_tripped"
    with pytest.raises(HostSchedulerError, match="does not match"):
        acknowledge_oom_count(
            state, host_id="chronos-dgx", expected_oom_kills=1, capacity=capacity(oom=2), now=NOW,
        )
    acknowledgement = acknowledge_oom_count(
        state, host_id="chronos-dgx", expected_oom_kills=2, capacity=capacity(oom=2), now=NOW,
    )
    assert acknowledgement["decision"] == "oom_acknowledged"
    granted = request(state, "board-2", host_capacity=capacity(oom=2))
    assert granted["decision"] == "acquired"


def test_stale_holder_and_waiter_are_reaped_without_reordering_live_requests(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    stale_holder = request(state, "board-1")
    assert request(state, "board-2")["decision"] == "wait"
    assert request(state, "board-3", now=NOW + timedelta(seconds=15))["decision"] == "wait"

    recovered = request(state, "board-3", now=NOW + timedelta(seconds=21))
    # Holder 1 is stale at 20s, but the still-live board-2 ticket remains first.
    assert recovered["reason"] == "fairness_queue"
    board_two = request(state, "board-2", now=NOW + timedelta(seconds=21))
    assert board_two["decision"] == "acquired"
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["counters"]["stale_holders_reaped"] == 1
    assert saved["holder"]["request_id"] == "board-2"
    with pytest.raises(HostSchedulerError, match="does not own"):
        release(state, stale_holder, now=NOW + timedelta(seconds=21))


def test_boot_change_discards_old_process_leases_and_resets_boot_local_oom_counter(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    request(state, "old-board", host_capacity=capacity(oom=7, boot="boot-a"))
    fresh = request(
        state,
        "new-board",
        now=NOW + timedelta(seconds=1),
        host_capacity=capacity(oom=0, boot="boot-b"),
    )
    assert fresh["decision"] == "acquired"
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["boot_id"] == "boot-b"
    assert saved["acknowledged_oom_kills"] == 0
    assert saved["counters"]["boot_resets"] == 1


def test_scheduler_rejects_permissive_or_symlinked_state(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    first = request(state, "board-1")
    state.chmod(0o640)
    with pytest.raises(HostSchedulerError, match="private and scheduler-owned"):
        request(state, "board-2")
    state.chmod(0o600)
    release(state, first)
    target = tmp_path / "target.json"
    state.rename(target)
    state.symlink_to(target)
    with pytest.raises(HostSchedulerError, match="non-symlink"):
        request(state, "board-3")


def test_bridge_fence_holds_the_global_slot_until_release(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir(mode=0o700)
    state = root / "state.json"
    meminfo = root / "meminfo"
    meminfo.write_text(
        "MemTotal:       16384000 kB\nMemAvailable:   12288000 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n",
        encoding="ascii",
    )
    oom = root / "memory.events"
    oom.write_text("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", encoding="ascii")
    boot = root / "boot_id"
    boot.write_text("12345678-1234-1234-1234-123456789abc\n", encoding="ascii")
    command = [
        sys.executable, str(ROOT / "agent" / "runtime_bridge.py"), "host-scheduler-fence",
        "--state", str(state), "--host-id", "chronos-dgx",
        "--required-memory-mb", "2048", "--reserve-memory-mb", "1024",
        "--memory-safety-factor", "2", "--max-swap-used-mb", "0",
        "--meminfo-path", str(meminfo), "--oom-events-path", str(oom), "--boot-id-path", str(boot),
    ]
    first = subprocess.Popen(
        [*command, "--request-id", "board-1", "--board-id", "84532:1"],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert first.stdout is not None
    assert first.stdout.readline().startswith("READY ")
    waiting = subprocess.run(
        [*command, "--request-id", "board-2", "--board-id", "84532:2"],
        cwd=ROOT, text=True, capture_output=True, check=True,
    )
    assert json.loads(waiting.stdout)["reason"] == "host_slot_busy"
    assert first.stdin is not None
    first.stdin.write("R")
    first.stdin.flush()
    assert first.wait(timeout=5) == 0

    second = subprocess.Popen(
        [*command, "--request-id", "board-2", "--board-id", "84532:2"],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert second.stdout is not None
    assert second.stdout.readline().startswith("READY ")
    assert second.stdin is not None
    second.stdin.write("R")
    second.stdin.flush()
    assert second.wait(timeout=5) == 0
