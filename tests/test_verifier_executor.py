from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from p42_prizes.runner_queue import MemorySnapshot
from p42_prizes.verifier_executor import (
    BoardExecution, ExecutorPolicy, HostCapacity, VerifierExecutor, VerifierExecutorError,
    acquire_singleton_lock, holder_expired,
    host_capacity_snapshot,
)


def test_same_boot_expiry_is_monotonic_and_ignores_clock_jumps() -> None:
    holder = {"boot_id": "boot-a", "deadline_monotonic_ns": 200}
    # Realtime may jump in either direction; it is deliberately absent from
    # the policy and cannot affect the result.
    assert holder_expired(holder, boot_id="boot-a", monotonic_ns=199) is False
    assert holder_expired(holder, boot_id="boot-a", monotonic_ns=200) is True
    assert holder_expired(holder, boot_id="boot-b", monotonic_ns=1) is True


def test_split_brain_executor_is_rejected_by_os_lock(tmp_path: Path) -> None:
    first = acquire_singleton_lock(tmp_path / "executor.lock")
    try:
        with pytest.raises(VerifierExecutorError, match="another verifier executor"):
            acquire_singleton_lock(tmp_path / "executor.lock")
    finally:
        os.close(first)
    second = acquire_singleton_lock(tmp_path / "executor.lock")
    os.close(second)


def test_capacity_reads_attested_effective_cgroup_memory_and_oom_counter(tmp_path: Path, monkeypatch) -> None:
    cgroup_root = tmp_path / "cgroup"
    cgroup = cgroup_root / "user.slice/app.slice"
    cgroup.mkdir(parents=True)
    (cgroup / "memory.current").write_text(str(1024**3), encoding="ascii")
    (cgroup / "memory.max").write_text(str(10 * 1024**3), encoding="ascii")
    (cgroup / "memory.events").write_text("low 0\nhigh 2\noom 3\noom_kill 4\n", encoding="ascii")
    attestation = tmp_path / "cgroup.json"
    attestation.write_text(json.dumps({
        "schema_version": "p42-rootless-docker-cgroup/v1", "boot_id": "boot-a",
        "docker_id": "daemon-a", "cgroup_path": "/user.slice/app.slice",
        "probe_cgroup_path": "/user.slice/app.slice/docker-probe.scope",
        "memory_current": 1024**3, "memory_max": 10 * 1024**3, "oom_kill": 4,
        "required_container_memory_mb": 8192, "daemon_headroom_mb": 2048,
    }), encoding="utf-8")
    monkeypatch.setattr("p42_prizes.verifier_executor.read_boot_id", lambda: "boot-a")
    capacity = host_capacity_snapshot(attestation, cgroup_root=cgroup_root)
    assert capacity.oom_kills == 4
    assert capacity.memory == MemorySnapshot(10 * 1024, 9 * 1024, 0)

    (cgroup / "memory.max").write_text("max\n", encoding="ascii")
    with pytest.raises(VerifierExecutorError, match="finite and numeric"):
        host_capacity_snapshot(attestation, cgroup_root=cgroup_root)


class FakeDocker:
    def __init__(self, events: list[str], *, fail=False):
        self.events = events
        self.fail = fail
        self.docker_host = "unix:///private/docker.sock"

    def reconcile(self):
        self.events.append("reconcile")
        if self.fail:
            raise VerifierExecutorError("orphans remain")


class FakeProcess:
    pid = 4242
    returncode = 0

    def __init__(self, events): self.events = events
    def communicate(self, timeout=None):
        self.events.append(f"worker:{timeout}")
        return json.dumps({"reason": "queue_empty"}) + "\n", ""


class FailedProcess(FakeProcess):
    returncode = 9

    def communicate(self, timeout=None):
        self.events.append(f"worker:{timeout}")
        return "", "worker crashed"


class UninterruptibleProcess(FakeProcess):
    returncode = None

    def communicate(self, timeout=None):
        self.events.append(f"worker:{timeout}")
        raise subprocess.TimeoutExpired("worker", timeout)

    def poll(self):
        return None

    def wait(self, timeout=None):
        self.events.append(f"wait:{timeout}")
        raise subprocess.TimeoutExpired("worker", timeout)


def executor(
    tmp_path: Path,
    docker,
    monotonic=lambda: 100,
    *,
    monotonic_seconds=lambda: 100.0,
    process_identity_reader=lambda _pid: None,
):
    board = BoardExecution("board-1", tmp_path / "queue.json", tmp_path / "tx", tmp_path / "stage",
                           tmp_path / "alerts.log", 100, 7)
    capacity = HostCapacity(MemorySnapshot(10_000, 9_000, 0), 0, "boot-a")
    return VerifierExecutor(
        boards={board.board_id: board}, state_path=tmp_path / "private" / "state.json", docker=docker,
        bridge_path=Path("/opt/p42/agent/runtime_bridge.py"), python="/usr/bin/python3",
        policy=ExecutorPolicy(reserve_memory_mb=100, max_swap_used_mb=0, memory_safety_factor=2),
        boot_id_reader=lambda: "boot-a", monotonic_ns=monotonic, monotonic=monotonic_seconds,
        capacity_reader=lambda: capacity, process_identity_reader=process_identity_reader,
    )


def request():
    return {"schema_version": "p42-verifier-executor-request/v1", "request_id": "sha256:" + "a" * 64,
            "board_id": "board-1", "chain_timestamp": "1800000000"}


def test_executor_reconciles_before_lease_and_after_intrinsic_deadline_scope(tmp_path: Path, monkeypatch) -> None:
    events = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: FakeProcess(events))
    result = executor(tmp_path, FakeDocker(events)).execute(request())
    assert result == {"reason": "queue_empty"}
    assert events[0] == "reconcile" and events[-1] == "reconcile"
    assert events[1] == "worker:6.0"
    assert json.loads((tmp_path / "private/state.json").read_text())["holder"] is None


def test_zero_cleanup_oom_delta_is_persisted_and_next_admission_runs(tmp_path: Path, monkeypatch) -> None:
    events = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: FakeProcess(events))
    service = executor(tmp_path, FakeDocker(events))
    assert service.execute(request()) == {"reason": "queue_empty"}
    cleanup = json.loads(service.state_path.read_text())["oom_attribution"]
    assert cleanup["terminal_outcome"] == "success"
    assert cleanup["oom_delta"] == cleanup["oom_kill_delta"] == 0
    assert service.execute(request()) == {"reason": "queue_empty"}


def test_uninterruptible_worker_never_blocks_service_and_is_durably_alerted(
    tmp_path: Path, monkeypatch,
) -> None:
    events = []
    process = UninterruptibleProcess(events)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(os, "killpg", lambda pid, sig: events.append(f"signal:{sig}"))
    service = executor(tmp_path, FakeDocker(events), process_identity_reader=lambda _pid: 777)
    with pytest.raises(VerifierExecutorError, match="durably alerted"):
        service.execute(request())
    alert = (tmp_path / "alerts.log").read_text()
    assert request()["request_id"] in alert and "uninterruptible" in alert
    state = json.loads(service.state_path.read_text())
    assert state["holder"] is None
    assert state["oom_attribution"]["terminal_outcome"] == "deadline_exceeded_child_unreaped"
    assert state["admission_stop"]["child_pid"] == process.pid
    assert state["admission_stop"]["child_start_time_ticks"] == 777
    assert process.poll() is None
    before = list(events)
    assert service.execute(request()) == {
        "reason": "unreaped_child_admission_stop", "selected_job_id": None,
    }
    assert events == before


def test_recovery_clears_unreaped_child_stop_only_after_identity_is_absent(
    tmp_path: Path, monkeypatch,
) -> None:
    events = []
    process = UninterruptibleProcess(events)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(os, "killpg", lambda pid, sig: events.append(f"signal:{sig}"))
    service = executor(tmp_path, FakeDocker(events), process_identity_reader=lambda _pid: 777)
    with pytest.raises(VerifierExecutorError, match="durably alerted"):
        service.execute(request())

    still_live = executor(tmp_path, FakeDocker(events), process_identity_reader=lambda _pid: 777)
    with pytest.raises(VerifierExecutorError, match="remains present"):
        still_live.recover()
    assert json.loads(still_live.state_path.read_text())["admission_stop"] is not None

    gone = executor(tmp_path, FakeDocker(events), process_identity_reader=lambda _pid: None)
    gone.recover()
    recovered = json.loads(gone.state_path.read_text())
    assert recovered["admission_stop"] is None
    assert recovered["last_recovery"] == "same_boot_unreaped_child_proven_absent"


def test_communicate_and_reap_timeouts_share_one_spawn_deadline(tmp_path: Path, monkeypatch) -> None:
    events = []
    clock = iter([100.0, 100.25])
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: FakeProcess(events))
    service = executor(
        tmp_path,
        FakeDocker(events),
        monotonic_seconds=lambda: next(clock),
    )

    assert service.execute(request()) == {"reason": "queue_empty"}
    assert events[1] == "worker:5.75"


def test_orphan_reconcile_failure_prevents_any_new_lease(tmp_path: Path, monkeypatch) -> None:
    events = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("worker must not start"))
    with pytest.raises(VerifierExecutorError, match="orphans remain"):
        executor(tmp_path, FakeDocker(events, fail=True)).execute(request())
    assert events == ["reconcile"]


def test_admission_uses_effective_cgroup_headroom_without_double_counting_daemon_reserve(
    tmp_path: Path, monkeypatch,
) -> None:
    events = []
    commands = []

    def popen(command, **_kwargs):
        commands.append(command)
        return FakeProcess(events)

    monkeypatch.setattr(subprocess, "Popen", popen)
    service = executor(tmp_path, FakeDocker(events))
    service.capacity_reader = lambda: HostCapacity(MemorySnapshot(300, 199, 0), 0, "boot-a", 200, 100)
    service._boot_id, service._acknowledged_oom_kills = "boot-a", 0
    assert service.execute(request())["reason"] == "memory_guard_tripped"
    service.capacity_reader = lambda: HostCapacity(MemorySnapshot(300, 200, 0), 0, "boot-a", 200, 100)
    assert service.execute(request()) == {"reason": "queue_empty"}
    command = commands[0]
    assert command[command.index("--reserve-memory-mb") + 1] == "0"
    assert command[command.index("--available-memory-mb") + 1] == "200"


def test_holder_state_is_boot_bound_monotonic_not_wall_clock(tmp_path: Path, monkeypatch) -> None:
    events = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: FakeProcess(events))
    observed = iter([5_000_000_000])
    service = executor(tmp_path, FakeDocker(events), monotonic=lambda: next(observed))
    service.execute(request())
    raw = (tmp_path / "private/state.json").read_text()
    assert "expires_at_utc" not in raw and "deadline_monotonic_ns" not in raw  # cleared only after reconciliation


def test_same_boot_restart_preserves_oom_guard_and_reboot_resets_only_after_reconcile(tmp_path: Path) -> None:
    events = []
    service = executor(tmp_path, FakeDocker(events))
    service._boot_id = "boot-a"
    service._acknowledged_oom_kills = 0
    service._acknowledged_oom_events = 0
    service._write_state(None)
    service.capacity_reader = lambda: HostCapacity(MemorySnapshot(10_000, 9_000, 0), 1, "boot-a")
    service.recover()
    assert service.execute(request())["reason"] == "oom_guard_tripped"

    rebooted = executor(tmp_path, FakeDocker(events))
    rebooted.capacity_reader = lambda: HostCapacity(MemorySnapshot(10_000, 9_000, 0), 0, "boot-b")
    rebooted.recover()
    assert rebooted._boot_id == "boot-b"
    assert rebooted._acknowledged_oom_kills == 0
    assert events.count("reconcile") >= 2


def test_post_worker_oom_delta_is_durably_attributed_and_guards_next_admission(
    tmp_path: Path, monkeypatch,
) -> None:
    events = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: FakeProcess(events))
    baseline = HostCapacity(MemorySnapshot(10_000, 9_000, 0), 2, "boot-a", oom_events=3)
    completed = HostCapacity(MemorySnapshot(10_000, 9_000, 0), 3, "boot-a", oom_events=5)
    snapshots = iter([baseline, completed, completed])
    service = executor(tmp_path, FakeDocker(events))
    service._boot_id = "boot-a"
    service._acknowledged_oom_kills = 2
    service._acknowledged_oom_events = 3
    service.capacity_reader = lambda: next(snapshots)

    assert service.execute(request()) == {"reason": "queue_empty"}
    state = json.loads(service.state_path.read_text())
    assert state["holder"] is None
    assert state["oom_attribution"] == {
        "schema_version": "p42-verifier-oom-attribution/v1",
        "request_id": request()["request_id"], "board_id": "board-1",
        "start_boot_id": "boot-a", "end_boot_id": "boot-a",
        "start_oom": 3, "start_oom_kill": 2, "end_oom": 5, "end_oom_kill": 3,
        "oom_delta": 2, "oom_kill_delta": 1,
        "terminal_outcome": "success",
    }
    assert service.execute(request())["reason"] == "oom_guard_tripped"


def test_worker_crash_oom_delta_keeps_request_attribution(tmp_path: Path, monkeypatch) -> None:
    events = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: FailedProcess(events))
    capacities = iter([
        HostCapacity(MemorySnapshot(10_000, 9_000, 0), 0, "boot-a", oom_events=0),
        HostCapacity(MemorySnapshot(10_000, 9_000, 0), 1, "boot-a", oom_events=1),
    ])
    service = executor(tmp_path, FakeDocker(events))
    service.capacity_reader = lambda: next(capacities)
    with pytest.raises(VerifierExecutorError, match="worker crashed"):
        service.execute(request())
    attribution = json.loads(service.state_path.read_text())["oom_attribution"]
    assert attribution["request_id"] == request()["request_id"]
    assert attribution["terminal_outcome"] == "worker_failed"
    assert attribution["end_oom_kill"] == 1


def test_restart_and_reboot_preserve_active_request_oom_attribution(tmp_path: Path) -> None:
    events = []
    service = executor(tmp_path, FakeDocker(events))
    service._boot_id = "boot-a"
    service._acknowledged_oom_kills = 4
    service._acknowledged_oom_events = 5
    holder = {
        "request_id": request()["request_id"], "board_id": "board-1", "boot_id": "boot-a",
        "started_monotonic_ns": 10, "deadline_monotonic_ns": 20, "pid": 42,
        "start_oom": 5, "start_oom_kill": 4,
    }
    service._write_state(holder)
    service.capacity_reader = lambda: HostCapacity(MemorySnapshot(10_000, 9_000, 0), 5, "boot-a", oom_events=7)
    service.recover()
    same_boot = json.loads(service.state_path.read_text())["oom_attribution"]
    assert same_boot["terminal_outcome"] == "executor_restart_recovery"
    assert same_boot["request_id"] == request()["request_id"]

    service._write_state(holder)
    rebooted = executor(tmp_path, FakeDocker(events))
    rebooted.capacity_reader = lambda: HostCapacity(MemorySnapshot(10_000, 9_000, 0), 0, "boot-b", oom_events=0)
    rebooted.recover()
    across_boot = json.loads(rebooted.state_path.read_text())["oom_attribution"]
    assert across_boot["terminal_outcome"] == "reboot_during_active_request"
    assert across_boot["start_boot_id"] == "boot-a" and across_boot["end_boot_id"] == "boot-b"
    assert rebooted.execute(request())["reason"] == "oom_guard_tripped"
