"""The relaunch wrapper (plan 1.4c). Offline: the run and the tunnel are stand-ins."""

from __future__ import annotations

from eval.run_resilient import supervise


class _Sim:
    def __init__(self, codes, tunnel_ok=True):
        self.codes, self.tunnel_ok = list(codes), tunnel_ok
        self.runs = self.tunnels = 0

    def run(self):
        self.runs += 1
        return self.codes.pop(0)

    def ensure_tunnel(self):
        self.tunnels += 1
        return self.tunnel_ok


def _supervise(sim, max_relaunches=5):
    return supervise(sim.run, sim.ensure_tunnel, max_relaunches=max_relaunches,
                     sleep=lambda s: None)


def test_a_run_that_finishes_is_not_relaunched():
    sim = _Sim([0])
    assert _supervise(sim) == 0 and sim.runs == 1


def test_a_stop_on_a_failed_call_is_relaunched_after_rebuilding_the_tunnel():
    """Exit status 2 = the harness stopped at a failed LLM call (Change 16)."""
    sim = _Sim([2, 2, 0])
    assert _supervise(sim) == 0
    assert sim.runs == 3 and sim.tunnels == 3      # tunnel checked before every run


def test_it_gives_up_after_the_relaunch_limit():
    sim = _Sim([2] * 10)
    assert _supervise(sim, max_relaunches=3) == 2
    assert sim.runs == 4                            # the first run + 3 relaunches


def test_any_other_exit_status_is_not_retried():
    """A crash of the harness itself is a bug; repeating it would not help."""
    sim = _Sim([1, 0])
    assert _supervise(sim) == 1 and sim.runs == 1


def test_no_run_starts_without_a_working_tunnel():
    sim = _Sim([0], tunnel_ok=False)
    assert _supervise(sim) == 3 and sim.runs == 0
